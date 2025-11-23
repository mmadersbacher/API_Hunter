use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::cli::{Cli, Commands};
use api_hunter::output::{write_csv, write_top_txt, RawEvent};
use std::time::Duration;

pub async fn run_from_cli(cli: Cli) -> anyhow::Result<()> {
    // Configure logging based on global flags.
    // Keep external crates (reqwest/hyper) at INFO to avoid flooding the CLI,
    // and ensure the noisy `js_fisher` gatherer doesn't spew even in our crate's debug mode.
    use tracing_subscriber::EnvFilter;
    let crate_level = if cli.debug { "debug" } else if cli.verbose { "info" } else { "warn" };
    // Build a filter string that sets our crate to the requested level but limits external noise.
    let filter_str = format!(
        "api_hunter={crate},api_hunter::gather::js_fisher=info,reqwest=info,hyper=info,h2=info",
        crate = crate_level
    );
    let env_filter = EnvFilter::try_new(&filter_str).unwrap_or_else(|_| EnvFilter::new(crate_level));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_ansi(true)
        .with_target(false)
        .init();

    match cli.command {
        Commands::Scan { target, out, mut concurrency, mut per_host, aggressive, mut with_gau, mut with_wayback, resume, mut retries, timeout, backoff_initial_ms, backoff_max_ms, lite, confirm_aggressive } => {
            tracing::info!(target=%target, out=%out, concurrency, per_host, aggressive, with_gau, with_wayback, retries, timeout, "Starting scan");
            if aggressive && !confirm_aggressive {
                eprintln!("Refusing to run in --aggressive mode without explicit confirmation.");
                std::process::exit(1);
            }
            if lite {
                concurrency = 8;
                per_host = 2;
                with_gau = false;
                with_wayback = false;
                retries = 1;
                tracing::info!("lite mode active: low concurrency and disabled heavy gatherers");
            }
            if retries > 10 { retries = 10; }
            run_scan(target, out, concurrency, per_host, aggressive, with_gau, with_wayback, resume, lite, retries, timeout, backoff_initial_ms, backoff_max_ms).await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_scan(target: String, out: String, concurrency: u16, per_host: u16, aggressive: bool, with_gau: bool, with_wayback: bool, resume: Option<String>, lite: bool, retries: u8, timeout: u64, backoff_initial_ms: u64, backoff_max_ms: u64) -> anyhow::Result<()> {
    let out_dir = PathBuf::from(&out);
    api_hunter::utils::ensure_dir(&out_dir)?;

    // Normalize the provided `target`: if the user passed a full URL (https://...)
    // extract the host so downstream gatherers that build `https://{host}` don't
    // end up with malformed `https://https://...` URLs.
    let domain = if target.starts_with("http://") || target.starts_with("https://") {
        match url::Url::parse(&target) {
            Ok(u) => u.host_str().map(|s| s.to_string()).unwrap_or(target.clone()),
            Err(_) => target.clone(),
        }
    } else {
        target.clone()
    };

    if let Some(resume_path) = resume {
        let events = api_hunter::utils::read_jsonl(PathBuf::from(resume_path))?;
        let refs: Vec<&RawEvent> = events.iter().collect();
        let jsonl_path = out_dir.join("target_raw.jsonl");
        let csv_path = out_dir.join("target_apis_sorted.csv");
        let top_path = out_dir.join("target_top.txt");
        api_hunter::output::write_jsonl(&jsonl_path, &refs)?;
        write_csv(&csv_path, &refs)?;
        write_top_txt(&top_path, &refs)?;
        println!("Wrote resumed outputs to {}", out_dir.display());
        return Ok(());
    }

    // Discover and gather candidates
    tracing::info!("Starting discovery phase for domain: {}", domain);
    let mut candidates: Vec<String> = Vec::new();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(1024);
    
    if with_wayback {
        tracing::debug!("Starting external waybackurls tool");
        let txc = tx.clone(); let t_target = domain.clone();
        tokio::spawn(async move { let _ = api_hunter::external::tools::try_run_waybackurls(&t_target, txc).await; });
    }
    if with_gau {
        tracing::debug!("Starting external gau tool");
        let txc = tx.clone(); let g_target = domain.clone();
        tokio::spawn(async move { let _ = api_hunter::external::tools::try_run_gau(&g_target, txc).await; });
    }

    // Bound gatherer calls so a slow remote or parsing bug won't hang discovery.
    if !with_wayback {
        tracing::debug!("Querying Wayback Machine CDX API...");
        match tokio::time::timeout(Duration::from_secs(5), api_hunter::gather::wayback::wayback_urls(&domain)).await {
            Ok(Ok(mut w)) => {
                let count = w.len();
                candidates.append(&mut w);
                tracing::info!("Wayback CDX: {} URLs found", count);
            }
            Ok(Err(e)) => { tracing::warn!("Wayback gather failed: {}", e); }
            Err(_) => { tracing::warn!("Wayback gather timed out (5s)"); }
        }
    }

    tracing::debug!("Fetching and analyzing JavaScript assets...");
    match tokio::time::timeout(Duration::from_secs(5), api_hunter::gather::js_fisher::fetch_and_extract(&domain)).await {
        Ok(Ok(js_endpoints)) => {
            let count = js_endpoints.len();
            candidates.extend(js_endpoints);
            tracing::info!("JS extraction: {} endpoints found", count);
        }
        Ok(Err(e)) => { tracing::warn!("JS extraction failed: {}", e); }
        Err(_) => { tracing::warn!("JS extraction timed out (5s)"); }
    }

    // Drop tx so the receiver knows no more data is coming
    drop(tx);
    
    let collect_task = tokio::spawn(async move {
        let start = std::time::Instant::now();
        let mut out = Vec::new();
        while start.elapsed().as_secs() < 2 {
            if let Some(line) = rx.recv().await { out.push(line); }
            else { break; }
        }
        out
    });
    
    tracing::debug!("Waiting for external tool results (max 2s)...");
    if let Ok(mut s) = collect_task.await {
        let ext_count = s.len();
        if ext_count > 0 {
            tracing::info!("External tools: {} URLs", ext_count);
        }
        candidates.append(&mut s);
    }

    candidates.sort(); candidates.dedup();
    let total_discovered = candidates.len();
    tracing::info!("Discovery complete: {} total URLs (before filtering)", total_discovered);
    
    let filtered: Vec<String> = candidates.into_iter().filter(|u| api_hunter::filter::api_patterns::is_api_candidate(u)).collect();
    let filtered_count = filtered.len();
    tracing::info!("Filtered to {} API candidates ({}% pass rate)", filtered_count, if total_discovered > 0 { (filtered_count * 100) / total_discovered } else { 0 });

    let client = reqwest::Client::builder().user_agent("api-hunter/0.1").build()?;
    let throttle = api_hunter::probe::throttle::Throttle::new(concurrency as usize, per_host as usize);

    let jsonl_path = out_dir.join("target_raw.jsonl");
    let (tx_jsonl, rx_jsonl) = tokio::sync::mpsc::channel::<RawEvent>(1024);
    let _jh_jsonl = api_hunter::output::spawn_jsonl_writer(jsonl_path.clone(), rx_jsonl);

    let csv_stream_path = out_dir.join("target_apis_stream.csv");
    let (tx_csv, rx_csv) = tokio::sync::mpsc::channel::<RawEvent>(1024);
    let _jh_csv = api_hunter::output::spawn_csv_writer(csv_stream_path.clone(), rx_csv);

    let probe_timeout = if lite { 3 } else { timeout };

    use futures::stream::{self, StreamExt};
    let cand_vec = filtered;
    let client_ref = &client;
    let throttle_ref = &throttle;

    let total = cand_vec.len();
    let processed = Arc::new(AtomicUsize::new(0));
    let mut results: Vec<RawEvent> = Vec::new();

    let stream = stream::iter(cand_vec.into_iter())
        .map(|cand| {
            let client = client_ref;
            let throttle = throttle_ref;
            let tx_jsonl = tx_jsonl.clone();
            let tx_csv = tx_csv.clone();
            let processed = processed.clone();
            async move {
                let idx = processed.fetch_add(1, Ordering::SeqCst) + 1;
                tracing::debug!("[{}/{}] Probing: {}", idx, total, cand);
                let res = api_hunter::probe::http_probe::probe_url(client, &cand, probe_timeout, Some(throttle), retries as usize, backoff_initial_ms, backoff_max_ms, aggressive).await;
                match res {
                    Ok(mut ev) => {
                        ev.score = api_hunter::scoring::score::score_event(&ev);
                        if let Some(ref js) = ev.json_sample { let keys = api_hunter::enrich::json_shape::detect_keys(js); for k in keys.iter().take(5) { ev.notes.push(format!("key:{}", k)); } }
                        let _ = tx_jsonl.send(ev.clone()).await;
                        let _ = tx_csv.send(ev.clone()).await;
                        tracing::info!("[{}/{}] {} -> {} (score: {})", idx, total, cand, ev.status, ev.score);
                        Some(ev)
                    }
                    Err(e) => {
                        tracing::debug!("[{}/{}] {} -> Error: {}", idx, total, cand, e);
                        None
                    }
                }
            }
        })
        .buffer_unordered(concurrency as usize);

    tracing::info!("Starting HTTP probe phase: {} candidates with concurrency {}", total, concurrency);
    // Use the CLI `timeout` as the global scan timeout so callers can control total run time.
    let scan_timeout = std::time::Duration::from_secs(timeout);

    let scan_fut = async {
        futures::pin_mut!(stream);
        while let Some(opt) = stream.next().await { if let Some(ev) = opt { results.push(ev); } }
        Ok::<(), anyhow::Error>(())
    };

    match tokio::time::timeout(scan_timeout, scan_fut).await {
        Ok(Ok(_)) => tracing::info!("Probe stream completed within {}s timeout", timeout),
        Ok(Err(e)) => tracing::error!("Probe stream aborted with error: {}", e),
        Err(_) => tracing::warn!("Global scan timeout reached ({}s), aborting remaining probes", timeout),
    }

    tracing::debug!("Flushing output writers...");
    drop(tx_jsonl); drop(tx_csv);
    if let Err(_) = tokio::time::timeout(std::time::Duration::from_secs(5), async { let _ = _jh_jsonl.await; let _ = _jh_csv.await; }).await {
        tracing::warn!("Output writers did not finish within 5s");
    }

    let refs: Vec<&RawEvent> = results.iter().collect();
    let success_count = refs.len();
    tracing::info!("Generating final reports for {} successful probes...", success_count);
    
    let csv_path = out_dir.join("target_apis_sorted.csv");
    let top_path = out_dir.join("target_top.txt");
    write_csv(&csv_path, &refs)?;
    write_top_txt(&top_path, &refs)?;

    println!("\nScan complete - {} APIs found", success_count);
    println!("Outputs written to: {}", out_dir.display());
    Ok(())
}
