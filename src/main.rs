use std::path::PathBuf;

use clap::Parser;
// removed unused serde_json::json import

mod config;
mod output;
mod utils;
mod probe;
mod discover;
mod gather;
mod enrich;
mod scoring;
mod filter;
mod external;

use crate::output::{write_csv, write_jsonl, write_top_txt, RawEvent};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// api-hunter: simple starter scaffold
#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Run a scan against a domain or file with domains
    Scan {
        /// Target domain (e.g. example.com) or path to file with newline-delimited domains
        target: String,

        /// Output directory
        #[arg(short, long, default_value = "./results")]
        out: String,

        /// Global concurrency
        #[arg(long, default_value_t = 50)]
        concurrency: u16,

        /// Per-host limit
        #[arg(long, default_value_t = 6)]
        per_host: u16,

        /// Enable aggressive features (ffuf bruteforce)
        #[arg(long, default_value_t = false)]
        aggressive: bool,

        /// Use gau if available
        #[arg(long, default_value_t = false)]
        with_gau: bool,

        /// Use waybackurls if available
        #[arg(long, default_value_t = false)]
        with_wayback: bool,

        /// Resume from existing JSONL
        #[arg(long)]
        resume: Option<String>,
        /// Number of probe retries (default: 3, max: 10)
        #[arg(long, default_value_t = 3_u8)]
        retries: u8,
        /// Per-request timeout in seconds (default: 10)
        #[arg(long, default_value_t = 10_u64)]
        timeout: u64,
        /// Initial backoff in milliseconds (default: 200)
        #[arg(long, default_value_t = 200_u64)]
        backoff_initial_ms: u64,
        /// Maximum backoff in milliseconds (default: 5000)
        #[arg(long, default_value_t = 5000_u64)]
        backoff_max_ms: u64,
        /// Conservative low-impact "lite" mode (reduces concurrency/timeouts, disables heavy gatherers)
        #[arg(long, default_value_t = false)]
        lite: bool,
        /// Confirm you have explicit permission to run aggressive scans (required when --aggressive used)
        #[arg(long, default_value_t = false)]
        confirm_aggressive: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // enable detailed debug logging for interactive runs
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
        .init();

    match cli.command {
        Commands::Scan { target, out, mut concurrency, mut per_host, aggressive, mut with_gau, mut with_wayback, resume, mut retries, timeout, backoff_initial_ms, backoff_max_ms, lite, confirm_aggressive } => {
            tracing::info!(target=%target, out=%out, concurrency, per_host, aggressive, with_gau, with_wayback, retries, timeout, "Starting scan");

            // Aggressive mode requires explicit confirmation
            if aggressive && !confirm_aggressive {
                eprintln!("Refusing to run in --aggressive mode without explicit confirmation.\n\nIf you have explicit permission from the target owner and understand the ethical responsibilities, re-run with --confirm-aggressive to acknowledge.");
                std::process::exit(1);
            }

            // If lite mode requested, apply conservative defaults
            if lite {
                concurrency = 8;
                per_host = 2;
                with_gau = false;
                with_wayback = false;
                // be more conservative in lite mode
                retries = 1;
                tracing::info!("lite mode active: low concurrency and disabled heavy gatherers");
            }

            // existing behavior below adapted to run scan for single domain
            // cap retries to 10
            if retries > 10 { retries = 10; }
            run_scan(target, out, concurrency, per_host, aggressive, with_gau, with_wayback, resume, lite, retries, timeout, backoff_initial_ms, backoff_max_ms).await?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_scan(target: String, out: String, concurrency: u16, per_host: u16, _aggressive: bool, with_gau: bool, with_wayback: bool, resume: Option<String>, lite: bool, retries: u8, timeout: u64, backoff_initial_ms: u64, backoff_max_ms: u64) -> anyhow::Result<()> {
    let out_dir = PathBuf::from(&out);
    utils::ensure_dir(&out_dir)?;

    if let Some(resume_path) = resume {
        let events = utils::read_jsonl(PathBuf::from(resume_path))?;
        let refs: Vec<&RawEvent> = events.iter().collect();
        let jsonl_path = out_dir.join("target_raw.jsonl");
        let csv_path = out_dir.join("target_apis_sorted.csv");
        let top_path = out_dir.join("target_top.txt");
        write_jsonl(&jsonl_path, &refs)?;
        write_csv(&csv_path, &refs)?;
        write_top_txt(&top_path, &refs)?;
        println!("Wrote resumed outputs to {}", out_dir.display());
        return Ok(());
    }

    // Discover subdomains via crt.sh
    let mut hosts = vec![target.clone()];
    if let Ok(mut found) = discover::crtsh::crtsh_subdomains(&target).await {
        hosts.append(&mut found);
    }

    // For MVP: gather candidate paths from wayback and gau if requested and available, stream outputs
    let mut candidates: Vec<String> = Vec::new();

    // Channel to receive lines from external tools
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(1024);

    // Spawn external tool runners if asked
    if with_wayback {
        let txc = tx.clone();
        let t_target = target.clone();
        tokio::spawn(async move {
            let _ = external::tools::try_run_waybackurls(&t_target, txc).await;
        });
    }
    if with_gau {
        let txc = tx.clone();
        let g_target = target.clone();
        tokio::spawn(async move {
            let _ = external::tools::try_run_gau(&g_target, txc).await;
        });
    }

    // Also add wayback CDX outputs (http) as fallback
    if !with_wayback {
        if let Ok(mut w) = gather::wayback::wayback_urls(&target).await {
            candidates.append(&mut w);
        }
    }

    // Simple JS fishing on host root pages for example
    if let Ok(js_endpoints) = gather::js_fisher::fetch_and_extract(&target).await {
        candidates.extend(js_endpoints);
    }

    // Collect streamed lines for a short period (non-blocking): drain channel for 2 seconds
    let mut streamed = Vec::new();
    let collect_task = tokio::spawn(async move {
        let start = std::time::Instant::now();
        while start.elapsed().as_secs() < 2 {
            if let Some(line) = rx.recv().await {
                streamed.push(line);
            } else {
                break;
            }
        }
        streamed
    });

    // Wait for collector to complete and merge
    if let Ok(mut s) = collect_task.await {
        candidates.append(&mut s);
    }

    // Dedup
    candidates.sort();
    candidates.dedup();

    // Filter candidates
    let filtered: Vec<String> = candidates.into_iter().filter(|u| filter::api_patterns::is_api_candidate(u)).collect();

    // Prepare client and throttle
    let client = reqwest::Client::builder().user_agent("api-hunter/0.1").build()?;
    let throttle = crate::probe::throttle::Throttle::new(concurrency as usize, per_host as usize);

    // Probe in parallel with bounded concurrency; use async writers for incremental output
    let jsonl_path = out_dir.join("target_raw.jsonl");
    let (tx_jsonl, rx_jsonl) = tokio::sync::mpsc::channel::<RawEvent>(1024);
    // spawn background JSONL writer
    let _jh_jsonl = crate::output::spawn_jsonl_writer(jsonl_path.clone(), rx_jsonl);

    // spawn background CSV writer (incremental)
    let csv_stream_path = out_dir.join("target_apis_stream.csv");
    let (tx_csv, rx_csv) = tokio::sync::mpsc::channel::<RawEvent>(1024);
    let _jh_csv = crate::output::spawn_csv_writer(csv_stream_path.clone(), rx_csv);

    let probe_timeout = if lite { 3 } else { timeout };

    use futures::stream::{self, StreamExt};

    let cand_vec = filtered;
    let client_ref = &client;
    let throttle_ref = &throttle;

    // progress counters for CLI visibility
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
                // announce start of probe for visibility
                let started = processed.load(Ordering::Relaxed);
                tracing::info!(candidate=%cand, start_index=started + 1, total, "starting probe");

                let res = probe::http_probe::probe_url(client, &cand, probe_timeout, Some(throttle), retries as usize, backoff_initial_ms, backoff_max_ms, _aggressive).await;

                // update progress and announce result
                let idx = processed.fetch_add(1, Ordering::SeqCst) + 1;
                match res {
                    Ok(mut ev) => {
                        ev.score = scoring::score::score_event(&ev);
                        if let Some(ref js) = ev.json_sample {
                            let keys = enrich::json_shape::detect_keys(js);
                            for k in keys.iter().take(5) {
                                ev.notes.push(format!("key:{}", k));
                            }
                        }
                        if let Err(e) = tx_jsonl.send(ev.clone()).await {
                            tracing::error!(error=%e, "failed to send event to jsonl writer");
                        }
                        if let Err(e) = tx_csv.send(ev.clone()).await {
                            tracing::error!(error=%e, "failed to send event to csv writer");
                        }
                        tracing::info!(candidate=%cand, index=idx, total, status=ev.status, "probe ok");
                        Some(ev)
                    }
                    Err(e) => {
                        tracing::warn!(candidate=%cand, index=idx, total, error=%e, "probe failed");
                        None
                    }
                }
            }
        })
        .buffer_unordered(concurrency as usize);

    // drive the stream and collect results with a global scan timeout (60s)
    tracing::debug!(total_candidates = total, "beginning probe stream");
    let scan_timeout = std::time::Duration::from_secs(60);

    let scan_fut = async {
        futures::pin_mut!(stream);
        while let Some(opt) = stream.next().await {
            if let Some(ev) = opt {
                results.push(ev);
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    match tokio::time::timeout(scan_timeout, scan_fut).await {
        Ok(Ok(_)) => tracing::info!("probe stream completed within timeout"),
        Ok(Err(e)) => tracing::error!(error=%e, "probe stream aborted with error"),
        Err(_) => tracing::error!("global scan timeout reached (60s), aborting remaining probes"),
    }

    // Close writers by dropping senders so background tasks can finish
    drop(tx_jsonl);
    drop(tx_csv);
    // wait a short while for writers to flush
    if let Err(e) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let _ = _jh_jsonl.await;
        let _ = _jh_csv.await;
    }).await {
        tracing::warn!(error=%e, "csv/jsonl writers did not finish within 5s after scan timeout");
    }

    // Final outputs
    let refs: Vec<&RawEvent> = results.iter().collect();
    let csv_path = out_dir.join("target_apis_sorted.csv");
    let top_path = out_dir.join("target_top.txt");
    write_csv(&csv_path, &refs)?;
    write_top_txt(&top_path, &refs)?;

    println!("Scan complete — outputs written to {}", out_dir.display());
    Ok(())
}
