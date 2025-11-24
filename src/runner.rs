use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::io::Write;

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
        Commands::Scan { target, out, mut concurrency, mut per_host, aggressive, mut with_gau, mut with_wayback, resume, mut retries, timeout, backoff_initial_ms, backoff_max_ms, lite, confirm_aggressive, fuzz_params, test_idor, deep_analysis, scan_admin, advanced_idor, anonymous, full_speed } => {
            tracing::info!(target=%target, out=%out, concurrency, per_host, aggressive, with_gau, with_wayback, retries, timeout, anonymous, full_speed, "Starting scan");
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
            run_scan(target, out, concurrency, per_host, aggressive, with_gau, with_wayback, resume, lite, retries, timeout, backoff_initial_ms, backoff_max_ms, fuzz_params, test_idor, deep_analysis, scan_admin, advanced_idor, anonymous, full_speed).await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_scan(target: String, out: String, concurrency: u16, per_host: u16, aggressive: bool, with_gau: bool, with_wayback: bool, resume: Option<String>, lite: bool, retries: u8, timeout: u64, backoff_initial_ms: u64, backoff_max_ms: u64, fuzz_params: bool, test_idor: bool, deep_analysis: bool, scan_admin: bool, advanced_idor: bool, anonymous: bool, full_speed: bool) -> anyhow::Result<()> {
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

    // Setup anonymous mode if requested
    let anonymizer = if anonymous {
        println!("🥷 Anonymous Mode Enabled");
        if full_speed {
            println!("🚀 Full-Speed Mode: All delays disabled");
        }
        
        // Try to load from environment first
        let anon = if let Some(anon) = api_hunter::anonymizer::Anonymizer::from_env(full_speed) {
            anon
        } else {
            // Fallback: Erstelle ohne Proxy (direkter Traffic mit Human-like Patterns)
            api_hunter::anonymizer::Anonymizer::new(full_speed)
        };
        
        // Check if residential proxy is configured
        if !anon.is_proxy_configured() {
            println!("\n⚠️  No residential proxy configured!");
            api_hunter::anonymizer::Anonymizer::print_proxy_setup_instructions();
            println!("⚠️  Continuing with direct connection + human-like patterns...\n");
        }
        
        anon.print_status();
        println!();
        
        Some(anon)
    } else {
        None
    };

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
        match tokio::time::timeout(Duration::from_secs(10), api_hunter::gather::wayback::wayback_urls(&domain)).await {
            Ok(Ok(mut w)) => {
                let count = w.len();
                candidates.append(&mut w);
                tracing::info!("Wayback CDX: {} URLs found", count);
            }
            Ok(Err(e)) => { tracing::warn!("Wayback gather failed: {}", e); }
            Err(_) => { tracing::warn!("Wayback gather timed out (10s)"); }
        }
    }

    tracing::debug!("Fetching and analyzing JavaScript assets...");
    match tokio::time::timeout(Duration::from_secs(12), api_hunter::gather::js_fisher::fetch_and_extract(&domain)).await {
        Ok(Ok(js_endpoints)) => {
            let count = js_endpoints.len();
            candidates.extend(js_endpoints);
            tracing::info!("JS extraction: {} endpoints found", count);
        }
        Ok(Err(e)) => { tracing::warn!("JS extraction failed: {}", e); }
        Err(_) => { tracing::warn!("JS extraction timed out (12s)"); }
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

    // Create HTTP client based on anonymous mode
    let client = if let Some(ref anon) = anonymizer {
        println!("🔐 Creating residential proxy client with human-like patterns...");
        match anon.create_stealth_client(timeout) {
            Ok(client) => {
                println!("✅ Anonymous client ready (TLS fingerprint: constant)\n");
                client
            }
            Err(e) => {
                eprintln!("⚠️  Failed to create anonymous client: {}", e);
                eprintln!("   Falling back to direct connection...");
                reqwest::Client::builder().user_agent("api-hunter/0.1").build()?
            }
        }
    } else {
        reqwest::Client::builder().user_agent("api-hunter/0.1").build()?
    };
    
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
            let anon_ref = anonymizer.as_ref();
            async move {
                // Human-like delay in anonymous mode (burst + pause pattern)
                if let Some(anon) = anon_ref {
                    anon.human_delay().await;
                }
                
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

    // Deep analysis phase (if enabled)
    if deep_analysis && success_count > 0 {
        tracing::info!("Starting deep analysis phase on {} APIs...", success_count);
        
        let analysis_timeout = tokio::time::Duration::from_secs(120);
        match tokio::time::timeout(analysis_timeout, run_deep_analysis(&client, &results, scan_admin, advanced_idor, &out_dir)).await {
            Ok(Ok(())) => tracing::info!("Deep analysis completed successfully"),
            Ok(Err(e)) => tracing::warn!("Deep analysis failed: {}", e),
            Err(_) => tracing::warn!("Deep analysis timed out after 120s"),
        };
    }

    // Parameter fuzzing phase (if enabled)
    if fuzz_params && success_count > 0 {
        tracing::info!("Starting parameter fuzzing phase on {} APIs...", success_count);
        
        // Set a longer timeout for intensive fuzzing
        let fuzz_timeout = tokio::time::Duration::from_secs(60);
        match tokio::time::timeout(fuzz_timeout, run_param_fuzzing(&client, &results, test_idor, &out_dir)).await {
            Ok(Ok(())) => tracing::info!("Parameter fuzzing completed successfully"),
            Ok(Err(e)) => tracing::warn!("Parameter fuzzing failed: {}", e),
            Err(_) => tracing::warn!("Parameter fuzzing timed out after 60s"),
        };
    }

    println!("\nScan complete - {} APIs found", success_count);
    if fuzz_params {
        println!("Parameter fuzzing results written to: {}", out_dir.join("fuzz_results.txt").display());
    }
    println!("Outputs written to: {}", out_dir.display());
    Ok(())
}

async fn run_param_fuzzing(
    client: &reqwest::Client,
    results: &[RawEvent],
    test_idor: bool,
    out_dir: &PathBuf,
) -> anyhow::Result<()> {
    use api_hunter::fuzz::param_discovery::{extract_params_from_url, extract_params_from_json, detect_path_ids, common_params};
    use api_hunter::fuzz::param_fuzzer::{smart_fuzz_parameter, test_idor as fuzz_test_idor};
    use std::collections::HashSet;
    use std::io::Write;
    
    // Open file for immediate writing
    let fuzz_path = out_dir.join("fuzz_results.txt");
    let mut fuzz_file = std::fs::File::create(&fuzz_path)?;
    writeln!(fuzz_file, "=== Parameter Fuzzing Results ===")?;
    writeln!(fuzz_file, "")?;
    
    let mut finding_count = 0;
    let mut discovered_params: HashSet<String> = HashSet::new();
    
    // Phase 1: Discover parameters from successful responses
    tracing::info!("Phase 1: Discovering parameters from {} successful responses...", results.len());
    for event in results {
        // Extract from URL
        let url_params = extract_params_from_url(&event.orig_url);
        discovered_params.extend(url_params.clone());
        
        // Extract from JSON response if available
        if let Some(ref json_sample) = event.json_sample {
            if let Ok(json_str) = serde_json::to_string(json_sample) {
                let json_params = extract_params_from_json(&json_str);
                discovered_params.extend(json_params);
            }
        }
        
        // Detect path IDs
        let path_ids = detect_path_ids(&event.orig_url);
        if !path_ids.is_empty() {
            tracing::debug!("Found {} potential ID segments in {}", path_ids.len(), event.orig_url);
        }
    }
    
    tracing::info!("Discovered {} unique parameters from responses ", discovered_params.len());
    
    // Phase 2: Test common parameters on endpoints without query strings
    tracing::info!("Phase 2: Testing common parameters on endpoints...");
    let common = common_params();
    let mut tested = 0;
    let max_endpoints_to_test = 50; // Test many more endpoints
    let max_params_per_endpoint = 10; // Test more params per endpoint
    
    for (idx, event) in results.iter().take(max_endpoints_to_test).enumerate() {
        // Skip if URL already has parameters
        if event.orig_url.contains('?') {
            tracing::debug!("Skipping {} (already has parameters)", event.orig_url);
            continue;
        }
        
        tracing::debug!("Testing endpoint {}/{}: {}", idx + 1, max_endpoints_to_test, event.orig_url);
        
        // Test a few common parameters
        for param in common.iter().take(max_params_per_endpoint) {
            tracing::debug!("  Testing parameter: {}", param);
            match smart_fuzz_parameter(client, &event.orig_url, param, None).await {
                Ok(fuzz_results) => {
                    for result in fuzz_results {
                        if result.different_response {
                            tracing::info!("Found interesting parameter: {} on {} (status: {}, size: {})", 
                                param, event.orig_url, result.status, result.response_size);
                            let ct = result.content_type.as_deref().unwrap_or("unknown");
                            let finding = format!(
                                "PARAM: {} = {} | URL: {} | Status: {} | Size: {} | Content-Type: {}",
                                param, result.test_value, event.orig_url, result.status, result.response_size, ct
                            );
                            // Write immediately to file
                            writeln!(fuzz_file, "{}", finding)?;
                            fuzz_file.flush()?;
                            finding_count += 1;
                        }
                    }
                    tested += 1;
                }
                Err(e) => {
                    tracing::debug!("Failed to fuzz parameter {}: {}", param, e);
                }
            }
            
            // Shorter delay between parameter tests
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
        
        // Shorter delay between endpoints
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    
    tracing::info!("Tested {} parameter combinations ", tested);
    
    // Phase 3: IDOR testing (if enabled)
    if test_idor {
        tracing::info!("Phase 3: Testing for IDOR vulnerabilities...");
        let mut idor_tested = 0;
        let max_idor_tests = 20; // Test more endpoints for IDOR
        
        for (idx, event) in results.iter().take(max_idor_tests).enumerate() {
            let url_params = extract_params_from_url(&event.orig_url);
            
            if url_params.is_empty() {
                continue;
            }
            
            tracing::debug!("IDOR test {}/{} on: {}", idx + 1, max_idor_tests, event.orig_url);
            
            for param in url_params {
                if param.to_lowercase().contains("id") || param.to_lowercase().contains("user") {
                    tracing::debug!("  Testing IDOR parameter: {}", param);
                    // Extract current value
                    if let Some(query_start) = event.orig_url.find('?') {
                        let query = &event.orig_url[query_start + 1..];
                        for pair in query.split('&') {
                            if let Some(eq_pos) = pair.find('=') {
                                let key = &pair[..eq_pos];
                                let val = &pair[eq_pos + 1..];
                                if key == param {
                                    tracing::debug!("Testing IDOR on {}={} in {}", param, val, event.orig_url);
                                    match fuzz_test_idor(client, &event.orig_url, &param, val).await {
                                        Ok(idor_results) => {
                                            for result in idor_results {
                                                if result.status == 200 || result.status == event.status {
                                                    tracing::warn!("Potential IDOR: {} with value {} returned status {}", 
                                                        event.orig_url, result.test_value, result.status);
                                                    let finding = format!(
                                                        "IDOR: {} | Original: {}={} | Test: {}={} | Status: {}",
                                                        event.orig_url, param, val, param, result.test_value, result.status
                                                    );
                                                    writeln!(fuzz_file, "{}", finding)?;
                                                    fuzz_file.flush()?;
                                                    finding_count += 1;
                                                }
                                            }
                                            idor_tested += 1;
                                        }
                                        Err(e) => {
                                            tracing::debug!("IDOR test failed: {}", e);
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            
            // Shorter delay between IDOR tests
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        
        tracing::info!("Completed {} IDOR tests ", idor_tested);
    } else {
        tracing::debug!("IDOR testing skipped (not enabled or no parameters found) ");
    }
    
    // Summary
    writeln!(fuzz_file, "")?;
    writeln!(fuzz_file, "=== Summary ===")?;
    writeln!(fuzz_file, "Total interesting findings: {}", finding_count)?;
    fuzz_file.flush()?;
    
    if finding_count > 0 {
        tracing::info!("Wrote {} fuzzing findings to {} ", finding_count, fuzz_path.display());
    } else {
        tracing::info!("No interesting fuzzing findings detected ");
    }
    
    Ok(())
}

async fn run_deep_analysis(
    client: &reqwest::Client,
    results: &[RawEvent],
    scan_admin: bool,
    advanced_idor: bool,
    out_dir: &PathBuf,
) -> anyhow::Result<()> {
    use api_hunter::analyze::api_analyzer::ApiAnalysis;
    use api_hunter::analyze::admin_scanner::{scan_admin_paths, RiskLevel};
    use api_hunter::fuzz::idor_tester::{test_idor_advanced, IdorRiskLevel};
    use api_hunter::fuzz::param_discovery::extract_params_from_url;
    
    let analysis_path = out_dir.join("analysis_results.json");
    let summary_path = out_dir.join("analysis_summary.txt");
    
    let mut all_analyses = Vec::new();
    let mut admin_findings = Vec::new();
    let mut idor_findings = Vec::new();
    
    // Phase 1: Analyze each API endpoint
    tracing::info!("Phase 1: Analyzing {} API endpoints...", results.len());
    for (idx, event) in results.iter().enumerate() {
        tracing::debug!("Analyzing {}/{}: {}", idx + 1, results.len(), event.orig_url);
        
        match ApiAnalysis::analyze(client, &event.orig_url).await {
            Ok(analysis) => {
                tracing::info!("Analyzed {}: {} findings", event.orig_url, analysis.findings.len());
                all_analyses.push(analysis);
            }
            Err(e) => {
                tracing::warn!("Failed to analyze {}: {}", event.orig_url, e);
            }
        }
        
        // Small delay between analyses
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
    
    // Write API analysis results immediately (in case later phases timeout)
    tracing::info!("Writing API analysis results...");
    let json_data = serde_json::json!({
        "analyses": all_analyses,
        "admin_findings": admin_findings,
        "idor_findings": idor_findings,
    });
    std::fs::write(&analysis_path, serde_json::to_string_pretty(&json_data)?)?;
    write_analysis_summary(&summary_path, &all_analyses, &admin_findings, &idor_findings)?;
    tracing::info!("Wrote partial results to: {}", analysis_path.display());
    
    // Phase 2: Admin endpoint scanning (if enabled)
    if scan_admin {
        tracing::info!("Phase 2: Scanning for admin/debug endpoints...");
        
        // Extract base URLs from results
        let mut base_urls = std::collections::HashSet::new();
        for event in results.iter() {
            if let Ok(parsed) = url::Url::parse(&event.orig_url) {
                if let Some(host) = parsed.host_str() {
                    let scheme = parsed.scheme();
                    let base = format!("{}://{}", scheme, host);
                    base_urls.insert(base);
                }
            }
        }
        
        for base_url in base_urls {
            tracing::info!("Scanning admin paths on: {}", base_url);
            match scan_admin_paths(client, &base_url).await {
                Ok(findings) => {
                    let critical_count = findings.iter().filter(|f| matches!(f.risk_level, RiskLevel::Critical)).count();
                    let high_count = findings.iter().filter(|f| matches!(f.risk_level, RiskLevel::High)).count();
                    tracing::info!("Found {} admin endpoints ({} critical, {} high)", findings.len(), critical_count, high_count);
                    admin_findings.extend(findings);
                }
                Err(e) => {
                    tracing::warn!("Admin scan failed for {}: {}", base_url, e);
                }
            }
        }
        
        // Write admin results immediately
        tracing::info!("Updating analysis results with admin findings...");
        let json_data = serde_json::json!({
            "analyses": all_analyses,
            "admin_findings": admin_findings,
            "idor_findings": idor_findings,
        });
        std::fs::write(&analysis_path, serde_json::to_string_pretty(&json_data)?)?;
        write_analysis_summary(&summary_path, &all_analyses, &admin_findings, &idor_findings)?;
    }
    
    // Phase 3: Advanced IDOR testing (if enabled)
    if advanced_idor {
        tracing::info!("Phase 3: Advanced IDOR testing...");
        let max_idor_tests = 30;
        
        for (idx, event) in results.iter().take(max_idor_tests).enumerate() {
            let url_params = extract_params_from_url(&event.orig_url);
            
            for param in url_params {
                if param.to_lowercase().contains("id") 
                    || param.to_lowercase().contains("user") 
                    || param.to_lowercase().contains("account") {
                    
                    // Extract parameter value
                    if let Some(query_start) = event.orig_url.find('?') {
                        let query = &event.orig_url[query_start + 1..];
                        for pair in query.split('&') {
                            if let Some(eq_pos) = pair.find('=') {
                                let key = &pair[..eq_pos];
                                let val = &pair[eq_pos + 1..];
                                if key == param {
                                    tracing::debug!("IDOR testing {}/{}: {}={}", idx + 1, max_idor_tests, param, val);
                                    match test_idor_advanced(client, &event.orig_url, &param, val).await {
                                        Ok(test_results) => {
                                            for result in test_results {
                                                if matches!(result.risk_level, IdorRiskLevel::Critical | IdorRiskLevel::High) {
                                                    tracing::warn!("IDOR found: {} - {:?}", event.orig_url, result.risk_level);
                                                    idor_findings.push(result);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tracing::debug!("IDOR test failed: {}", e);
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            
            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
        }
    }
    
    // Write JSON results (final update with all phases)
    tracing::info!("Writing final analysis results...");
    let json_data = serde_json::json!({
        "analyses": all_analyses,
        "admin_findings": admin_findings,
        "idor_findings": idor_findings,
    });
    std::fs::write(&analysis_path, serde_json::to_string_pretty(&json_data)?)?;
    
    // Write summary
    let (critical, high, medium) = write_analysis_summary(&summary_path, &all_analyses, &admin_findings, &idor_findings)?;
    
    println!("\n=== Deep Analysis Complete ===");
    println!("🔴 Critical: {} | 🟠 High: {} | 🟡 Medium: {}", critical, high, medium);
    println!("Results: {}", analysis_path.display());
    println!("Summary: {}", summary_path.display());
    
    Ok(())
}

fn write_analysis_summary(
    summary_path: &PathBuf,
    all_analyses: &[api_hunter::analyze::api_analyzer::ApiAnalysis],
    admin_findings: &[api_hunter::analyze::admin_scanner::AdminScanResult],
    idor_findings: &[api_hunter::fuzz::idor_tester::IdorTestResult],
) -> anyhow::Result<(usize, usize, usize)> {
    use api_hunter::analyze::admin_scanner::RiskLevel;
    use api_hunter::fuzz::idor_tester::IdorRiskLevel;
    
    let mut summary_file = std::fs::File::create(summary_path)?;
    writeln!(summary_file, "=== Deep Analysis Summary ===")?;
    writeln!(summary_file, "")?;
    
    // API Analysis Summary
    writeln!(summary_file, "API Endpoints Analyzed: {}", all_analyses.len())?;
    let mut critical_findings = 0;
    let mut high_findings = 0;
    let mut medium_findings = 0;
    
    writeln!(summary_file, "")?;
    writeln!(summary_file, "=== Security Issues by Endpoint ===")?;
    for analysis in all_analyses {
        if !analysis.findings.is_empty() {
            writeln!(summary_file, "")?;
            writeln!(summary_file, "URL: {}", analysis.url)?;
            writeln!(summary_file, "Status: {}", analysis.status)?;
            
            if let Some(ref sec) = analysis.security_analysis {
                writeln!(summary_file, "Security Score: {}/100", sec.security_score)?;
                
                if sec.security_score < 70 {
                    writeln!(summary_file, "⚠️  LOW SECURITY SCORE")?;
                    high_findings += 1;
                }
            }
            
            if let Some(ref cors) = analysis.cors_analysis {
                if cors.is_misconfigured {
                    writeln!(summary_file, "⚠️  CORS MISCONFIGURED")?;
                    for vuln in &cors.vulnerabilities {
                        writeln!(summary_file, "  - {}", vuln)?;
                    }
                    high_findings += 1;
                }
            }
            
            for finding in &analysis.findings {
                writeln!(summary_file, "  - {}", finding)?;
                if finding.contains("password") || finding.contains("secret") || finding.contains("token") {
                    critical_findings += 1;
                } else if finding.contains("PUBLIC") || finding.contains("CORS") {
                    high_findings += 1;
                } else {
                    medium_findings += 1;
                }
            }
            
            if let Some(ref tech) = analysis.technology {
                if !tech.framework.is_empty() {
                    writeln!(summary_file, "Technology: {}", tech.framework.join(", "))?;
                }
            }
        }
    }
    
    // Admin Findings
    if !admin_findings.is_empty() {
        writeln!(summary_file, "")?;
        writeln!(summary_file, "=== Admin/Debug Endpoints Found ===")?;
        for finding in admin_findings {
            let risk_emoji = match finding.risk_level {
                RiskLevel::Critical => "🔴",
                RiskLevel::High => "🟠",
                RiskLevel::Medium => "🟡",
                RiskLevel::Low => "🔵",
            };
            writeln!(summary_file, "{} {} - Status: {} - Auth: {}", 
                risk_emoji, finding.url, finding.status, 
                if finding.requires_auth { "Required" } else { "Not Required" })?;
            
            match finding.risk_level {
                RiskLevel::Critical => critical_findings += 1,
                RiskLevel::High => high_findings += 1,
                RiskLevel::Medium => medium_findings += 1,
                _ => {}
            }
        }
    }
    
    // IDOR Findings
    if !idor_findings.is_empty() {
        writeln!(summary_file, "")?;
        writeln!(summary_file, "=== IDOR Vulnerabilities ===")?;
        for finding in idor_findings {
            let risk_emoji = match finding.risk_level {
                IdorRiskLevel::Critical => "🔴 CRITICAL",
                IdorRiskLevel::High => "🟠 HIGH",
                IdorRiskLevel::Medium => "🟡 MEDIUM",
                IdorRiskLevel::Info => "ℹ️  INFO",
            };
            writeln!(summary_file, "{} - {}", risk_emoji, finding.url)?;
            writeln!(summary_file, "  Parameter: {} (original: {}, test: {})", 
                finding.parameter, finding.original_value, finding.test_value)?;
            writeln!(summary_file, "  Evidence: {}", finding.evidence)?;
            
            match finding.risk_level {
                IdorRiskLevel::Critical => critical_findings += 1,
                IdorRiskLevel::High => high_findings += 1,
                IdorRiskLevel::Medium => medium_findings += 1,
                _ => {}
            }
        }
    }
    
    // Overall Summary
    writeln!(summary_file, "")?;
    writeln!(summary_file, "=== Overall Summary ===")?;
    writeln!(summary_file, "🔴 Critical Issues: {}", critical_findings)?;
    writeln!(summary_file, "🟠 High Issues: {}", high_findings)?;
    writeln!(summary_file, "🟡 Medium Issues: {}", medium_findings)?;
    writeln!(summary_file, "")?;
    writeln!(summary_file, "Total Issues: {}", critical_findings + high_findings + medium_findings)?;
    
    summary_file.flush()?;
    
    Ok((critical_findings, high_findings, medium_findings))
}
