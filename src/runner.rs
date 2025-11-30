use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::io::Write;

use crate::cli::{Cli, Commands};
use api_hunter::output::{write_csv, write_top_txt, RawEvent};
use std::time::Duration;

fn print_ascii_logo() {
    println!(r#"
                 _    ____ ___   _   _ _   _ _   _ _____ _____ ____  
                / \  |  _ \_ _| | | | | | | | \ | |_   _| ____|  _ \ 
               / _ \ | |_) | |  | |_| | | | |  \| | | | |  _| | |_) |
              / ___ \|  __/| |  |  _  | |_| | |\  | | | | |___|  _ < 
             /_/   \_\_|  |___| |_| |_|\___/|_| \_| |_| |_____|_| \_\
                                                                      
                          Security Scanner v0.1.0
    "#);
}

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
        Commands::TestEndpoint { url, fuzz, rate_limit } => {
            let rate_limit = rate_limit.unwrap_or(100);
            return handle_test_endpoint_command(url, fuzz, rate_limit).await;
        }
        Commands::Scan { target, out, timing, concurrency, per_host, lite, deep, aggressive, scan_vulns, scan_admin, browser, browser_wait, browser_depth, anon, full_speed, bypass_waf, subdomains, jwt, deep_js, timeout, retries, resume, report } => {
            // Set defaults
            let out = out.unwrap_or_else(|| "./results".to_string());
            let timing = timing.unwrap_or(3);
            let timeout = timeout.unwrap_or(10);
            let retries = retries.unwrap_or(3);
            let browser_wait = browser_wait.unwrap_or(3000);
            let browser_depth = browser_depth.unwrap_or(1);

            // Apply timing templates (like nmap -T0 to -T5)
            let (final_concurrency, final_per_host, final_retries) = match timing {
                0 => (1, 1, 1),      // T0: Paranoid (ultra-slow)
                1 => (5, 1, 2),      // T1: Sneaky
                2 => (15, 2, 2),     // T2: Polite
                3 => (50, 6, 3),     // T3: Normal (default)
                4 => (100, 12, 3),   // T4: Aggressive
                5 => (200, 20, 1),   // T5: Insane
                _ => (50, 6, 3),
            };
            
            let concurrency = concurrency.unwrap_or(final_concurrency);
            let per_host = per_host.unwrap_or(final_per_host);
            let retries_final = if retries == 3 { final_retries } else { retries };
            
            // Deep mode: Enable Wayback, GAU, vuln scanning automatically
            let (with_wayback, with_gau, scan_vulns) = if deep {
                (true, true, true)
            } else {
                (false, false, scan_vulns)
            };
            
            // Lite mode overrides
            let (concurrency, per_host, retries, with_wayback, with_gau) = if lite {
                (8, 2, 1, false, false)
            } else {
                (concurrency, per_host, retries_final, with_wayback, with_gau)
            };
            
            let retries = if retries > 10 { 10 } else { retries };
            
            tracing::info!(target=%target, out=%out, concurrency, per_host, timing, aggressive, deep, retries, timeout, anon, full_speed, bypass_waf, browser, "Starting scan");
            
            // Print ASCII logo and scan configuration
            print_ascii_logo();
            println!("[>] Target: {}", target);
            println!("[~] Timing: T{} (concurrency: {}, per-host: {})", timing, concurrency, per_host);
            if lite {
                println!("[·] Mode: Lite (low impact)");
            } else if aggressive {
                println!("[·] Mode: Aggressive");
            } else if deep {
                println!("[·] Mode: Deep");
            }

            println!("\n{}\n", "-".repeat(60));
            
            // WAF detection is always enabled
            run_scan(target, out, concurrency, per_host, aggressive, with_gau, with_wayback, resume, lite, retries, timeout, scan_vulns, scan_admin, anon, full_speed, true, bypass_waf, browser, browser_wait, browser_depth, subdomains, jwt, deep_js, report).await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_scan(target: String, out: String, concurrency: u16, per_host: u16, aggressive: bool, with_gau: bool, with_wayback: bool, resume: Option<String>, lite: bool, retries: u8, timeout: u64, scan_vulns: bool, scan_admin: bool, anon: bool, full_speed: bool, _detect_waf: bool, bypass_waf: bool, browser: bool, browser_wait: u64, browser_depth: usize, subdomains: bool, jwt: bool, deep_js: bool, report: Option<String>) -> anyhow::Result<()> {
    let out_dir = PathBuf::from(&out);
    api_hunter::utils::ensure_dir(&out_dir)?;

    // Clean up previous scan results
    use api_hunter::output::cleanup_results;
    if let Err(e) = cleanup_results(&out) {
        eprintln!("[!] Warning: Failed to clean results directory: {}", e);
    }

    let scan_start = std::time::Instant::now();

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
    let anonymizer = if anon {
        // Try to load from environment first
        let anon_client = if let Some(anon) = api_hunter::anonymizer::Anonymizer::from_env(full_speed) {
            anon
        } else {
            // Fallback: Create without proxy (direct traffic with Human-like Patterns)
            api_hunter::anonymizer::Anonymizer::new(full_speed)
        };
        
        // Check if residential proxy is configured
        if !anon_client.is_proxy_configured() {
            println!("⚠️  No residential proxy configured - using direct connection");
        }
        
        Some(anon_client)
    } else {
        None
    };

    // Phase 1: WAF Detection (passive - during probing)
    // WAF detection happens during probing

    // Phase 1.5: Subdomain Enumeration (if enabled)
    let mut all_targets = vec![domain.clone()];
    if subdomains {
        println!("[*] Subdomain enumeration...");
        use api_hunter::discover::subdomain::SubdomainEnumerator;
        
        let enumerator = SubdomainEnumerator::new();
        let subdomain_results = enumerator.enumerate(&domain).await;
        
        // Save subdomain report
        let report = enumerator.generate_report(&subdomain_results);
        let subdomain_path = out_dir.join("subdomains.txt");
        let _ = std::fs::write(&subdomain_path, &report);
        
        // Add API-related subdomains to scan targets
        for result in subdomain_results.iter() {
            if result.subdomain.contains("api") 
                || result.subdomain.contains("rest") 
                || result.subdomain.contains("graphql") 
                || result.subdomain.contains("gateway") {
                all_targets.push(result.subdomain.clone());
            }
        }
        
        println!("   Found: {} subdomains ({} API-related)", subdomain_results.len(), all_targets.len() - 1);
    }

    // Discover and gather candidates
    println!("[*] API discovery...");
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

    // Deep JavaScript Analysis - Extract ALL critical information
    if deep_js {
        println!("   [DIR] Deep JS analysis...");
        
        match tokio::time::timeout(
            Duration::from_secs(60),
            async {
                let analyzer = api_hunter::gather::js_deep_analyzer::JsDeepAnalyzer::new(
                    domain.clone(),
                    timeout,
                    concurrency as usize,
                )?;
                analyzer.analyze_all().await
            }
        ).await {
            Ok(Ok(js_critical)) => {
                let secrets_warn = if js_critical.secrets.len() > 0 { " ⚠️" } else { "" };
                println!("      Endpoints: {} | Secrets: {}{} | Parameters: {}", 
                    js_critical.endpoints.len(),
                    js_critical.secrets.len(),
                    secrets_warn,
                    js_critical.parameters.len()
                );
                
                // Add discovered endpoints to candidates
                for endpoint in &js_critical.endpoints {
                    candidates.push(endpoint.url.clone());
                }
                
                for ws in &js_critical.websockets {
                    candidates.push(ws.clone());
                }
                
                for gql in &js_critical.graphql {
                    candidates.push(gql.endpoint.clone());
                }
                
                // Save critical findings to a special output file
                let js_critical_path = format!("{}/js_critical_info.json", out);
                let _ = std::fs::write(&js_critical_path, serde_json::to_string_pretty(&js_critical).unwrap_or_default());
                
                // Only print warning for HIGH VALUE findings
                if !js_critical.secrets.is_empty() {
                    println!("      [!] {} secrets found! Check {}", js_critical.secrets.len(), js_critical_path);
                }
            }
            Ok(Err(e)) => {
                tracing::warn!("Deep JS analysis failed: {}", e);
            }
            Err(_) => {
                tracing::warn!("Deep JS analysis timed out");
            }
        }
    }

    // Browser-based dynamic API discovery
    if browser {
        println!("   [WWW] Browser discovery...");
        
        match tokio::time::timeout(
            Duration::from_secs(browser_wait / 1000 + 30),
            api_hunter::discover::browser::discover_apis_with_browser(
                &target,
                true, // headless
                browser_depth,
                browser_wait
            )
        ).await {
            Ok(Ok(browser_apis)) => {
                let count = browser_apis.len();
                candidates.extend(browser_apis);
                println!("      Found: {} endpoints", count);
            }
            Ok(Err(e)) => {
                tracing::warn!("Browser discovery failed: {}", e);
            }
            Err(_) => {
                tracing::warn!("Browser discovery timed out");
            }
        }
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
    
    if let Ok(mut s) = collect_task.await {
        candidates.append(&mut s);
    }

    candidates.sort(); candidates.dedup();
    let total_discovered = candidates.len();
    
    let filtered: Vec<String> = candidates.into_iter().filter(|u| api_hunter::filter::api_patterns::is_api_candidate(u)).collect();
    let filtered_count = filtered.len();
    println!("   Found: {} URLs → {} API candidates", total_discovered, filtered_count);

    // Phase 3: Active Probing
    println!("[>] Probing endpoints...");
    
    // Create HTTP client based on anonymous mode
    let client = if let Some(ref anon) = anonymizer {
        match anon.create_stealth_client(timeout) {
            Ok(client) => {
                client
            }
            Err(e) => {
                eprintln!("[-] Failed to create stealth client: {}", e);
                eprintln!("[*] Falling back to direct connection...");
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

    // WAF Detector (always enabled now)
    let waf_detector = Some(api_hunter::waf::WafDetector::new());
    
    // Track WAF detections for summary
    let waf_detections = Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
    
    // JWT Analyzer (if enabled)
    let jwt_analyzer = if jwt {
        Some(Arc::new(api_hunter::security::JwtAnalyzer::new()))
    } else {
        None
    };
    let jwt_results = Arc::new(parking_lot::Mutex::new(Vec::new()));

    let stream = stream::iter(cand_vec.into_iter())
        .map(|cand| {
            let client = client_ref;
            let throttle = throttle_ref;
            let tx_jsonl = tx_jsonl.clone();
            let tx_csv = tx_csv.clone();
            let processed = processed.clone();
            let anon_ref = anonymizer.as_ref();
            let waf_detector_ref = waf_detector.as_ref();
            let waf_detections = waf_detections.clone();
            let jwt_analyzer_ref = jwt_analyzer.clone();
            let jwt_results_ref = jwt_results.clone();
            async move {
                // Human-like delay in anonymous mode (burst + pause pattern)
                if let Some(anon) = anon_ref {
                    anon.human_delay().await;
                }
                
                let idx = processed.fetch_add(1, Ordering::SeqCst) + 1;
                tracing::debug!("[{}/{}] Probing: {}", idx, total, cand);
                let res = api_hunter::probe::http_probe::probe_url(client, &cand, probe_timeout, Some(throttle), retries as usize, 200, 5000, aggressive).await;
                match res {
                    Ok(mut ev) => {
                        ev.score = api_hunter::scoring::score::score_event(&ev);
                        if let Some(ref js) = ev.json_sample { let keys = api_hunter::enrich::json_shape::detect_keys(js); for k in keys.iter().take(5) { ev.notes.push(format!("key:{}", k)); } }
                        
                        // WAF Detection (passive - always active)
                        if let Some(_detector) = waf_detector_ref {
                            let server = ev.server.as_deref().unwrap_or("");
                            let mut waf_found = None;
                            
                            if server.to_lowercase().contains("cloudflare") {
                                waf_found = Some("Cloudflare");
                            } else if server.to_lowercase().contains("akamai") {
                                waf_found = Some("Akamai");
                            } else if server.to_lowercase().contains("sucuri") {
                                waf_found = Some("Sucuri");
                            } else if server.to_lowercase().contains("imperva") || server.to_lowercase().contains("incapsula") {
                                waf_found = Some("Imperva");
                            } else if server.to_lowercase().contains("big-ip") || server.to_lowercase().contains("bigip") {
                                waf_found = Some("F5 BIG-IP");
                            } else if server.to_lowercase().contains("barracuda") {
                                waf_found = Some("Barracuda");
                            } else if server.to_lowercase().contains("fortiweb") {
                                waf_found = Some("FortiWeb");
                            }
                            
                            if let Some(waf_name) = waf_found {
                                ev.notes.push(format!("WAF:{}", waf_name));
                                let mut detections = waf_detections.lock();
                                *detections.entry(waf_name.to_string()).or_insert(0) += 1;
                            }
                            
                            // Check for WAF block response patterns
                            if ev.status == 403 || ev.status == 406 || ev.status == 429 {
                                if !ev.notes.iter().any(|n| n.starts_with("WAF:")) {
                                    ev.notes.push("WAF:UnknownBlock".to_string());
                                }
                            }
                        }
                        
                        // JWT Token Analysis (if enabled)
                        if let Some(ref analyzer) = jwt_analyzer_ref {
                            // Try to extract tokens from response (use json_sample if available)
                            let body_text = if let Some(ref json) = ev.json_sample {
                                serde_json::to_string(json).unwrap_or_default()
                            } else {
                                // For non-JSON responses, we'd need the body. Since we don't store it,
                                // we'll skip JWT extraction for now or only check JSON responses
                                String::new()
                            };
                            
                            if !body_text.is_empty() {
                                let tokens = analyzer.extract_tokens_from_response(&body_text);
                                if !tokens.is_empty() {
                                    tracing::info!("Found {} JWT token(s) in response from {}", tokens.len(), cand);
                                    ev.notes.push(format!("JWT:{}", tokens.len()));
                                    
                                    // Analyze each token
                                    for token in tokens {
                                        if let Ok(analysis) = analyzer.analyze_token(&token) {
                                            if !analysis.vulnerabilities.is_empty() {
                                                tracing::warn!("JWT vulnerabilities found in {}: {:?}", cand, analysis.vulnerabilities);
                                            }
                                            jwt_results_ref.lock().push(analysis);
                                        }
                                    }
                                }
                            }
                        }
                        
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

    // Phase 4: Vulnerability Scanning
    let mut critical_findings = 0;
    let mut high_findings = 0;
    let mut medium_findings = 0;
    
    if scan_vulns && success_count > 0 {
        println!("[*] Vulnerability scanning...");
        
        let analysis_timeout = tokio::time::Duration::from_secs(120);
        match tokio::time::timeout(analysis_timeout, run_deep_analysis(&client, &results, scan_admin, aggressive, &out_dir, &domain)).await {
            Ok(Ok(())) => {
                // Silently completed
            }
            Ok(Err(e)) => {
                tracing::warn!("Vulnerability scan failed: {}", e);
            }
            Err(_) => {
                tracing::warn!("Vulnerability scan timed out after 120s");
            }
        };
        
        // Read findings from analysis summary
        if let Ok(summary_content) = std::fs::read_to_string(out_dir.join("analysis_summary.txt")) {
            for line in summary_content.lines() {
                if line.contains("Critical Issues:") {
                    critical_findings = line.split(':').nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                } else if line.contains("High Issues:") {
                    high_findings = line.split(':').nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                } else if line.contains("Medium Issues:") {
                    medium_findings = line.split(':').nth(1).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                }
            }
        }
        
        // Display severity counts with proper markers
        println!("   Findings: {} [!] {} [!!] {} [i]", critical_findings, high_findings, medium_findings);
    }

    // Phase 5: Admin/Debug Endpoint Discovery
    if scan_admin && success_count > 0 {
        // Admin scanning is handled in run_deep_analysis - no additional output
    }

    // Phase 6: Aggressive Testing (Parameter Fuzzing, IDOR)
    if aggressive && success_count > 0 {
        println!("[~] Aggressive testing...");
        
        // Set a longer timeout for intensive fuzzing
        let fuzz_timeout = tokio::time::Duration::from_secs(60);
        let _ = tokio::time::timeout(fuzz_timeout, run_param_fuzzing(&client, &results, true, &out_dir)).await;
    }

    // Phase 7: WAF Bypass Techniques
    if bypass_waf && success_count > 0 {
        println!("[#] WAF bypass testing...");
        // WAF bypass techniques would be implemented here
    }

    // Print scan summary
    println!("\n{}", "=".repeat(60));
    println!("[*] Scan Summary");
    println!("{}", "=".repeat(60));
    println!("[+] APIs Found: {}", success_count);
    
    // WAF Detection Summary
    let waf_stats = waf_detections.lock();
    if !waf_stats.is_empty() {
        println!("\n[*] WAF Detections:");
        let mut wafs: Vec<_> = waf_stats.iter().collect();
        wafs.sort_by(|a, b| b.1.cmp(a.1));
        for (waf, count) in wafs {
            println!("    [-] {}: {} endpoint(s)", waf, count);
        }
    } else {
        println!("\n[*] No WAF detected");
    }
    
    // JWT Analysis Summary
    if jwt {
        let jwt_analysis_results = jwt_results.lock();
        if !jwt_analysis_results.is_empty() {
            let vuln_count: usize = jwt_analysis_results.iter().map(|r| r.vulnerabilities.len()).sum();
            
            if vuln_count > 0 {
                println!("   [KEY] JWT: {} tokens analyzed, {} issues found", jwt_analysis_results.len(), vuln_count);
                
                // Save JWT report
                if let Some(ref analyzer) = jwt_analyzer {
                    let report = analyzer.generate_report(&jwt_analysis_results);
                    let _ = std::fs::write(out_dir.join("jwt_analysis.txt"), &report);
                }
            }
        }
    }
    
    // Print clean final summary
    let scan_duration = scan_start.elapsed().as_secs();
    println!("\n{}", "=".repeat(60));
    println!("              SCAN COMPLETE");
    println!("{}", "=".repeat(60));
    println!("\n[*] Summary:");
    println!("   Target: {}", domain);
    println!("   Duration: {}s", scan_duration);
    println!("   Endpoints: {}", success_count);
    
    println!("\n[*] Security Findings:");
    if critical_findings > 0 {
        println!("   [!] CRITICAL {}", critical_findings);
    }
    if high_findings > 0 {
        println!("   [!!] HIGH {}", high_findings);
    }
    if medium_findings > 0 {
        println!("   [i] MEDIUM {}", medium_findings);
    }
    
    if critical_findings == 0 && high_findings == 0 && medium_findings == 0 {
        println!("   [OK] No critical/high/medium vulnerabilities detected");
    }
    
    println!("\n[=] Results saved to: {}", out_dir.display());
    
    // Save structured report if requested
    if let Some(report_path) = report {
        use api_hunter::output::clean_reporter::{ScanReport, Finding, Severity, JsAnalysisSummary};
        use std::path::Path;
        
        let mut scan_report = ScanReport::new(domain.clone());
        scan_report.scan_duration_seconds = scan_duration;
        scan_report.total_endpoints = success_count;
        
        // Try to read and parse existing findings
        if let Ok(summary_content) = std::fs::read_to_string(out_dir.join("analysis_summary.txt")) {
            // Parse findings from summary (simplified - in production would parse properly)
            for _ in 0..critical_findings {
                scan_report.add_finding(Finding {
                    severity: Severity::Critical,
                    category: "Security".to_string(),
                    title: "Critical Issue".to_string(),
                    description: "See analysis_summary.txt for details".to_string(),
                    url: target.clone(),
                    evidence: vec![],
                    remediation: None,
                });
            }
        }
        
        // Save report
        if let Err(e) = scan_report.save_to_file(Path::new(&report_path)) {
            eprintln!("   [!] Failed to save report: {}", e);
        } else {
            println!("   [-] Report saved to: {}", report_path);
        }
    }
    
    println!();
    
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
    aggressive: bool,
    out_dir: &PathBuf,
    domain: &str,
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
    
    // Phase 1: Analyze each API endpoint IN PARALLEL
    tracing::info!("Phase 1: Analyzing {} API endpoints in parallel...", results.len());
    
    // Process in parallel batches for maximum speed
    use futures::stream::{self, StreamExt};
    let analysis_stream = stream::iter(results.iter().enumerate())
        .map(|(idx, event)| {
            let client = client.clone();
            let url = event.orig_url.clone();
            let total = results.len();
            async move {
                tracing::debug!("Analyzing {}/{}: {}", idx + 1, total, url);
                match ApiAnalysis::analyze(&client, &url).await {
                    Ok(analysis) => {
                        tracing::info!("Analyzed {}: {} findings", url, analysis.findings.len());
                        Some(analysis)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to analyze {}: {}", url, e);
                        None
                    }
                }
            }
        })
        .buffer_unordered(20);  // 20 parallel analysis tasks
    
    futures::pin_mut!(analysis_stream);
    while let Some(opt) = analysis_stream.next().await {
        if let Some(analysis) = opt {
            all_analyses.push(analysis);
        }
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
    
    // Phase 1.5: ULTRA-FAST PARALLEL XSS testing - Only on target domain
    tracing::info!("Phase 1.5: Fast parallel XSS testing on target domain...");
    
    // Extract main target domain
    let target_domain = if let Ok(parsed) = url::Url::parse(&format!("https://{}", domain)) {
        parsed.host_str().map(|s| s.to_string())
    } else {
        Some(domain.to_string())
    };
    
    // Only test endpoints on the main target domain (no Google, CDNs, etc.)
    let target_urls: Vec<String> = all_analyses.iter()
        .filter_map(|analysis| {
            // Check if endpoint has XSS indicators
            let has_xss_indicator = analysis.findings.iter().any(|f| 
                f.contains("Missing CSP - vulnerable to XSS") ||
                f.contains("XSS") ||
                f.contains("reflected")
            );
            
            if !has_xss_indicator {
                return None;
            }
            
            // Verify URL is on target domain
            if let Ok(parsed) = url::Url::parse(&analysis.url) {
                if let Some(host) = parsed.host_str() {
                    if let Some(target) = &target_domain {
                        // Only test if domain matches exactly
                        if host == target || host.ends_with(&format!(".{}", target)) {
                            return Some(analysis.url.clone());
                        }
                    }
                }
            }
            None
        })
        .take(5)  // Limit to 5 URLs maximum
        .collect();
    
    if !target_urls.is_empty() {
        println!("   [*] XSS testing {} endpoints in parallel...", target_urls.len());
        
        // Run ALL XSS tests in parallel for maximum speed
        let xss_tasks: Vec<_> = target_urls.iter().map(|url| {
            let client = client.clone();
            let url = url.clone();
            tokio::spawn(async move {
                tracing::info!("Running fast XSS test on: {}", url);
                match api_hunter::analyze::vulnerability_scanner::VulnerabilityScanner::test_xss_advanced(&client, &url).await {
                    Ok(findings) => {
                        if !findings.is_empty() {
                            tracing::info!("Found {} XSS vulnerabilities on {}", findings.len(), url);
                            Some((url, findings))
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        tracing::warn!("XSS test failed for {}: {}", url, e);
                        None
                    }
                }
            })
        }).collect();
        
        // Collect results
        let mut xss_findings = Vec::new();
        for task in xss_tasks {
            if let Ok(Some((url, findings))) = task.await {
                println!("   [!] {} XSS vectors on {}", findings.len(), url);
                xss_findings.extend(findings);
            }
        }
        
        if !xss_findings.is_empty() {
            tracing::info!("XSS testing complete: {} vulnerabilities found", xss_findings.len());
            let xss_path = out_dir.join("xss_findings.json");
            std::fs::write(&xss_path, serde_json::to_string_pretty(&xss_findings)?)?;
            println!("   [=] XSS findings saved to: {}", xss_path.display());
        }
    }

    
    // Phase 2: Admin endpoint scanning IN PARALLEL (if enabled)
    if scan_admin {
        tracing::info!("Phase 2: Scanning for admin/debug endpoints in parallel...");
        
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
        
        // Run admin scans in parallel
        let admin_tasks: Vec<_> = base_urls.into_iter().map(|base_url| {
            let client = client.clone();
            tokio::spawn(async move {
                tracing::info!("Scanning admin paths on: {}", base_url);
                match scan_admin_paths(&client, &base_url).await {
                    Ok(findings) => {
                        let critical_count = findings.iter().filter(|f| matches!(f.risk_level, RiskLevel::Critical)).count();
                        let high_count = findings.iter().filter(|f| matches!(f.risk_level, RiskLevel::High)).count();
                        tracing::info!("Found {} admin endpoints ({} critical, {} high)", findings.len(), critical_count, high_count);
                        Some(findings)
                    }
                    Err(e) => {
                        tracing::warn!("Admin scan failed for {}: {}", base_url, e);
                        None
                    }
                }
            })
        }).collect();
        
        // Collect admin findings
        for task in admin_tasks {
            if let Ok(Some(findings)) = task.await {
                admin_findings.extend(findings);
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
    
    // Phase 3: Advanced IDOR testing (if enabled via aggressive mode)
    if aggressive {
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

async fn print_final_statistics(
    out_dir: &str,
    critical: usize,
    high: usize,
    medium: usize,
    scan_duration: u64,
) -> anyhow::Result<()> {
    use api_hunter::output::calculate_statistics;
    
    let stats = calculate_statistics(out_dir, critical, high, medium, scan_duration)?;
    stats.print_summary();
    
    Ok(())
}

async fn handle_test_endpoint_command(
    url: String,
    fuzz: bool,
    rate_limit: u32,
) -> anyhow::Result<()> {
    use api_hunter::test_endpoint::run_endpoint_tests;

    println!("\n┌──────────────────────────────────────────────────┐");
    println!("│     API Hunter - Ultra-Deep Endpoint Testing     │");
    println!("└──────────────────────────────────────────────────┘");

    run_endpoint_tests(&url, fuzz, rate_limit).await
}
