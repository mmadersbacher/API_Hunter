use std::fs;
use std::path::Path;
use anyhow::Result;

/// Clean up results directory before new scan
pub fn cleanup_results(results_dir: &str) -> Result<()> {
    let path = Path::new(results_dir);
    
    if path.exists() {
        println!("[*] Cleaning previous scan results...");
        
        // Remove all files in results directory
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Err(e) = fs::remove_file(&path) {
                        eprintln!("[!] Failed to remove {}: {}", path.display(), e);
                    } else {
                        println!("[-] Removed: {}", path.file_name().unwrap_or_default().to_string_lossy());
                    }
                }
            }
        }
        
        println!("[+] Results directory cleaned");
    } else {
        // Create results directory if it doesn't exist
        fs::create_dir_all(path)?;
        println!("[+] Created results directory: {}", results_dir);
    }
    
    Ok(())
}

/// Enhanced result statistics
#[derive(Debug, Clone)]
pub struct ScanStatistics {
    pub total_apis_found: usize,
    pub apis_by_status: std::collections::HashMap<u16, usize>,
    pub apis_by_content_type: std::collections::HashMap<String, usize>,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub avg_response_time_ms: u64,
    pub fastest_api_ms: u64,
    pub slowest_api_ms: u64,
    pub total_scan_time_seconds: u64,
}

impl ScanStatistics {
    pub fn new() -> Self {
        Self {
            total_apis_found: 0,
            apis_by_status: std::collections::HashMap::new(),
            apis_by_content_type: std::collections::HashMap::new(),
            critical_findings: 0,
            high_findings: 0,
            medium_findings: 0,
            low_findings: 0,
            avg_response_time_ms: 0,
            fastest_api_ms: u64::MAX,
            slowest_api_ms: 0,
            total_scan_time_seconds: 0,
        }
    }

    pub fn print_summary(&self) {
        println!("\n╔════════════════════════════════════════════════════════════════════════════╗");
        println!("║                          SCAN SUMMARY REPORT                               ║");
        println!("╚════════════════════════════════════════════════════════════════════════════╝");
        
        println!("\n[*] API Discovery:");
        println!("    Total APIs Found: {}", self.total_apis_found);
        
        if !self.apis_by_status.is_empty() {
            println!("\n[*] Status Code Distribution:");
            let mut status_vec: Vec<_> = self.apis_by_status.iter().collect();
            status_vec.sort_by_key(|(code, _)| *code);
            for (status, count) in status_vec {
                let status_label = match *status {
                    200..=299 => "✓ Success",
                    300..=399 => "→ Redirect",
                    400..=499 => "⚠ Client Error",
                    500..=599 => "✗ Server Error",
                    _ => "? Unknown",
                };
                println!("      {}: {} ({})", status, count, status_label);
            }
        }

        if !self.apis_by_content_type.is_empty() {
            println!("\n[*] Content-Type Distribution:");
            let mut ct_vec: Vec<_> = self.apis_by_content_type.iter().collect();
            ct_vec.sort_by(|a, b| b.1.cmp(a.1));
            for (ct, count) in ct_vec.iter().take(10) {
                println!("      {}: {}", ct, count);
            }
        }

        println!("\n[*] Security Findings:");
        println!("    🔴 Critical: {}", self.critical_findings);
        println!("    🟠 High:     {}", self.high_findings);
        println!("    🟡 Medium:   {}", self.medium_findings);
        println!("    🔵 Low:      {}", self.low_findings);
        
        let total_vulns = self.critical_findings + self.high_findings + self.medium_findings + self.low_findings;
        if total_vulns > 0 {
            println!("    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("    Total Issues: {}", total_vulns);
        }

        if self.total_apis_found > 0 {
            println!("\n[*] Performance Metrics:");
            println!("    Average Response Time: {}ms", self.avg_response_time_ms);
            println!("    Fastest API:           {}ms", self.fastest_api_ms);
            println!("    Slowest API:           {}ms", self.slowest_api_ms);
        }

        println!("\n[*] Scan Duration: {}s", self.total_scan_time_seconds);
        
        println!("\n╔════════════════════════════════════════════════════════════════════════════╗");
        println!("║                         END OF REPORT                                      ║");
        println!("╚════════════════════════════════════════════════════════════════════════════╝\n");
    }
}

/// Calculate statistics from results
pub fn calculate_statistics(
    results_dir: &str,
    critical: usize,
    high: usize,
    medium: usize,
    scan_duration: u64,
) -> Result<ScanStatistics> {
    use std::collections::HashMap;

    let mut stats = ScanStatistics::new();
    stats.critical_findings = critical;
    stats.high_findings = high;
    stats.medium_findings = medium;
    stats.total_scan_time_seconds = scan_duration;

    // Read CSV for detailed stats
    let csv_path = format!("{}/target_apis_sorted.csv", results_dir);
    if let Ok(content) = fs::read_to_string(&csv_path) {
        let lines: Vec<&str> = content.lines().skip(1).collect(); // Skip header
        stats.total_apis_found = lines.len();

        let mut total_response_time: u64 = 0;
        let mut response_count = 0;

        for line in lines {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 8 {
                // Parse status code
                if let Ok(status) = parts[1].parse::<u16>() {
                    *stats.apis_by_status.entry(status).or_insert(0) += 1;
                }

                // Parse content type
                let content_type = parts[4].trim_matches('"');
                if !content_type.is_empty() {
                    let ct_simplified = content_type.split(';').next().unwrap_or(content_type).to_string();
                    *stats.apis_by_content_type.entry(ct_simplified).or_insert(0) += 1;
                }

                // Parse response time
                if let Ok(response_ms) = parts[7].parse::<u64>() {
                    total_response_time += response_ms;
                    response_count += 1;
                    stats.fastest_api_ms = stats.fastest_api_ms.min(response_ms);
                    stats.slowest_api_ms = stats.slowest_api_ms.max(response_ms);
                }
            }
        }

        if response_count > 0 {
            stats.avg_response_time_ms = total_response_time / response_count;
        }

        if stats.fastest_api_ms == u64::MAX {
            stats.fastest_api_ms = 0;
        }
    }

    Ok(stats)
}
