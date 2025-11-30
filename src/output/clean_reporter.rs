use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn emoji(&self) -> &str {
        match self {
            Severity::Critical => "[!]",
            Severity::High => "[!!]",
            Severity::Medium => "[i]",
            Severity::Low => "[·]",
            Severity::Info => "[*]",
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    pub fn color_code(&self) -> &str {
        match self {
            Severity::Critical => "\x1b[1;91m", // Bright Red
            Severity::High => "\x1b[1;33m",     // Bright Yellow
            Severity::Medium => "\x1b[1;93m",   // Yellow
            Severity::Low => "\x1b[1;94m",      // Blue
            Severity::Info => "\x1b[1;96m",     // Cyan
        }
    }

    pub fn reset_color() -> &'static str {
        "\x1b[0m"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub description: String,
    pub url: String,
    pub evidence: Vec<String>,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub scan_duration_seconds: u64,
    pub total_endpoints: usize,
    pub findings: Vec<Finding>,
    pub endpoints_tested: Vec<String>,
    pub js_analysis: Option<JsAnalysisSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsAnalysisSummary {
    pub endpoints_found: usize,
    pub secrets_found: usize,
    pub parameters_found: usize,
    pub domains_found: usize,
}

impl ScanReport {
    pub fn new(target: String) -> Self {
        Self {
            target,
            scan_duration_seconds: 0,
            total_endpoints: 0,
            findings: Vec::new(),
            endpoints_tested: Vec::new(),
            js_analysis: None,
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn severity_counts(&self) -> HashMap<Severity, usize> {
        let mut counts = HashMap::new();
        counts.insert(Severity::Critical, 0);
        counts.insert(Severity::High, 0);
        counts.insert(Severity::Medium, 0);
        counts.insert(Severity::Low, 0);
        counts.insert(Severity::Info, 0);

        for finding in &self.findings {
            *counts.entry(finding.severity.clone()).or_insert(0) += 1;
        }

        counts
    }

    /// Print clean CLI output - only essential information
    pub fn print_summary(&self) {
        println!("\n{}", "=".repeat(60));
        println!("              SCAN COMPLETE");
        println!("{}", "=".repeat(60));

        let counts = self.severity_counts();
        
        println!("\n[*] Summary:");
        println!("   Target: {}", self.target);
        println!("   Duration: {}s", self.scan_duration_seconds);
        println!("   Endpoints: {}", self.total_endpoints);

        if let Some(ref js) = self.js_analysis {
            println!("\n[DIR] JavaScript Analysis:");
            println!("   Endpoints: {}", js.endpoints_found);
            if js.secrets_found > 0 {
                println!("   {} Secrets: {} [!]", Severity::Critical.emoji(), js.secrets_found);
            }
            println!("   Parameters: {}", js.parameters_found);
        }

        println!("\n[*] Security Findings:");
        
        let critical = counts.get(&Severity::Critical).unwrap_or(&0);
        let high = counts.get(&Severity::High).unwrap_or(&0);
        let medium = counts.get(&Severity::Medium).unwrap_or(&0);
        let low = counts.get(&Severity::Low).unwrap_or(&0);

        if *critical > 0 {
            println!("   {} {} {}", Severity::Critical.emoji(), Severity::Critical.label(), critical);
        }
        if *high > 0 {
            println!("   {} {} {}", Severity::High.emoji(), Severity::High.label(), high);
        }
        if *medium > 0 {
            println!("   {} {} {}", Severity::Medium.emoji(), Severity::Medium.label(), medium);
        }
        if *low > 0 {
            println!("   {} {} {}", Severity::Low.emoji(), Severity::Low.label(), low);
        }

        if self.findings.is_empty() {
            println!("   [OK] No vulnerabilities detected");
        }

        // Show critical/high findings details
        let important = self.findings.iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .collect::<Vec<_>>();

        if !important.is_empty() {
            println!("\n[!] Important Findings:");
            for finding in important.iter().take(5) {
                println!("\n   {} {} - {}", 
                    finding.severity.emoji(), 
                    finding.category, 
                    finding.title
                );
                println!("   URL: {}", finding.url);
                if !finding.evidence.is_empty() {
                    println!("   Evidence: {}", finding.evidence.first().unwrap_or(&"".to_string()));
                }
            }
        }

        println!("\n[=] Detailed results saved to: ./results/");
        println!();
    }

    /// Save detailed report to file
    pub fn save_to_file(&self, path: &Path) -> std::io::Result<()> {
        let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("txt");

        match extension {
            "json" => {
                let json = serde_json::to_string_pretty(self)?;
                fs::write(path, json)?;
            }
            _ => {
                // Default to text format
                let text = self.format_text_report();
                fs::write(path, text)?;
            }
        }

        Ok(())
    }

    fn format_text_report(&self) -> String {
        let mut report = String::new();
        
        report.push_str("═══════════════════════════════════════════════════════════\n");
        report.push_str("                    SECURITY SCAN REPORT\n");
        report.push_str("═══════════════════════════════════════════════════════════\n\n");

        report.push_str(&format!("Target: {}\n", self.target));
        report.push_str(&format!("Duration: {}s\n", self.scan_duration_seconds));
        report.push_str(&format!("Endpoints Tested: {}\n\n", self.total_endpoints));

        if let Some(ref js) = self.js_analysis {
            report.push_str("JavaScript Analysis:\n");
            report.push_str(&format!("  - Endpoints found: {}\n", js.endpoints_found));
            report.push_str(&format!("  - Secrets found: {}\n", js.secrets_found));
            report.push_str(&format!("  - Parameters found: {}\n", js.parameters_found));
            report.push_str(&format!("  - Domains found: {}\n\n", js.domains_found));
        }

        let counts = self.severity_counts();
        report.push_str("Security Findings:\n");
        report.push_str(&format!("  [!] CRITICAL: {}\n", counts.get(&Severity::Critical).unwrap_or(&0)));
        report.push_str(&format!("  [!!] HIGH: {}\n", counts.get(&Severity::High).unwrap_or(&0)));
        report.push_str(&format!("  [i] MEDIUM: {}\n", counts.get(&Severity::Medium).unwrap_or(&0)));
        report.push_str(&format!("  [·] LOW: {}\n\n", counts.get(&Severity::Low).unwrap_or(&0)));

        // Group findings by severity
        let mut sorted_findings = self.findings.clone();
        sorted_findings.sort_by(|a, b| a.severity.cmp(&b.severity));

        for severity in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low] {
            let severity_findings: Vec<_> = sorted_findings.iter()
                .filter(|f| f.severity == severity)
                .collect();

            if !severity_findings.is_empty() {
                report.push_str(&format!("\n{} {} SEVERITY FINDINGS\n", severity.emoji(), severity.label()));
                report.push_str(&"─".repeat(60));
                report.push_str("\n\n");

                for (i, finding) in severity_findings.iter().enumerate() {
                    report.push_str(&format!("{}. {}: {}\n", i + 1, finding.category, finding.title));
                    report.push_str(&format!("   URL: {}\n", finding.url));
                    report.push_str(&format!("   Description: {}\n", finding.description));
                    
                    if !finding.evidence.is_empty() {
                        report.push_str("   Evidence:\n");
                        for evidence in &finding.evidence {
                            report.push_str(&format!("     - {}\n", evidence));
                        }
                    }
                    
                    if let Some(ref remediation) = finding.remediation {
                        report.push_str(&format!("   Remediation: {}\n", remediation));
                    }
                    report.push_str("\n");
                }
            }
        }

        report.push_str("\n═══════════════════════════════════════════════════════════\n");
        report.push_str("                      END OF REPORT\n");
        report.push_str("═══════════════════════════════════════════════════════════\n");

        report
    }
}
