use clap::Parser;

#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable detailed debug logging (global)
    #[arg(long, default_value_t = false)]
    pub debug: bool,

    /// Enable verbose logging (global)
    #[arg(long, default_value_t = false)]
    pub verbose: bool,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    /// Run a scan against a domain or file with domains
    Scan {
        /// Target domain (e.g. example.com) or path to file with newline-delimited domains
        target: String,

        /// Output directory
        #[arg(short = 'o', long, default_value = "./results")]
        out: String,

        /// Conservative low-impact mode (fast, passive)
        #[arg(long, default_value_t = false)]
        lite: bool,

        /// Deep analysis: Wayback, GAU, JS extraction, vuln scanning
        #[arg(long, default_value_t = false)]
        deep: bool,

        /// Aggressive mode: Bruteforce, admin paths, parameter fuzzing
        #[arg(short = 'A', long, default_value_t = false)]
        aggressive: bool,

        /// Scan for vulnerabilities (SQLi, XSS, RCE, SSRF, etc.) - like nmap -sV
        #[arg(long = "sV", default_value_t = false)]
        scan_vulns: bool,

        /// Scan for admin/debug endpoints - like nmap -sA
        #[arg(long = "sA", default_value_t = false)]
        scan_admin: bool,

        /// Enable headless browser for dynamic API discovery
        #[arg(short = 'B', long, default_value_t = false)]
        browser: bool,

        /// Browser wait time in ms (default: 3000)
        #[arg(long, default_value_t = 3000_u64)]
        browser_wait: u64,

        /// Browser crawl depth (default: 1)
        #[arg(long, default_value_t = 1_usize)]
        browser_depth: usize,

        /// Anonymous mode: Residential proxies + human-like patterns
        #[arg(long, default_value_t = false)]
        anon: bool,

        /// Full-speed mode: Skip delays (use with --anon)
        #[arg(long, default_value_t = false)]
        full_speed: bool,

        /// Enable WAF bypass techniques
        #[arg(long, default_value_t = false)]
        bypass_waf: bool,

        /// Enable subdomain enumeration (crt.sh + DNS bruteforce)
        #[arg(long, default_value_t = false)]
        subdomains: bool,

        /// Analyze JWT tokens in responses
        #[arg(long, default_value_t = false)]
        jwt: bool,

        /// Deep JavaScript analysis: Extract API endpoints, tokens, secrets, parameters from all JS files
        #[arg(long, default_value_t = false)]
        deep_js: bool,

        /// Timing template: T0 (paranoid) to T5 (insane) - like nmap -T4
        #[arg(short = 'T', long, value_parser = clap::value_parser!(u8).range(0..=5), default_value_t = 3)]
        timing: u8,

        /// Global concurrency (overrides -T template)
        #[arg(short = 'c', long)]
        concurrency: Option<u16>,

        /// Per-host limit (overrides -T template)
        #[arg(long)]
        per_host: Option<u16>,

        /// Request timeout in seconds (default: 10)
        #[arg(long, default_value_t = 10_u64)]
        timeout: u64,

        /// Number of retries (default: 3, max: 10)
        #[arg(short = 'r', long, default_value_t = 3_u8)]
        retries: u8,

        /// Resume from existing JSONL
        #[arg(long)]
        resume: Option<String>,

        /// Save detailed report to file (JSON or TXT format)
        #[arg(long, value_name = "FILE")]
        report: Option<String>,
    },

    /// Ultra-deep endpoint testing with all security checks
    TestEndpoint {
        /// API endpoint URL to test
        url: String,

        /// Include fuzzing tests (SQLi, XSS, SSRF, etc.)
        #[arg(short = 'F', long, default_value_t = false)]
        fuzz: bool,

        /// Number of requests for rate limit testing (default: 100)
        #[arg(short = 'n', long, default_value_t = 100)]
        rate_limit: u32,
    },
}

pub fn parse_cli() -> Cli {
    Cli::parse()
}
