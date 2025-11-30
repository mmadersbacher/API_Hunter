use clap::Parser;

#[derive(clap::Parser, Debug)]
#[command(
    author,
    version,
    about = "API Hunter - Advanced API Security Scanner",
    long_about = None,
    after_help = "EXAMPLES:
  Basic scan:
    apihunter scan example.com

  Deep security scan:
    apihunter scan example.com --deep --sV

  Anonymous stealth scan:
    apihunter scan example.com --anon --lite -T1

  Full aggressive scan:
    apihunter scan example.com -A --deep --sV --sA

  Scan multiple domains:
    apihunter scan domains.txt -o ./results

For more information: https://github.com/mmadersbacher/API_Hunter"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable detailed debug logging
    #[arg(long, global = true)]
    pub debug: bool,

    /// Enable verbose output
    #[arg(long, global = true)]
    pub verbose: bool,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    #[command(
        about = "Run a scan against a domain or file with domains",
        long_about = "Scan a target domain for API endpoints and security vulnerabilities.\n\nScan Modes:\n  --lite          Fast passive scan\n  --deep          Deep analysis (Wayback, JS extraction, vuln scanning)\n  -A              Aggressive mode (bruteforce, admin paths, fuzzing)\n  --sV            Vulnerability scanning (like nmap)\n  --sA            Admin endpoint scanning (like nmap)"
    )]
    Scan {
        /// Target domain (e.g., example.com) or path to file with newline-delimited domains
        target: String,

        // === OUTPUT OPTIONS ===
        /// Output directory [default: ./results]
        #[arg(short = 'o', long)]
        out: Option<String>,

        /// Save detailed report to file (JSON or TXT format)
        #[arg(long, value_name = "FILE")]
        report: Option<String>,

        // === SCAN MODES ===
        /// Conservative low-impact mode (fast, passive)
        #[arg(long)]
        lite: bool,

        /// Deep analysis: Wayback, GAU, JS extraction, vuln scanning
        #[arg(long)]
        deep: bool,

        /// Aggressive mode: Bruteforce, admin paths, parameter fuzzing
        #[arg(short = 'A', long)]
        aggressive: bool,

        // === SECURITY SCANNING ===
        /// Scan for vulnerabilities (SQLi, XSS, RCE, SSRF, etc.)
        #[arg(long = "sV")]
        scan_vulns: bool,

        /// Scan for admin/debug endpoints
        #[arg(long = "sA")]
        scan_admin: bool,

        /// Analyze JWT tokens in responses
        #[arg(long)]
        jwt: bool,

        /// Deep JavaScript analysis: Extract endpoints, tokens, secrets
        #[arg(long)]
        deep_js: bool,

        // === DISCOVERY OPTIONS ===
        /// Enable subdomain enumeration (crt.sh + DNS bruteforce)
        #[arg(long)]
        subdomains: bool,

        /// Enable headless browser for dynamic API discovery
        #[arg(short = 'B', long)]
        browser: bool,

        /// Browser wait time in ms [default: 3000]
        #[arg(long)]
        browser_wait: Option<u64>,

        /// Browser crawl depth [default: 1]
        #[arg(long)]
        browser_depth: Option<usize>,

        // === STEALTH & EVASION ===
        /// Anonymous mode: Residential proxies + human-like patterns
        #[arg(long)]
        anon: bool,

        /// Full-speed mode: Skip delays (use with --anon)
        #[arg(long)]
        full_speed: bool,

        /// Enable WAF bypass techniques
        #[arg(long)]
        bypass_waf: bool,

        // === TIMING & PERFORMANCE ===
        /// Timing template: T0 (paranoid) to T5 (insane) [default: T3]
        #[arg(short = 'T', long, value_parser = clap::value_parser!(u8).range(0..=5))]
        timing: Option<u8>,

        /// Global concurrency (overrides -T template)
        #[arg(short = 'c', long)]
        concurrency: Option<u16>,

        /// Per-host limit (overrides -T template)
        #[arg(long)]
        per_host: Option<u16>,

        /// Request timeout in seconds [default: 10]
        #[arg(long)]
        timeout: Option<u64>,

        /// Number of retries [default: 3, max: 10]
        #[arg(short = 'r', long)]
        retries: Option<u8>,

        // === RESUME ===
        /// Resume from existing JSONL
        #[arg(long)]
        resume: Option<String>,
    },

    #[command(
        about = "Ultra-deep endpoint testing with all security checks",
        long_about = "Test a single API endpoint with comprehensive security analysis.\n\nIncludes: CORS, headers, TLS, rate limiting, JWT analysis, and optional fuzzing."
    )]
    TestEndpoint {
        /// API endpoint URL to test
        url: String,

        /// Include fuzzing tests (SQLi, XSS, SSRF, etc.)
        #[arg(short = 'F', long)]
        fuzz: bool,

        /// Number of requests for rate limit testing [default: 100]
        #[arg(short = 'n', long)]
        rate_limit: Option<u32>,
    },
}

pub fn parse_cli() -> Cli {
    Cli::parse()
}
