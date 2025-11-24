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

        /// Enable parameter fuzzing to discover hidden parameters
        #[arg(long, default_value_t = false)]
        fuzz_params: bool,

        /// Test for IDOR vulnerabilities on ID parameters
        #[arg(long, default_value_t = false)]
        test_idor: bool,

        /// Deep analysis mode: analyze headers, CORS, security, fingerprint technologies
        #[arg(long, default_value_t = false)]
        deep_analysis: bool,

        /// Scan for admin/debug endpoints
        #[arg(long, default_value_t = false)]
        scan_admin: bool,

        /// Advanced IDOR testing with multiple techniques
        #[arg(long, default_value_t = false)]
        advanced_idor: bool,

        /// Anonymous mode: Route traffic through residential proxies with human-like patterns
        #[arg(long, default_value_t = false)]
        anonymous: bool,

        /// Full-speed mode: Skip all delays and rate limiting (still anonymous)
        #[arg(long, default_value_t = false)]
        full_speed: bool,
    },
}

pub fn parse_cli() -> Cli {
    Cli::parse()
}
