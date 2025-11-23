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
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt::init();

    match cli.command {
        Commands::Scan { target, out, concurrency, per_host, aggressive, with_gau, with_wayback, resume } => {
            tracing::info!(target=%target, out=%out, concurrency, per_host, aggressive, with_gau, with_wayback, "Starting scan");

            // existing behavior below adapted to run scan for single domain
            run_scan(target, out, concurrency, per_host, aggressive, with_gau, with_wayback, resume).await?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_scan(target: String, out: String, concurrency: u16, per_host: u16, _aggressive: bool, with_gau: bool, with_wayback: bool, resume: Option<String>) -> anyhow::Result<()> {
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

    // Probe each candidate (sequential for MVP — future: parallel with bounded tasks)
    let mut results: Vec<RawEvent> = Vec::new();
    for cand in filtered.iter() {
        match probe::http_probe::probe_url(&client, cand, 3, Some(&throttle)).await {
            Ok(mut ev) => {
                ev.score = scoring::score::score_event(&ev);
                // json key detection
                if let Some(ref js) = ev.json_sample {
                    let keys = enrich::json_shape::detect_keys(js);
                    for k in keys.iter().take(5) {
                        ev.notes.push(format!("key:{}", k));
                    }
                }
                results.push(ev);
                // incremental write
                let path = out_dir.join("target_raw.jsonl");
                let last = results.last().unwrap();
                write_jsonl(&path, &[last])?;
            }
            Err(e) => {
                tracing::warn!(candidate=%cand, error=%e, "probe failed");
            }
        }
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
