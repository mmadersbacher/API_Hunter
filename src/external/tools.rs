use crate::external::runner;
use anyhow::Result;
use tokio::sync::mpsc::Sender;
use which::which;

pub async fn try_run_gau(domain: &str, tx: Sender<String>) -> Result<Option<u32>> {
    if which("gau").is_err() { return Ok(None); }
    let args = [domain];
    let pid = runner::stream_cmd_lines("gau", &args, tx).await?;
    Ok(Some(pid))
}

pub async fn try_run_waybackurls(domain: &str, tx: Sender<String>) -> Result<Option<u32>> {
    if which("waybackurls").is_err() { return Ok(None); }
    let args = [domain];
    let pid = runner::stream_cmd_lines("waybackurls", &args, tx).await?;
    Ok(Some(pid))
}

#[allow(dead_code)]
pub async fn try_run_hakrawler(domain: &str, tx: Sender<String>) -> Result<Option<u32>> {
    if which("hakrawler").is_err() { return Ok(None); }
    let args = ["-url", domain];
    let pid = runner::stream_cmd_lines("hakrawler", &args, tx).await?;
    Ok(Some(pid))
}

#[allow(dead_code)]
pub async fn try_run_ffuf(target: &str, wordlist: &str, tx: Sender<String>) -> Result<Option<u32>> {
    if which("ffuf").is_err() { return Ok(None); }
    // Example: ffuf -u https://example.com/FUZZ -w wordlist
    let args = ["-u", &format!("{}{{}}", target), "-w", wordlist];
    let pid = runner::stream_cmd_lines("ffuf", &args, tx).await?;
    Ok(Some(pid))
}
