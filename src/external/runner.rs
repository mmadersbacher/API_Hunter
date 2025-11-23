use anyhow::Result;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::Sender;

/// Spawn a command and stream stdout lines into the provided sender.
/// Returns the child PID on success.
pub async fn stream_cmd_lines(cmd: &str, args: &[&str], tx: Sender<String>) -> Result<u32> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    if let Some(stdout) = child.stdout.take() {
        let mut reader = BufReader::new(stdout).lines();
        tokio::spawn(async move {
            while let Ok(Some(line)) = reader.next_line().await {
                let _ = tx.send(line).await;
            }
        });
    }

    let pid = child.id().unwrap_or_default();
    // detach: don't await child here; caller may handle lifecycle
    Ok(pid)
}
