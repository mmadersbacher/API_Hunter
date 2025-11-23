use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use crate::output::writer_jsonl::RawEvent;

/// Spawn a background task that writes received RawEvent items as JSONL to `path`.
/// Returns a sender that the caller can use to send events.
pub fn spawn_jsonl_writer(path: PathBuf, mut rx: mpsc::Receiver<RawEvent>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Try to open file, create if missing, append
        match OpenOptions::new().create(true).append(true).open(&path).await {
            Ok(mut f) => {
                while let Some(ev) = rx.recv().await {
                    match serde_json::to_vec(&ev) {
                        Ok(mut v) => {
                            // serde_json::to_vec doesn't include newline; add it
                            if let Err(e) = f.write_all(&v).await {
                                tracing::error!(error=%e, "failed to write jsonl bytes");
                            }
                            if let Err(e) = f.write_all(b"\n").await {
                                tracing::error!(error=%e, "failed to write newline to jsonl");
                            }
                        }
                        Err(e) => {
                            tracing::error!(error=%e, "failed to serialize RawEvent");
                        }
                    }
                }
                // flush on close
                if let Err(e) = f.flush().await {
                    tracing::error!(error=%e, "failed to flush jsonl writer");
                }
            }
            Err(e) => {
                tracing::error!(error=%e, path=%path.display(), "failed to open jsonl output file");
            }
        }
    })
}
