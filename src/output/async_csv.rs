use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use crate::output::writer_jsonl::RawEvent;

/// Spawn a background task that writes received RawEvent items as CSV to `path`.
/// CSV columns: orig_url,final_url,status,content_type,response_ms,score,is_graphql,notes
pub fn spawn_csv_writer(path: PathBuf, mut rx: mpsc::Receiver<RawEvent>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        match OpenOptions::new().create(true).append(true).open(&path).await {
            Ok(mut f) => {
                // If file was just created and empty, write header. We can't easily check size here without extra stat, so attempt to write header if file is empty by seeking would be extra work; keep header idempotent.
                let header = "orig_url,final_url,status,content_type,response_ms,score,is_graphql,notes\n";
                if let Err(e) = f.write_all(header.as_bytes()).await {
                    tracing::error!(error=%e, "failed to write csv header");
                }

                while let Some(ev) = rx.recv().await {
                    // helper to quote and escape CSV field
                    let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
                    let content_type = ev.content_type.as_ref().map(|v| v.as_str()).unwrap_or("");
                    let notes = ev.notes.join(";");
                    let is_graphql = if ev.is_graphql { "1" } else { "0" };
                    let response_ms = ev.response_ms.map(|m| m.to_string()).unwrap_or_default();
                    let status = ev.status.to_string();

                    let content_type_field = if content_type.is_empty() { "".to_string() } else { q(content_type) };

                    let line = format!(
                        "{},{},{},{},{},{},{},{}\n",
                        q(&ev.orig_url),
                        q(&ev.final_url),
                        status,
                        content_type_field,
                        response_ms,
                        ev.score,
                        is_graphql,
                        q(&notes)
                    );

                    if let Err(e) = f.write_all(line.as_bytes()).await {
                        tracing::error!(error=%e, "failed to write csv line");
                    }
                }

                if let Err(e) = f.flush().await {
                    tracing::error!(error=%e, "failed to flush csv writer");
                }
            }
            Err(e) => {
                tracing::error!(error=%e, path=%path.display(), "failed to open csv output file");
            }
        }
    })
}
