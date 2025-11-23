use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub orig_url: String,
    pub final_url: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub server: Option<String>,
    pub content_length: Option<u64>,
    pub response_ms: Option<u64>,
    pub tls_issuer: Option<String>,
    pub is_graphql: bool,
    pub json_sample: Option<Value>,
    pub score: i32,
    pub notes: Vec<String>,
}

pub fn write_jsonl(path: &Path, items: &[&RawEvent]) -> anyhow::Result<()> {
    let mut f = OpenOptions::new().append(true).create(true).open(path)?;
    for it in items {
        let line = serde_json::to_string(it)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
    }
    Ok(())
}

pub fn write_top_txt(path: &Path, items: &[&RawEvent]) -> anyhow::Result<()> {
    use std::fs;
    let mut lines = Vec::new();
    for it in items.iter().take(10) {
        let _tag = if it.json_sample.is_some() { "json" } else { "" };
        let ms = it.response_ms.map(|m| m.to_string()).unwrap_or_else(|| "-".into());
        lines.push(format!("[{}] {} {} — {}ms — notes: {}",
            it.score, it.status, it.final_url, ms, it.notes.join(", ")));
    }
    fs::write(path, lines.join("\n"))?;
    Ok(())
}
