use std::fs;
use std::path::Path;

pub fn ensure_dir(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

pub fn read_jsonl(path: std::path::PathBuf) -> anyhow::Result<Vec<crate::output::writer_jsonl::RawEvent>> {
    let mut out = Vec::new();
    let data = std::fs::read_to_string(path)?;
    for line in data.lines() {
        if line.trim().is_empty() { continue; }
        let v: crate::output::writer_jsonl::RawEvent = serde_json::from_str(line)?;
        out.push(v);
    }
    Ok(out)
}
