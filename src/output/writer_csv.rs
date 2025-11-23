use crate::output::writer_jsonl::RawEvent;
use csv::Writer;
use std::fs::File;
use std::path::Path;

pub fn write_csv(path: &Path, items: &[&RawEvent]) -> anyhow::Result<()> {
    let f = File::create(path)?;
    let mut w = Writer::from_writer(f);
    w.write_record(["score","status","final_url","orig_url","content_type","server","content_length","response_ms","tls_issuer","flags","notes"])?;
    for it in items {
        let flags = if it.is_graphql { "graphql" } else { "" };
        w.write_record(&[
            it.score.to_string(),
            it.status.to_string(),
            it.final_url.clone(),
            it.orig_url.clone(),
            it.content_type.clone().unwrap_or_default(),
            it.server.clone().unwrap_or_default(),
            it.content_length.map(|v| v.to_string()).unwrap_or_default(),
            it.response_ms.map(|v| v.to_string()).unwrap_or_default(),
            it.tls_issuer.clone().unwrap_or_default(),
            flags.to_string(),
            it.notes.join(", "),
        ])?;
    }
    w.flush()?;
    Ok(())
}
