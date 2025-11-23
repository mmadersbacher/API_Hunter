use anyhow::Result;
use reqwest::Client;

/// Query Wayback CDX API for URLs related to the domain.
pub async fn wayback_urls(domain: &str) -> Result<Vec<String>> {
    // cdX API: return original URLs
    let url = format!("https://web.archive.org/cdx/search/cdx?url=*.{}&output=json&fl=original&collapse=urlkey", domain);
    let client = Client::new();
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(vec![]);
    }
    let v: serde_json::Value = resp.json().await?;
    let mut out = Vec::new();
    if let Some(arr) = v.as_array() {
        for item in arr.iter().skip(1) {
            if let Some(s) = item.as_str() {
                out.push(s.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}
