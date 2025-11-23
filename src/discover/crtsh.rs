use anyhow::Result;
use reqwest::Client;

pub async fn crtsh_subdomains(domain: &str) -> Result<Vec<String>> {
    let client = Client::new();
    let q = format!("%25.{}", domain);
    let url = format!("https://crt.sh/?q={}&output=json", urlencoding::encode(&q));
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok(vec![]);
    }
    let txt = resp.text().await?;
    // crt.sh sometimes returns non-JSON on failure; attempt parse
    let v: serde_json::Value = serde_json::from_str(&txt)?;
    let mut out = Vec::new();
    if let Some(arr) = v.as_array() {
        for item in arr {
            if let Some(name) = item.get("name_value").and_then(|n| n.as_str()) {
                // name_value can contain multiple names separated by newlines
                for n in name.split('\n') {
                    let s = n.trim().to_string();
                    if !s.is_empty() {
                        out.push(s);
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}
