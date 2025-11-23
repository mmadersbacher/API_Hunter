use anyhow::Result;
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use url::Url;

/// Fetch the root page and extract JS asset URLs, then fetch JS and extract endpoint-like strings.
pub async fn fetch_and_extract(domain: &str) -> Result<Vec<String>> {
    let base = format!("https://{}", domain);
    let client = Client::new();
    let mut out = Vec::new();

    let resp = client.get(&base).send().await;
    if resp.is_err() { return Ok(out); }
    let body = resp.unwrap().text().await?;
    let document = Html::parse_document(&body);
    let sel = Selector::parse("script").unwrap();
    let url_re = Regex::new(r#"(?:fetch|axios\.|new WebSocket\(|XMLHttpRequest\(|\/[/\w\-\.]+(?:\:\d+)?(?:\/[^"'\s]*)?)"#).unwrap();

    for script in document.select(&sel) {
        if let Some(src) = script.value().attr("src") {
            let js_url = Url::parse(&base).and_then(|b| b.join(src)).map(|u| u.to_string()).unwrap_or_else(|_| src.to_string());
            if let Ok(resp) = client.get(&js_url).send().await {
                if let Ok(js_text) = resp.text().await {
                    for cap in url_re.captures_iter(&js_text) {
                        let s = cap.get(0).map(|m| m.as_str().to_string()).unwrap_or_default();
                        // crude normalization: if looks like path, make absolute
                        if s.starts_with('/') {
                            if let Ok(u) = Url::parse(&base).and_then(|b| b.join(&s)) { out.push(u.to_string()); }
                        } else if s.starts_with("http") {
                            out.push(s);
                        }
                    }
                }
            }
        }
    }

    // Also scan inline scripts for endpoints
    let inline_re = Regex::new(r#"fetch\(['\"]([^'\"]+)['\"]"#).unwrap();
    for cap in inline_re.captures_iter(&body) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str();
            if s.starts_with('/') {
                if let Ok(u) = Url::parse(&base).and_then(|b| b.join(s)) { out.push(u.to_string()); }
            } else if s.starts_with("http") {
                out.push(s.to_string());
            }
        }
    }

    out.sort(); out.dedup();
    Ok(out)
}
