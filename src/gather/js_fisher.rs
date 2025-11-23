use anyhow::Result;
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use url::Url;

/// Fetch the root page and extract JS asset URLs, then fetch JS and extract endpoint-like strings.
pub async fn fetch_and_extract(domain: &str) -> Result<Vec<String>> {
    let base = format!("https://{}", domain);
    
    // Build a client with reasonable timeouts to prevent hangs
    let client = match Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error=%e, "failed to build http client");
            return Ok(Vec::new());
        }
    };
    
    let mut out = Vec::new();
    
    // Fetch root page with error handling
    let resp = match client.get(&base).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(domain=%domain, error=%e, "js_fisher: failed to fetch root page");
            return Ok(out);
        }
    };
    
    // Avoid pulling arbitrarily large root pages into memory; cap at 256KB.
    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(domain=%domain, error=%e, "js_fisher: failed to read response body");
            return Ok(out);
        }
    };
    
    let max_root = 256 * 1024usize;
    let body = String::from_utf8_lossy(&body_bytes[..std::cmp::min(body_bytes.len(), max_root)]).to_string();
    
    let document = Html::parse_document(&body);
    let sel = match Selector::parse("script") {
        Ok(s) => s,
        Err(_) => return Ok(out),
    };
    
    let url_re = match Regex::new(r#"(?:fetch|axios\.|new WebSocket\(|XMLHttpRequest\(|\/[/\w\-\.]+(?:\:\d+)?(?:\/[^"'\s]*)?)"#) {
        Ok(r) => r,
        Err(_) => return Ok(out),
    };

    // Process external script tags
    for script in document.select(&sel) {
        if let Some(src) = script.value().attr("src") {
            let js_url = Url::parse(&base)
                .and_then(|b| b.join(src))
                .map(|u| u.to_string())
                .unwrap_or_else(|_| src.to_string());
            
            // Fetch JS file with error handling
            let js_resp = match client.get(&js_url).send().await {
                Ok(r) => r,
                Err(_) => continue, // Skip this JS file on error
            };
            
            // Limit JS asset size to avoid huge downloads; cap to 512KB per file.
            let bytes = match js_resp.bytes().await {
                Ok(b) => b,
                Err(_) => continue,
            };
            
            let max_js = 512 * 1024usize;
            let js_text = String::from_utf8_lossy(&bytes[..std::cmp::min(bytes.len(), max_js)]).to_string();
            
            for cap in url_re.captures_iter(&js_text) {
                if let Some(m) = cap.get(0) {
                    let s = m.as_str();
                    // crude normalization: if looks like path, make absolute
                    if s.starts_with('/') {
                        if let Ok(u) = Url::parse(&base).and_then(|b| b.join(s)) {
                            out.push(u.to_string());
                        }
                    } else if s.starts_with("http") {
                        out.push(s.to_string());
                    }
                }
            }
        }
    }

    // Also scan inline scripts for endpoints
    let inline_re = match Regex::new(r#"fetch\(['\"]([^'\"]+)['\"]"#) {
        Ok(r) => r,
        Err(_) => {
            // Still return what we found so far
            out.sort();
            out.dedup();
            return Ok(out);
        }
    };
    
    for cap in inline_re.captures_iter(&body) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str();
            if s.starts_with('/') {
                if let Ok(u) = Url::parse(&base).and_then(|b| b.join(s)) {
                    out.push(u.to_string());
                }
            } else if s.starts_with("http") {
                out.push(s.to_string());
            }
        }
    }

    out.sort();
    out.dedup();
    
    // Prevent returning an excessively long list that would flood the CLI.
    let max_results = 200usize;
    if out.len() > max_results {
        out.truncate(max_results);
    }
    
    tracing::debug!(domain=%domain, count=%out.len(), "js_fisher extracted endpoints");
    Ok(out)
}
