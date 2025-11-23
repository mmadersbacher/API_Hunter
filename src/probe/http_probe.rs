use std::time::Instant;
use reqwest::Client;
use serde_json::json;
use url::Url;

use crate::output::writer_jsonl::RawEvent;
use crate::probe::throttle::Throttle;

fn extract_host(url: &str) -> Option<String> {
    Url::parse(url).ok().and_then(|u| u.host_str().map(|s| s.to_string()))
}

/// Probe URL with optional throttle. If `throttle` is Some, an acquire is awaited before performing requests.
pub async fn probe_url(client: &Client, url: &str, timeout_secs: u64, throttle: Option<&Throttle>) -> anyhow::Result<RawEvent> {
    // apply throttle if present
    if let Some(t) = throttle {
        if let Some(host) = extract_host(url) {
            let _p = t.acquire(&host).await; // permit held until dropped
            // After acquiring permit, perform probe with retries/backoff
            return probe_with_retries(client, url, timeout_secs, Some(t), &host).await;
        }
    }
    probe_with_retries(client, url, timeout_secs, None, "").await
}

async fn probe_with_retries(client: &Client, url: &str, timeout_secs: u64, throttle: Option<&Throttle>, host: &str) -> anyhow::Result<RawEvent> {
    let mut tries = 0usize;
    let mut backoff = 200u64; // ms
    loop {
        tries += 1;
        let res = probe_url_inner(client, url, timeout_secs).await;
        match res {
            Ok(ev) => {
                // If WAF-like responses (detected by notes containing waf or status 429/5xx repeated), cool down host
                if ev.status == 429 || (ev.status >= 500 && ev.status < 600) {
                    if let Some(t) = throttle {
                        if !host.is_empty() {
                            t.cool_down_host(host, 1, 30); // reduce to 1 for 30s
                        }
                    }
                }
                return Ok(ev);
            }
            Err(e) => {
                if tries >= 3 {
                    return Err(e);
                }
                // exponential backoff
                tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
                backoff *= 2;
                continue;
            }
        }
    }
}

async fn probe_url_inner(client: &Client, url: &str, timeout_secs: u64) -> anyhow::Result<RawEvent> {
    let start = Instant::now();

    // Try HEAD first
    let head_resp = tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), client.head(url).send()).await;

    let mut status = 0u16;
    let mut content_type: Option<String> = None;
    let mut server: Option<String> = None;
    let mut content_length: Option<u64> = None;
    let mut body_sample = None;
    let mut is_graphql = false;

    match head_resp {
        Ok(Ok(r)) => {
            status = r.status().as_u16();
            content_type = r.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            server = r.headers().get(reqwest::header::SERVER).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            content_length = r.headers().get(reqwest::header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|s| s.parse().ok());
            // If HEAD indicates no body but status suggests body may exist, do GET
            if status == 405 || status == 501 || content_type.is_none() {
                // fallback to GET below
            }
        }
        _ => {
            // HEAD failed or timed out; we'll try GET
        }
    }

    // If HEAD didn't give us enough, do a partial GET
    if content_type.is_none() || status == 405 || status == 501 || status == 0 {
        let get_resp = tokio::time::timeout(std::time::Duration::from_secs(timeout_secs),
            client.get(url).header(reqwest::header::RANGE, "bytes=0-8191").send()).await;

        if let Ok(Ok(r)) = get_resp {
            status = r.status().as_u16();
            content_type = r.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            server = r.headers().get(reqwest::header::SERVER).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            content_length = r.headers().get(reqwest::header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|s| s.parse().ok());
            if let Ok(bytes) = r.bytes().await {
                let slice = &bytes[..std::cmp::min(4096, bytes.len())];
                if let Ok(text) = std::str::from_utf8(slice) {
                    // Try parse JSON sample
                    if let Ok(j) = serde_json::from_str::<serde_json::Value>(text) {
                        is_graphql = j.get("data").is_some() || j.get("errors").is_some();
                        body_sample = Some(j);
                    } else {
                        // not JSON; keep small textual sample
                        body_sample = Some(json!({"_sample": &text[0..std::cmp::min(200, text.len())]}));
                    }
                }
            }
        }
    }

    let elapsed = start.elapsed().as_millis() as u64;

    let orig = url.to_string();
    let final_url = url.to_string();

    // WAF detection rudimentary: check server header for cloudflare
    let mut notes = Vec::new();
    if let Some(ref s) = server {
        if s.to_lowercase().contains("cloudflare") {
            notes.push("waf:cloudflare".to_string());
        }
    }

    Ok(RawEvent {
        orig_url: orig,
        final_url,
        status,
        content_type,
        server,
        content_length,
        response_ms: Some(elapsed),
        tls_issuer: None,
        is_graphql,
        json_sample: body_sample,
        score: 0,
        notes,
    })
}
