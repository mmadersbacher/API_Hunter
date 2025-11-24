use anyhow::Result;
use reqwest::Client;
use url::Url;

/// Test values for different parameter types
pub struct ParamTestValues {
    pub numeric_ids: Vec<String>,
    pub boolean_values: Vec<String>,
    pub string_values: Vec<String>,
    pub special_chars: Vec<String>,
}

impl Default for ParamTestValues {
    fn default() -> Self {
        Self {
            numeric_ids: vec![
                "0".to_string(),
                "1".to_string(),
                "2".to_string(),
                "99".to_string(),
                "100".to_string(),
                "999".to_string(),
                "-1".to_string(),
            ],
            boolean_values: vec![
                "true".to_string(),
                "false".to_string(),
                "1".to_string(),
                "0".to_string(),
            ],
            string_values: vec![
                "test".to_string(),
                "admin".to_string(),
                "user".to_string(),
                "a".to_string(),
            ],
            special_chars: vec![
                "'".to_string(),
                "\"".to_string(),
                "<script>".to_string(),
                "../".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParamFuzzResult {
    pub url: String,
    pub param_name: String,
    pub test_value: String,
    pub status: u16,
    pub response_size: usize,
    pub response_time_ms: u64,
    pub different_response: bool,
    pub content_type: Option<String>,
}

/// Fuzz a parameter with different values
pub async fn fuzz_parameter(
    client: &Client,
    base_url: &str,
    param_name: &str,
    test_values: &[String],
    baseline_status: Option<u16>,
    baseline_size: Option<usize>,
) -> Result<Vec<ParamFuzzResult>> {
    let mut results = Vec::new();
    
    for test_value in test_values {
        let test_url = build_url_with_param(base_url, param_name, test_value)?;
        
        let start = std::time::Instant::now();
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let content_type = resp.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                
                let body = resp.bytes().await.unwrap_or_default();
                let response_size = body.len();
                let response_time_ms = start.elapsed().as_millis() as u64;
                
                // Enhanced response difference detection
                let mut different_response = false;
                
                // 1. Status code changed
                if let Some(bs) = baseline_status {
                    if status != bs {
                        different_response = true;
                    }
                }
                
                // 2. Significant size difference (more sensitive)
                if let Some(bz) = baseline_size {
                    let size_diff = (response_size as i64 - bz as i64).abs();
                    // Flag if difference is >50 bytes OR >10% of baseline
                    if size_diff > 50 || (bz > 0 && size_diff as f64 / bz as f64 > 0.1) {
                        different_response = true;
                    }
                }
                
                // 3. Response not empty (potentially interesting)
                if response_size > 0 && baseline_size.map(|bz| bz == 0).unwrap_or(false) {
                    different_response = true;
                }
                
                // 4. Success status on previously failing endpoint
                if status >= 200 && status < 300 {
                    if let Some(bs) = baseline_status {
                        if bs >= 400 {
                            different_response = true;
                        }
                    }
                }
                
                // 5. Different content type
                if response_size > 0 {
                    different_response = true; // Any response with content is worth noting
                }
                
                results.push(ParamFuzzResult {
                    url: test_url,
                    param_name: param_name.to_string(),
                    test_value: test_value.clone(),
                    status,
                    response_size,
                    response_time_ms,
                    different_response,
                    content_type,
                });
            }
            Err(_) => {
                // Request failed, skip
                continue;
            }
        }
        
        // Small delay to avoid overwhelming the server
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }
    
    Ok(results)
}

/// Test for IDOR by trying sequential IDs
pub async fn test_idor(
    client: &Client,
    base_url: &str,
    param_name: &str,
    original_id: &str,
) -> Result<Vec<ParamFuzzResult>> {
    let mut test_ids = Vec::new();
    
    // If original_id is numeric, try adjacent IDs
    if let Ok(id_num) = original_id.parse::<i64>() {
        for offset in [-2, -1, 1, 2, 10, 100] {
            let new_id = id_num + offset;
            if new_id > 0 {
                test_ids.push(new_id.to_string());
            }
        }
    } else {
        // For non-numeric IDs, just try common values
        test_ids.extend(vec![
            "1".to_string(),
            "2".to_string(),
            "admin".to_string(),
            "test".to_string(),
        ]);
    }
    
    fuzz_parameter(client, base_url, param_name, &test_ids, None, None).await
}

/// Build URL with a specific parameter value
fn build_url_with_param(base_url: &str, param_name: &str, param_value: &str) -> Result<String> {
    let mut url = Url::parse(base_url)?;
    
    // Add or replace the parameter
    url.query_pairs_mut()
        .clear()
        .append_pair(param_name, param_value);
    
    // Preserve existing query params from base_url
    if let Some(query) = Url::parse(base_url).ok().and_then(|u| u.query().map(String::from)) {
        let mut found = false;
        for pair in query.split('&') {
            if let Some(eq_pos) = pair.find('=') {
                let key = &pair[..eq_pos];
                let val = &pair[eq_pos + 1..];
                if key == param_name {
                    found = true;
                } else {
                    url.query_pairs_mut().append_pair(key, val);
                }
            }
        }
        if !found {
            url.query_pairs_mut().append_pair(param_name, param_value);
        }
    }
    
    Ok(url.to_string())
}

/// Smart parameter fuzzing - detect parameter type and test accordingly
pub async fn smart_fuzz_parameter(
    client: &Client,
    base_url: &str,
    param_name: &str,
    current_value: Option<&str>,
) -> Result<Vec<ParamFuzzResult>> {
    let test_values = ParamTestValues::default();
    
    // Determine parameter type from name and current value
    let values = if param_name.to_lowercase().contains("id") || param_name.to_lowercase().contains("user") {
        &test_values.numeric_ids
    } else if param_name.to_lowercase().contains("bool") || param_name == "active" || param_name == "enabled" {
        &test_values.boolean_values
    } else {
        &test_values.string_values
    };
    
    // Get baseline if current value exists
    let (baseline_status, baseline_size) = if let Some(val) = current_value {
        let baseline_url = build_url_with_param(base_url, param_name, val)?;
        if let Ok(resp) = client.get(&baseline_url).send().await {
            let status = resp.status().as_u16();
            let size = resp.bytes().await.map(|b| b.len()).unwrap_or(0);
            (Some(status), Some(size))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };
    
    fuzz_parameter(client, base_url, param_name, values, baseline_status, baseline_size).await
}
