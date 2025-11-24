use anyhow::Result;
use reqwest::Client;
use url::Url;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdorTestResult {
    pub url: String,
    pub parameter: String,
    pub original_value: String,
    pub test_value: String,
    pub original_status: u16,
    pub test_status: u16,
    pub original_size: usize,
    pub test_size: usize,
    pub is_vulnerable: bool,
    pub risk_level: IdorRiskLevel,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IdorRiskLevel {
    Critical,  // Different data returned for modified ID
    High,      // Same status but different size
    Medium,    // Suspicious pattern
    Info,      // Informational only
}

/// Advanced IDOR testing with multiple techniques
pub async fn test_idor_advanced(
    client: &Client,
    url: &str,
    param_name: &str,
    original_value: &str,
) -> Result<Vec<IdorTestResult>> {
    let mut results = Vec::new();
    
    // Get baseline
    let (orig_status, orig_size, orig_body) = fetch_response(client, url).await?;
    
    // Generate test values based on original value type
    let test_values = generate_idor_test_values(original_value);
    
    for test_value in test_values {
        // Build URL with modified parameter
        let test_url = replace_param_value(url, param_name, &test_value)?;
        
        // Fetch test response
        match fetch_response(client, &test_url).await {
            Ok((test_status, test_size, test_body)) => {
                // Analyze for IDOR vulnerability
                let (is_vulnerable, risk_level, evidence) = analyze_idor_response(
                    orig_status,
                    orig_size,
                    &orig_body,
                    test_status,
                    test_size,
                    &test_body,
                    original_value,
                    &test_value,
                );
                
                if is_vulnerable {
                    results.push(IdorTestResult {
                        url: url.to_string(),
                        parameter: param_name.to_string(),
                        original_value: original_value.to_string(),
                        test_value: test_value.clone(),
                        original_status: orig_status,
                        test_status,
                        original_size: orig_size,
                        test_size,
                        is_vulnerable,
                        risk_level,
                        evidence,
                    });
                }
            }
            Err(_) => continue,
        }
        
        // Delay between requests
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    
    Ok(results)
}

fn generate_idor_test_values(original: &str) -> Vec<String> {
    let mut values = Vec::new();
    
    // Try to parse as number
    if let Ok(num) = original.parse::<i64>() {
        // Sequential IDs
        values.push((num - 1).to_string());
        values.push((num + 1).to_string());
        values.push((num - 10).to_string());
        values.push((num + 10).to_string());
        
        // Common test values
        values.push("1".to_string());
        values.push("2".to_string());
        values.push("100".to_string());
        values.push("999".to_string());
        values.push("0".to_string());
        
        // Negative values
        values.push("-1".to_string());
        
        // Large values
        values.push("999999".to_string());
    } else if original.contains('-') && original.len() == 36 {
        // UUID - try variations
        values.push("00000000-0000-0000-0000-000000000000".to_string());
        values.push("11111111-1111-1111-1111-111111111111".to_string());
        
        // Modify last segment
        let parts: Vec<&str> = original.split('-').collect();
        if parts.len() == 5 {
            values.push(format!("{}-{}-{}-{}-000000000000", parts[0], parts[1], parts[2], parts[3]));
        }
    } else if original.len() >= 16 && original.chars().all(|c| c.is_alphanumeric()) {
        // Hash-like ID
        values.push("0".repeat(original.len()));
        values.push("1".repeat(original.len()));
        values.push("a".repeat(original.len()));
    } else {
        // String-based ID
        values.push("admin".to_string());
        values.push("test".to_string());
        values.push("user".to_string());
        values.push("1".to_string());
    }
    
    values
}

fn analyze_idor_response(
    orig_status: u16,
    orig_size: usize,
    orig_body: &str,
    test_status: u16,
    test_size: usize,
    test_body: &str,
    orig_value: &str,
    test_value: &str,
) -> (bool, IdorRiskLevel, String) {
    // Critical: 200 OK with different data
    if test_status == 200 && orig_status == 200 {
        let size_diff = (orig_size as i64 - test_size as i64).abs();
        
        // Bodies are significantly different
        if size_diff > 50 && test_body != orig_body {
            return (
                true,
                IdorRiskLevel::Critical,
                format!("Different data returned: {} bytes vs {} bytes (modified {} -> {})", 
                    orig_size, test_size, orig_value, test_value)
            );
        }
        
        // Check for different user data patterns
        if orig_body.contains("\"id\"") && test_body.contains("\"id\"") {
            // Extract IDs and compare
            if !test_body.contains(&format!("\"id\":\"{}", orig_value)) 
                && test_body.contains(&format!("\"id\":\"{}", test_value)) {
                return (
                    true,
                    IdorRiskLevel::Critical,
                    format!("Access to different user ID: {} (original: {})", test_value, orig_value)
                );
            }
        }
    }
    
    // High: Success with modified ID (potential lateral movement)
    if test_status == 200 && orig_status != 200 {
        return (
            true,
            IdorRiskLevel::High,
            format!("Modified ID {} returned 200 (original {} returned {})", 
                test_value, orig_value, orig_status)
        );
    }
    
    // Medium: Different error or size with modified ID
    if test_status != orig_status && (test_status == 200 || test_status == 403 || test_status == 401) {
        return (
            true,
            IdorRiskLevel::Medium,
            format!("Status changed from {} to {} with modified ID", orig_status, test_status)
        );
    }
    
    (false, IdorRiskLevel::Info, String::new())
}

async fn fetch_response(client: &Client, url: &str) -> Result<(u16, usize, String)> {
    let resp = client.get(url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await?;
    
    let status = resp.status().as_u16();
    let body = resp.text().await?;
    let size = body.len();
    
    Ok((status, size, body))
}

fn replace_param_value(url: &str, param_name: &str, new_value: &str) -> Result<String> {
    let mut parsed = Url::parse(url)?;
    
    // Modify query parameters
    let mut new_pairs = Vec::new();
    let mut found = false;
    
    for (key, _) in parsed.query_pairs() {
        if key == param_name {
            new_pairs.push((key.to_string(), new_value.to_string()));
            found = true;
        } else {
            new_pairs.push((key.to_string(), parsed.query_pairs().find(|(k, _)| *k == key).unwrap().1.to_string()));
        }
    }
    
    if !found {
        new_pairs.push((param_name.to_string(), new_value.to_string()));
    }
    
    parsed.query_pairs_mut().clear();
    for (key, value) in new_pairs {
        parsed.query_pairs_mut().append_pair(&key, &value);
    }
    
    Ok(parsed.to_string())
}
