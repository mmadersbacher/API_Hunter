use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use anyhow::Result;

/// Advanced API testing module for deep security analysis
pub struct AdvancedTester {
    client: Client,
    url: String,
}

#[derive(Debug, Clone)]
pub struct TestResult {
    pub test_name: String,
    pub method: String,
    pub status: u16,
    pub response_time_ms: u64,
    pub vulnerability: Option<String>,
    pub severity: Severity,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl AdvancedTester {
    pub fn new(url: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()?;

        Ok(Self {
            client,
            url: url.to_string(),
        })
    }

    /// Test all HTTP methods comprehensively
    pub async fn test_http_methods(&self) -> Vec<TestResult> {
        let methods = vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::HEAD,
            Method::OPTIONS,
            Method::TRACE,
        ];

        let mut results = Vec::new();

        for method in methods {
            let start = Instant::now();
            let method_str = method.as_str().to_string();

            match self.client.request(method, &self.url).send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let elapsed = start.elapsed().as_millis() as u64;

                    // Check for dangerous methods
                    let (vuln, severity) = match method_str.as_str() {
                        "TRACE" if status < 400 => {
                            (Some("TRACE method enabled - XST vulnerability".to_string()), Severity::High)
                        }
                        "PUT" | "DELETE" if status < 400 => {
                            (Some(format!("{} method accessible without auth", method_str)), Severity::High)
                        }
                        _ => (None, Severity::Info),
                    };

                    results.push(TestResult {
                        test_name: format!("{} Method Test", method_str),
                        method: method_str.clone(),
                        status,
                        response_time_ms: elapsed,
                        vulnerability: vuln,
                        severity,
                        details: format!("Response: {}", status),
                    });
                }
                Err(e) => {
                    results.push(TestResult {
                        test_name: format!("{} Method Test", method_str),
                        method: method_str.clone(),
                        status: 0,
                        response_time_ms: start.elapsed().as_millis() as u64,
                        vulnerability: None,
                        severity: Severity::Info,
                        details: format!("Error: {}", e),
                    });
                }
            }
        }

        results
    }

    /// Test SQL Injection payloads
    pub async fn test_sql_injection(&self, param_name: &str) -> Vec<TestResult> {
        let payloads = vec![
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' OR 'x'='x",
            "1; DROP TABLE users--",
            "' OR 1=1#",
        ];

        self.test_parameter_fuzzing(param_name, &payloads, "SQL Injection").await
    }

    /// Test NoSQL Injection payloads
    pub async fn test_nosql_injection(&self, param_name: &str) -> Vec<TestResult> {
        let payloads = vec![
            "[$ne]",
            "{\"$gt\":\"\"}",
            "{\"$ne\":null}",
            "true, $where: '1 == 1'",
            "', $or: [ {}, { 'a':'a",
            "{\"$regex\":\".*\"}",
        ];

        self.test_parameter_fuzzing(param_name, &payloads, "NoSQL Injection").await
    }

    /// Test XSS payloads
    pub async fn test_xss(&self, param_name: &str) -> Vec<TestResult> {
        let payloads = vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        ];

        self.test_parameter_fuzzing(param_name, &payloads, "XSS").await
    }

    /// Test SSRF payloads
    pub async fn test_ssrf(&self, param_name: &str) -> Vec<TestResult> {
        let payloads = vec![
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "http://metadata.google.internal/",
        ];

        self.test_parameter_fuzzing(param_name, &payloads, "SSRF").await
    }

    /// Test Path Traversal
    pub async fn test_path_traversal(&self, param_name: &str) -> Vec<TestResult> {
        let payloads = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ];

        self.test_parameter_fuzzing(param_name, &payloads, "Path Traversal").await
    }

    /// Generic parameter fuzzing
    async fn test_parameter_fuzzing(
        &self,
        param_name: &str,
        payloads: &[&str],
        test_type: &str,
    ) -> Vec<TestResult> {
        let mut results = Vec::new();

        for payload in payloads {
            let url = format!("{}?{}={}", self.url, param_name, payload);
            let start = Instant::now();

            match self.client.get(&url).send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let elapsed = start.elapsed().as_millis() as u64;
                    let body = response.text().await.unwrap_or_default();

                    // Check for SQL errors
                    let sql_errors = vec![
                        "sql syntax", "mysql", "postgresql", "ora-", "syntax error",
                        "unclosed quotation", "quoted string", "database error",
                    ];

                    // Check for reflection in response
                    let reflected = body.contains(payload);

                    let (vuln, severity) = if sql_errors.iter().any(|e| body.to_lowercase().contains(e)) {
                        (Some(format!("{} detected: SQL error in response", test_type)), Severity::Critical)
                    } else if reflected && test_type == "XSS" {
                        (Some(format!("{} detected: Payload reflected", test_type)), Severity::High)
                    } else if status == 200 && elapsed > 5000 {
                        (Some(format!("{} possible: Slow response", test_type)), Severity::Medium)
                    } else {
                        (None, Severity::Info)
                    };

                    results.push(TestResult {
                        test_name: format!("{} Test", test_type),
                        method: "GET".to_string(),
                        status,
                        response_time_ms: elapsed,
                        vulnerability: vuln,
                        severity,
                        details: format!("Payload: {}", payload),
                    });
                }
                Err(_) => continue,
            }
        }

        results
    }

    /// Test for common JWT vulnerabilities
    pub async fn test_jwt_security(&self, token: &str) -> Vec<TestResult> {
        let mut results = Vec::new();

        // Test 1: None algorithm
        let test_tokens = vec![
            ("None Algorithm", token.replace("HS256", "none")),
            ("Empty Signature", {
                let parts: Vec<&str> = token.split('.').collect();
                if parts.len() == 3 {
                    format!("{}.{}.", parts[0], parts[1])
                } else {
                    token.to_string()
                }
            }),
        ];

        for (test_name, test_token) in test_tokens {
            let start = Instant::now();

            match self.client
                .get(&self.url)
                .header("Authorization", format!("Bearer {}", test_token))
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let elapsed = start.elapsed().as_millis() as u64;

                    let (vuln, severity) = if status == 200 {
                        (Some(format!("JWT vulnerability: {} bypass", test_name)), Severity::Critical)
                    } else {
                        (None, Severity::Info)
                    };

                    results.push(TestResult {
                        test_name: format!("JWT {} Test", test_name),
                        method: "GET".to_string(),
                        status,
                        response_time_ms: elapsed,
                        vulnerability: vuln,
                        severity,
                        details: format!("Modified JWT tested"),
                    });
                }
                Err(_) => continue,
            }
        }

        results
    }

    /// Test rate limiting
    pub async fn test_rate_limiting(&self, num_requests: u32) -> Vec<TestResult> {
        let mut results = Vec::new();
        let mut status_codes: HashMap<u16, u32> = HashMap::new();

        println!("[*] Testing rate limiting with {} requests...", num_requests);

        for i in 0..num_requests {
            let start = Instant::now();

            match self.client.get(&self.url).send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let elapsed = start.elapsed().as_millis() as u64;
                    *status_codes.entry(status).or_insert(0) += 1;

                    if status == 429 {
                        results.push(TestResult {
                            test_name: "Rate Limiting Test".to_string(),
                            method: "GET".to_string(),
                            status,
                            response_time_ms: elapsed,
                            vulnerability: None,
                            severity: Severity::Info,
                            details: format!("Rate limit hit after {} requests", i + 1),
                        });
                        break;
                    }
                }
                Err(_) => continue,
            }
        }

        if !status_codes.contains_key(&429) {
            results.push(TestResult {
                test_name: "Rate Limiting Test".to_string(),
                method: "GET".to_string(),
                status: 0,
                response_time_ms: 0,
                vulnerability: Some("No rate limiting detected".to_string()),
                severity: Severity::Medium,
                details: format!("Sent {} requests without rate limit", num_requests),
            });
        }

        results
    }

    /// Test CORS configuration
    pub async fn test_cors(&self) -> Vec<TestResult> {
        let mut results = Vec::new();
        let origins = vec![
            "https://evil.com",
            "null",
            "https://attacker.com",
        ];

        for origin in origins {
            let start = Instant::now();

            match self.client
                .get(&self.url)
                .header("Origin", origin)
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let elapsed = start.elapsed().as_millis() as u64;
                    let cors_header = response
                        .headers()
                        .get("access-control-allow-origin")
                        .and_then(|h| h.to_str().ok());

                    let (vuln, severity) = if cors_header == Some("*") {
                        (Some("CORS misconfiguration: Wildcard origin".to_string()), Severity::High)
                    } else if cors_header == Some(origin) {
                        (Some(format!("CORS reflects arbitrary origin: {}", origin)), Severity::High)
                    } else {
                        (None, Severity::Info)
                    };

                    results.push(TestResult {
                        test_name: "CORS Test".to_string(),
                        method: "GET".to_string(),
                        status,
                        response_time_ms: elapsed,
                        vulnerability: vuln,
                        severity,
                        details: format!("Origin: {}, CORS: {:?}", origin, cors_header),
                    });
                }
                Err(_) => continue,
            }
        }

        results
    }

    /// Deep response analysis
    pub async fn analyze_response_deep(&self) -> Result<Value> {
        let response = self.client.get(&self.url).send().await?;
        
        let status = response.status().as_u16();
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = response.text().await?;

        // Try to parse as JSON
        let json_parsed = serde_json::from_str::<Value>(&body).ok();

        // Check for sensitive data patterns
        let sensitive_patterns = vec![
            "password", "token", "secret", "api_key", "private", "ssn",
            "credit_card", "api-key", "apikey", "auth", "session",
        ];

        let sensitive_found: Vec<String> = sensitive_patterns
            .iter()
            .filter(|p| body.to_lowercase().contains(*p))
            .map(|s| s.to_string())
            .collect();

        Ok(json!({
            "status": status,
            "headers": headers,
            "body_length": body.len(),
            "is_json": json_parsed.is_some(),
            "json_structure": json_parsed,
            "sensitive_data_hints": sensitive_found,
            "has_stack_trace": body.contains("at ") || body.contains("Traceback"),
            "has_sql_error": body.to_lowercase().contains("sql") && body.to_lowercase().contains("error"),
        }))
    }
}

/// Print test results in professional format
pub fn print_results(results: &[TestResult]) {
    println!("\n[*] Advanced Security Test Results");
    println!("================================================================================");

    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    for result in results {
        if result.vulnerability.is_some() {
            let icon = match result.severity {
                Severity::Critical => { critical += 1; "[!] CRITICAL" },
                Severity::High => { high += 1; "[!] HIGH" },
                Severity::Medium => { medium += 1; "[!] MEDIUM" },
                Severity::Low => { low += 1; "[-] LOW" },
                Severity::Info => continue,
            };

            println!("{}: {}", icon, result.test_name);
            println!("    Vulnerability: {}", result.vulnerability.as_ref().unwrap());
            println!("    Method: {} | Status: {} | Time: {}ms", 
                     result.method, result.status, result.response_time_ms);
            println!("    Details: {}", result.details);
            println!();
        }
    }

    println!("================================================================================");
    println!("[+] Summary: {} Critical, {} High, {} Medium, {} Low", 
             critical, high, medium, low);
    println!("================================================================================\n");
}
