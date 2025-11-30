use crate::http_client::HttpClient;
use anyhow::Result;
use std::collections::HashMap;
use tokio::time::{timeout, Duration};
use base64::Engine;

#[derive(Debug, Clone)]
pub struct AuthResult {
    pub url: String,
    pub auth_methods: Vec<AuthMethod>,
    pub vulnerabilities: Vec<AuthVulnerability>,
}

#[derive(Debug, Clone)]
pub struct AuthMethod {
    pub method_type: String,
    pub detected_in: String,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct AuthVulnerability {
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
    pub evidence: Option<String>,
}

pub struct AuthTester {
    client: HttpClient,
}

impl AuthTester {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Comprehensive authentication testing
    pub async fn test_endpoint(&self, url: &str) -> Result<AuthResult> {
        let mut result = AuthResult {
            url: url.to_string(),
            auth_methods: Vec::new(),
            vulnerabilities: Vec::new(),
        };

        // Test sequentially
        if let Ok(methods) = self.detect_auth_methods(url).await {
            result.auth_methods.extend(methods);
        }

        if let Ok(vulns) = self.test_api_key_vulnerabilities(url).await {
            result.vulnerabilities.extend(vulns);
        }

        if let Ok(vulns) = self.test_jwt_vulnerabilities(url).await {
            result.vulnerabilities.extend(vulns);
        }

        if let Ok(vulns) = self.test_oauth_vulnerabilities(url).await {
            result.vulnerabilities.extend(vulns);
        }

        if let Ok(vulns) = self.test_basic_auth_vulnerabilities(url).await {
            result.vulnerabilities.extend(vulns);
        }

        if let Ok(vulns) = self.test_session_vulnerabilities(url).await {
            result.vulnerabilities.extend(vulns);
        }

        Ok(result)
    }

    /// Detect authentication methods
    async fn detect_auth_methods(&self, url: &str) -> Result<Vec<AuthMethod>> {
        let mut methods = Vec::new();

        match timeout(Duration::from_secs(3), self.client.get(url)).await {
            Ok(Ok(response)) => {
                let headers = response.headers();
                let status = response.status();

                // Check WWW-Authenticate header
                if let Some(www_auth) = headers.get("www-authenticate") {
                    if let Ok(value) = www_auth.to_str() {
                        let mut details = HashMap::new();
                        details.insert("header".to_string(), value.to_string());

                        if value.to_lowercase().contains("bearer") {
                            methods.push(AuthMethod {
                                method_type: "Bearer Token".to_string(),
                                detected_in: "WWW-Authenticate header".to_string(),
                                details: details.clone(),
                            });
                        }

                        if value.to_lowercase().contains("basic") {
                            methods.push(AuthMethod {
                                method_type: "Basic Auth".to_string(),
                                detected_in: "WWW-Authenticate header".to_string(),
                                details: details.clone(),
                            });
                        }

                        if value.to_lowercase().contains("digest") {
                            methods.push(AuthMethod {
                                method_type: "Digest Auth".to_string(),
                                detected_in: "WWW-Authenticate header".to_string(),
                                details,
                            });
                        }
                    }
                }

                // Check response body
                if let Ok(body) = response.text().await {
                    let body_lower = body.to_lowercase();

                    // Check for OAuth mentions
                    if body_lower.contains("oauth") || body_lower.contains("authorize") {
                        methods.push(AuthMethod {
                            method_type: "OAuth".to_string(),
                            detected_in: "Response body".to_string(),
                            details: HashMap::new(),
                        });
                    }

                    // Check for API key patterns
                    if body_lower.contains("api_key") || body_lower.contains("apikey") 
                        || body_lower.contains("x-api-key") {
                        methods.push(AuthMethod {
                            method_type: "API Key".to_string(),
                            detected_in: "Response body".to_string(),
                            details: HashMap::new(),
                        });
                    }

                    // Check for JWT patterns
                    if body_lower.contains("jwt") || body_lower.contains("token") {
                        methods.push(AuthMethod {
                            method_type: "JWT".to_string(),
                            detected_in: "Response body".to_string(),
                            details: HashMap::new(),
                        });
                    }
                }

                // Check for 401/403 indicating auth required
                if status.as_u16() == 401 || status.as_u16() == 403 {
                    let mut details = HashMap::new();
                    details.insert("status".to_string(), status.to_string());
                    methods.push(AuthMethod {
                        method_type: "Authentication Required".to_string(),
                        detected_in: format!("HTTP {}", status.as_u16()),
                        details,
                    });
                }
            }
            _ => {}
        }

        Ok(methods)
    }

    /// Test API key vulnerabilities
    async fn test_api_key_vulnerabilities(&self, url: &str) -> Result<Vec<AuthVulnerability>> {
        let mut vulns = Vec::new();

        // Test common API key parameter names
        let api_key_params = vec![
            "api_key", "apikey", "key", "token", "access_token",
            "auth", "authorization", "api-key", "x-api-key"
        ];

        for param in api_key_params {
            // Test in query parameter
            let test_url = format!("{}?{}=test123", url, param);
            
            match timeout(Duration::from_secs(2), self.client.get(&test_url)).await {
                Ok(Ok(response)) => {
                    let status = response.status().as_u16();
                    
                    // If we get anything other than 401/403, API key might be accepted
                    if status != 401 && status != 403 {
                        if let Ok(body) = response.text().await {
                            if !body.to_lowercase().contains("invalid") 
                                && !body.to_lowercase().contains("unauthorized") {
                                vulns.push(AuthVulnerability {
                                    vuln_type: "Weak API Key Validation".to_string(),
                                    severity: "HIGH".to_string(),
                                    description: format!("API accepts '{}' parameter without proper validation", param),
                                    evidence: Some(format!("Parameter: {}", param)),
                                });
                            }
                        }
                    }
                }
                _ => {}
            }

            // Test in header
            let mut headers = HashMap::new();
            headers.insert(param.to_string(), "test123".to_string());
            
            match timeout(Duration::from_secs(2), self.client.get_with_headers(url, &headers)).await {
                Ok(Ok(response)) => {
                    let status = response.status().as_u16();
                    
                    if status != 401 && status != 403 {
                        if let Ok(body) = response.text().await {
                            if !body.to_lowercase().contains("invalid") 
                                && !body.to_lowercase().contains("unauthorized") {
                                vulns.push(AuthVulnerability {
                                    vuln_type: "Weak API Key Header Validation".to_string(),
                                    severity: "HIGH".to_string(),
                                    description: format!("API accepts '{}' header without proper validation", param),
                                    evidence: Some(format!("Header: {}", param)),
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Test API key in URL path
        let path_test = format!("{}/test123", url.trim_end_matches('/'));
        match timeout(Duration::from_secs(2), self.client.get(&path_test)).await {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    vulns.push(AuthVulnerability {
                        vuln_type: "API Key in URL Path".to_string(),
                        severity: "MEDIUM".to_string(),
                        description: "API might accept keys in URL path - insecure practice".to_string(),
                        evidence: Some("Path parameter accepted".to_string()),
                    });
                }
            }
            _ => {}
        }

        Ok(vulns)
    }

    /// Test JWT vulnerabilities
    async fn test_jwt_vulnerabilities(&self, url: &str) -> Result<Vec<AuthVulnerability>> {
        let mut vulns = Vec::new();

        // Test None algorithm vulnerability
        let none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.";
        
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), format!("Bearer {}", none_jwt));
        
        match timeout(Duration::from_secs(2), self.client.get_with_headers(url, &headers)).await {
            Ok(Ok(response)) => {
                let status = response.status().as_u16();
                if status != 401 && status != 403 {
                    vulns.push(AuthVulnerability {
                        vuln_type: "JWT None Algorithm Accepted".to_string(),
                        severity: "CRITICAL".to_string(),
                        description: "API accepts JWT with 'none' algorithm - complete bypass possible".to_string(),
                        evidence: Some("None algorithm JWT accepted".to_string()),
                    });
                }
            }
            _ => {}
        }

        // Test weak JWT secret (common secrets)
        let weak_secrets = vec!["secret", "password", "123456", "admin", "test"];
        for secret in weak_secrets {
            // Create simple JWT with weak secret (base64 encoded)
            let weak_jwt = format!(
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.{}",
                secret
            );
            
            let mut headers = HashMap::new();
            headers.insert("Authorization".to_string(), format!("Bearer {}", weak_jwt));
            
            match timeout(Duration::from_secs(2), self.client.get_with_headers(url, &headers)).await {
                Ok(Ok(response)) => {
                    if response.status().is_success() {
                        vulns.push(AuthVulnerability {
                            vuln_type: "Weak JWT Secret".to_string(),
                            severity: "CRITICAL".to_string(),
                            description: format!("JWT might use weak secret: '{}'", secret),
                            evidence: Some(format!("Weak secret: {}", secret)),
                        });
                        break; // Found one, no need to test more
                    }
                }
                _ => {}
            }
        }

        // Test expired token handling
        let expired_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNTE2MjM5MDIyfQ.invalidSignature";
        
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), format!("Bearer {}", expired_jwt));
        
        match timeout(Duration::from_secs(2), self.client.get_with_headers(url, &headers)).await {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    vulns.push(AuthVulnerability {
                        vuln_type: "Expired JWT Accepted".to_string(),
                        severity: "HIGH".to_string(),
                        description: "API accepts expired JWT tokens".to_string(),
                        evidence: Some("Expired token accepted".to_string()),
                    });
                }
            }
            _ => {}
        }

        Ok(vulns)
    }

    /// Test OAuth vulnerabilities
    async fn test_oauth_vulnerabilities(&self, url: &str) -> Result<Vec<AuthVulnerability>> {
        let mut vulns = Vec::new();

        // Test OAuth token in query parameter
        let oauth_url = format!("{}?access_token=test_token_123", url);
        
        match timeout(Duration::from_secs(2), self.client.get(&oauth_url)).await {
            Ok(Ok(response)) => {
                let status = response.status().as_u16();
                if status != 401 && status != 403 {
                    if let Ok(body) = response.text().await {
                        if !body.to_lowercase().contains("invalid") {
                            vulns.push(AuthVulnerability {
                                vuln_type: "OAuth Token in Query Parameter".to_string(),
                                severity: "MEDIUM".to_string(),
                                description: "API accepts OAuth tokens in URL query - tokens may be logged".to_string(),
                                evidence: Some("Query parameter accepted".to_string()),
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        // Test token reuse/refresh
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer revoked_token_123".to_string());
        
        match timeout(Duration::from_secs(2), self.client.get_with_headers(url, &headers)).await {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    vulns.push(AuthVulnerability {
                        vuln_type: "No Token Revocation".to_string(),
                        severity: "HIGH".to_string(),
                        description: "API might not properly validate token revocation".to_string(),
                        evidence: Some("Potentially revoked token accepted".to_string()),
                    });
                }
            }
            _ => {}
        }

        Ok(vulns)
    }

    /// Test Basic Auth vulnerabilities
    async fn test_basic_auth_vulnerabilities(&self, url: &str) -> Result<Vec<AuthVulnerability>> {
        let mut vulns = Vec::new();

        // Test common weak credentials
        let weak_creds = vec![
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("test", "test"),
            ("api", "api"),
        ];

        for (username, password) in weak_creds {
            let auth_str = format!("{}:{}", username, password);
            let encoded = base64::engine::general_purpose::STANDARD.encode(auth_str.as_bytes());
            
            let mut headers = HashMap::new();
            headers.insert("Authorization".to_string(), format!("Basic {}", encoded));
            
            match timeout(Duration::from_secs(2), self.client.get_with_headers(url, &headers)).await {
                Ok(Ok(response)) => {
                    if response.status().is_success() {
                        vulns.push(AuthVulnerability {
                            vuln_type: "Weak Basic Auth Credentials".to_string(),
                            severity: "CRITICAL".to_string(),
                            description: format!("API accepts weak credentials: {}:{}", username, password),
                            evidence: Some(format!("Credentials: {}:{}", username, password)),
                        });
                        break; // Found one, enough proof
                    }
                }
                _ => {}
            }
        }

        // Test Basic Auth over HTTP (if URL is HTTP)
        if url.starts_with("http://") {
            vulns.push(AuthVulnerability {
                vuln_type: "Basic Auth Over HTTP".to_string(),
                severity: "HIGH".to_string(),
                description: "Basic Auth used over unencrypted HTTP - credentials exposed".to_string(),
                evidence: Some("HTTP endpoint detected".to_string()),
            });
        }

        Ok(vulns)
    }

    /// Test session vulnerabilities
    async fn test_session_vulnerabilities(&self, url: &str) -> Result<Vec<AuthVulnerability>> {
        let mut vulns = Vec::new();

        // Test session fixation
        let mut headers = HashMap::new();
        headers.insert("Cookie".to_string(), "sessionid=attacker_session_123".to_string());
        
        match timeout(Duration::from_secs(2), self.client.get_with_headers(url, &headers)).await {
            Ok(Ok(response)) => {
                if let Some(set_cookie) = response.headers().get("set-cookie") {
                    if let Ok(cookie_value) = set_cookie.to_str() {
                        if cookie_value.contains("attacker_session_123") {
                            vulns.push(AuthVulnerability {
                                vuln_type: "Session Fixation".to_string(),
                                severity: "HIGH".to_string(),
                                description: "API accepts user-supplied session IDs".to_string(),
                                evidence: Some("Session ID preserved".to_string()),
                            });
                        }
                    }
                }

                // Check for missing security flags
                if let Some(set_cookie) = response.headers().get("set-cookie") {
                    if let Ok(cookie_value) = set_cookie.to_str() {
                        let cookie_lower = cookie_value.to_lowercase();
                        
                        if !cookie_lower.contains("httponly") {
                            vulns.push(AuthVulnerability {
                                vuln_type: "Missing HTTPOnly Flag".to_string(),
                                severity: "MEDIUM".to_string(),
                                description: "Session cookies missing HTTPOnly flag - XSS can steal sessions".to_string(),
                                evidence: Some("HTTPOnly flag not set".to_string()),
                            });
                        }

                        if !cookie_lower.contains("secure") && url.starts_with("https://") {
                            vulns.push(AuthVulnerability {
                                vuln_type: "Missing Secure Flag".to_string(),
                                severity: "MEDIUM".to_string(),
                                description: "HTTPS session cookies missing Secure flag".to_string(),
                                evidence: Some("Secure flag not set".to_string()),
                            });
                        }

                        if !cookie_lower.contains("samesite") {
                            vulns.push(AuthVulnerability {
                                vuln_type: "Missing SameSite Flag".to_string(),
                                severity: "MEDIUM".to_string(),
                                description: "Session cookies missing SameSite flag - CSRF possible".to_string(),
                                evidence: Some("SameSite flag not set".to_string()),
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(vulns)
    }
}
