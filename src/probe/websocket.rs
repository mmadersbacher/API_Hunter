use anyhow::Result;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct WebSocketEndpoint {
    pub url: String,
    pub is_websocket: bool,
    pub protocols: Vec<String>,
    pub extensions: Vec<String>,
}

pub struct WebSocketTester {
    timeout: Duration,
}

impl WebSocketTester {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }

    /// Detect WebSocket endpoints from common patterns
    pub async fn discover_websocket(&self, base_url: &str) -> Vec<String> {
        let common_paths = vec![
            "/ws",
            "/websocket",
            "/socket.io",
            "/api/ws",
            "/api/websocket",
            "/v1/ws",
            "/v2/ws",
            "/realtime",
            "/stream",
            "/live",
            "/updates",
            "/events",
            "/notifications",
        ];

        let mut found = Vec::new();
        let ws_base = base_url.replace("http://", "ws://").replace("https://", "wss://");

        for path in common_paths {
            let url = format!("{}{}", ws_base.trim_end_matches('/'), path);
            
            // Test if WebSocket upgrade is possible
            if self.test_websocket_upgrade(&url).await {
                println!("[+] WebSocket endpoint found: {}", url);
                found.push(url);
            }
        }

        found
    }

    /// Test if URL supports WebSocket upgrade
    async fn test_websocket_upgrade(&self, url: &str) -> bool {
        use reqwest::Client;
        
        let client = Client::builder()
            .timeout(self.timeout)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        // Try HTTP Upgrade request
        let http_url = url.replace("ws://", "http://").replace("wss://", "https://");
        
        if let Ok(response) = client
            .get(&http_url)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
        {
            let status = response.status().as_u16();
            // 101 Switching Protocols or 426 Upgrade Required
            if status == 101 || status == 426 {
                return true;
            }
            
            // Check for WebSocket-related headers
            let headers = response.headers();
            if headers.contains_key("Sec-WebSocket-Accept") 
                || headers.get("Upgrade").and_then(|v| v.to_str().ok()) == Some("websocket") {
                return true;
            }
        }

        false
    }

    /// Test WebSocket vulnerabilities
    pub async fn test_websocket_vulnerabilities(&self, url: &str) -> Vec<WebSocketVulnerability> {
        let mut vulns = Vec::new();

        // Test 1: Missing origin check
        if self.test_origin_bypass(url).await {
            vulns.push(WebSocketVulnerability {
                name: "Missing Origin Validation".to_string(),
                severity: "High".to_string(),
                description: "WebSocket accepts connections from any origin".to_string(),
                details: "CSRF attacks via WebSocket possible".to_string(),
            });
        }

        // Test 2: No authentication required
        if self.test_no_auth(url).await {
            vulns.push(WebSocketVulnerability {
                name: "No Authentication Required".to_string(),
                severity: "Critical".to_string(),
                description: "WebSocket connection possible without authentication".to_string(),
                details: "Unauthorized access to real-time data".to_string(),
            });
        }

        vulns
    }

    async fn test_origin_bypass(&self, url: &str) -> bool {
        use reqwest::Client;
        
        let client = Client::builder()
            .timeout(self.timeout)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let http_url = url.replace("ws://", "http://").replace("wss://", "https://");
        
        if let Ok(response) = client
            .get(&http_url)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Origin", "https://evil.com")
            .send()
            .await
        {
            response.status().as_u16() == 101
        } else {
            false
        }
    }

    async fn test_no_auth(&self, url: &str) -> bool {
        use reqwest::Client;
        
        let client = Client::builder()
            .timeout(self.timeout)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let http_url = url.replace("ws://", "http://").replace("wss://", "https://");
        
        if let Ok(response) = client
            .get(&http_url)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
        {
            response.status().as_u16() == 101
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
pub struct WebSocketVulnerability {
    pub name: String,
    pub severity: String,
    pub description: String,
    pub details: String,
}

pub fn print_websocket_results(endpoints: &[String], vulns: &[WebSocketVulnerability]) {
    if endpoints.is_empty() {
        return;
    }

    println!("\n[*] WebSocket Analysis Results");
    println!("================================================================================");
    println!("[+] Found {} WebSocket endpoint(s)", endpoints.len());
    
    for (i, endpoint) in endpoints.iter().enumerate() {
        println!("  {}. {}", i + 1, endpoint);
    }

    if !vulns.is_empty() {
        println!("\n[!] Vulnerabilities Found:");
        for vuln in vulns {
            let icon = match vuln.severity.as_str() {
                "Critical" => "[!] CRITICAL",
                "High" => "[!] HIGH",
                "Medium" => "[!] MEDIUM",
                "Low" => "[-] LOW",
                _ => "[*] INFO",
            };
            println!("\n{}: {}", icon, vuln.name);
            println!("    Description: {}", vuln.description);
            println!("    Details: {}", vuln.details);
        }
    }

    println!("================================================================================\n");
}
