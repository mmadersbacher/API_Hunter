use anyhow::Result;
use reqwest::Client;
use serde::{Serialize, Deserialize};

/// Common admin/debug paths to test
pub fn admin_paths() -> Vec<&'static str> {
    vec![
        "/admin",
        "/admin/",
        "/administrator",
        "/admin/login",
        "/admin/dashboard",
        "/admin/panel",
        "/admin/config",
        "/admin/settings",
        "/api/admin",
        "/api/v1/admin",
        "/api/v2/admin",
        "/backend",
        "/backend/admin",
        "/console",
        "/control",
        "/cp",
        "/dashboard",
        "/debug",
        "/debug/",
        "/internal",
        "/internal/",
        "/manage",
        "/management",
        "/manager",
        "/panel",
        "/phpmyadmin",
        "/staff",
        "/supervisor",
        "/sysadmin",
        "/system",
        "/test",
        "/wp-admin",
        "/.env",
        "/.git/config",
        "/config.json",
        "/swagger",
        "/swagger-ui",
        "/api-docs",
        "/graphql",
        "/graphiql",
        "/actuator",
        "/actuator/health",
        "/health",
        "/status",
        "/metrics",
        "/info",
        "/version",
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminScanResult {
    pub url: String,
    pub status: u16,
    pub accessible: bool,
    pub requires_auth: bool,
    pub response_size: usize,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,  // Publicly accessible admin interface
    High,      // Accessible debug/internal endpoint
    Medium,    // Exposed but requires auth
    Low,       // Not accessible (404/403)
}

/// Test admin paths on a base URL
pub async fn scan_admin_paths(client: &Client, base_url: &str) -> Result<Vec<AdminScanResult>> {
    let mut results = Vec::new();
    
    // Extract base URL (protocol + domain)
    let parsed = url::Url::parse(base_url)?;
    let base = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
    
    for path in admin_paths() {
        let test_url = format!("{}{}", base, path);
        
        match client.get(&test_url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await 
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.bytes().await.unwrap_or_default();
                let size = body.len();
                
                let (accessible, requires_auth, risk_level) = match status {
                    200..=299 => {
                        // Check if it's actually an admin interface
                        let body_str = String::from_utf8_lossy(&body).to_lowercase();
                        let is_admin = body_str.contains("admin") 
                            || body_str.contains("dashboard")
                            || body_str.contains("login")
                            || body_str.contains("management");
                        
                        if is_admin {
                            (true, false, RiskLevel::Critical)
                        } else if path.contains("debug") || path.contains("internal") {
                            (true, false, RiskLevel::High)
                        } else {
                            (true, false, RiskLevel::Medium)
                        }
                    }
                    401 | 403 => {
                        // Exists but requires authentication
                        (false, true, RiskLevel::Medium)
                    }
                    _ => (false, false, RiskLevel::Low),
                };
                
                if accessible || requires_auth {
                    results.push(AdminScanResult {
                        url: test_url,
                        status,
                        accessible,
                        requires_auth,
                        response_size: size,
                        risk_level,
                    });
                }
            }
            Err(_) => {
                // Request failed, skip
                continue;
            }
        }
        
        // Small delay to avoid overwhelming server
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    
    Ok(results)
}
