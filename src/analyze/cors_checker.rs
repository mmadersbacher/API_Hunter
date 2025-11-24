use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CorsAnalysis {
    pub has_cors: bool,
    pub allow_origin: Option<String>,
    pub allow_credentials: bool,
    pub allow_methods: Vec<String>,
    pub allow_headers: Vec<String>,
    pub expose_headers: Vec<String>,
    pub max_age: Option<String>,
    pub is_misconfigured: bool,
    pub vulnerabilities: Vec<String>,
}

impl CorsAnalysis {
    pub fn analyze(headers: &HashMap<String, String>) -> Self {
        let mut vulnerabilities = Vec::new();
        
        let allow_origin = headers.get("access-control-allow-origin").cloned();
        let has_cors = allow_origin.is_some();
        
        let allow_credentials = headers
            .get("access-control-allow-credentials")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        
        let allow_methods = headers
            .get("access-control-allow-methods")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();
        
        let allow_headers = headers
            .get("access-control-allow-headers")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();
        
        let expose_headers = headers
            .get("access-control-expose-headers")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();
        
        let max_age = headers.get("access-control-max-age").cloned();
        
        // Check for misconfigurations
        let mut is_misconfigured = false;
        
        if let Some(ref origin) = allow_origin {
            // Wildcard with credentials is a misconfiguration
            if origin == "*" && allow_credentials {
                vulnerabilities.push("CRITICAL: Wildcard origin (*) with credentials enabled".to_string());
                is_misconfigured = true;
            }
            
            // Wildcard origin is overly permissive
            if origin == "*" {
                vulnerabilities.push("WARNING: Wildcard origin (*) allows any domain".to_string());
                is_misconfigured = true;
            }
            
            // Null origin accepted
            if origin == "null" {
                vulnerabilities.push("WARNING: Null origin accepted - exploitable".to_string());
                is_misconfigured = true;
            }
        }
        
        // Check for dangerous methods
        for method in &allow_methods {
            if method == "DELETE" || method == "PUT" || method == "PATCH" {
                vulnerabilities.push(format!("INFO: Dangerous method allowed: {}", method));
            }
        }
        
        CorsAnalysis {
            has_cors,
            allow_origin,
            allow_credentials,
            allow_methods,
            allow_headers,
            expose_headers,
            max_age,
            is_misconfigured,
            vulnerabilities,
        }
    }
}
