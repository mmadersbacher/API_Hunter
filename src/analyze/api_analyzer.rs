use anyhow::Result;
use reqwest::Client;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

use super::security_headers::SecurityHeaderAnalysis;
use super::fingerprint::TechnologyFingerprint;
use super::cors_checker::CorsAnalysis;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAnalysis {
    pub url: String,
    pub status: u16,
    pub method: String,
    
    // Response analysis
    pub content_type: Option<String>,
    pub response_size: usize,
    pub response_time_ms: u64,
    pub body_preview: String, // First 500 chars
    
    // Headers
    pub headers: HashMap<String, String>,
    pub security_analysis: Option<SecurityHeaderAnalysis>,
    pub cors_analysis: Option<CorsAnalysis>,
    pub technology: Option<TechnologyFingerprint>,
    
    // OPTIONS request results
    pub allowed_methods: Vec<String>,
    
    // Public accessibility
    pub is_public: bool,
    pub requires_auth: bool,
    
    // Security findings
    pub findings: Vec<String>,
}

impl ApiAnalysis {
    pub async fn analyze(client: &Client, url: &str) -> Result<Self> {
        let start = std::time::Instant::now();
        
        // Main request
        let resp = client.get(url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?;
        
        let status = resp.status().as_u16();
        let response_time_ms = start.elapsed().as_millis() as u64;
        
        // Extract headers
        let mut headers = HashMap::new();
        for (key, value) in resp.headers() {
            if let Ok(v) = value.to_str() {
                headers.insert(key.as_str().to_lowercase(), v.to_string());
            }
        }
        
        let content_type = headers.get("content-type").cloned();
        
        // Get body
        let body_bytes = resp.bytes().await?;
        let response_size = body_bytes.len();
        let body = String::from_utf8_lossy(&body_bytes);
        
        // Body preview (first 500 chars)
        let body_preview = if body.len() > 500 {
            format!("{}...", &body[..500])
        } else {
            body.to_string()
        };
        
        // Analyze security headers
        let security_analysis = Some(SecurityHeaderAnalysis::analyze(&headers));
        
        // Analyze CORS
        let cors_analysis = Some(CorsAnalysis::analyze(&headers));
        
        // Technology fingerprinting
        let technology = Some(TechnologyFingerprint::analyze(&headers, &body));
        
        // Test OPTIONS method
        let allowed_methods = test_options(client, url).await.unwrap_or_default();
        
        // Determine accessibility
        let is_public = status >= 200 && status < 300;
        let requires_auth = status == 401 || status == 403;
        
        // Collect findings
        let mut findings = Vec::new();
        
        if is_public {
            findings.push("PUBLIC: Endpoint is publicly accessible without authentication".to_string());
        }
        
        if let Some(ref sec) = security_analysis {
            findings.extend(sec.findings.clone());
        }
        
        if let Some(ref cors) = cors_analysis {
            findings.extend(cors.vulnerabilities.clone());
        }
        
        // Check for sensitive data exposure
        if body.contains("password") || body.contains("secret") || body.contains("token") {
            findings.push("SENSITIVE: Response may contain sensitive data".to_string());
        }
        
        if body.contains("error") || body.contains("exception") || body.contains("stack trace") {
            findings.push("INFO: Error messages or stack traces exposed".to_string());
        }
        
        Ok(ApiAnalysis {
            url: url.to_string(),
            status,
            method: "GET".to_string(),
            content_type,
            response_size,
            response_time_ms,
            body_preview,
            headers,
            security_analysis,
            cors_analysis,
            technology,
            allowed_methods,
            is_public,
            requires_auth,
            findings,
        })
    }
}

async fn test_options(client: &Client, url: &str) -> Result<Vec<String>> {
    match client.request(reqwest::Method::OPTIONS, url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await 
    {
        Ok(resp) => {
            let methods = resp.headers()
                .get("allow")
                .or_else(|| resp.headers().get("access-control-allow-methods"))
                .and_then(|v| v.to_str().ok())
                .map(|s| s.split(',').map(|m| m.trim().to_string()).collect())
                .unwrap_or_default();
            Ok(methods)
        }
        Err(_) => Ok(Vec::new()),
    }
}

// Make SecurityHeaderAnalysis serializable
impl Serialize for SecurityHeaderAnalysis {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SecurityHeaderAnalysis", 8)?;
        state.serialize_field("has_hsts", &self.has_hsts)?;
        state.serialize_field("has_csp", &self.has_csp)?;
        state.serialize_field("has_x_frame_options", &self.has_x_frame_options)?;
        state.serialize_field("has_x_content_type_options", &self.has_x_content_type_options)?;
        state.serialize_field("has_referrer_policy", &self.has_referrer_policy)?;
        state.serialize_field("has_permissions_policy", &self.has_permissions_policy)?;
        state.serialize_field("missing_headers", &self.missing_headers)?;
        state.serialize_field("security_score", &self.security_score)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SecurityHeaderAnalysis {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        unimplemented!("Deserialization not needed")
    }
}

impl Serialize for CorsAnalysis {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CorsAnalysis", 9)?;
        state.serialize_field("has_cors", &self.has_cors)?;
        state.serialize_field("allow_origin", &self.allow_origin)?;
        state.serialize_field("allow_credentials", &self.allow_credentials)?;
        state.serialize_field("allow_methods", &self.allow_methods)?;
        state.serialize_field("allow_headers", &self.allow_headers)?;
        state.serialize_field("expose_headers", &self.expose_headers)?;
        state.serialize_field("max_age", &self.max_age)?;
        state.serialize_field("is_misconfigured", &self.is_misconfigured)?;
        state.serialize_field("vulnerabilities", &self.vulnerabilities)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for CorsAnalysis {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        unimplemented!("Deserialization not needed")
    }
}

impl Serialize for TechnologyFingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("TechnologyFingerprint", 6)?;
        state.serialize_field("server", &self.server)?;
        state.serialize_field("framework", &self.framework)?;
        state.serialize_field("cdn", &self.cdn)?;
        state.serialize_field("language", &self.language)?;
        state.serialize_field("database_hints", &self.database_hints)?;
        state.serialize_field("technologies", &self.technologies)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for TechnologyFingerprint {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        unimplemented!("Deserialization not needed")
    }
}
