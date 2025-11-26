use reqwest::Response;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WafType {
    Cloudflare,
    Imperva,
    Akamai,
    F5BigIP,
    ModSecurity,
    AwsWaf,
    AzureWaf,
    Sucuri,
    Wordfence,
    Barracuda,
    Fortiweb,
    Wallarm,
    Unknown(String),
    None,
}

impl WafType {
    pub fn name(&self) -> &str {
        match self {
            WafType::Cloudflare => "Cloudflare",
            WafType::Imperva => "Imperva Incapsula",
            WafType::Akamai => "Akamai Kona Site Defender",
            WafType::F5BigIP => "F5 BIG-IP ASM",
            WafType::ModSecurity => "ModSecurity",
            WafType::AwsWaf => "AWS WAF",
            WafType::AzureWaf => "Azure WAF",
            WafType::Sucuri => "Sucuri CloudProxy",
            WafType::Wordfence => "Wordfence",
            WafType::Barracuda => "Barracuda WAF",
            WafType::Fortiweb => "Fortinet FortiWeb",
            WafType::Wallarm => "Wallarm",
            WafType::Unknown(name) => name,
            WafType::None => "None",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetection {
    pub waf_type: WafType,
    pub confidence: f32, // 0.0 - 1.0
    pub evidence: Vec<String>,
    pub headers_found: Vec<String>,
    pub cookies_found: Vec<String>,
}

pub struct WafDetector {
    signatures: Vec<super::signatures::WafSignature>,
}

impl WafDetector {
    pub fn new() -> Self {
        Self {
            signatures: super::signatures::load_signatures(),
        }
    }

    /// Detect WAF from response headers, cookies, and body
    pub async fn detect(&self, response: &Response, body: &str) -> WafDetection {
        let headers = response.headers();
        let mut detected_wafs: Vec<(WafType, f32, Vec<String>)> = Vec::new();

        // Check each signature
        for sig in &self.signatures {
            let mut confidence: f32 = 0.0;
            let mut evidence = Vec::new();
            let mut headers_found = Vec::new();
            let mut cookies_found = Vec::new();

            // Check headers
            for (header_name, header_pattern) in &sig.headers {
                if let Some(header_value) = headers.get(header_name) {
                    if let Ok(value_str) = header_value.to_str() {
                        if value_str.to_lowercase().contains(&header_pattern.to_lowercase()) {
                            confidence += 0.3;
                            evidence.push(format!("Header: {} = {}", header_name, value_str));
                            headers_found.push(format!("{}: {}", header_name, value_str));
                        }
                    }
                }
            }

            // Check server header specifically
            if let Some(server) = headers.get("server") {
                if let Ok(server_str) = server.to_str() {
                    for pattern in &sig.server_patterns {
                        if server_str.to_lowercase().contains(&pattern.to_lowercase()) {
                            confidence += 0.4;
                            evidence.push(format!("Server: {}", server_str));
                            headers_found.push(format!("server: {}", server_str));
                        }
                    }
                }
            }

            // Check cookies
            if let Some(cookie_header) = headers.get("set-cookie") {
                if let Ok(cookie_str) = cookie_header.to_str() {
                    for cookie_pattern in &sig.cookies {
                        if cookie_str.contains(cookie_pattern) {
                            confidence += 0.25;
                            evidence.push(format!("Cookie: {}", cookie_pattern));
                            cookies_found.push(cookie_pattern.clone());
                        }
                    }
                }
            }

            // Check body patterns (only if we have some confidence already)
            if confidence > 0.0 {
                for body_pattern in &sig.body_patterns {
                    if body.contains(body_pattern) {
                        confidence += 0.15;
                        evidence.push(format!("Body pattern: {}", body_pattern));
                    }
                }
            }

            // Cap confidence at 1.0
            confidence = confidence.min(1.0);

            if confidence > 0.3 {
                detected_wafs.push((sig.waf_type.clone(), confidence, evidence));
            }
        }

        // Return the WAF with highest confidence
        if let Some((waf_type, confidence, evidence)) = detected_wafs.iter().max_by(|a, b| {
            a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)
        }) {
            WafDetection {
                waf_type: waf_type.clone(),
                confidence: *confidence,
                evidence: evidence.clone(),
                headers_found: Vec::new(), // Populated separately
                cookies_found: Vec::new(),
            }
        } else {
            WafDetection {
                waf_type: WafType::None,
                confidence: 0.0,
                evidence: Vec::new(),
                headers_found: Vec::new(),
                cookies_found: Vec::new(),
            }
        }
    }

    /// Quick check if response indicates WAF blocking
    pub fn is_blocked_response(status: u16, body: &str) -> bool {
        // Common WAF block status codes
        if status == 403 || status == 406 || status == 429 || status == 503 {
            // Check for common block messages
            let block_patterns = vec![
                "access denied",
                "forbidden",
                "blocked",
                "firewall",
                "security policy",
                "request rejected",
                "suspicious activity",
                "rate limit",
                "captcha",
                "challenge",
                "ray id", // Cloudflare
                "incident id", // Imperva
                "reference #", // Akamai
            ];

            let body_lower = body.to_lowercase();
            for pattern in block_patterns {
                if body_lower.contains(pattern) {
                    return true;
                }
            }
        }

        false
    }

    /// Detect WAF by sending a harmless test payload
    /// Only used when --detect-waf flag is explicitly set
    pub async fn active_detection(
        &self,
        client: &reqwest::Client,
        url: &str,
    ) -> Result<WafDetection, Box<dyn std::error::Error>> {
        // Send a harmless but "suspicious-looking" request
        // This won't actually exploit anything
        let test_url = format!("{}?test=<script>", url);
        
        let response = client
            .get(&test_url)
            .send()
            .await?;

        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.text().await?;
        
        // Create a fake response for detection (since we consumed the original)
        let detection = WafDetection {
            waf_type: WafType::None,
            confidence: 0.0,
            evidence: Vec::new(),
            headers_found: Vec::new(),
            cookies_found: Vec::new(),
        };
        // TODO: Implement proper detection without consuming response

        Ok(detection)
    }
}

impl Default for WafDetector {
    fn default() -> Self {
        Self::new()
    }
}
