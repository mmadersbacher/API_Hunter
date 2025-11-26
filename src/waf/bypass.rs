use super::detector::WafType;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BypassTechnique {
    // Encoding techniques
    UrlEncoding,
    DoubleUrlEncoding,
    UnicodeEncoding,
    MixedCaseEncoding,
    
    // HTTP manipulation
    VerbTampering(Vec<String>), // GET, POST, HEAD, OPTIONS, PUT, PATCH
    ContentTypeManipulation(Vec<String>),
    HeaderInjection(Vec<(String, String)>),
    
    // Path manipulation
    PathObfuscation,
    PathTraversal,
    NullByteInjection,
    
    // Advanced techniques
    ParameterPollution,
    IpRotation,
    SlowRequests,
    
    // WAF-specific bypasses
    CloudflareBypass,
    ImpervaBypass,
    AkamaiBypass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassResult {
    pub success: bool,
    pub technique: BypassTechnique,
    pub status_code: Option<u16>,
    pub response_size: Option<usize>,
    pub evidence: String,
}

pub struct WafBypass {
    waf_type: WafType,
}

impl WafBypass {
    pub fn new(waf_type: WafType) -> Self {
        Self { waf_type }
    }

    /// Get recommended bypass strategies for detected WAF
    pub fn get_strategies(&self) -> Vec<BypassTechnique> {
        match self.waf_type {
            WafType::Cloudflare => vec![
                BypassTechnique::IpRotation,
                BypassTechnique::SlowRequests,
                BypassTechnique::HeaderInjection(vec![
                    ("X-Forwarded-For".to_string(), "127.0.0.1".to_string()),
                    ("X-Real-IP".to_string(), "127.0.0.1".to_string()),
                ]),
                BypassTechnique::VerbTampering(vec!["HEAD".to_string(), "OPTIONS".to_string()]),
                BypassTechnique::PathObfuscation,
            ],
            WafType::Imperva => vec![
                BypassTechnique::IpRotation,
                BypassTechnique::ContentTypeManipulation(vec![
                    "text/plain".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ]),
                BypassTechnique::PathTraversal,
                BypassTechnique::VerbTampering(vec!["PUT".to_string(), "PATCH".to_string()]),
            ],
            WafType::Akamai => vec![
                BypassTechnique::IpRotation,
                BypassTechnique::HeaderInjection(vec![
                    ("X-Forwarded-Host".to_string(), "localhost".to_string()),
                    ("X-Original-URL".to_string(), "/".to_string()),
                ]),
                BypassTechnique::PathObfuscation,
                BypassTechnique::DoubleUrlEncoding,
            ],
            WafType::ModSecurity => vec![
                BypassTechnique::MixedCaseEncoding,
                BypassTechnique::UrlEncoding,
                BypassTechnique::PathObfuscation,
                BypassTechnique::NullByteInjection,
            ],
            WafType::AwsWaf => vec![
                BypassTechnique::IpRotation,
                BypassTechnique::VerbTampering(vec!["OPTIONS".to_string(), "HEAD".to_string()]),
                BypassTechnique::HeaderInjection(vec![
                    ("X-Forwarded-For".to_string(), "10.0.0.1".to_string()),
                ]),
            ],
            _ => vec![
                // Generic bypass techniques
                BypassTechnique::IpRotation,
                BypassTechnique::PathObfuscation,
                BypassTechnique::VerbTampering(vec![
                    "HEAD".to_string(),
                    "OPTIONS".to_string(),
                    "PUT".to_string(),
                ]),
                BypassTechnique::UrlEncoding,
                BypassTechnique::HeaderInjection(vec![
                    ("X-Forwarded-For".to_string(), "127.0.0.1".to_string()),
                ]),
            ],
        }
    }

    /// Apply path obfuscation to URL
    pub fn obfuscate_path(url: &str) -> Vec<String> {
        let mut variations = Vec::new();
        
        if let Ok(parsed) = url::Url::parse(url) {
            let base = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
            let path = parsed.path();
            
            // Original
            variations.push(url.to_string());
            
            // Add trailing slash
            if !path.ends_with('/') {
                variations.push(format!("{}{}/", base, path));
            }
            
            // Add /./
            variations.push(format!("{}{}", base, path.replace('/', "/./")));
            
            // Add //
            variations.push(format!("{}{}", base, path.replace('/', "//")));
            
            // URL encode some characters
            let encoded = path
                .replace('/', "%2F")
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i > 0 && i < path.len() - 1 && c.is_ascii_alphabetic() {
                        format!("%{:02X}", c as u8)
                    } else {
                        c.to_string()
                    }
                })
                .collect::<String>();
            if encoded != path {
                variations.push(format!("{}{}", base, encoded));
            }
            
            // Case variation
            let case_varied = path
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_uppercase().to_string()
                    } else {
                        c.to_lowercase().to_string()
                    }
                })
                .collect::<String>();
            variations.push(format!("{}{}", base, case_varied));
        }
        
        variations
    }

    /// Apply URL encoding variations
    pub fn encode_variations(input: &str) -> Vec<String> {
        vec![
            input.to_string(),
            urlencoding::encode(input).to_string(),
            // Double encoding
            urlencoding::encode(&urlencoding::encode(input).to_string()).to_string(),
            // Mixed case hex encoding
            input
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() && rand::random::<bool>() {
                        format!("%{:02X}", c as u8)
                    } else {
                        c.to_string()
                    }
                })
                .collect(),
        ]
    }

    /// Test a specific bypass technique
    /// WARNING: Only call this when user explicitly enables bypass testing!
    pub async fn test_bypass(
        &self,
        client: &Client,
        url: &str,
        technique: &BypassTechnique,
    ) -> Result<BypassResult, Box<dyn std::error::Error>> {
        match technique {
            BypassTechnique::PathObfuscation => {
                let variations = Self::obfuscate_path(url);
                for variant in variations {
                    if let Ok(response) = client.get(&variant).send().await {
                        let status = response.status().as_u16();
                        let body = response.text().await.unwrap_or_default();
                        
                        if status == 200 && !super::detector::WafDetector::is_blocked_response(status, &body) {
                            return Ok(BypassResult {
                                success: true,
                                technique: technique.clone(),
                                status_code: Some(status),
                                response_size: Some(body.len()),
                                evidence: format!("Path obfuscation succeeded: {}", variant),
                            });
                        }
                    }
                }
            }
            BypassTechnique::VerbTampering(verbs) => {
                for verb_str in verbs {
                    let method = match verb_str.as_str() {
                        "HEAD" => Method::HEAD,
                        "OPTIONS" => Method::OPTIONS,
                        "PUT" => Method::PUT,
                        "PATCH" => Method::PATCH,
                        "DELETE" => Method::DELETE,
                        _ => Method::GET,
                    };
                    
                    if let Ok(response) = client.request(method.clone(), url).send().await {
                        let status = response.status().as_u16();
                        let body = response.text().await.unwrap_or_default();
                        
                        if status == 200 && !super::detector::WafDetector::is_blocked_response(status, &body) {
                            return Ok(BypassResult {
                                success: true,
                                technique: technique.clone(),
                                status_code: Some(status),
                                response_size: Some(body.len()),
                                evidence: format!("Verb tampering succeeded with {}", verb_str),
                            });
                        }
                    }
                }
            }
            BypassTechnique::HeaderInjection(headers) => {
                let mut request = client.get(url);
                for (key, value) in headers {
                    request = request.header(key, value);
                }
                
                if let Ok(response) = request.send().await {
                    let status = response.status().as_u16();
                    let body = response.text().await.unwrap_or_default();
                    
                    if status == 200 && !super::detector::WafDetector::is_blocked_response(status, &body) {
                        return Ok(BypassResult {
                            success: true,
                            technique: technique.clone(),
                            status_code: Some(status),
                            response_size: Some(body.len()),
                            evidence: "Header injection succeeded".to_string(),
                        });
                    }
                }
            }
            BypassTechnique::IpRotation => {
                // This is handled by the residential proxy in anonymizer.rs
                // Just return info that IP rotation should be enabled
                return Ok(BypassResult {
                    success: true,
                    technique: technique.clone(),
                    status_code: None,
                    response_size: None,
                    evidence: "Enable --anonymous flag for IP rotation via residential proxies".to_string(),
                });
            }
            _ => {
                // Other techniques not yet implemented
            }
        }

        Ok(BypassResult {
            success: false,
            technique: technique.clone(),
            status_code: None,
            response_size: None,
            evidence: "Bypass technique failed or not implemented".to_string(),
        })
    }

    /// Get human-readable explanation of technique
    pub fn explain_technique(technique: &BypassTechnique) -> &'static str {
        match technique {
            BypassTechnique::UrlEncoding => "URL encode special characters to bypass signature matching",
            BypassTechnique::DoubleUrlEncoding => "Double URL encoding to evade decoders",
            BypassTechnique::VerbTampering(_) => "Use alternative HTTP methods (HEAD, OPTIONS, PUT) that may not be filtered",
            BypassTechnique::PathObfuscation => "Add //, /./, trailing slashes to obfuscate paths",
            BypassTechnique::HeaderInjection(_) => "Inject headers like X-Forwarded-For to appear as internal request",
            BypassTechnique::IpRotation => "Rotate IP addresses using residential proxies to avoid rate limiting",
            BypassTechnique::ContentTypeManipulation(_) => "Change Content-Type header to bypass content inspection",
            BypassTechnique::ParameterPollution => "Send same parameter multiple times to confuse parsing",
            BypassTechnique::PathTraversal => r"Use ../ or ..\ in paths to access restricted endpoints",
            BypassTechnique::NullByteInjection => "Inject null bytes (%00) to truncate strings",
            BypassTechnique::SlowRequests => "Send requests very slowly to stay under rate limits",
            _ => "WAF-specific bypass technique",
        }
    }
}
