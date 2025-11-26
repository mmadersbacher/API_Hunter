use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtToken {
    pub raw: String,
    pub header: serde_json::Value,
    pub payload: serde_json::Value,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum JwtVulnerability {
    NoneAlgorithm,
    WeakSecret(String),
    ExpiredToken,
    AlgorithmConfusion,
    MissingSignature,
    WeakAlgorithm(String),
    KidInjection,
}

#[derive(Debug, Clone)]
pub struct JwtAnalysisResult {
    pub token: JwtToken,
    pub vulnerabilities: Vec<JwtVulnerability>,
    pub is_valid: bool,
    pub algorithm: String,
    pub expires_at: Option<i64>,
}

pub struct JwtAnalyzer {
    common_secrets: Vec<String>,
}

impl JwtAnalyzer {
    pub fn new() -> Self {
        Self {
            common_secrets: vec![
                "secret".to_string(),
                "your-256-bit-secret".to_string(),
                "your-secret".to_string(),
                "secretkey".to_string(),
                "secret123".to_string(),
                "password".to_string(),
                "123456".to_string(),
                "default".to_string(),
                "jwt-secret".to_string(),
                "my-secret".to_string(),
                "test".to_string(),
                "dev".to_string(),
                "admin".to_string(),
                "root".to_string(),
                "changeme".to_string(),
            ],
        }
    }

    /// Extract JWT tokens from response body
    pub fn extract_tokens_from_response(&self, body: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        
        // Pattern: eyJ (base64 encoded JSON starting with {")
        let parts: Vec<&str> = body.split("eyJ").collect();
        
        for i in 1..parts.len() {
            let potential_token = format!("eyJ{}", parts[i].split_whitespace().next().unwrap_or(""));
            
            // JWT format: xxx.yyy.zzz (3 parts separated by dots)
            let dot_count = potential_token.chars().filter(|&c| c == '.').count();
            if dot_count == 2 {
                // Extract until next non-base64 char
                let end_pos = potential_token
                    .chars()
                    .position(|c| !c.is_alphanumeric() && c != '.' && c != '-' && c != '_')
                    .unwrap_or(potential_token.len());
                
                let token = &potential_token[..end_pos];
                if token.len() > 20 && self.is_likely_jwt(token) {
                    tokens.push(token.to_string());
                }
            }
        }
        
        tokens
    }

    /// Check if string is likely a JWT token
    fn is_likely_jwt(&self, token: &str) -> bool {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return false;
        }
        
        // All parts should be base64url
        parts.iter().all(|part| {
            !part.is_empty() && part.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        })
    }

    /// Parse and analyze JWT token
    pub fn analyze_token(&self, token: &str) -> Result<JwtAnalysisResult, String> {
        let parts: Vec<&str> = token.split('.').collect();
        
        if parts.len() != 3 {
            return Err("Invalid JWT format: expected 3 parts".to_string());
        }

        // Decode header
        let header = self.decode_base64url(parts[0])
            .and_then(|h| serde_json::from_str::<serde_json::Value>(&h).ok())
            .ok_or("Failed to decode header")?;

        // Decode payload
        let payload = self.decode_base64url(parts[1])
            .and_then(|p| serde_json::from_str::<serde_json::Value>(&p).ok())
            .ok_or("Failed to decode payload")?;

        let signature = parts[2].to_string();
        let algorithm = header["alg"].as_str().unwrap_or("unknown").to_string();

        let jwt_token = JwtToken {
            raw: token.to_string(),
            header: header.clone(),
            payload: payload.clone(),
            signature: signature.clone(),
        };

        let mut vulnerabilities = Vec::new();

        // Check for "none" algorithm
        if algorithm.to_lowercase() == "none" {
            vulnerabilities.push(JwtVulnerability::NoneAlgorithm);
        }

        // Check for weak algorithms
        if matches!(algorithm.to_lowercase().as_str(), "hs256" | "hs384" | "hs512") {
            vulnerabilities.push(JwtVulnerability::WeakAlgorithm(algorithm.clone()));
        }

        // Check if signature is empty
        if signature.is_empty() {
            vulnerabilities.push(JwtVulnerability::MissingSignature);
        }

        // Check expiration
        let expires_at = payload["exp"].as_i64();
        if let Some(exp) = expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            
            if exp < now {
                vulnerabilities.push(JwtVulnerability::ExpiredToken);
            }
        }

        // Check for kid injection vulnerability
        if let Some(kid) = header["kid"].as_str() {
            if kid.contains("../") || kid.contains("..\\") || kid.starts_with('/') {
                vulnerabilities.push(JwtVulnerability::KidInjection);
            }
        }

        // Try weak secret bruteforce for HMAC algorithms
        if algorithm.starts_with("HS") {
            if let Some(secret) = self.bruteforce_hmac_secret(token) {
                vulnerabilities.push(JwtVulnerability::WeakSecret(secret));
            }
        }

        Ok(JwtAnalysisResult {
            token: jwt_token,
            vulnerabilities,
            is_valid: false, // We don't have the real secret to validate
            algorithm,
            expires_at,
        })
    }

    /// Decode base64url encoded string
    fn decode_base64url(&self, input: &str) -> Option<String> {
        use base64::{engine::general_purpose, Engine as _};
        
        // Base64url to standard base64
        let base64 = input
            .replace('-', "+")
            .replace('_', "/");
        
        // Add padding
        let padding = (4 - base64.len() % 4) % 4;
        let padded = format!("{}{}", base64, "=".repeat(padding));
        
        general_purpose::STANDARD.decode(&padded)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }

    /// Bruteforce HMAC secret with common secrets
    fn bruteforce_hmac_secret(&self, token: &str) -> Option<String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let message = format!("{}.{}", parts[0], parts[1]);
        let expected_sig = parts[2];

        for secret in &self.common_secrets {
            if self.verify_hmac_sha256(&message, secret, expected_sig) {
                return Some(secret.clone());
            }
        }

        None
    }

    /// Verify HMAC-SHA256 signature
    fn verify_hmac_sha256(&self, message: &str, secret: &str, expected_sig: &str) -> bool {
        use base64::{engine::general_purpose, Engine as _};
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
            Ok(m) => m,
            Err(_) => return false,
        };

        mac.update(message.as_bytes());
        let result = mac.finalize();
        let signature = result.into_bytes();

        // Convert to base64url
        let sig_base64url = general_purpose::URL_SAFE_NO_PAD.encode(&signature);

        sig_base64url == expected_sig
    }

    /// Generate analysis report
    pub fn generate_report(&self, results: &[JwtAnalysisResult]) -> String {
        let mut report = String::new();
        
        report.push_str("=== JWT Token Analysis ===\n\n");
        
        for (idx, result) in results.iter().enumerate() {
            report.push_str(&format!("Token #{}\n", idx + 1));
            report.push_str(&format!("Algorithm: {}\n", result.algorithm));
            
            if let Some(exp) = result.expires_at {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                
                if exp < now {
                    report.push_str(&format!("Expiration: EXPIRED ({} seconds ago)\n", now - exp));
                } else {
                    report.push_str(&format!("Expiration: Valid (expires in {} seconds)\n", exp - now));
                }
            }
            
            if result.vulnerabilities.is_empty() {
                report.push_str("Status: No vulnerabilities detected\n");
            } else {
                report.push_str(&format!("Status: {} VULNERABILITIES FOUND\n", result.vulnerabilities.len()));
                
                for vuln in &result.vulnerabilities {
                    match vuln {
                        JwtVulnerability::NoneAlgorithm => {
                            report.push_str("  [!] CRITICAL: 'none' algorithm - signature not verified!\n");
                        }
                        JwtVulnerability::WeakSecret(secret) => {
                            report.push_str(&format!("  [!] CRITICAL: Weak secret cracked: '{}'\n", secret));
                        }
                        JwtVulnerability::ExpiredToken => {
                            report.push_str("  [!] HIGH: Token is expired\n");
                        }
                        JwtVulnerability::AlgorithmConfusion => {
                            report.push_str("  [!] HIGH: Potential algorithm confusion vulnerability\n");
                        }
                        JwtVulnerability::MissingSignature => {
                            report.push_str("  [!] CRITICAL: Missing signature\n");
                        }
                        JwtVulnerability::WeakAlgorithm(alg) => {
                            report.push_str(&format!("  [!] MEDIUM: Weak algorithm: {}\n", alg));
                        }
                        JwtVulnerability::KidInjection => {
                            report.push_str("  [!] HIGH: Kid header injection detected (path traversal)\n");
                        }
                    }
                }
            }
            
            // Show decoded payload (first 200 chars)
            let payload_str = serde_json::to_string_pretty(&result.token.payload).unwrap_or_default();
            let preview = if payload_str.len() > 200 {
                format!("{}...", &payload_str[..200])
            } else {
                payload_str
            };
            report.push_str(&format!("\nPayload Preview:\n{}\n", preview));
            report.push_str("\n");
        }
        
        report
    }
}

impl Default for JwtAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tokens() {
        let analyzer = JwtAnalyzer::new();
        let body = r#"{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}"#;
        
        let tokens = analyzer.extract_tokens_from_response(body);
        assert!(!tokens.is_empty());
    }

    #[test]
    fn test_analyze_weak_secret() {
        let analyzer = JwtAnalyzer::new();
        // Token with "secret" as the secret
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        
        let result = analyzer.analyze_token(token);
        assert!(result.is_ok());
    }
}
