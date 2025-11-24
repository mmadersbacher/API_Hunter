use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SecurityHeaderAnalysis {
    pub has_hsts: bool,
    pub has_csp: bool,
    pub has_x_frame_options: bool,
    pub has_x_content_type_options: bool,
    pub has_referrer_policy: bool,
    pub has_permissions_policy: bool,
    pub missing_headers: Vec<String>,
    pub security_score: u8, // 0-100
    pub findings: Vec<String>,
}

impl SecurityHeaderAnalysis {
    pub fn analyze(headers: &HashMap<String, String>) -> Self {
        let mut missing = Vec::new();
        let mut findings = Vec::new();
        let mut score = 100u8;

        // Check for HSTS
        let has_hsts = headers.contains_key("strict-transport-security");
        if !has_hsts {
            missing.push("Strict-Transport-Security".to_string());
            findings.push("Missing HSTS - not enforcing HTTPS".to_string());
            score = score.saturating_sub(15);
        }

        // Check for CSP
        let has_csp = headers.contains_key("content-security-policy");
        if !has_csp {
            missing.push("Content-Security-Policy".to_string());
            findings.push("Missing CSP - vulnerable to XSS".to_string());
            score = score.saturating_sub(20);
        }

        // Check for X-Frame-Options
        let has_x_frame = headers.contains_key("x-frame-options");
        if !has_x_frame {
            missing.push("X-Frame-Options".to_string());
            findings.push("Missing X-Frame-Options - vulnerable to clickjacking".to_string());
            score = score.saturating_sub(15);
        }

        // Check for X-Content-Type-Options
        let has_x_content = headers.contains_key("x-content-type-options");
        if !has_x_content {
            missing.push("X-Content-Type-Options".to_string());
            findings.push("Missing X-Content-Type-Options - MIME sniffing possible".to_string());
            score = score.saturating_sub(10);
        }

        // Check for Referrer-Policy
        let has_referrer = headers.contains_key("referrer-policy");
        if !has_referrer {
            missing.push("Referrer-Policy".to_string());
            findings.push("Missing Referrer-Policy - information leakage possible".to_string());
            score = score.saturating_sub(10);
        }

        // Check for Permissions-Policy
        let has_permissions = headers.contains_key("permissions-policy") || headers.contains_key("feature-policy");
        if !has_permissions {
            missing.push("Permissions-Policy".to_string());
            findings.push("Missing Permissions-Policy - no feature restriction".to_string());
            score = score.saturating_sub(10);
        }

        // Check for dangerous headers
        if let Some(server) = headers.get("server") {
            if server.to_lowercase().contains("version") || server.contains("/") {
                findings.push(format!("Server header leaks version: {}", server));
                score = score.saturating_sub(5);
            }
        }

        if let Some(x_powered) = headers.get("x-powered-by") {
            findings.push(format!("X-Powered-By leaks technology: {}", x_powered));
            score = score.saturating_sub(5);
        }

        SecurityHeaderAnalysis {
            has_hsts,
            has_csp,
            has_x_frame_options: has_x_frame,
            has_x_content_type_options: has_x_content,
            has_referrer_policy: has_referrer,
            has_permissions_policy: has_permissions,
            missing_headers: missing,
            security_score: score,
            findings,
        }
    }
}
