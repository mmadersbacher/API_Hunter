use serde::{Serialize, Deserialize};
use super::vulnerability_scanner::VulnerabilitySeverity;

/// Strict risk classification with detailed scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskClassification {
    pub final_severity: VulnerabilitySeverity,
    pub score: f32,
    pub category: String,
    pub justification: String,
    pub factors: Vec<ClassificationFactor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationFactor {
    pub factor: String,
    pub weight: f32,
    pub description: String,
}

pub struct RiskClassifier;

impl RiskClassifier {
    /// Classify security header issues (STRICT: Usually Low/Info)
    pub fn classify_security_header(
        header_name: &str,
        _security_score: i32,
        has_public_access: bool,
        has_sensitive_data: bool,
    ) -> RiskClassification {
        let mut score = 0.0;
        let mut factors = Vec::new();
        
        // Missing security headers are LOW unless combined with other factors
        match header_name {
            "HSTS" => {
                score += 1.5;
                factors.push(ClassificationFactor {
                    factor: "Missing HSTS".to_string(),
                    weight: 1.5,
                    description: "HTTPS not enforced - MitM possible".to_string(),
                });
            }
            "CSP" => {
                score += 2.0;
                factors.push(ClassificationFactor {
                    factor: "Missing CSP".to_string(),
                    weight: 2.0,
                    description: "XSS protection missing".to_string(),
                });
            }
            "X-Frame-Options" => {
                score += 1.5;
                factors.push(ClassificationFactor {
                    factor: "Missing X-Frame-Options".to_string(),
                    weight: 1.5,
                    description: "Clickjacking possible".to_string(),
                });
            }
            _ => {
                score += 1.0;
                factors.push(ClassificationFactor {
                    factor: format!("Missing {}", header_name),
                    weight: 1.0,
                    description: "Minor security header missing".to_string(),
                });
            }
        }
        
        // Amplify if combined with other factors
        if has_public_access {
            score += 1.0;
            factors.push(ClassificationFactor {
                factor: "Public Access".to_string(),
                weight: 1.0,
                description: "Endpoint publicly accessible".to_string(),
            });
        }
        
        if has_sensitive_data {
            score += 2.0;
            factors.push(ClassificationFactor {
                factor: "Sensitive Data".to_string(),
                weight: 2.0,
                description: "Endpoint handles sensitive information".to_string(),
            });
        }
        
        // Determine severity based on total score
        let severity = if score >= 8.0 {
            VulnerabilitySeverity::High
        } else if score >= 5.0 {
            VulnerabilitySeverity::Medium
        } else if score >= 2.0 {
            VulnerabilitySeverity::Low
        } else {
            VulnerabilitySeverity::Info
        };
        
        RiskClassification {
            final_severity: severity,
            score,
            category: "Security Headers".to_string(),
            justification: format!("Missing {} header with score {:.1}", header_name, score),
            factors,
        }
    }
    
    /// Classify CORS issues (STRICT: Critical only if credentials + wildcard)
    pub fn classify_cors_issue(
        has_wildcard: bool,
        has_credentials: bool,
        allows_dangerous_methods: bool,
        accepts_null_origin: bool,
        has_sensitive_operations: bool,
    ) -> RiskClassification {
        let mut score = 0.0;
        let mut factors = Vec::new();
        
        // CRITICAL: Wildcard + Credentials = Account Takeover
        if has_wildcard && has_credentials {
            score = 9.5;
            factors.push(ClassificationFactor {
                factor: "Wildcard Origin + Credentials".to_string(),
                weight: 9.5,
                description: "CRITICAL: Any domain can access with user credentials - Account Takeover possible".to_string(),
            });
            
            return RiskClassification {
                final_severity: VulnerabilitySeverity::Critical,
                score,
                category: "CORS Misconfiguration".to_string(),
                justification: "Wildcard CORS with credentials enabled - direct account takeover vector".to_string(),
                factors,
            };
        }
        
        // HIGH: Null origin accepted with sensitive operations
        if accepts_null_origin && has_sensitive_operations {
            score = 7.5;
            factors.push(ClassificationFactor {
                factor: "Null Origin Accepted".to_string(),
                weight: 5.0,
                description: "Attacker can use sandbox iframe to bypass CORS".to_string(),
            });
            factors.push(ClassificationFactor {
                factor: "Sensitive Operations".to_string(),
                weight: 2.5,
                description: "Endpoint performs state-changing operations".to_string(),
            });
        } else if has_wildcard {
            score = 4.0;
            factors.push(ClassificationFactor {
                factor: "Wildcard Origin".to_string(),
                weight: 4.0,
                description: "Any domain can read responses (no credentials)".to_string(),
            });
        }
        
        if allows_dangerous_methods {
            score += 2.0;
            factors.push(ClassificationFactor {
                factor: "Dangerous Methods".to_string(),
                weight: 2.0,
                description: "PUT/DELETE/PATCH allowed cross-origin".to_string(),
            });
        }
        
        let severity = if score >= 8.0 {
            VulnerabilitySeverity::Critical
        } else if score >= 6.0 {
            VulnerabilitySeverity::High
        } else if score >= 3.0 {
            VulnerabilitySeverity::Medium
        } else {
            VulnerabilitySeverity::Low
        };
        
        RiskClassification {
            final_severity: severity,
            score,
            category: "CORS Misconfiguration".to_string(),
            justification: format!("CORS misconfiguration with score {:.1}", score),
            factors,
        }
    }
    
    /// Classify IDOR findings (STRICT: Critical only if different user data confirmed)
    pub fn classify_idor(
        status_changed: bool,
        size_difference: i32,
        has_user_data_in_response: bool,
        original_status: u16,
        test_status: u16,
        response_contains_different_id: bool,
    ) -> RiskClassification {
        let mut score = 0.0;
        let mut factors = Vec::new();
        
        // CRITICAL: Confirmed different user data accessed
        if response_contains_different_id && test_status == 200 {
            score = 9.8;
            factors.push(ClassificationFactor {
                factor: "Different User Data Accessible".to_string(),
                weight: 9.8,
                description: "CONFIRMED: Can access other users' data by changing ID".to_string(),
            });
            
            return RiskClassification {
                final_severity: VulnerabilitySeverity::Critical,
                score,
                category: "IDOR".to_string(),
                justification: "Confirmed IDOR - different user data accessible".to_string(),
                factors,
            };
        }
        
        // HIGH: Status changed to success + significant size difference
        if status_changed && original_status != 200 && test_status == 200 && size_difference.abs() > 100 {
            score = 7.5;
            factors.push(ClassificationFactor {
                factor: "Unauthorized Access".to_string(),
                weight: 5.0,
                description: "Modified ID returns 200 OK where original didn't".to_string(),
            });
            factors.push(ClassificationFactor {
                factor: "Data Returned".to_string(),
                weight: 2.5,
                description: format!("Response size difference: {} bytes", size_difference),
            });
        } else if size_difference.abs() > 500 && has_user_data_in_response {
            score = 6.5;
            factors.push(ClassificationFactor {
                factor: "Large Response Difference".to_string(),
                weight: 4.0,
                description: format!("Response size changed by {} bytes", size_difference),
            });
            factors.push(ClassificationFactor {
                factor: "User Data Present".to_string(),
                weight: 2.5,
                description: "Response contains user-related data".to_string(),
            });
        } else if status_changed {
            score = 3.0;
            factors.push(ClassificationFactor {
                factor: "Status Code Change".to_string(),
                weight: 3.0,
                description: format!("Status changed: {} -> {}", original_status, test_status),
            });
        } else {
            score = 1.0;
            factors.push(ClassificationFactor {
                factor: "Minor Response Difference".to_string(),
                weight: 1.0,
                description: "Small differences observed".to_string(),
            });
        }
        
        let severity = if score >= 8.0 {
            VulnerabilitySeverity::Critical
        } else if score >= 6.0 {
            VulnerabilitySeverity::High
        } else if score >= 3.0 {
            VulnerabilitySeverity::Medium
        } else {
            VulnerabilitySeverity::Low
        };
        
        RiskClassification {
            final_severity: severity,
            score,
            category: "IDOR".to_string(),
            justification: format!("IDOR test with score {:.1}", score),
            factors,
        }
    }
    
    /// Classify admin endpoint findings (STRICT: Critical only if no auth + sensitive operations)
    pub fn classify_admin_endpoint(
        is_public: bool,
        requires_auth: bool,
        status_code: u16,
        path: &str,
        has_sensitive_operations: bool,
        response_size: usize,
    ) -> RiskClassification {
        let mut score = 0.0;
        let mut factors = Vec::new();
        
        // Determine endpoint sensitivity
        let is_highly_sensitive = path.contains("admin") 
            || path.contains("dashboard") 
            || path.contains("config")
            || path.contains("settings")
            || path.contains("delete")
            || path.contains("user");
        
        let is_debug_endpoint = path.contains("debug") 
            || path.contains("internal")
            || path.contains("test")
            || path.contains(".env");
        
        // CRITICAL: Public admin panel without auth
        if is_public && !requires_auth && status_code == 200 && is_highly_sensitive && has_sensitive_operations {
            score = 9.5;
            factors.push(ClassificationFactor {
                factor: "Public Admin Access".to_string(),
                weight: 6.0,
                description: "Admin panel accessible without authentication".to_string(),
            });
            factors.push(ClassificationFactor {
                factor: "Sensitive Operations".to_string(),
                weight: 3.5,
                description: "Can perform state-changing administrative actions".to_string(),
            });
            
            return RiskClassification {
                final_severity: VulnerabilitySeverity::Critical,
                score,
                category: "Access Control".to_string(),
                justification: "Public admin panel without authentication - full system compromise possible".to_string(),
                factors,
            };
        }
        
        // HIGH: Public debug/internal endpoint with data
        if is_public && !requires_auth && status_code == 200 && is_debug_endpoint && response_size > 500 {
            score = 7.5;
            factors.push(ClassificationFactor {
                factor: "Debug Endpoint Exposed".to_string(),
                weight: 5.0,
                description: "Internal debugging endpoint publicly accessible".to_string(),
            });
            factors.push(ClassificationFactor {
                factor: "Data Exposure".to_string(),
                weight: 2.5,
                description: format!("Response size: {} bytes", response_size),
            });
        } else if is_public && !requires_auth && status_code == 200 {
            score = 4.0;
            factors.push(ClassificationFactor {
                factor: "Exposed Admin Path".to_string(),
                weight: 4.0,
                description: "Admin-related endpoint accessible without auth".to_string(),
            });
        } else if status_code == 200 && requires_auth {
            score = 2.0;
            factors.push(ClassificationFactor {
                factor: "Admin Endpoint Found".to_string(),
                weight: 2.0,
                description: "Admin endpoint requires authentication (properly secured)".to_string(),
            });
        } else {
            score = 0.5;
            factors.push(ClassificationFactor {
                factor: "Admin Path Exists".to_string(),
                weight: 0.5,
                description: "Admin path found but not accessible".to_string(),
            });
        }
        
        let severity = if score >= 8.0 {
            VulnerabilitySeverity::Critical
        } else if score >= 6.0 {
            VulnerabilitySeverity::High
        } else if score >= 3.0 {
            VulnerabilitySeverity::Medium
        } else if score >= 1.0 {
            VulnerabilitySeverity::Low
        } else {
            VulnerabilitySeverity::Info
        };
        
        RiskClassification {
            final_severity: severity,
            score,
            category: "Access Control".to_string(),
            justification: format!("Admin endpoint {} with score {:.1}", path, score),
            factors,
        }
    }
}
