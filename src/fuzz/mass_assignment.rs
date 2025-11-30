use crate::http_client::HttpClient;
use anyhow::Result;
use serde_json::{json, Value};
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
pub struct MassAssignmentResult {
    pub url: String,
    pub vulnerabilities: Vec<MassAssignmentVuln>,
    pub hidden_params: Vec<HiddenParameter>,
}

#[derive(Debug, Clone)]
pub struct MassAssignmentVuln {
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
    pub parameter: String,
    pub payload: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HiddenParameter {
    pub name: String,
    pub accepted: bool,
    pub potential_impact: String,
}

pub struct MassAssignmentTester {
    client: HttpClient,
}

impl MassAssignmentTester {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Test endpoint for mass assignment vulnerabilities
    pub async fn test_endpoint(&self, url: &str, method: &str) -> Result<MassAssignmentResult> {
        let mut result = MassAssignmentResult {
            url: url.to_string(),
            vulnerabilities: Vec::new(),
            hidden_params: Vec::new(),
        };

        // Test sequentially to avoid type issues
        match self.test_privilege_escalation(url, method).await {
            Ok((vulns, params)) => {
                result.vulnerabilities.extend(vulns);
                result.hidden_params.extend(params);
            }
            Err(e) => tracing::warn!("Privilege escalation test failed: {}", e),
        }

        match self.test_hidden_field_injection(url, method).await {
            Ok((vulns, params)) => {
                result.vulnerabilities.extend(vulns);
                result.hidden_params.extend(params);
            }
            Err(e) => tracing::warn!("Hidden field injection test failed: {}", e),
        }

        match self.test_role_manipulation(url, method).await {
            Ok((vulns, params)) => {
                result.vulnerabilities.extend(vulns);
                result.hidden_params.extend(params);
            }
            Err(e) => tracing::warn!("Role manipulation test failed: {}", e),
        }

        match self.test_id_manipulation(url, method).await {
            Ok((vulns, params)) => {
                result.vulnerabilities.extend(vulns);
                result.hidden_params.extend(params);
            }
            Err(e) => tracing::warn!("ID manipulation test failed: {}", e),
        }

        match self.test_status_manipulation(url, method).await {
            Ok((vulns, params)) => {
                result.vulnerabilities.extend(vulns);
                result.hidden_params.extend(params);
            }
            Err(e) => tracing::warn!("Status manipulation test failed: {}", e),
        }

        Ok(result)
    }

    /// Test privilege escalation via mass assignment
    async fn test_privilege_escalation(&self, url: &str, method: &str) -> Result<(Vec<MassAssignmentVuln>, Vec<HiddenParameter>)> {
        let mut vulns = Vec::new();
        let mut params = Vec::new();

        // Privilege escalation parameters
        let priv_params = vec![
            ("is_admin", json!(true)),
            ("isAdmin", json!(true)),
            ("admin", json!(true)),
            ("is_superuser", json!(true)),
            ("isSuperuser", json!(true)),
            ("superuser", json!(true)),
            ("role", json!("admin")),
            ("user_role", json!("admin")),
            ("userRole", json!("admin")),
            ("privileges", json!(["admin", "superuser"])),
            ("permissions", json!(["admin", "write", "delete"])),
            ("access_level", json!(999)),
            ("accessLevel", json!(999)),
            ("is_staff", json!(true)),
            ("isStaff", json!(true)),
        ];

        for (param_name, param_value) in priv_params {
            let payload = json!({
                "username": "test",
                "email": "test@test.com",
                param_name: param_value,
            });

            let test_result = self.send_request(url, method, &payload).await;
            
            match test_result {
                Ok((status, body)) => {
                    if status >= 200 && status < 300 {
                        // Check if parameter was accepted
                        if self.check_param_accepted(&body, param_name, &param_value) {
                            vulns.push(MassAssignmentVuln {
                                vuln_type: "Privilege Escalation".to_string(),
                                severity: "CRITICAL".to_string(),
                                description: format!("Parameter '{}' accepted - may allow privilege escalation", param_name),
                                parameter: param_name.to_string(),
                                payload: Some(payload.to_string()),
                            });

                            params.push(HiddenParameter {
                                name: param_name.to_string(),
                                accepted: true,
                                potential_impact: "CRITICAL - Privilege escalation".to_string(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Ok((vulns, params))
    }

    /// Test hidden field injection
    async fn test_hidden_field_injection(&self, url: &str, method: &str) -> Result<(Vec<MassAssignmentVuln>, Vec<HiddenParameter>)> {
        let mut vulns = Vec::new();
        let mut params = Vec::new();

        // Common hidden fields
        let hidden_fields = vec![
            ("id", json!(999999)),
            ("user_id", json!(1)),
            ("userId", json!(1)),
            ("account_id", json!(1)),
            ("accountId", json!(1)),
            ("created_at", json!("2020-01-01T00:00:00Z")),
            ("createdAt", json!("2020-01-01T00:00:00Z")),
            ("updated_at", json!("2020-01-01T00:00:00Z")),
            ("updatedAt", json!("2020-01-01T00:00:00Z")),
            ("deleted_at", json!(null)),
            ("deletedAt", json!(null)),
            ("is_deleted", json!(false)),
            ("isDeleted", json!(false)),
            ("verified", json!(true)),
            ("is_verified", json!(true)),
            ("isVerified", json!(true)),
            ("active", json!(true)),
            ("is_active", json!(true)),
            ("isActive", json!(true)),
        ];

        for (param_name, param_value) in hidden_fields {
            let payload = json!({
                "username": "test",
                param_name: param_value,
            });

            let test_result = self.send_request(url, method, &payload).await;
            
            match test_result {
                Ok((status, body)) => {
                    if status >= 200 && status < 300 {
                        if self.check_param_accepted(&body, param_name, &param_value) {
                            vulns.push(MassAssignmentVuln {
                                vuln_type: "Hidden Field Injection".to_string(),
                                severity: "HIGH".to_string(),
                                description: format!("Hidden field '{}' accepted - may allow data manipulation", param_name),
                                parameter: param_name.to_string(),
                                payload: Some(payload.to_string()),
                            });

                            params.push(HiddenParameter {
                                name: param_name.to_string(),
                                accepted: true,
                                potential_impact: "HIGH - Data manipulation".to_string(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Ok((vulns, params))
    }

    /// Test role manipulation
    async fn test_role_manipulation(&self, url: &str, method: &str) -> Result<(Vec<MassAssignmentVuln>, Vec<HiddenParameter>)> {
        let mut vulns = Vec::new();
        let mut params = Vec::new();

        // Role-related parameters
        let roles = vec![
            ("role_id", json!(1)),
            ("roleId", json!(1)),
            ("group_id", json!(1)),
            ("groupId", json!(1)),
            ("roles", json!(["admin", "moderator"])),
            ("groups", json!(["admin"])),
            ("user_type", json!("admin")),
            ("userType", json!("admin")),
            ("account_type", json!("premium")),
            ("accountType", json!("premium")),
        ];

        for (param_name, param_value) in roles {
            let payload = json!({
                "username": "test",
                param_name: param_value,
            });

            let test_result = self.send_request(url, method, &payload).await;
            
            match test_result {
                Ok((status, body)) => {
                    if status >= 200 && status < 300 {
                        if self.check_param_accepted(&body, param_name, &param_value) {
                            vulns.push(MassAssignmentVuln {
                                vuln_type: "Role Manipulation".to_string(),
                                severity: "HIGH".to_string(),
                                description: format!("Role parameter '{}' accepted - may allow unauthorized access", param_name),
                                parameter: param_name.to_string(),
                                payload: Some(payload.to_string()),
                            });

                            params.push(HiddenParameter {
                                name: param_name.to_string(),
                                accepted: true,
                                potential_impact: "HIGH - Role manipulation".to_string(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Ok((vulns, params))
    }

    /// Test ID manipulation
    async fn test_id_manipulation(&self, url: &str, method: &str) -> Result<(Vec<MassAssignmentVuln>, Vec<HiddenParameter>)> {
        let mut vulns = Vec::new();
        let mut params = Vec::new();

        // ID-related parameters
        let id_params = vec![
            ("id", json!("00000000-0000-0000-0000-000000000001")),
            ("uuid", json!("00000000-0000-0000-0000-000000000001")),
            ("_id", json!("507f1f77bcf86cd799439011")),
            ("object_id", json!("507f1f77bcf86cd799439011")),
            ("pk", json!(1)),
            ("primary_key", json!(1)),
        ];

        for (param_name, param_value) in id_params {
            let payload = json!({
                "username": "test",
                param_name: param_value,
            });

            let test_result = self.send_request(url, method, &payload).await;
            
            match test_result {
                Ok((status, body)) => {
                    if status >= 200 && status < 300 {
                        if self.check_param_accepted(&body, param_name, &param_value) {
                            vulns.push(MassAssignmentVuln {
                                vuln_type: "ID Manipulation".to_string(),
                                severity: "MEDIUM".to_string(),
                                description: format!("ID parameter '{}' accepted - may allow object hijacking", param_name),
                                parameter: param_name.to_string(),
                                payload: Some(payload.to_string()),
                            });

                            params.push(HiddenParameter {
                                name: param_name.to_string(),
                                accepted: true,
                                potential_impact: "MEDIUM - ID manipulation".to_string(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Ok((vulns, params))
    }

    /// Test status manipulation
    async fn test_status_manipulation(&self, url: &str, method: &str) -> Result<(Vec<MassAssignmentVuln>, Vec<HiddenParameter>)> {
        let mut vulns = Vec::new();
        let mut params = Vec::new();

        // Status-related parameters
        let status_params = vec![
            ("status", json!("approved")),
            ("state", json!("approved")),
            ("approval_status", json!("approved")),
            ("approvalStatus", json!("approved")),
            ("payment_status", json!("paid")),
            ("paymentStatus", json!("paid")),
            ("verified_status", json!("verified")),
            ("verifiedStatus", json!("verified")),
            ("enabled", json!(true)),
            ("disabled", json!(false)),
            ("locked", json!(false)),
            ("is_locked", json!(false)),
            ("isLocked", json!(false)),
        ];

        for (param_name, param_value) in status_params {
            let payload = json!({
                "username": "test",
                param_name: param_value,
            });

            let test_result = self.send_request(url, method, &payload).await;
            
            match test_result {
                Ok((status, body)) => {
                    if status >= 200 && status < 300 {
                        if self.check_param_accepted(&body, param_name, &param_value) {
                            vulns.push(MassAssignmentVuln {
                                vuln_type: "Status Manipulation".to_string(),
                                severity: "MEDIUM".to_string(),
                                description: format!("Status parameter '{}' accepted - may bypass workflows", param_name),
                                parameter: param_name.to_string(),
                                payload: Some(payload.to_string()),
                            });

                            params.push(HiddenParameter {
                                name: param_name.to_string(),
                                accepted: true,
                                potential_impact: "MEDIUM - Status bypass".to_string(),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Ok((vulns, params))
    }

    /// Send HTTP request based on method
    async fn send_request(&self, url: &str, method: &str, payload: &Value) -> Result<(u16, String)> {
        let result = match method.to_uppercase().as_str() {
            "POST" => {
                timeout(Duration::from_secs(3), self.client.post_json(url, payload)).await??
            }
            "PUT" => {
                timeout(Duration::from_secs(3), self.client.put_json(url, payload)).await??
            }
            "PATCH" => {
                timeout(Duration::from_secs(3), self.client.patch_json(url, payload)).await??
            }
            _ => {
                timeout(Duration::from_secs(3), self.client.post_json(url, payload)).await??
            }
        };

        let status = result.status().as_u16();
        let body = result.text().await?;

        Ok((status, body))
    }

    /// Check if parameter was accepted in response
    fn check_param_accepted(&self, body: &str, param_name: &str, param_value: &Value) -> bool {
        // Try to parse as JSON
        if let Ok(json_body) = serde_json::from_str::<Value>(body) {
            // Check if parameter appears in response with same value
            if let Some(obj) = json_body.as_object() {
                if let Some(value) = obj.get(param_name) {
                    // Parameter exists in response - likely accepted
                    return true;
                }
            }
        }

        // Also check in plain text
        let body_lower = body.to_lowercase();
        let param_lower = param_name.to_lowercase();
        
        // If body contains the parameter name, likely accepted
        body_lower.contains(&param_lower)
    }

    /// Discover hidden parameters through parameter pollution
    pub async fn discover_hidden_params(&self, url: &str, method: &str) -> Result<Vec<String>> {
        let mut hidden_params = Vec::new();

        // Common parameter patterns
        let param_patterns = vec![
            // Privilege parameters
            "admin", "is_admin", "isAdmin", "role", "user_role", "userRole",
            "superuser", "is_superuser", "isSuperuser", "privileges", "permissions",
            
            // ID parameters
            "id", "user_id", "userId", "account_id", "accountId", "uuid", "_id",
            
            // Status parameters
            "status", "state", "active", "is_active", "isActive", "verified",
            "is_verified", "isVerified", "enabled", "disabled",
            
            // Metadata parameters
            "created_at", "createdAt", "updated_at", "updatedAt", "deleted_at",
            "deletedAt", "is_deleted", "isDeleted",
            
            // Financial parameters
            "price", "cost", "amount", "balance", "credits", "payment_status",
            "paymentStatus", "subscription", "plan",
        ];

        let tasks: Vec<_> = param_patterns.iter().map(|param| {
            let param_str = param.to_string();
            let mut payload_map = serde_json::Map::new();
            payload_map.insert("test".to_string(), json!("value"));
            payload_map.insert(param_str, json!("test_value"));
            let payload = Value::Object(payload_map);
            
            let client = self.client.clone();
            let url = url.to_string();
            let method = method.to_string();
            
            async move {
                let result = match method.to_uppercase().as_str() {
                    "POST" => timeout(Duration::from_secs(3), client.post_json(&url, &payload)).await,
                    "PUT" => timeout(Duration::from_secs(3), client.put_json(&url, &payload)).await,
                    "PATCH" => timeout(Duration::from_secs(3), client.patch_json(&url, &payload)).await,
                    _ => timeout(Duration::from_secs(3), client.post_json(&url, &payload)).await,
                };
                
                match result {
                    Ok(Ok(response)) => {
                        let status = response.status().as_u16();
                        if let Ok(body) = response.text().await {
                            Some((status, body))
                        } else {
                            None
                        }
                    }
                    _ => None
                }
            }
        }).collect();

        let results = futures::future::join_all(tasks).await;
        
        for (i, result) in results.into_iter().enumerate() {
            if let Some((status, body)) = result {
                if status >= 200 && status < 300 {
                    if body.contains(param_patterns[i]) {
                        hidden_params.push(param_patterns[i].to_string());
                    }
                }
            }
        }

        Ok(hidden_params)
    }
}
