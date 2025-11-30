use crate::http_client::HttpClient;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
pub struct VersionedEndpoint {
    pub base_url: String,
    pub versions: Vec<ApiVersion>,
    pub vulnerabilities: Vec<VersionVulnerability>,
}

#[derive(Debug, Clone)]
pub struct ApiVersion {
    pub version: String,
    pub url: String,
    pub status_code: u16,
    pub is_deprecated: bool,
    pub accessible: bool,
    pub endpoints_found: usize,
}

#[derive(Debug, Clone)]
pub struct VersionVulnerability {
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
    pub affected_versions: Vec<String>,
}

pub struct VersionDetector {
    client: HttpClient,
}

impl VersionDetector {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Discover all API versions
    pub async fn discover_versions(&self, base_url: &str) -> Result<VersionedEndpoint> {
        let mut result = VersionedEndpoint {
            base_url: base_url.to_string(),
            versions: Vec::new(),
            vulnerabilities: Vec::new(),
        };

        // Test common version patterns in parallel
        let version_patterns = self.generate_version_patterns(base_url);
        
        let mut tasks = Vec::new();
        for url in &version_patterns {
            tasks.push(self.test_version_endpoint(url));
        }

        let results = futures::future::join_all(tasks).await;
        
        for (_i, test_result) in results.into_iter().enumerate() {
            if let Ok(Some(version_info)) = test_result {
                result.versions.push(version_info);
            }
        }

        // Test for version-specific vulnerabilities
        if !result.versions.is_empty() {
            result.vulnerabilities = self.test_version_vulnerabilities(&result.versions).await?;
        }

        Ok(result)
    }

    /// Generate common version URL patterns
    fn generate_version_patterns(&self, base_url: &str) -> Vec<String> {
        let base = base_url.trim_end_matches('/');
        let mut patterns = Vec::new();

        // Common version formats
        let versions = vec![
            "v1", "v2", "v3", "v4", "v5",
            "1", "2", "3", "4", "5",
            "1.0", "2.0", "3.0", "1.1", "2.1",
        ];

        // Common patterns
        for version in &versions {
            patterns.push(format!("{}/api/{}", base, version));
            patterns.push(format!("{}/{}", base, version));
            patterns.push(format!("{}/api/{}/", base, version));
            patterns.push(format!("{}/{}/api", base, version));
        }

        // Query parameter versions
        patterns.push(format!("{}?version=1", base));
        patterns.push(format!("{}?version=2", base));
        patterns.push(format!("{}?v=1", base));
        patterns.push(format!("{}?v=2", base));
        patterns.push(format!("{}?api-version=1", base));
        patterns.push(format!("{}?api-version=2", base));

        // Subdomain versions
        if let Some(domain) = self.extract_domain(base) {
            patterns.push(format!("https://v1.{}", domain));
            patterns.push(format!("https://v2.{}", domain));
            patterns.push(format!("https://api-v1.{}", domain));
            patterns.push(format!("https://api-v2.{}", domain));
        }

        patterns
    }

    /// Test if version endpoint exists
    async fn test_version_endpoint(&self, url: &str) -> Result<Option<ApiVersion>> {
        match timeout(Duration::from_secs(3), self.client.get(url)).await {
            Ok(Ok(response)) => {
                let status = response.status().as_u16();
                
                // Consider 200, 401, 403 as "exists" (auth required still means endpoint exists)
                if status == 200 || status == 401 || status == 403 {
                    let version = self.extract_version_from_url(url);
                    let is_deprecated = self.check_if_deprecated(&response).await;
                    
                    Ok(Some(ApiVersion {
                        version: version.clone(),
                        url: url.to_string(),
                        status_code: status,
                        is_deprecated,
                        accessible: status == 200,
                        endpoints_found: 0, // Will be populated later
                    }))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    /// Extract version identifier from URL
    fn extract_version_from_url(&self, url: &str) -> String {
        // Try to extract version like v1, v2, 1.0, etc.
        let patterns = vec![
            r"v(\d+)",
            r"/(\d+\.\d+)",
            r"/(\d+)",
            r"version=(\d+)",
            r"v=(\d+)",
        ];

        for pattern in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(captures) = re.captures(url) {
                    if let Some(version) = captures.get(1) {
                        return version.as_str().to_string();
                    }
                }
            }
        }

        "unknown".to_string()
    }

    /// Check if version is deprecated
    async fn check_if_deprecated(&self, response: &reqwest::Response) -> bool {
        // Check deprecation headers
        if response.headers().get("deprecation").is_some() {
            return true;
        }

        if response.headers().get("sunset").is_some() {
            return true;
        }

        false
    }

    /// Extract domain from URL
    fn extract_domain(&self, url: &str) -> Option<String> {
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                return Some(host.to_string());
            }
        }
        None
    }

    /// Test for version-specific vulnerabilities
    async fn test_version_vulnerabilities(&self, versions: &[ApiVersion]) -> Result<Vec<VersionVulnerability>> {
        let mut vulns = Vec::new();

        // Check for deprecated versions still accessible
        let deprecated: Vec<_> = versions.iter()
            .filter(|v| v.is_deprecated && v.accessible)
            .collect();

        if !deprecated.is_empty() {
            vulns.push(VersionVulnerability {
                vuln_type: "Deprecated Version Accessible".to_string(),
                severity: "MEDIUM".to_string(),
                description: "Deprecated API versions are still accessible and may contain unfixed vulnerabilities".to_string(),
                affected_versions: deprecated.iter().map(|v| v.version.clone()).collect(),
            });
        }

        // Check for multiple accessible versions
        let accessible: Vec<_> = versions.iter()
            .filter(|v| v.accessible)
            .collect();

        if accessible.len() > 2 {
            vulns.push(VersionVulnerability {
                vuln_type: "Multiple Active Versions".to_string(),
                severity: "LOW".to_string(),
                description: format!("Multiple API versions ({}) are active - increases attack surface", accessible.len()),
                affected_versions: accessible.iter().map(|v| v.version.clone()).collect(),
            });
        }

        // Test version downgrade attacks
        if versions.len() >= 2 {
            let downgrade_vulns = self.test_version_downgrade(versions).await?;
            vulns.extend(downgrade_vulns);
        }

        // Test version enumeration
        if !versions.is_empty() {
            let enum_vulns = self.test_version_enumeration(versions).await?;
            vulns.extend(enum_vulns);
        }

        Ok(vulns)
    }

    /// Test version downgrade attacks
    async fn test_version_downgrade(&self, versions: &[ApiVersion]) -> Result<Vec<VersionVulnerability>> {
        let mut vulns = Vec::new();

        // Find oldest and newest versions
        let sorted_versions: Vec<_> = versions.iter()
            .filter(|v| v.accessible)
            .collect();

        if sorted_versions.len() < 2 {
            return Ok(vulns);
        }

        // Test if older version accepts same authentication as newer version
        for old_version in sorted_versions.iter().take(sorted_versions.len() - 1) {
            // Test with version header downgrade
            let mut headers = HashMap::new();
            headers.insert("Accept-Version".to_string(), old_version.version.clone());
            
            match timeout(Duration::from_secs(3), 
                self.client.get_with_headers(&old_version.url, &headers)).await {
                Ok(Ok(response)) => {
                    if response.status().is_success() {
                        vulns.push(VersionVulnerability {
                            vuln_type: "Version Downgrade Possible".to_string(),
                            severity: "HIGH".to_string(),
                            description: format!("API allows downgrading to older version {} which may have security issues", old_version.version),
                            affected_versions: vec![old_version.version.clone()],
                        });
                    }
                }
                _ => {}
            }
        }

        Ok(vulns)
    }

    /// Test version enumeration vulnerabilities
    async fn test_version_enumeration(&self, versions: &[ApiVersion]) -> Result<Vec<VersionVulnerability>> {
        let mut vulns = Vec::new();

        // Check if version info is exposed
        for version in versions {
            match timeout(Duration::from_secs(3), self.client.get(&version.url)).await {
                Ok(Ok(response)) => {
                    // Check for version disclosure in headers
                    if let Some(server) = response.headers().get("server") {
                        if let Ok(value) = server.to_str() {
                            if value.contains("version") || value.contains(&version.version) {
                                vulns.push(VersionVulnerability {
                                    vuln_type: "Version Information Disclosure".to_string(),
                                    severity: "LOW".to_string(),
                                    description: "API version information exposed in headers - aids attackers".to_string(),
                                    affected_versions: vec![version.version.clone()],
                                });
                            }
                        }
                    }

                    // Check response body
                    if let Ok(body) = response.text().await {
                        if body.contains("version") || body.contains(&version.version) {
                            vulns.push(VersionVulnerability {
                                vuln_type: "Version Information in Response".to_string(),
                                severity: "LOW".to_string(),
                                description: "API version exposed in response body".to_string(),
                                affected_versions: vec![version.version.clone()],
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(vulns)
    }

    /// Enumerate endpoints for each version
    pub async fn enumerate_version_endpoints(&self, version: &ApiVersion) -> Result<Vec<String>> {
        let mut endpoints = HashSet::new();

        // Common API endpoints to test
        let common_paths = vec![
            "/users", "/user", "/auth", "/login", "/api", "/health",
            "/status", "/docs", "/swagger", "/openapi", "/graphql",
            "/admin", "/config", "/settings", "/profile",
        ];

        let base_url = version.url.trim_end_matches('/').to_string();
        
        for path in &common_paths {
            let url = format!("{}{}", base_url, path);
            if let Ok(true) = self.test_endpoint_exists(&url).await {
                endpoints.insert(url);
            }
        }

        Ok(endpoints.into_iter().collect())
    }

    /// Test if endpoint exists
    async fn test_endpoint_exists(&self, url: &str) -> Result<bool> {
        match timeout(Duration::from_secs(2), self.client.get(url)).await {
            Ok(Ok(response)) => {
                let status = response.status().as_u16();
                // 200, 401, 403 means endpoint exists
                Ok(status == 200 || status == 401 || status == 403)
            }
            _ => Ok(false),
        }
    }
}
