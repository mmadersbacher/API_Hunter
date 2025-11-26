use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SubdomainResult {
    pub subdomain: String,
    pub source: String,
}

pub struct SubdomainEnumerator {
    client: reqwest::Client,
    common_prefixes: Vec<String>,
}

impl SubdomainEnumerator {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            client,
            common_prefixes: Self::load_common_prefixes(),
        }
    }

    /// Load common subdomain prefixes
    fn load_common_prefixes() -> Vec<String> {
        vec![
            // API-related
            "api", "api-dev", "api-staging", "api-test", "api-prod", "api1", "api2", "api3",
            "rest", "graphql", "gateway", "apigw", "api-gateway",
            // Development/Testing
            "dev", "develop", "development", "test", "testing", "qa", "staging", "stage",
            "uat", "preprod", "pre-prod", "sandbox", "demo",
            // Admin/Internal
            "admin", "administrator", "internal", "intranet", "private", "secure",
            "mgmt", "management", "portal", "console", "dashboard",
            // Mobile
            "mobile", "m", "app", "ios", "android",
            // Services
            "www", "web", "blog", "shop", "store", "cdn", "static", "assets", "media",
            "mail", "smtp", "imap", "pop3", "webmail", "email",
            // Cloud/Infrastructure
            "cloud", "s3", "storage", "backup", "upload", "download",
            "jenkins", "gitlab", "github", "ci", "cd", "build",
            // Monitoring/Logging
            "monitor", "monitoring", "metrics", "logs", "logging", "grafana", "kibana",
            // Documentation
            "docs", "documentation", "wiki", "help", "support",
            // Versions
            "v1", "v2", "v3", "v4", "v5",
            // Old/Legacy
            "old", "legacy", "deprecated", "backup", "archive",
            // Others
            "beta", "alpha", "rc", "canary", "preview",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Enumerate subdomains using multiple methods
    pub async fn enumerate(&self, domain: &str) -> Vec<SubdomainResult> {
        let mut results = HashSet::new();

        // Method 1: Certificate Transparency (crt.sh)
        if let Ok(crt_results) = self.query_crtsh(domain).await {
            for subdomain in crt_results {
                results.insert(SubdomainResult {
                    subdomain: subdomain.clone(),
                    source: "crt.sh".to_string(),
                });
            }
        }

        // Method 2: DNS Bruteforce (common prefixes)
        let dns_results = self.dns_bruteforce(domain).await;
        for subdomain in dns_results {
            results.insert(SubdomainResult {
                subdomain: subdomain.clone(),
                source: "dns-bruteforce".to_string(),
            });
        }

        results.into_iter().collect()
    }

    /// Query crt.sh Certificate Transparency logs
    async fn query_crtsh(&self, domain: &str) -> Result<Vec<String>, String> {
        let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
        
        tracing::debug!("Querying crt.sh for domain: {}", domain);

        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("crt.sh request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("crt.sh returned status: {}", response.status()));
        }

        let body = response.text().await
            .map_err(|e| format!("Failed to read crt.sh response: {}", e))?;

        // Parse JSON response
        let entries: Vec<CrtShEntry> = serde_json::from_str(&body)
            .map_err(|e| format!("Failed to parse crt.sh JSON: {}", e))?;

        let mut subdomains = HashSet::new();
        
        for entry in entries {
            // Parse common_name
            if let Some(cn) = entry.common_name {
                if cn.ends_with(domain) {
                    subdomains.insert(cn.to_lowercase());
                }
            }
            
            // Parse name_value (can contain multiple domains)
            if let Some(nv) = entry.name_value {
                for name in nv.split('\n') {
                    let name = name.trim().to_lowercase();
                    if name.ends_with(domain) && !name.starts_with('*') {
                        subdomains.insert(name);
                    }
                }
            }
        }

        tracing::info!("crt.sh found {} subdomains", subdomains.len());
        Ok(subdomains.into_iter().collect())
    }

    /// DNS bruteforce with common prefixes
    async fn dns_bruteforce(&self, domain: &str) -> Vec<String> {
        use tokio::task::JoinSet;
        
        let mut tasks = JoinSet::new();
        let mut found_subdomains = Vec::new();

        tracing::debug!("Starting DNS bruteforce for {} prefixes", self.common_prefixes.len());

        // Spawn concurrent DNS resolution tasks
        for prefix in &self.common_prefixes {
            let subdomain = format!("{}.{}", prefix, domain);
            let subdomain_clone = subdomain.clone();
            
            tasks.spawn(async move {
                if Self::dns_resolve(&subdomain_clone).await {
                    Some(subdomain_clone)
                } else {
                    None
                }
            });
        }

        // Collect results
        let mut resolved_count = 0;
        while let Some(result) = tasks.join_next().await {
            if let Ok(Some(subdomain)) = result {
                found_subdomains.push(subdomain);
                resolved_count += 1;
            }
        }

        tracing::info!("DNS bruteforce found {} subdomains", resolved_count);
        found_subdomains
    }

    /// Resolve DNS for a subdomain
    async fn dns_resolve(subdomain: &str) -> bool {
        use tokio::net::lookup_host;
        
        // Try to resolve the subdomain
        match lookup_host(format!("{}:443", subdomain)).await {
            Ok(mut addrs) => addrs.next().is_some(),
            Err(_) => false,
        }
    }

    /// Generate subdomain report
    pub fn generate_report(&self, results: &[SubdomainResult]) -> String {
        let mut report = String::new();
        
        report.push_str("=== Subdomain Enumeration Results ===\n\n");
        report.push_str(&format!("Total subdomains found: {}\n\n", results.len()));

        // Group by source
        let mut by_source: std::collections::HashMap<String, Vec<&SubdomainResult>> = std::collections::HashMap::new();
        for result in results {
            by_source.entry(result.source.clone()).or_default().push(result);
        }

        for (source, subdomains) in by_source.iter() {
            report.push_str(&format!("\n[{}] - {} subdomains:\n", source, subdomains.len()));
            for sub in subdomains {
                report.push_str(&format!("  - {}\n", sub.subdomain));
            }
        }

        // Highlight API-related subdomains
        let api_subdomains: Vec<_> = results.iter()
            .filter(|r| r.subdomain.contains("api") || r.subdomain.contains("rest") || r.subdomain.contains("graphql"))
            .collect();

        if !api_subdomains.is_empty() {
            report.push_str(&format!("\n[!] API-related subdomains ({}):\n", api_subdomains.len()));
            for sub in api_subdomains {
                report.push_str(&format!("  [+] {} (from {})\n", sub.subdomain, sub.source));
            }
        }

        report
    }
}

impl Default for SubdomainEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    common_name: Option<String>,
    name_value: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_resolve() {
        // Test with a known domain
        let result = SubdomainEnumerator::dns_resolve("www.google.com").await;
        assert!(result);

        // Test with non-existent domain
        let result = SubdomainEnumerator::dns_resolve("thisdomainreallydoesnotexist123456789.com").await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_crtsh_query() {
        let enumerator = SubdomainEnumerator::new();
        // Test with a known domain
        if let Ok(results) = enumerator.query_crtsh("github.com").await {
            assert!(!results.is_empty());
        }
    }
}
