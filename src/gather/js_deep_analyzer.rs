//! Advanced JavaScript Deep Analysis - Extract all critical information from JS files
//! This module mimics what a bug bounty hunter manually does in F12 DevTools Network tab

use anyhow::Result;
use regex::Regex;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use url::Url;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::task::JoinSet;

/// Critical information extracted from JavaScript files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsCriticalInfo {
    /// API endpoints discovered
    pub endpoints: Vec<ApiEndpoint>,
    /// Authentication tokens, API keys, secrets
    pub secrets: Vec<Secret>,
    /// Subdomains and external domains
    pub domains: Vec<String>,
    /// Path parameters and query parameters
    pub parameters: Vec<Parameter>,
    /// WebSocket endpoints
    pub websockets: Vec<String>,
    /// GraphQL endpoints and queries
    pub graphql: Vec<GraphQLInfo>,
    /// Internal paths and routes
    pub routes: Vec<String>,
    /// S3 buckets, GCS buckets, Azure storage
    pub cloud_storage: Vec<CloudStorage>,
    /// Email addresses
    pub emails: Vec<String>,
    /// Internal comments and debug info
    pub comments: Vec<String>,
    /// Third-party integrations
    pub integrations: Vec<Integration>,
    /// Source map URLs
    pub source_maps: Vec<String>,
    /// Version information
    pub versions: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub url: String,
    pub method: String,
    pub source_file: String,
    pub context: String, // Surrounding code for context
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub secret_type: SecretType,
    pub value: String,
    pub source_file: String,
    pub line_context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecretType {
    ApiKey,
    BearerToken,
    JwtToken,
    AwsKey,
    PrivateKey,
    Password,
    ClientSecret,
    WebhookUrl,
    DatabaseUrl,
    Generic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub param_type: ParamType,
    pub example_value: Option<String>,
    pub source_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParamType {
    Query,
    Path,
    Body,
    Header,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLInfo {
    pub endpoint: String,
    pub queries: Vec<String>,
    pub mutations: Vec<String>,
    pub source_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudStorage {
    pub storage_type: StorageType,
    pub bucket_url: String,
    pub source_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    S3,
    GCS,
    Azure,
    Cloudflare,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integration {
    pub service: String,
    pub identifier: String,
    pub source_file: String,
}

/// Deep JavaScript Analyzer
pub struct JsDeepAnalyzer {
    client: Client,
    base_domain: String,
    max_js_size: usize,
    max_concurrent: usize,
}

impl JsDeepAnalyzer {
    pub fn new(base_domain: String, timeout_secs: u64, max_concurrent: usize) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(true)
            .pool_max_idle_per_host(50)
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .build()?;

        Ok(Self {
            client,
            base_domain,
            max_js_size: 2 * 1024 * 1024, // 2MB per file
            max_concurrent,
        })
    }

    /// Main entry point: Discover and analyze all JavaScript files
    pub async fn analyze_all(&self) -> Result<JsCriticalInfo> {
        tracing::info!("Starting deep JavaScript analysis for {}", self.base_domain);

        // Step 1: Discover all JS files
        let js_files = self.discover_js_files().await?;
        tracing::info!("Found {} JavaScript files to analyze", js_files.len());

        if js_files.is_empty() {
            return Ok(JsCriticalInfo::default());
        }

        // Step 2: Analyze all JS files concurrently
        let results = Arc::new(DashMap::new());
        let mut tasks = JoinSet::new();

        for (idx, js_url) in js_files.iter().enumerate() {
            if idx >= self.max_concurrent && tasks.len() >= self.max_concurrent {
                // Wait for one task to complete before adding more
                let _ = tasks.join_next().await;
            }

            let client = self.client.clone();
            let url = js_url.clone();
            let results = Arc::clone(&results);
            let max_size = self.max_js_size;
            let base_domain = self.base_domain.clone();

            tasks.spawn(async move {
                match Self::fetch_and_analyze_js(&client, &url, &base_domain, max_size).await {
                    Ok(info) => {
                        results.insert(url.clone(), info);
                    }
                    Err(e) => {
                        tracing::debug!("Failed to analyze {}: {}", url, e);
                    }
                }
            });
        }

        // Wait for all tasks to complete
        while tasks.join_next().await.is_some() {}

        // Step 3: Aggregate all results
        let aggregated = self.aggregate_results(results);
        
        tracing::info!(
            "Deep JS Analysis complete: {} endpoints, {} secrets, {} parameters",
            aggregated.endpoints.len(),
            aggregated.secrets.len(),
            aggregated.parameters.len()
        );

        Ok(aggregated)
    }

    /// Discover all JavaScript files from the base domain
    async fn discover_js_files(&self) -> Result<Vec<String>> {
        let base_url = format!("https://{}", self.base_domain);
        let mut js_files = HashSet::new();

        // Fetch root page
        match self.client.get(&base_url).send().await {
            Ok(resp) => {
                if let Ok(body) = resp.text().await {
                    let document = Html::parse_document(&body);
                    
                    // Parse <script src="...">
                    if let Ok(script_sel) = Selector::parse("script[src]") {
                        for element in document.select(&script_sel) {
                            if let Some(src) = element.value().attr("src") {
                                if let Ok(js_url) = self.resolve_url(&base_url, src) {
                                    if js_url.ends_with(".js") || js_url.contains(".js?") {
                                        js_files.insert(js_url);
                                    }
                                }
                            }
                        }
                    }

                    // Also extract JS files referenced in inline scripts and HTML
                    let js_ref_regex = Regex::new(r#"["'`]((?:https?:)?//[^"'`\s]+\.js(?:\?[^"'`\s]*)?|/[^"'`\s]+\.js(?:\?[^"'`\s]*)?)["'`]"#).unwrap();
                    for cap in js_ref_regex.captures_iter(&body) {
                        if let Some(m) = cap.get(1) {
                            if let Ok(js_url) = self.resolve_url(&base_url, m.as_str()) {
                                js_files.insert(js_url);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to fetch root page: {}", e);
            }
        }

        // Also check common JS paths
        let common_paths = vec![
            "/static/js/main.js",
            "/assets/js/app.js",
            "/js/bundle.js",
            "/dist/app.js",
            "/build/main.js",
            "/_next/static/chunks/main.js",
            "/webpack/runtime.js",
        ];

        for path in common_paths {
            if let Ok(url) = self.resolve_url(&base_url, path) {
                js_files.insert(url);
            }
        }

        Ok(js_files.into_iter().collect())
    }

    /// Fetch and analyze a single JavaScript file
    async fn fetch_and_analyze_js(
        client: &Client,
        js_url: &str,
        base_domain: &str,
        max_size: usize,
    ) -> Result<JsCriticalInfo> {
        let resp = client.get(js_url).send().await?;
        let bytes = resp.bytes().await?;
        
        let content = String::from_utf8_lossy(
            &bytes[..std::cmp::min(bytes.len(), max_size)]
        ).to_string();

        Ok(Self::analyze_js_content(&content, js_url, base_domain))
    }

    /// Analyze JavaScript content and extract critical information
    fn analyze_js_content(content: &str, source_file: &str, base_domain: &str) -> JsCriticalInfo {
        let mut info = JsCriticalInfo::default();
        info.endpoints = Self::extract_endpoints(content, source_file, base_domain);
        info.secrets = Self::extract_secrets(content, source_file);
        info.domains = Self::extract_domains(content);
        info.parameters = Self::extract_parameters(content, source_file);
        info.websockets = Self::extract_websockets(content);
        info.graphql = Self::extract_graphql(content, source_file);
        info.routes = Self::extract_routes(content);
        info.cloud_storage = Self::extract_cloud_storage(content, source_file);
        info.emails = Self::extract_emails(content);
        info.comments = Self::extract_comments(content);
        info.integrations = Self::extract_integrations(content, source_file);
        info.source_maps = Self::extract_source_maps(content);
        info.versions = Self::extract_versions(content);

        info
    }

    /// Extract API endpoints with HTTP methods
    fn extract_endpoints(content: &str, source_file: &str, base_domain: &str) -> Vec<ApiEndpoint> {
        let mut endpoints = Vec::new();
        let patterns = vec![
            // fetch() calls
            (r#"fetch\s*\(\s*["'`]([^"'`]+)["'`]"#, "GET"),
            (r#"fetch\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*\{[^}]*method\s*:\s*["'`](\w+)["'`]"#, ""),
            // axios calls
            (r#"axios\.get\s*\(\s*["'`]([^"'`]+)["'`]"#, "GET"),
            (r#"axios\.post\s*\(\s*["'`]([^"'`]+)["'`]"#, "POST"),
            (r#"axios\.put\s*\(\s*["'`]([^"'`]+)["'`]"#, "PUT"),
            (r#"axios\.delete\s*\(\s*["'`]([^"'`]+)["'`]"#, "DELETE"),
            (r#"axios\.patch\s*\(\s*["'`]([^"'`]+)["'`]"#, "PATCH"),
            (r#"axios\(\s*\{[^}]*url\s*:\s*["'`]([^"'`]+)["'`]"#, "GET"),
            // XMLHttpRequest
            (r#"\.open\s*\(\s*["'`](\w+)["'`]\s*,\s*["'`]([^"'`]+)["'`]"#, ""),
            // jQuery ajax
            (r#"\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["'`]([^"'`]+)["'`]"#, "GET"),
            (r#"\$\.get\s*\(\s*["'`]([^"'`]+)["'`]"#, "GET"),
            (r#"\$\.post\s*\(\s*["'`]([^"'`]+)["'`]"#, "POST"),
            // URL constructors
            (r#"new\s+URL\s*\(\s*["'`]([^"'`]+)["'`]"#, "GET"),
            // API path definitions
            (r#"(?:path|route|endpoint|url)\s*:\s*["'`]([/\w\-\{\}]+)["'`]"#, "GET"),
        ];

        for (pattern, default_method) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    let url = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                    let method = if default_method.is_empty() {
                        cap.get(2).map(|m| m.as_str().to_uppercase()).unwrap_or_else(|| "GET".to_string())
                    } else {
                        default_method.to_string()
                    };

                    if !url.is_empty() && Self::is_valid_endpoint(url) {
                        // Get surrounding context (50 chars before and after)
                        let start = cap.get(0).unwrap().start();
                        let context_start = start.saturating_sub(50);
                        let context_end = std::cmp::min(start + 150, content.len());
                        let context = content[context_start..context_end].to_string();

                        endpoints.push(ApiEndpoint {
                            url: url.to_string(),
                            method,
                            source_file: source_file.to_string(),
                            context: context.replace('\n', " ").trim().to_string(),
                        });
                    }
                }
            }
        }

        // Deduplicate
        endpoints.sort_by(|a, b| a.url.cmp(&b.url));
        endpoints.dedup_by(|a, b| a.url == b.url && a.method == b.method);
        endpoints
    }

    /// Extract secrets, API keys, tokens
    fn extract_secrets(content: &str, source_file: &str) -> Vec<Secret> {
        let mut secrets = Vec::new();

        let patterns = vec![
            // API Keys
            (r#"(?i)api[_-]?key\s*[:=]\s*["'`]([A-Za-z0-9_\-]{20,})["'`]"#, SecretType::ApiKey),
            (r#"(?i)apikey\s*[:=]\s*["'`]([A-Za-z0-9_\-]{20,})["'`]"#, SecretType::ApiKey),
            // Bearer tokens
            (r#"(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})"#, SecretType::BearerToken),
            (r#"(?i)authorization\s*:\s*["'`]Bearer\s+([^"'`]+)["'`]"#, SecretType::BearerToken),
            // JWT tokens (looks like xxx.yyy.zzz)
            (r#"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"#, SecretType::JwtToken),
            // AWS keys
            (r#"(?i)AKIA[0-9A-Z]{16}"#, SecretType::AwsKey),
            (r#"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["'`]([^"'`]+)["'`]"#, SecretType::AwsKey),
            // Private keys
            (r#"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"#, SecretType::PrivateKey),
            // Passwords
            (r#"(?i)password\s*[:=]\s*["'`]([^"'`]{8,})["'`]"#, SecretType::Password),
            // Client secrets
            (r#"(?i)client[_-]?secret\s*[:=]\s*["'`]([A-Za-z0-9_\-]{20,})["'`]"#, SecretType::ClientSecret),
            // Webhook URLs
            (r#"https://hooks\.slack\.com/services/[A-Z0-9/]+"#, SecretType::WebhookUrl),
            (r#"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"#, SecretType::WebhookUrl),
            // Database URLs
            (r#"(?i)(?:mongodb|mysql|postgresql|postgres)://[^"'\s]+"#, SecretType::DatabaseUrl),
        ];

        for (pattern, secret_type) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    let value = cap.get(1)
                        .or_else(|| cap.get(0))
                        .map(|m| m.as_str())
                        .unwrap_or("");

                    if !value.is_empty() && value.len() >= 8 {
                        // Get line context
                        let start = cap.get(0).unwrap().start();
                        let line_start = content[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
                        let line_end = content[start..].find('\n').map(|i| start + i).unwrap_or(content.len());
                        let line_context = content[line_start..line_end].trim().to_string();

                        // Filter out obvious test/example values
                        if !Self::is_test_value(value) {
                            secrets.push(Secret {
                                secret_type: secret_type.clone(),
                                value: value.to_string(),
                                source_file: source_file.to_string(),
                                line_context,
                            });
                        }
                    }
                }
            }
        }

        secrets
    }

    /// Extract subdomains and external domains
    fn extract_domains(content: &str) -> Vec<String> {
        let mut domains = HashSet::new();
        
        let domain_regex = Regex::new(r#"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+)"#).unwrap();
        
        for cap in domain_regex.captures_iter(content) {
            if let Some(domain) = cap.get(1) {
                let d = domain.as_str();
                if d.contains('.') && !d.ends_with(".js") && !d.ends_with(".css") {
                    domains.insert(d.to_string());
                }
            }
        }

        domains.into_iter().collect()
    }

    /// Extract parameters (query, path, body, headers)
    fn extract_parameters(content: &str, source_file: &str) -> Vec<Parameter> {
        let mut params = Vec::new();

        // Query parameters: ?param=value or &param=value
        let query_regex = Regex::new(r#"[?&]([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^&\s"'`]+)"#).unwrap();
        for cap in query_regex.captures_iter(content) {
            if let Some(name) = cap.get(1) {
                params.push(Parameter {
                    name: name.as_str().to_string(),
                    param_type: ParamType::Query,
                    example_value: cap.get(2).map(|m| m.as_str().to_string()),
                    source_file: source_file.to_string(),
                });
            }
        }

        // Path parameters: {id}, :id, ${id}
        let path_regex = Regex::new(r#"[/:](\{[a-zA-Z_][a-zA-Z0-9_]*\}|:[a-zA-Z_][a-zA-Z0-9_]*|\$\{[a-zA-Z_][a-zA-Z0-9_]*\})"#).unwrap();
        for cap in path_regex.captures_iter(content) {
            if let Some(name) = cap.get(1) {
                let param_name = name.as_str()
                    .trim_start_matches('{').trim_end_matches('}')
                    .trim_start_matches(':')
                    .trim_start_matches("${").trim_end_matches('}');
                params.push(Parameter {
                    name: param_name.to_string(),
                    param_type: ParamType::Path,
                    example_value: None,
                    source_file: source_file.to_string(),
                });
            }
        }

        // Header parameters
        let header_regex = Regex::new(r#"(?i)headers?\s*:\s*\{[^}]*["'`]([A-Za-z\-]+)["'`]\s*:\s*["'`]([^"'`]+)["'`]"#).unwrap();
        for cap in header_regex.captures_iter(content) {
            if let Some(name) = cap.get(1) {
                params.push(Parameter {
                    name: name.as_str().to_string(),
                    param_type: ParamType::Header,
                    example_value: cap.get(2).map(|m| m.as_str().to_string()),
                    source_file: source_file.to_string(),
                });
            }
        }

        params.sort_by(|a, b| a.name.cmp(&b.name));
        params.dedup_by(|a, b| a.name == b.name && std::mem::discriminant(&a.param_type) == std::mem::discriminant(&b.param_type));
        params
    }

    /// Extract WebSocket endpoints
    fn extract_websockets(content: &str) -> Vec<String> {
        let mut websockets = HashSet::new();
        
        let ws_regex = Regex::new(r#"(?:new\s+WebSocket|ws://|wss://)["'`]?(wss?://[^"'`\s]+)["'`]?"#).unwrap();
        
        for cap in ws_regex.captures_iter(content) {
            if let Some(ws_url) = cap.get(1) {
                websockets.insert(ws_url.as_str().to_string());
            }
        }

        websockets.into_iter().collect()
    }

    /// Extract GraphQL endpoints and operations
    fn extract_graphql(content: &str, source_file: &str) -> Vec<GraphQLInfo> {
        let mut graphql_info = Vec::new();

        // Find GraphQL endpoints
        let endpoint_regex = Regex::new(r#"["'`](/graphql|/api/graphql|/v1/graphql)["'`]"#).unwrap();
        let mut endpoints = HashSet::new();
        
        for cap in endpoint_regex.captures_iter(content) {
            if let Some(ep) = cap.get(1) {
                endpoints.insert(ep.as_str().to_string());
            }
        }

        // Extract queries and mutations
        let query_regex = Regex::new(r#"(?:query|mutation)\s+([A-Za-z_][A-Za-z0-9_]*)"#).unwrap();
        let mut queries = Vec::new();
        let mut mutations = Vec::new();

        for cap in query_regex.captures_iter(content) {
            if let Some(op) = cap.get(0) {
                let operation = op.as_str();
                if operation.starts_with("query") {
                    if let Some(name) = cap.get(1) {
                        queries.push(name.as_str().to_string());
                    }
                } else if operation.starts_with("mutation") {
                    if let Some(name) = cap.get(1) {
                        mutations.push(name.as_str().to_string());
                    }
                }
            }
        }

        if !endpoints.is_empty() || !queries.is_empty() || !mutations.is_empty() {
            for endpoint in endpoints.iter() {
                graphql_info.push(GraphQLInfo {
                    endpoint: endpoint.clone(),
                    queries: queries.clone(),
                    mutations: mutations.clone(),
                    source_file: source_file.to_string(),
                });
            }

            if endpoints.is_empty() && (!queries.is_empty() || !mutations.is_empty()) {
                graphql_info.push(GraphQLInfo {
                    endpoint: "/graphql".to_string(),
                    queries,
                    mutations,
                    source_file: source_file.to_string(),
                });
            }
        }

        graphql_info
    }

    /// Extract internal routes and paths
    fn extract_routes(content: &str) -> Vec<String> {
        let mut routes = HashSet::new();
        
        let route_regex = Regex::new(r#"(?:path|route)\s*:\s*["'`]([/\w\-\{\}:]+)["'`]"#).unwrap();
        
        for cap in route_regex.captures_iter(content) {
            if let Some(route) = cap.get(1) {
                routes.insert(route.as_str().to_string());
            }
        }

        routes.into_iter().collect()
    }

    /// Extract cloud storage URLs (S3, GCS, Azure, Cloudflare R2)
    fn extract_cloud_storage(content: &str, source_file: &str) -> Vec<CloudStorage> {
        let mut storage = Vec::new();

        let patterns = vec![
            (r#"https?://[a-zA-Z0-9\-]+\.s3[.\-]?(?:[a-zA-Z0-9\-]+)?\.amazonaws\.com/[^\s"'`]+"#, StorageType::S3),
            (r#"https?://s3\.amazonaws\.com/[a-zA-Z0-9\-]+/[^\s"'`]+"#, StorageType::S3),
            (r#"https?://storage\.googleapis\.com/[a-zA-Z0-9\-]+/[^\s"'`]+"#, StorageType::GCS),
            (r#"https?://[a-zA-Z0-9\-]+\.storage\.googleapis\.com/[^\s"'`]+"#, StorageType::GCS),
            (r#"https?://[a-zA-Z0-9\-]+\.blob\.core\.windows\.net/[^\s"'`]+"#, StorageType::Azure),
            (r#"https?://[a-zA-Z0-9\-]+\.r2\.cloudflarestorage\.com/[^\s"'`]+"#, StorageType::Cloudflare),
        ];

        for (pattern, storage_type) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    if let Some(url) = cap.get(0) {
                        storage.push(CloudStorage {
                            storage_type: storage_type.clone(),
                            bucket_url: url.as_str().to_string(),
                            source_file: source_file.to_string(),
                        });
                    }
                }
            }
        }

        storage
    }

    /// Extract email addresses
    fn extract_emails(content: &str) -> Vec<String> {
        let mut emails = HashSet::new();
        
        let email_regex = Regex::new(r#"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"#).unwrap();
        
        for cap in email_regex.captures_iter(content) {
            if let Some(email) = cap.get(0) {
                let e = email.as_str();
                if !e.contains("example.com") && !e.contains("test.com") {
                    emails.insert(e.to_string());
                }
            }
        }

        emails.into_iter().collect()
    }

    /// Extract interesting comments (TODO, FIXME, BUG, HACK, debug info)
    fn extract_comments(content: &str) -> Vec<String> {
        let mut comments = Vec::new();
        
        // Single line comments with keywords
        let comment_regex = Regex::new(r#"//\s*(TODO|FIXME|HACK|BUG|XXX|DEBUG|API|TOKEN|KEY|SECRET|PASSWORD)[:\s]([^\n]{10,100})"#).unwrap();
        
        for cap in comment_regex.captures_iter(content) {
            if let Some(comment) = cap.get(0) {
                comments.push(comment.as_str().trim().to_string());
            }
        }

        // Multi-line comments with keywords
        let multi_comment_regex = Regex::new(r#"/\*[\s\S]*?(TODO|FIXME|HACK|BUG|XXX|DEBUG|API|TOKEN|KEY|SECRET|PASSWORD)[\s\S]{10,200}?\*/"#).unwrap();
        
        for cap in multi_comment_regex.captures_iter(content) {
            if let Some(comment) = cap.get(0) {
                let cleaned = comment.as_str()
                    .replace("/*", "")
                    .replace("*/", "")
                    .replace('\n', " ")
                    .trim()
                    .to_string();
                if cleaned.len() > 10 {
                    comments.push(cleaned);
                }
            }
        }

        comments.truncate(50); // Limit to 50 comments
        comments
    }

    /// Extract third-party integrations (Stripe, PayPal, Twilio, etc.)
    fn extract_integrations(content: &str, source_file: &str) -> Vec<Integration> {
        let mut integrations = Vec::new();

        let patterns = vec![
            (r#"(?i)stripe\.com|pk_(?:test|live)_[A-Za-z0-9]+"#, "Stripe"),
            (r#"(?i)paypal\.com|client-id=[A-Za-z0-9\-_]+"#, "PayPal"),
            (r#"(?i)twilio\.com|AC[a-z0-9]{32}"#, "Twilio"),
            (r#"(?i)sendgrid\.com|SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"#, "SendGrid"),
            (r#"(?i)google(?:apis)?\.com|AIza[A-Za-z0-9_\-]{35}"#, "Google"),
            (r#"(?i)firebase\.com|firebase[A-Za-z0-9:_\-]+"#, "Firebase"),
            (r#"(?i)analytics\.google\.com|UA-\d+-\d+|G-[A-Z0-9]+"#, "Google Analytics"),
            (r#"(?i)sentry\.io|[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io"#, "Sentry"),
            (r#"(?i)intercom\.io|app_id:\s*["']([a-z0-9]+)["']"#, "Intercom"),
            (r#"(?i)segment\.com|writeKey:\s*["']([A-Za-z0-9]+)["']"#, "Segment"),
        ];

        for (pattern, service) in patterns {
            if let Ok(re) = Regex::new(pattern) {
                for cap in re.captures_iter(content) {
                    let identifier = cap.get(1)
                        .or_else(|| cap.get(0))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default();

                    integrations.push(Integration {
                        service: service.to_string(),
                        identifier,
                        source_file: source_file.to_string(),
                    });
                }
            }
        }

        integrations.dedup_by(|a, b| a.service == b.service);
        integrations
    }

    /// Extract source map URLs
    fn extract_source_maps(content: &str) -> Vec<String> {
        let mut source_maps = HashSet::new();
        
        let sourcemap_regex = Regex::new(r#"sourceMappingURL=([^\s]+\.map)"#).unwrap();
        
        for cap in sourcemap_regex.captures_iter(content) {
            if let Some(map_url) = cap.get(1) {
                source_maps.insert(map_url.as_str().to_string());
            }
        }

        source_maps.into_iter().collect()
    }

    /// Extract version information
    fn extract_versions(content: &str) -> HashMap<String, String> {
        let mut versions = HashMap::new();

        let version_regex = Regex::new(r#"(?i)version["']?\s*:\s*["']([0-9]+\.[0-9]+\.[0-9]+[^"']*)["']"#).unwrap();
        
        for cap in version_regex.captures_iter(content) {
            if let Some(version) = cap.get(1) {
                versions.insert("app_version".to_string(), version.as_str().to_string());
                break;
            }
        }

        // Framework versions
        let frameworks = vec![
            ("react", r#"react(?:@|/)([0-9]+\.[0-9]+\.[0-9]+)"#),
            ("vue", r#"vue(?:@|/)([0-9]+\.[0-9]+\.[0-9]+)"#),
            ("angular", r#"@angular/core(?:@|/)([0-9]+\.[0-9]+\.[0-9]+)"#),
            ("next", r#"next(?:@|/)([0-9]+\.[0-9]+\.[0-9]+)"#),
        ];

        for (name, pattern) in frameworks {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(cap) = re.captures(content) {
                    if let Some(version) = cap.get(1) {
                        versions.insert(name.to_string(), version.as_str().to_string());
                    }
                }
            }
        }

        versions
    }

    /// Aggregate results from all JS files
    fn aggregate_results(&self, results: Arc<DashMap<String, JsCriticalInfo>>) -> JsCriticalInfo {
        let mut aggregated = JsCriticalInfo::default();

        for entry in results.iter() {
            let info = entry.value();
            aggregated.endpoints.extend(info.endpoints.clone());
            aggregated.secrets.extend(info.secrets.clone());
            aggregated.domains.extend(info.domains.clone());
            aggregated.parameters.extend(info.parameters.clone());
            aggregated.websockets.extend(info.websockets.clone());
            aggregated.graphql.extend(info.graphql.clone());
            aggregated.routes.extend(info.routes.clone());
            aggregated.cloud_storage.extend(info.cloud_storage.clone());
            aggregated.emails.extend(info.emails.clone());
            aggregated.comments.extend(info.comments.clone());
            aggregated.integrations.extend(info.integrations.clone());
            aggregated.source_maps.extend(info.source_maps.clone());
            
            for (k, v) in &info.versions {
                aggregated.versions.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }

        // Deduplicate
        aggregated.endpoints.sort_by(|a, b| a.url.cmp(&b.url));
        aggregated.endpoints.dedup_by(|a, b| a.url == b.url && a.method == b.method);

        aggregated.secrets.sort_by(|a, b| a.value.cmp(&b.value));
        aggregated.secrets.dedup_by(|a, b| a.value == b.value);

        aggregated.domains.sort();
        aggregated.domains.dedup();

        aggregated.parameters.sort_by(|a, b| a.name.cmp(&b.name));
        aggregated.parameters.dedup_by(|a, b| a.name == b.name);

        aggregated.websockets.sort();
        aggregated.websockets.dedup();

        aggregated.emails.sort();
        aggregated.emails.dedup();

        aggregated.routes.sort();
        aggregated.routes.dedup();

        aggregated
    }

    fn resolve_url(&self, base: &str, relative: &str) -> Result<String> {
        let base_url = Url::parse(base)?;
        let full_url = base_url.join(relative)?;
        Ok(full_url.to_string())
    }

    fn is_valid_endpoint(url: &str) -> bool {
        // Filter out obvious non-endpoints
        let invalid_patterns = vec![
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
            ".css", ".woff", ".woff2", ".ttf", ".eot",
            "data:", "blob:", "javascript:", "about:",
        ];

        let url_lower = url.to_lowercase();
        
        for pattern in invalid_patterns {
            if url_lower.contains(pattern) {
                return false;
            }
        }

        true
    }

    fn is_test_value(value: &str) -> bool {
        let test_patterns = vec![
            "test", "example", "demo", "sample", "fake", "mock",
            "your_api_key", "your-api-key", "xxx", "yyy", "zzz",
            "123456", "abcdef", "replace_me", "change_me",
        ];

        let value_lower = value.to_lowercase();
        
        for pattern in test_patterns {
            if value_lower.contains(pattern) {
                return true;
            }
        }

        false
    }
}

impl Default for JsCriticalInfo {
    fn default() -> Self {
        Self {
            endpoints: Vec::new(),
            secrets: Vec::new(),
            domains: Vec::new(),
            parameters: Vec::new(),
            websockets: Vec::new(),
            graphql: Vec::new(),
            routes: Vec::new(),
            cloud_storage: Vec::new(),
            emails: Vec::new(),
            comments: Vec::new(),
            integrations: Vec::new(),
            source_maps: Vec::new(),
            versions: HashMap::new(),
        }
    }
}
