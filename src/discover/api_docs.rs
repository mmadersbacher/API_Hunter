use reqwest::Client;
use anyhow::Result;
use serde_json::Value;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ApiDocumentation {
    pub doc_type: String,
    pub url: String,
    pub endpoints_count: usize,
    pub version: Option<String>,
    pub title: Option<String>,
}

pub struct ApiDocsDiscovery {
    client: Client,
}

impl ApiDocsDiscovery {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
        }
    }

    /// Discover API documentation endpoints
    pub async fn discover(&self, base_url: &str) -> Vec<ApiDocumentation> {
        let mut docs = Vec::new();

        // Common documentation paths
        let paths = vec![
            // Swagger/OpenAPI
            ("/swagger.json", "Swagger/OpenAPI"),
            ("/swagger.yaml", "Swagger/OpenAPI"),
            ("/swagger.yml", "Swagger/OpenAPI"),
            ("/openapi.json", "Swagger/OpenAPI"),
            ("/openapi.yaml", "Swagger/OpenAPI"),
            ("/api-docs", "Swagger/OpenAPI"),
            ("/api/swagger.json", "Swagger/OpenAPI"),
            ("/api/v1/swagger.json", "Swagger/OpenAPI"),
            ("/api/v2/swagger.json", "Swagger/OpenAPI"),
            ("/v1/api-docs", "Swagger/OpenAPI"),
            ("/v2/api-docs", "Swagger/OpenAPI"),
            ("/swagger/v1/swagger.json", "Swagger/OpenAPI"),
            ("/docs/swagger.json", "Swagger/OpenAPI"),
            ("/api/docs", "Swagger UI"),
            ("/swagger-ui.html", "Swagger UI"),
            ("/swagger-ui/", "Swagger UI"),
            
            // GraphQL
            ("/graphql", "GraphQL"),
            ("/api/graphql", "GraphQL"),
            ("/graphql/schema", "GraphQL Schema"),
            ("/api/graphql/schema", "GraphQL Schema"),
            
            // WADL
            ("/application.wadl", "WADL"),
            ("/api/application.wadl", "WADL"),
            
            // Postman
            ("/postman.json", "Postman Collection"),
            ("/api/postman.json", "Postman Collection"),
            ("/postman_collection.json", "Postman Collection"),
            
            // API Blueprint
            ("/api.md", "API Blueprint"),
            ("/api.apib", "API Blueprint"),
            ("/apiary.apib", "API Blueprint"),
            
            // RAML
            ("/api.raml", "RAML"),
            
            // Other
            ("/api.json", "Generic API Spec"),
            ("/api/spec", "API Specification"),
            ("/api-specification", "API Specification"),
            ("/.well-known/api", "Well-Known API"),
        ];

        for (path, doc_type) in paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status().is_success() {
                    let content_type = response
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");

                    if content_type.contains("json") || content_type.contains("yaml") 
                        || content_type.contains("text") || content_type.is_empty() {
                        
                        if let Ok(body) = response.text().await {
                            if self.is_valid_api_doc(&body, doc_type) {
                                println!("[+] API Documentation found: {} ({})", url, doc_type);
                                
                                let (endpoints_count, version, title) = self.parse_doc_info(&body, doc_type);
                                
                                docs.push(ApiDocumentation {
                                    doc_type: doc_type.to_string(),
                                    url,
                                    endpoints_count,
                                    version,
                                    title,
                                });
                            }
                        }
                    }
                }
            }
        }

        docs
    }

    fn is_valid_api_doc(&self, content: &str, doc_type: &str) -> bool {
        match doc_type {
            "Swagger/OpenAPI" => {
                content.contains("\"swagger\"") || content.contains("\"openapi\"")
                    || content.contains("swagger:") || content.contains("openapi:")
            }
            "GraphQL" | "GraphQL Schema" => {
                content.contains("query") || content.contains("mutation") 
                    || content.contains("__schema")
            }
            "WADL" => content.contains("<application") && content.contains("wadl"),
            "Postman Collection" => content.contains("\"schema\"") && content.contains("postman"),
            "API Blueprint" => content.contains("# ") && content.contains("## "),
            "RAML" => content.contains("#%RAML"),
            _ => content.len() > 100 && (content.contains("api") || content.contains("endpoint")),
        }
    }

    fn parse_doc_info(&self, content: &str, doc_type: &str) -> (usize, Option<String>, Option<String>) {
        let mut endpoints_count = 0;
        let mut version = None;
        let mut title = None;

        match doc_type {
            "Swagger/OpenAPI" => {
                if let Ok(json) = serde_json::from_str::<Value>(content) {
                    // Count paths
                    if let Some(paths) = json.get("paths").and_then(|p| p.as_object()) {
                        endpoints_count = paths.len();
                    }
                    
                    // Get version
                    version = json.get("info")
                        .and_then(|i| i.get("version"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    
                    // Get title
                    title = json.get("info")
                        .and_then(|i| i.get("title"))
                        .and_then(|t| t.as_str())
                        .map(|s| s.to_string());
                }
            }
            "GraphQL" => {
                endpoints_count = content.matches("query").count() + content.matches("mutation").count();
            }
            _ => {
                // Generic counting
                endpoints_count = content.matches("/api").count();
            }
        }

        (endpoints_count, version, title)
    }

    /// Extract endpoints from Swagger/OpenAPI spec
    pub async fn extract_swagger_endpoints(&self, url: &str) -> Result<Vec<String>> {
        let response = self.client.get(url).send().await?;
        let json: Value = response.json().await?;
        
        let mut endpoints = Vec::new();
        
        if let Some(paths) = json.get("paths").and_then(|p| p.as_object()) {
            for (path, _) in paths {
                endpoints.push(path.clone());
            }
        }
        
        Ok(endpoints)
    }
}

pub fn print_api_docs_results(docs: &[ApiDocumentation]) {
    if docs.is_empty() {
        return;
    }

    println!("\n[*] API Documentation Discovery Results");
    println!("================================================================================");
    println!("[+] Found {} API documentation(s)", docs.len());
    
    for (i, doc) in docs.iter().enumerate() {
        println!("\n  {}. {}", i + 1, doc.doc_type);
        println!("     URL: {}", doc.url);
        if let Some(title) = &doc.title {
            println!("     Title: {}", title);
        }
        if let Some(version) = &doc.version {
            println!("     Version: {}", version);
        }
        if doc.endpoints_count > 0 {
            println!("     Endpoints: {}", doc.endpoints_count);
        }
    }

    println!("================================================================================\n");
}
