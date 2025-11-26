use reqwest::Client;
use serde_json::{json, Value};
use anyhow::Result;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct GraphQLEndpoint {
    pub url: String,
    pub has_introspection: bool,
    pub schema: Option<Value>,
    pub queries: Vec<String>,
    pub mutations: Vec<String>,
    pub types: Vec<String>,
}

pub struct GraphQLTester {
    client: Client,
}

impl GraphQLTester {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
        }
    }

    /// Test if endpoint is GraphQL and supports introspection
    pub async fn test_graphql(&self, url: &str) -> Result<GraphQLEndpoint> {
        let introspection_query = json!({
            "query": r#"
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        types {
                            name
                            kind
                            description
                            fields {
                                name
                                description
                                type { name kind }
                            }
                        }
                    }
                }
            "#
        });

        let start = Instant::now();
        let response = self.client
            .post(url)
            .json(&introspection_query)
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let elapsed = start.elapsed().as_millis();
        let status = response.status();
        let body: Value = response.json().await?;

        let has_introspection = body.get("data")
            .and_then(|d| d.get("__schema"))
            .is_some();

        let mut queries = Vec::new();
        let mut mutations = Vec::new();
        let mut types = Vec::new();

        if has_introspection {
            if let Some(schema) = body.get("data").and_then(|d| d.get("__schema")) {
                // Extract types
                if let Some(type_array) = schema.get("types").and_then(|t| t.as_array()) {
                    for type_obj in type_array {
                        if let Some(name) = type_obj.get("name").and_then(|n| n.as_str()) {
                            types.push(name.to_string());

                            // Extract fields as potential queries
                            if let Some(fields) = type_obj.get("fields").and_then(|f| f.as_array()) {
                                for field in fields {
                                    if let Some(field_name) = field.get("name").and_then(|n| n.as_str()) {
                                        if name == "Query" {
                                            queries.push(field_name.to_string());
                                        } else if name == "Mutation" {
                                            mutations.push(field_name.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        println!("[*] GraphQL Test: {} - Status: {} - Time: {}ms", url, status, elapsed);
        if has_introspection {
            println!("[+] GraphQL introspection ENABLED");
            println!("    Queries: {}", queries.len());
            println!("    Mutations: {}", mutations.len());
            println!("    Types: {}", types.len());
        }

        Ok(GraphQLEndpoint {
            url: url.to_string(),
            has_introspection,
            schema: if has_introspection { Some(body) } else { None },
            queries,
            mutations,
            types,
        })
    }

    /// Test common GraphQL vulnerabilities
    pub async fn test_graphql_vulnerabilities(&self, url: &str) -> Vec<GraphQLVulnerability> {
        let mut vulns = Vec::new();

        // Test 1: Introspection enabled (info leak)
        if let Ok(endpoint) = self.test_graphql(url).await {
            if endpoint.has_introspection {
                vulns.push(GraphQLVulnerability {
                    name: "GraphQL Introspection Enabled".to_string(),
                    severity: "Medium".to_string(),
                    description: "Schema introspection is publicly accessible".to_string(),
                    details: format!("Exposed {} queries, {} mutations, {} types", 
                                    endpoint.queries.len(), 
                                    endpoint.mutations.len(), 
                                    endpoint.types.len()),
                });
            }
        }

        // Test 2: Query depth attack
        let deep_query = json!({
            "query": "{ a { b { c { d { e { f { g { h { i { j } } } } } } } } } }"
        });

        if let Ok(response) = self.client.post(url).json(&deep_query).send().await {
            if response.status().is_success() {
                vulns.push(GraphQLVulnerability {
                    name: "No Query Depth Limit".to_string(),
                    severity: "Medium".to_string(),
                    description: "Deep nested queries are not blocked".to_string(),
                    details: "DoS via deeply nested queries possible".to_string(),
                });
            }
        }

        // Test 3: Batch query attack
        let batch_query = json!([
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]);

        if let Ok(response) = self.client.post(url).json(&batch_query).send().await {
            if response.status().is_success() {
                vulns.push(GraphQLVulnerability {
                    name: "Batch Query DoS".to_string(),
                    severity: "High".to_string(),
                    description: "Batched queries are not rate-limited".to_string(),
                    details: "DoS via batch query amplification possible".to_string(),
                });
            }
        }

        // Test 4: Field duplication attack
        let dup_query = json!({
            "query": "{ __typename __typename __typename __typename __typename }"
        });

        if let Ok(response) = self.client.post(url).json(&dup_query).send().await {
            if response.status().is_success() {
                vulns.push(GraphQLVulnerability {
                    name: "Field Duplication Attack".to_string(),
                    severity: "Low".to_string(),
                    description: "Duplicate fields are processed".to_string(),
                    details: "Resource exhaustion via field duplication".to_string(),
                });
            }
        }

        vulns
    }

    /// Detect GraphQL endpoints from common paths
    pub async fn discover_graphql(&self, base_url: &str) -> Vec<String> {
        let common_paths = vec![
            "/graphql",
            "/api/graphql",
            "/v1/graphql",
            "/v2/graphql",
            "/graphql/v1",
            "/query",
            "/api/query",
            "/gql",
            "/api/gql",
        ];

        let mut found = Vec::new();

        for path in common_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            
            // Test with simple query
            let test_query = json!({"query": "{ __typename }"});
            
            if let Ok(response) = self.client
                .post(&url)
                .json(&test_query)
                .header("Content-Type", "application/json")
                .send()
                .await
            {
                if response.status().is_success() {
                    if let Ok(body) = response.text().await {
                        if body.contains("data") || body.contains("errors") {
                            println!("[+] GraphQL endpoint found: {}", url);
                            found.push(url);
                        }
                    }
                }
            }
        }

        found
    }
}

#[derive(Debug, Clone)]
pub struct GraphQLVulnerability {
    pub name: String,
    pub severity: String,
    pub description: String,
    pub details: String,
}

pub fn print_graphql_results(endpoint: &GraphQLEndpoint, vulns: &[GraphQLVulnerability]) {
    println!("\n[*] GraphQL Analysis Results");
    println!("================================================================================");
    println!("[*] Endpoint: {}", endpoint.url);
    println!("[*] Introspection: {}", if endpoint.has_introspection { "ENABLED" } else { "DISABLED" });
    
    if endpoint.has_introspection {
        println!("\n[*] Schema Information:");
        println!("    Queries: {}", endpoint.queries.len());
        if !endpoint.queries.is_empty() {
            for (i, q) in endpoint.queries.iter().take(10).enumerate() {
                println!("      {}. {}", i + 1, q);
            }
            if endpoint.queries.len() > 10 {
                println!("      ... and {} more", endpoint.queries.len() - 10);
            }
        }
        
        println!("    Mutations: {}", endpoint.mutations.len());
        if !endpoint.mutations.is_empty() {
            for (i, m) in endpoint.mutations.iter().take(10).enumerate() {
                println!("      {}. {}", i + 1, m);
            }
            if endpoint.mutations.len() > 10 {
                println!("      ... and {} more", endpoint.mutations.len() - 10);
            }
        }
        
        println!("    Types: {}", endpoint.types.len());
    }

    if !vulns.is_empty() {
        println!("\n[!] Vulnerabilities Found:");
        for vuln in vulns {
            let icon = match vuln.severity.as_str() {
                "Critical" => "[!] CRITICAL",
                "High" => "[!] HIGH",
                "Medium" => "[!] MEDIUM",
                "Low" => "[-] LOW",
                _ => "[*] INFO",
            };
            println!("\n{}: {}", icon, vuln.name);
            println!("    Description: {}", vuln.description);
            println!("    Details: {}", vuln.details);
        }
    }

    println!("================================================================================\n");
}
