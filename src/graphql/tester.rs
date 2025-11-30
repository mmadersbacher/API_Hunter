use crate::http_client::HttpClient;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashSet;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
pub struct GraphQLEndpoint {
    pub url: String,
    pub has_introspection: bool,
    pub schema: Option<GraphQLSchema>,
    pub vulnerabilities: Vec<GraphQLVulnerability>,
}

#[derive(Debug, Clone)]
pub struct GraphQLSchema {
    pub types: Vec<String>,
    pub queries: Vec<String>,
    pub mutations: Vec<String>,
    pub has_sensitive_fields: bool,
}

#[derive(Debug, Clone)]
pub struct GraphQLVulnerability {
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
    pub payload: Option<String>,
}

pub struct GraphQLTester {
    client: HttpClient,
}

impl GraphQLTester {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Test if URL is a GraphQL endpoint
    pub async fn is_graphql_endpoint(&self, url: &str) -> bool {
        // Try common GraphQL endpoints
        let graphql_paths = vec![
            url.to_string(),
            format!("{}/graphql", url.trim_end_matches('/')),
            format!("{}/graphiql", url.trim_end_matches('/')),
            format!("{}/api/graphql", url.trim_end_matches('/')),
            format!("{}/v1/graphql", url.trim_end_matches('/')),
        ];

        for test_url in graphql_paths {
            if let Ok(result) = timeout(Duration::from_secs(3), self.test_graphql_query(&test_url)).await {
                if result.unwrap_or(false) {
                    return true;
                }
            }
        }
        false
    }

    async fn test_graphql_query(&self, url: &str) -> Result<bool> {
        let query = json!({
            "query": "{ __typename }"
        });

        match self.client.post_json(url, &query).await {
            Ok(response) => {
                if let Ok(body) = response.text().await {
                    return Ok(body.contains("__typename") || body.contains("data"));
                }
                Ok(false)
            }
            Err(_) => Ok(false),
        }
    }

    /// Deep test GraphQL endpoint
    pub async fn test_endpoint(&self, url: &str) -> Result<GraphQLEndpoint> {
        let mut endpoint = GraphQLEndpoint {
            url: url.to_string(),
            has_introspection: false,
            schema: None,
            vulnerabilities: Vec::new(),
        };

        // Test introspection
        if let Ok(schema) = self.test_introspection(url).await {
            endpoint.has_introspection = true;
            endpoint.schema = Some(schema);
        }

        // Test for vulnerabilities sequentially
        if let Ok(vulns) = self.test_batch_query_attack(url).await {
            endpoint.vulnerabilities.extend(vulns);
        }
        
        if let Ok(vulns) = self.test_circular_query(url).await {
            endpoint.vulnerabilities.extend(vulns);
        }
        
        if let Ok(vulns) = self.test_field_duplication(url).await {
            endpoint.vulnerabilities.extend(vulns);
        }
        
        if let Ok(vulns) = self.test_directive_overload(url).await {
            endpoint.vulnerabilities.extend(vulns);
        }
        
        if let Ok(vulns) = self.test_alias_overload(url).await {
            endpoint.vulnerabilities.extend(vulns);
        }

        // Test mutations if schema available
        if let Some(ref schema) = endpoint.schema {
            if !schema.mutations.is_empty() {
                if let Ok(mutation_vulns) = self.test_mutations(url, schema).await {
                    endpoint.vulnerabilities.extend(mutation_vulns);
                }
            }
        }

        Ok(endpoint)
    }

    /// Test GraphQL introspection
    async fn test_introspection(&self, url: &str) -> Result<GraphQLSchema> {
        let introspection_query = json!({
            "query": r#"
                query IntrospectionQuery {
                    __schema {
                        queryType { name }
                        mutationType { name }
                        types {
                            name
                            kind
                            fields {
                                name
                                type { name }
                            }
                        }
                    }
                }
            "#
        });

        let response = timeout(
            Duration::from_secs(5),
            self.client.post_json(url, &introspection_query)
        ).await.context("Introspection timeout")??;

        let body = response.text().await?;
        let data: Value = serde_json::from_str(&body)?;

        let mut schema = GraphQLSchema {
            types: Vec::new(),
            queries: Vec::new(),
            mutations: Vec::new(),
            has_sensitive_fields: false,
        };

        if let Some(schema_data) = data.get("data").and_then(|d| d.get("__schema")) {
            // Extract types
            if let Some(types) = schema_data.get("types").and_then(|t| t.as_array()) {
                for type_obj in types {
                    if let Some(name) = type_obj.get("name").and_then(|n| n.as_str()) {
                        schema.types.push(name.to_string());

                        // Check for sensitive fields
                        if let Some(fields) = type_obj.get("fields").and_then(|f| f.as_array()) {
                            for field in fields {
                                if let Some(field_name) = field.get("name").and_then(|n| n.as_str()) {
                                    let lower = field_name.to_lowercase();
                                    if lower.contains("password") || lower.contains("token") 
                                        || lower.contains("secret") || lower.contains("key")
                                        || lower.contains("credit") || lower.contains("ssn") {
                                        schema.has_sensitive_fields = true;
                                    }

                                    if type_obj.get("name").and_then(|n| n.as_str()) == Some("Query") {
                                        schema.queries.push(field_name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Extract mutations
            if let Some(mutation_type) = schema_data.get("mutationType") {
                if let Some(mutation_name) = mutation_type.get("name").and_then(|n| n.as_str()) {
                    schema.mutations.push(mutation_name.to_string());
                }
            }
        }

        Ok(schema)
    }

    /// Test batch query attack (resource exhaustion)
    async fn test_batch_query_attack(&self, url: &str) -> Result<Vec<GraphQLVulnerability>> {
        let mut vulns = Vec::new();

        // Create batch of 50 identical queries
        let batch: Vec<Value> = (0..50)
            .map(|i| {
                json!({
                    "query": format!("query Q{} {{ __typename }}", i)
                })
            })
            .collect();

        match timeout(Duration::from_secs(3), self.client.post_json(url, &json!(batch))).await {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    vulns.push(GraphQLVulnerability {
                        vuln_type: "Batch Query Attack".to_string(),
                        severity: "HIGH".to_string(),
                        description: "GraphQL accepts batch queries without rate limiting - can cause resource exhaustion".to_string(),
                        payload: Some("50 batched queries accepted".to_string()),
                    });
                }
            }
            _ => {}
        }

        Ok(vulns)
    }

    /// Test circular query (depth attack)
    async fn test_circular_query(&self, url: &str) -> Result<Vec<GraphQLVulnerability>> {
        let mut vulns = Vec::new();

        let deep_query = json!({
            "query": r#"
                query {
                    a: __schema { types { name fields { name type { name fields { name type { name } } } } } }
                    b: __schema { types { name fields { name type { name fields { name type { name } } } } } }
                    c: __schema { types { name fields { name type { name fields { name type { name } } } } } }
                }
            "#
        });

        match timeout(Duration::from_secs(3), self.client.post_json(url, &deep_query)).await {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    vulns.push(GraphQLVulnerability {
                        vuln_type: "Deep Query Attack".to_string(),
                        severity: "MEDIUM".to_string(),
                        description: "GraphQL allows deeply nested queries without depth limiting".to_string(),
                        payload: Some("Deep nested query accepted".to_string()),
                    });
                }
            }
            _ => {}
        }

        Ok(vulns)
    }

    /// Test field duplication attack
    async fn test_field_duplication(&self, url: &str) -> Result<Vec<GraphQLVulnerability>> {
        let mut vulns = Vec::new();

        // Create query with many duplicate fields
        let duplicated_fields: String = (0..100)
            .map(|i| format!("field{}: __typename", i))
            .collect::<Vec<_>>()
            .join(" ");

        let query = json!({
            "query": format!("{{ {} }}", duplicated_fields)
        });

        match timeout(Duration::from_secs(3), self.client.post_json(url, &query)).await {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    vulns.push(GraphQLVulnerability {
                        vuln_type: "Field Duplication Attack".to_string(),
                        severity: "MEDIUM".to_string(),
                        description: "GraphQL accepts excessive field aliasing without complexity limits".to_string(),
                        payload: Some("100 aliased fields accepted".to_string()),
                    });
                }
            }
            _ => {}
        }

        Ok(vulns)
    }

    /// Test directive overload
    async fn test_directive_overload(&self, url: &str) -> Result<Vec<GraphQLVulnerability>> {
        let mut vulns = Vec::new();

        let directive_query = json!({
            "query": r#"
                query {
                    __typename @skip(if: true) @skip(if: true) @skip(if: true) @skip(if: true)
                }
            "#
        });

        match timeout(Duration::from_secs(3), self.client.post_json(url, &directive_query)).await {
            Ok(Ok(_)) => {
                vulns.push(GraphQLVulnerability {
                    vuln_type: "Directive Overload".to_string(),
                    severity: "LOW".to_string(),
                    description: "GraphQL accepts multiple duplicate directives".to_string(),
                    payload: Some("Multiple @skip directives accepted".to_string()),
                });
            }
            _ => {}
        }

        Ok(vulns)
    }

    /// Test alias overload
    async fn test_alias_overload(&self, url: &str) -> Result<Vec<GraphQLVulnerability>> {
        let mut vulns = Vec::new();

        let aliases: String = (0..200)
            .map(|i| format!("alias{}: __typename", i))
            .collect::<Vec<_>>()
            .join(" ");

        let query = json!({
            "query": format!("{{ {} }}", aliases)
        });

        match timeout(Duration::from_secs(3), self.client.post_json(url, &query)).await {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    vulns.push(GraphQLVulnerability {
                        vuln_type: "Alias Overload".to_string(),
                        severity: "HIGH".to_string(),
                        description: "GraphQL accepts excessive aliases - can cause severe resource exhaustion".to_string(),
                        payload: Some("200 aliases accepted".to_string()),
                    });
                }
            }
            _ => {}
        }

        Ok(vulns)
    }

    /// Test mutations for vulnerabilities
    async fn test_mutations(&self, url: &str, schema: &GraphQLSchema) -> Result<Vec<GraphQLVulnerability>> {
        let mut vulns = Vec::new();

        // Test if mutations are accessible without authentication
        for mutation in &schema.mutations {
            let query = json!({
                "query": format!("mutation {{ {} }}", mutation)
            });

            match timeout(Duration::from_secs(3), self.client.post_json(url, &query)).await {
                Ok(Ok(response)) => {
                    let body = response.text().await?;
                    
                    // Check if mutation executed without auth
                    if !body.contains("Unauthorized") && !body.contains("forbidden") 
                        && !body.contains("authentication") && !body.contains("permission") {
                        vulns.push(GraphQLVulnerability {
                            vuln_type: "Unauthenticated Mutation".to_string(),
                            severity: "CRITICAL".to_string(),
                            description: format!("Mutation '{}' may be accessible without authentication", mutation),
                            payload: Some(mutation.clone()),
                        });
                    }
                }
                _ => {}
            }
        }

        Ok(vulns)
    }

    /// Discover GraphQL endpoints from base URL
    pub async fn discover_endpoints(&self, base_url: &str) -> Vec<String> {
        let mut endpoints = HashSet::new();
        let base = base_url.trim_end_matches('/');

        let common_paths = vec![
            "/graphql",
            "/graphiql",
            "/api/graphql",
            "/v1/graphql",
            "/v2/graphql",
            "/v3/graphql",
            "/query",
            "/api/query",
            "/gql",
            "/api/gql",
        ];

        let urls: Vec<String> = common_paths.iter()
            .map(|path| format!("{}{}", base, path))
            .collect();

        let mut tasks = Vec::new();
        for url in &urls {
            tasks.push(self.is_graphql_endpoint(url));
        }

        let results = futures::future::join_all(tasks).await;
        for (i, is_graphql) in results.into_iter().enumerate() {
            if is_graphql {
                endpoints.insert(urls[i].clone());
            }
        }

        endpoints.into_iter().collect()
    }
}
