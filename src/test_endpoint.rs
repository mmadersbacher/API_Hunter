use crate::probe::advanced_tests::{AdvancedTester, print_results};
use crate::probe::graphql::{GraphQLTester, print_graphql_results};
use crate::probe::websocket::{WebSocketTester, print_websocket_results};
use crate::discover::api_docs::{ApiDocsDiscovery, print_api_docs_results};
use anyhow::Result;

pub async fn run_endpoint_tests(url: &str, include_fuzzing: bool, num_rate_limit_requests: u32) -> Result<()> {
    println!("\n[*] Starting Ultra-Deep API Endpoint Analysis");
    println!("[*] Target: {}", url);
    println!("================================================================================\n");

    let tester = AdvancedTester::new(url)?;

    // Phase 0: API Documentation Discovery
    println!("[*] Phase 0: API Documentation Discovery");
    let base_url = extract_base_url(url);
    let docs_discovery = ApiDocsDiscovery::new();
    let api_docs = docs_discovery.discover(&base_url).await;
    print_api_docs_results(&api_docs);

    // Phase 0.5: GraphQL Detection & Testing
    println!("[*] Phase 0.5: GraphQL Detection & Testing");
    let graphql_tester = GraphQLTester::new();
    let graphql_endpoints = graphql_tester.discover_graphql(&base_url).await;
    
    for endpoint in &graphql_endpoints {
        if let Ok(gql_endpoint) = graphql_tester.test_graphql(endpoint).await {
            let gql_vulns = graphql_tester.test_graphql_vulnerabilities(endpoint).await;
            print_graphql_results(&gql_endpoint, &gql_vulns);
        }
    }

    // Phase 0.6: WebSocket Detection
    println!("[*] Phase 0.6: WebSocket Detection");
    let ws_tester = WebSocketTester::new();
    let ws_endpoints = ws_tester.discover_websocket(&base_url).await;
    
    let mut ws_vulns = Vec::new();
    for endpoint in &ws_endpoints {
        let vulns = ws_tester.test_websocket_vulnerabilities(endpoint).await;
        ws_vulns.extend(vulns);
    }
    print_websocket_results(&ws_endpoints, &ws_vulns);

    // Phase 1: HTTP Methods
    println!("[*] Phase 1: HTTP Method Testing");
    let method_results = tester.test_http_methods().await;
    print_results(&method_results);

    // Phase 2: CORS Testing
    println!("[*] Phase 2: CORS Configuration Testing");
    let cors_results = tester.test_cors().await;
    print_results(&cors_results);

    // Phase 3: Rate Limiting
    println!("[*] Phase 3: Rate Limiting Testing");
    let rate_results = tester.test_rate_limiting(num_rate_limit_requests).await;
    print_results(&rate_results);

    // Phase 4: Deep Response Analysis
    println!("[*] Phase 4: Deep Response Analysis");
    match tester.analyze_response_deep().await {
        Ok(analysis) => {
            println!("{}", serde_json::to_string_pretty(&analysis)?);
        }
        Err(e) => {
            println!("[!] Error analyzing response: {}", e);
        }
    }

    // Phase 5: Security Fuzzing (optional)
    if include_fuzzing {
        println!("\n[*] Phase 5: Security Fuzzing Tests");
        println!("[!] Warning: Aggressive testing - may trigger WAF/IDS");
        
        println!("\n[*] Testing SQL Injection...");
        let sql_results = tester.test_sql_injection("id").await;
        print_results(&sql_results);

        println!("[*] Testing NoSQL Injection...");
        let nosql_results = tester.test_nosql_injection("id").await;
        print_results(&nosql_results);

        println!("[*] Testing XSS...");
        let xss_results = tester.test_xss("query").await;
        print_results(&xss_results);

        println!("[*] Testing SSRF...");
        let ssrf_results = tester.test_ssrf("url").await;
        print_results(&ssrf_results);

        println!("[*] Testing Path Traversal...");
        let path_results = tester.test_path_traversal("file").await;
        print_results(&path_results);
    }

    println!("\n[+] Ultra-Deep Analysis Complete");
    println!("================================================================================\n");

    Ok(())
}

fn extract_base_url(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""))
    } else {
        url.to_string()
    }
}
