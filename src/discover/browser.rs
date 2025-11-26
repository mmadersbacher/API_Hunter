//! Browser-based API Discovery using Chrome DevTools Protocol

use anyhow::{Result, Context};
use chromiumoxide::browser::{Browser, BrowserConfig};
use futures::StreamExt;
use std::collections::HashSet;
use std::sync::Arc;
use parking_lot::Mutex;
use url;

#[derive(Debug, Clone)]
pub struct ApiEndpoint {
    pub url: String,
    pub method: String,
}

pub struct BrowserDiscovery {
    browser: Arc<Browser>,
    discovered_apis: Arc<Mutex<HashSet<String>>>,
    wait_time_ms: u64,
}

impl BrowserDiscovery {
    pub async fn new(headless: bool, _max_depth: usize, wait_time_ms: u64) -> Result<Self> {
        tracing::info!("Initializing headless Chrome for API discovery");
        
        let mut config = BrowserConfig::builder();
        
        if headless {
            config = config.no_sandbox()
                .args(vec![
                    "--headless",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                    "--disable-gpu",
                    "--window-size=1920,1080",
                ]);
        }

        let (browser, mut handler) = Browser::launch(config.build().map_err(|e| anyhow::anyhow!("Browser config error: {}", e))?)
            .await
            .context("Failed to launch browser")?;

        tokio::spawn(async move {
            while handler.next().await.is_some() {}
        });

        Ok(Self {
            browser: Arc::new(browser),
            discovered_apis: Arc::new(Mutex::new(HashSet::new())),
            wait_time_ms,
        })
    }

    pub async fn discover(&self, target_url: &str) -> Result<Vec<ApiEndpoint>> {
        tracing::info!("Starting browser API discovery: {}", target_url);
        
        // Parse base URL for relative path resolution
        let base_url = if let Ok(url) = url::Url::parse(target_url) {
            format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""))
        } else {
            target_url.to_string()
        };
        
        let page = self.browser.new_page("about:blank").await?;
        let _ = page.goto(target_url).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(self.wait_time_ms)).await;

        let js_code = r#"
            (function() {
                const urls = new Set();
                const scripts = Array.from(document.scripts);
                scripts.forEach(script => {
                    try {
                        const content = script.textContent || '';
                        const matches = content.match(/["'`]((?:https?:)?\/\/[^"'`\s]+|\/[^"'`\s]+)["'`]/g);
                        if (matches) {
                            matches.forEach(m => {
                                const url = m.slice(1, -1);
                                if (url.includes('/api') || url.includes('.json') || url.match(/\/v\d/)) {
                                    urls.add(url);
                                }
                            });
                        }
                    } catch(e) {}
                });
                return Array.from(urls);
            })()
        "#;

        if let Ok(result) = page.evaluate(js_code).await {
            if let Ok(urls) = result.into_value::<Vec<String>>() {
                for url in urls {
                    // Convert relative URLs to absolute
                    let full_url = if url.starts_with("http") {
                        url
                    } else if url.starts_with("//") {
                        format!("https:{}", url)
                    } else if url.starts_with("/") {
                        format!("{}{}", base_url, url)
                    } else {
                        continue; // Skip invalid URLs
                    };
                    
                    if Self::is_api_request(&full_url) {
                        self.discovered_apis.lock().insert(full_url);
                    }
                }
            }
        }

        let _ = self.simulate_interactions(&page).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(self.wait_time_ms / 2)).await;

        let discovered_urls = self.discovered_apis.lock().clone();
        let api_endpoints: Vec<ApiEndpoint> = discovered_urls.into_iter()
            .map(|url| ApiEndpoint {
                url,
                method: "GET".to_string(),
            })
            .collect();

        tracing::info!("Browser discovered {} APIs", api_endpoints.len());
        Ok(api_endpoints)
    }

    async fn simulate_interactions(&self, page: &chromiumoxide::Page) -> Result<()> {
        let _ = page.evaluate("window.scrollTo(0, document.body.scrollHeight);").await;
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        let _ = page.evaluate("window.scrollTo(0, 0);").await;
        Ok(())
    }

    fn is_api_request(url: &str) -> bool {
        let url_lower = url.to_lowercase();
        
        if url_lower.starts_with("data:") || url_lower.starts_with("blob:") {
            return false;
        }

        let api_indicators = [
            "/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql",
            ".json", "/json/", "/ajax/", "/data/", "/endpoint/"
        ];

        api_indicators.iter().any(|pattern| url_lower.contains(pattern))
    }
}

pub async fn discover_apis_with_browser(
    target: &str,
    headless: bool,
    max_depth: usize,
    wait_time_ms: u64,
) -> Result<Vec<String>> {
    let discovery = BrowserDiscovery::new(headless, max_depth, wait_time_ms).await?;
    let endpoints = discovery.discover(target).await?;
    Ok(endpoints.into_iter().map(|ep| ep.url).collect())
}
