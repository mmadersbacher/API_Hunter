use reqwest::{Client, ClientBuilder};
use std::time::Duration;
use once_cell::sync::Lazy;

/// High-performance HTTP client with all optimizations enabled
pub static OPTIMIZED_CLIENT: Lazy<Client> = Lazy::new(|| {
    create_optimized_client(10, 300)
});

/// Create optimized HTTP client with connection pooling and HTTP/2
pub fn create_optimized_client(timeout_secs: u64, max_idle_connections: usize) -> Client {
    ClientBuilder::new()
        // Connection pooling - reuse connections aggressively
        .pool_max_idle_per_host(max_idle_connections)
        .pool_idle_timeout(Some(Duration::from_secs(90)))
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .tcp_nodelay(true) // Disable Nagle's algorithm for lower latency
        
        // Timeouts
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(5))
        
        // Compression
        .gzip(true)
        .brotli(true)
        
        // TLS optimizations
        .use_rustls_tls()
        .tls_sni(true)
        .https_only(false) // Allow both HTTP and HTTPS
        
        // Redirects
        .redirect(reqwest::redirect::Policy::limited(5))
        
        // User agent
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        
        // Disable certificate validation for pentesting (ONLY for security research!)
        .danger_accept_invalid_certs(true)
        
        .build()
        .expect("Failed to build HTTP client")
}

/// Create client for aggressive scanning
pub fn create_aggressive_client() -> Client {
    create_optimized_client(5, 500) // Short timeout, many connections
}

/// Create client for stealth/lite mode
pub fn create_stealth_client() -> Client {
    ClientBuilder::new()
        .http1_only() // Some targets don't like HTTP/2
        .pool_max_idle_per_host(10)
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0")
        .use_rustls_tls()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("Failed to build stealth client")
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_client_creation() {
        let client = create_optimized_client(10, 100);
        assert!(client.timeout().is_some());
    }
}
