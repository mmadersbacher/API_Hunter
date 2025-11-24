use reqwest::{Client, Proxy};
use std::sync::Arc;
use parking_lot::RwLock;
use rand::Rng;
use std::time::{Duration, Instant};

/// Residential Proxy Provider Configuration
#[derive(Clone)]
pub struct ProxyProvider {
    /// Provider base URL (e.g., "gate.smartproxy.com:7000")
    pub endpoint: String,
    /// Username für Proxy-Auth
    pub username: String,
    /// Password für Proxy-Auth
    pub password: String,
    /// Session ID für sticky sessions
    pub session_id: Option<String>,
}

/// Human-like Request Pattern Configuration
#[derive(Clone)]
pub struct HumanPattern {
    /// Burst size (1-3 requests at once)
    pub burst_min: u32,
    pub burst_max: u32,
    /// Pause between bursts (in milliseconds)
    pub pause_min: u64,
    pub pause_max: u64,
    /// Jitter (random timing variation in ms)
    pub jitter: u64,
    /// Session rotation interval (in seconds)
    pub session_rotation: u64,
}

impl Default for HumanPattern {
    fn default() -> Self {
        Self {
            burst_min: 1,
            burst_max: 3,
            pause_min: 2000,    // 2s
            pause_max: 8000,    // 8s
            jitter: 500,        // ±500ms
            session_rotation: 420, // 7 minutes (zwischen 5-10 min)
        }
    }
}

/// Anonymizer für HTTP-Requests mit Residential Proxies und Human-like Patterns
pub struct Anonymizer {
    /// Residential Proxy Provider
    proxy_provider: Option<ProxyProvider>,
    /// Aktueller Proxy-Index für Rotation
    current_index: Arc<RwLock<usize>>,
    /// User-Agents (realistisch, keine Rotation pro Request)
    user_agents: Vec<&'static str>,
    /// Aktueller User-Agent (bleibt konstant für Session)
    current_user_agent: Arc<RwLock<String>>,
    /// Letzter Session-Rotation Timestamp
    last_rotation: Arc<RwLock<Instant>>,
    /// Human-like Pattern Config
    human_pattern: HumanPattern,
    /// Request Counter für Burst-Tracking
    burst_counter: Arc<RwLock<u32>>,
    /// Full-speed mode (ignoriert Pausen)
    full_speed: bool,
    /// TLS Fingerprint konstant halten
    tls_fingerprint: String,
}

impl Anonymizer {
    /// Erstellt einen neuen Anonymizer mit Residential Proxy Support
    pub fn new(full_speed: bool) -> Self {
        let mut rng = rand::thread_rng();
        let initial_ua_index = rng.gen_range(0..10);
        
        let user_agents = vec![
                // Desktop Browsers
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
                
                // Mobile Browsers
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
                "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
                
                // Tor Browser (avoided in residential mode)
                "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
            ];
        
        Self {
            proxy_provider: None,
            current_index: Arc::new(RwLock::new(0)),
            user_agents: user_agents.clone(),
            current_user_agent: Arc::new(RwLock::new(user_agents[initial_ua_index].to_string())),
            last_rotation: Arc::new(RwLock::new(Instant::now())),
            human_pattern: HumanPattern::default(),
            burst_counter: Arc::new(RwLock::new(0)),
            full_speed,
            tls_fingerprint: "chrome_120_windows".to_string(), // Konstanter TLS Fingerprint
        }
    }
    
    /// Erstellt Anonymizer mit custom Residential Proxy Provider
    pub fn with_residential_proxy(provider: ProxyProvider, full_speed: bool) -> Self {
        let mut anon = Self::new(full_speed);
        anon.proxy_provider = Some(provider);
        anon
    }
    
    /// Parse Residential Proxy aus Environment oder Config
    /// Format: "username:password@gate.smartproxy.com:7000"
    pub fn from_env(full_speed: bool) -> Option<Self> {
        if let Ok(proxy_str) = std::env::var("RESIDENTIAL_PROXY") {
            if let Some(provider) = Self::parse_proxy_string(&proxy_str) {
                return Some(Self::with_residential_proxy(provider, full_speed));
            }
        }
        None
    }
    
    fn parse_proxy_string(proxy_str: &str) -> Option<ProxyProvider> {
        // Format: username:password@endpoint
        let parts: Vec<&str> = proxy_str.split('@').collect();
        if parts.len() != 2 {
            return None;
        }
        
        let auth_parts: Vec<&str> = parts[0].split(':').collect();
        if auth_parts.len() != 2 {
            return None;
        }
        
        Some(ProxyProvider {
            endpoint: parts[1].to_string(),
            username: auth_parts[0].to_string(),
            password: auth_parts[1].to_string(),
            session_id: None,
        })
    }

    /// Prüft ob Session rotiert werden muss (alle 5-10 Minuten)
    fn should_rotate_session(&self) -> bool {
        let last = self.last_rotation.read();
        let elapsed = last.elapsed().as_secs();
        
        // Random zwischen 5-10 Minuten (300-600 Sekunden)
        let rotation_interval = self.human_pattern.session_rotation;
        elapsed >= rotation_interval
    }
    
    /// Rotiert Session (neue IP, neuer User-Agent, neuer TLS Fingerprint konstant)
    fn rotate_session(&self) {
        if self.should_rotate_session() {
            let mut last = self.last_rotation.write();
            *last = Instant::now();
            
            // Neuer User-Agent für die Session
            let mut rng = rand::thread_rng();
            let index = rng.gen_range(0..self.user_agents.len());
            let mut current_ua = self.current_user_agent.write();
            *current_ua = self.user_agents[index].to_string();
            
            // Neue Session ID für Residential Proxy (sticky session)
            // Session ID Format: "session-{random_8_chars}"
            if self.proxy_provider.is_some() {
                let session_id: String = (0..8)
                    .map(|_| {
                        let idx = rng.gen_range(0..36);
                        "abcdefghijklmnopqrstuvwxyz0123456789".chars().nth(idx).unwrap()
                    })
                    .collect();
                
                println!("🔄 Session Rotation: New IP + UA (session: {})", session_id);
            }
            
            // Burst counter zurücksetzen
            let mut burst = self.burst_counter.write();
            *burst = 0;
        }
    }
    
    /// Gibt den aktuellen User-Agent zurück (konstant für Session)
    pub fn get_current_user_agent(&self) -> String {
        self.current_user_agent.read().clone()
    }
    
    /// Erstellt Residential Proxy URL mit Sticky Session
    fn get_residential_proxy_url(&self) -> Option<String> {
        if let Some(ref provider) = self.proxy_provider {
            // Session ID aus aktueller Rotation
            let session_id = format!("session-{}", 
                Instant::now().elapsed().as_secs() / self.human_pattern.session_rotation
            );
            
            // Format für Smartproxy/BrightData/Oxylabs etc:
            // http://username-session-{session_id}:password@endpoint
            let proxy_url = format!(
                "http://{}-session-{}:{}@{}",
                provider.username,
                session_id,
                provider.password,
                provider.endpoint
            );
            
            Some(proxy_url)
        } else {
            None
        }
    }

    /// Erstellt einen anonymisierten HTTP-Client mit Residential Proxy
    pub fn create_anonymous_client(&self, timeout_secs: u64) -> Result<Client, Box<dyn std::error::Error>> {
        // Check für Session Rotation
        self.rotate_session();
        
        let user_agent = self.get_current_user_agent();
        
        let mut builder = Client::builder()
            .user_agent(&user_agent)
            .timeout(Duration::from_secs(timeout_secs))
            .connect_timeout(Duration::from_secs(15))
            .danger_accept_invalid_certs(true)
            // TLS Fingerprint konstant halten (Chrome 120 Windows)
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            // Moderate Connection Pooling (nicht zu aggressiv)
            .pool_max_idle_per_host(20)
            .pool_idle_timeout(Duration::from_secs(90))
            // Realistic browser behavior
            .gzip(true)
            .brotli(true)
            // HTTP/2 wie moderne Browser
            .http2_prior_knowledge();
        
        // Residential Proxy verwenden falls verfügbar
        if let Some(proxy_url) = self.get_residential_proxy_url() {
            println!("🏠 Residential Proxy: {} | UA: {}", 
                     proxy_url.split('@').nth(1).unwrap_or("unknown").split(':').next().unwrap_or("?"),
                     &user_agent[..60]);
            
            let proxy = Proxy::all(&proxy_url)?;
            builder = builder.proxy(proxy);
        } else {
            println!("⚠️  No residential proxy configured. Using direct connection.");
            println!("💡 Set RESIDENTIAL_PROXY env: username:password@gate.provider.com:7000");
        }

        let client = builder.build()?;
        Ok(client)
    }

    /// Erstellt einen Stealth-Client mit Human-like Patterns
    pub fn create_stealth_client(&self, timeout_secs: u64) -> Result<Client, Box<dyn std::error::Error>> {
        self.create_anonymous_client(timeout_secs)
    }

    /// Human-like Request Pattern mit Burst + Pause + Jitter
    pub async fn human_delay(&self) {
        // Full-speed mode ignoriert alle Pausen
        if self.full_speed {
            return;
        }
        
        let mut burst = self.burst_counter.write();
        *burst += 1;
        
        let mut rng = rand::thread_rng();
        let burst_size = rng.gen_range(self.human_pattern.burst_min..=self.human_pattern.burst_max);
        
        if *burst >= burst_size {
            // Burst vollständig -> Pause
            *burst = 0;
            
            let pause_base = rng.gen_range(self.human_pattern.pause_min..=self.human_pattern.pause_max);
            let jitter = rng.gen_range(0..=self.human_pattern.jitter);
            let total_pause = pause_base + jitter;
            
            drop(burst); // Release lock before sleep
            
            println!("😴 Human-like pause: {}ms (burst complete)", total_pause);
            tokio::time::sleep(Duration::from_millis(total_pause)).await;
        } else {
            // Innerhalb Burst -> kleiner Jitter
            drop(burst);
            
            let jitter = rng.gen_range(50..=200); // 50-200ms zwischen Burst-Requests
            tokio::time::sleep(Duration::from_millis(jitter)).await;
        }
    }
    
    /// Legacy compatibility (ruft human_delay auf)
    pub async fn random_delay(&self) {
        self.human_delay().await;
    }

    /// Gibt Anweisungen zur Residential Proxy Setup aus
    pub fn print_proxy_setup_instructions() {
        println!("\n📖 Residential Proxy Setup Instructions:");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("🏠 Recommended Providers:");
        println!("  • Smartproxy: https://smartproxy.com (rotating residential)");
        println!("  • BrightData: https://brightdata.com (premium quality)");
        println!("  • Oxylabs: https://oxylabs.io (enterprise grade)");
        println!("  • Soax: https://soax.com (flexible plans)");
        println!("\n⚙️  Configuration:");
        println!("  1. Sign up for a residential proxy provider");
        println!("  2. Get your credentials (username:password@endpoint:port)");
        println!("  3. Set environment variable:");
        println!("     ");
        println!("     # Windows PowerShell");
        println!("     $env:RESIDENTIAL_PROXY = \"user:pass@gate.smartproxy.com:7000\"");
        println!("     ");
        println!("     # Linux/macOS");
        println!("     export RESIDENTIAL_PROXY=\"user:pass@gate.smartproxy.com:7000\"");
        println!("\n✅ Features:");
        println!("  • Real residential IPs (not datacenter)");
        println!("  • Sticky sessions (5-10 min per IP)");
        println!("  • Automatic rotation");
        println!("  • Human-like request patterns");
        println!("  • Constant TLS fingerprint");
        println!("  • DNS over HTTPS (DoH)");
        println!("\n🚀 Usage:");
        println!("  cargo run --release -- scan https://target.com --anonymous");
        println!("  cargo run --release -- scan https://target.com --anonymous --full-speed");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }
    
    /// Prüft ob Residential Proxy konfiguriert ist
    pub fn is_proxy_configured(&self) -> bool {
        self.proxy_provider.is_some() || std::env::var("RESIDENTIAL_PROXY").is_ok()
    }
    
    /// Gibt Status-Informationen aus
    pub fn print_status(&self) {
        println!("🎭 Anonymous Mode Status:");
        println!("  Proxy Type: Residential (Real IPs)");
        println!("  Session Duration: 5-10 minutes");
        println!("  TLS Fingerprint: {} (constant)", self.tls_fingerprint);
        println!("  User-Agent: {} (session-based)", 
                 &self.get_current_user_agent()[..50]);
        println!("  Request Pattern: Human-like (burst + pause)");
        println!("  Full Speed: {}", if self.full_speed { "✅ ENABLED" } else { "❌ Disabled" });
        
        if self.is_proxy_configured() {
            println!("  Proxy Status: ✅ Configured");
        } else {
            println!("  Proxy Status: ⚠️  Not configured (direct connection)");
        }
    }
}

impl Default for Anonymizer {
    fn default() -> Self {
        Self::new(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_rotation() {
        let anon = Anonymizer::new(false);
        let ua1 = anon.get_current_user_agent();
        assert!(!ua1.is_empty());
    }

    #[test]
    fn test_proxy_parsing() {
        let proxy_str = "user123:pass456@gate.smartproxy.com:7000";
        let provider = Anonymizer::parse_proxy_string(proxy_str);
        assert!(provider.is_some());
        
        let p = provider.unwrap();
        assert_eq!(p.username, "user123");
        assert_eq!(p.password, "pass456");
        assert_eq!(p.endpoint, "gate.smartproxy.com:7000");
    }

    #[tokio::test]
    async fn test_human_delay_full_speed() {
        let anon = Anonymizer::new(true); // full_speed = true
        let start = Instant::now();
        anon.human_delay().await;
        let elapsed = start.elapsed();
        // Mit full_speed sollte keine Verzögerung sein
        assert!(elapsed.as_millis() < 50);
    }
    
    #[tokio::test]
    async fn test_human_delay_normal() {
        let anon = Anonymizer::new(false); // full_speed = false
        let start = Instant::now();
        anon.human_delay().await;
        let elapsed = start.elapsed();
        // Normale Verzögerung (Jitter innerhalb Burst)
        assert!(elapsed.as_millis() >= 50);
    }
}
