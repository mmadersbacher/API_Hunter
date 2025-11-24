use regex::Regex;

/// Enhanced heuristic: returns true if URL looks like an API endpoint.
/// More aggressive detection to find all possible APIs.
pub fn is_api_candidate(u: &str) -> bool {
    // Exclude common static extensions ONLY
    let lower = u.to_lowercase();
    for ext in [
        ".css", ".woff", ".woff2", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".map",
        ".ttf", ".eot", ".otf", ".webp", ".bmp", ".tiff",
    ] {
        if lower.ends_with(ext) {
            return false;
        }
    }

    // Common API path patterns (highly confident)
    if lower.contains("/api/")
        || lower.contains("/graphql")
        || lower.contains("/rest/")
        || lower.contains("wp-json")
        || lower.contains("/service/")
        || lower.contains("/services/")
        || lower.contains("/endpoint/")
        || lower.contains("/endpoints/")
    {
        return true;
    }

    // Data format endpoints
    if lower.ends_with(".json")
        || lower.ends_with(".xml")
        || lower.ends_with(".jsonp")
        || lower.contains(".json?")
        || lower.contains(".xml?")
    {
        return true;
    }

    // Versioned API paths (v1, v2, v3, etc.)
    let re = Regex::new(r"/v\d+(/|$)").unwrap();
    if re.is_match(u) {
        return true;
    }

    // Authentication & authorization endpoints
    if lower.contains("/login") 
        || lower.contains("/signin")
        || lower.contains("/signup")
        || lower.contains("/register")
        || lower.contains("/token") 
        || lower.contains("/auth")
        || lower.contains("/oauth")
        || lower.contains("/sso")
        || lower.contains("/saml")
    {
        return true;
    }

    // Common API resource patterns
    if lower.contains("/user") 
        || lower.contains("/account")
        || lower.contains("/profile")
        || lower.contains("/data")
        || lower.contains("/config")
        || lower.contains("/settings")
        || lower.contains("/me")
        || lower.contains("/info")
        || lower.contains("/status")
        || lower.contains("/health")
        || lower.contains("/ping")
        || lower.contains("/version")
    {
        return true;
    }

    // CRUD-like paths
    if lower.contains("/create")
        || lower.contains("/read")
        || lower.contains("/update")
        || lower.contains("/delete")
        || lower.contains("/get")
        || lower.contains("/post")
        || lower.contains("/put")
        || lower.contains("/patch")
        || lower.contains("/list")
        || lower.contains("/search")
        || lower.contains("/query")
        || lower.contains("/fetch")
    {
        return true;
    }

    // Common business domain terms
    if lower.contains("/product")
        || lower.contains("/order")
        || lower.contains("/customer")
        || lower.contains("/payment")
        || lower.contains("/transaction")
        || lower.contains("/invoice")
        || lower.contains("/cart")
        || lower.contains("/checkout")
        || lower.contains("/item")
        || lower.contains("/category")
        || lower.contains("/content")
        || lower.contains("/blog")
        || lower.contains("/post")
        || lower.contains("/comment")
        || lower.contains("/message")
        || lower.contains("/notification")
        || lower.contains("/event")
        || lower.contains("/analytics")
        || lower.contains("/metric")
        || lower.contains("/report")
        || lower.contains("/export")
        || lower.contains("/import")
        || lower.contains("/upload")
        || lower.contains("/download")
        || lower.contains("/file")
        || lower.contains("/document")
        || lower.contains("/image")
        || lower.contains("/asset")
        || lower.contains("/media")
        || lower.contains("/resource")
    {
        return true;
    }

    // Database/Backend patterns
    if lower.contains("/db/")
        || lower.contains("/database/")
        || lower.contains("/admin/")
        || lower.contains("/manage/")
        || lower.contains("/dashboard/")
        || lower.contains("/backend/")
        || lower.contains("/internal/")
        || lower.contains("/private/")
        || lower.contains("/public/")
    {
        return true;
    }

    // Modern frameworks (Next.js, Nuxt, etc.)
    if lower.contains("/_next/")
        || lower.contains("/_nuxt/")
        || lower.contains("/api-")
        || lower.contains("/rpc/")
        || lower.contains("/trpc/")
        || lower.contains("/jsonrpc")
        || lower.contains("/xmlrpc")
    {
        return true;
    }

    // WebSocket & realtime APIs
    if lower.contains("/ws/")
        || lower.contains("/websocket")
        || lower.contains("/socket.io")
        || lower.contains("/realtime")
        || lower.contains("/stream")
        || lower.contains("/channel")
        || lower.contains("/pubsub")
        || lower.contains("/subscribe")
        || lower.contains("/publish")
    {
        return true;
    }

    // Third-party integrations
    if lower.contains("/stripe")
        || lower.contains("/paypal")
        || lower.contains("/firebase")
        || lower.contains("/aws")
        || lower.contains("/azure")
        || lower.contains("/gcp")
        || lower.contains("/google")
        || lower.contains("/facebook")
        || lower.contains("/twitter")
        || lower.contains("/github")
        || lower.contains("/slack")
        || lower.contains("/webhook")
        || lower.contains("/callback")
    {
        return true;
    }

    // Check if URL has query parameters (often indicates dynamic API)
    if u.contains('?') && (u.matches('=').count() > 0) {
        return true;
    }

    // Path has 3+ segments with numeric/alphanumeric IDs (REST pattern)
    if let Ok(parsed) = url::Url::parse(u) {
        let segments: Vec<&str> = parsed.path().split('/').filter(|s| !s.is_empty()).collect();
        if segments.len() >= 3 {
            // Check if any segment looks like an ID
            for seg in &segments {
                if seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') 
                    && seg.len() >= 8 
                    && seg.chars().any(|c| c.is_ascii_digit()) 
                {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_patterns() {
        assert!(is_api_candidate("https://example.com/api/v1/users"));
        assert!(is_api_candidate("https://example.com/v2/items"));
        assert!(is_api_candidate("https://example.com/graphql"));
        assert!(!is_api_candidate("https://example.com/style.css"));
    }
}
