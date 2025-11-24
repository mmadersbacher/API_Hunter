use regex::Regex;
use std::collections::HashSet;

/// Comprehensive list of common parameter names found in APIs
pub fn common_params() -> Vec<&'static str> {
    vec![
        // IDs and identifiers
        "id", "ID", "_id", "user", "user_id", "userid", "uid", "userId",
        "account", "account_id", "accountId", "customer_id", "customerId",
        "client_id", "clientId", "session_id", "sessionId",
        "transaction_id", "transactionId", "order_id", "orderId",
        "product_id", "productId", "item_id", "itemId",
        "post_id", "postId", "message_id", "messageId",
        "request_id", "requestId", "correlation_id", "correlationId",
        
        // Authentication & Authorization
        "token", "access_token", "accessToken", "refresh_token", "refreshToken",
        "api_key", "apikey", "apiKey", "key", "secret",
        "auth", "authorization", "bearer", "jwt",
        "password", "pwd", "pass", "code", "otp",
        "signature", "sig", "hash", "checksum",
        
        // Pagination & Filtering
        "page", "per_page", "perPage", "page_size", "pageSize",
        "limit", "offset", "size", "count", "max", "min",
        "skip", "take", "top", "first", "last",
        
        // Search & Query
        "q", "query", "search", "s", "term", "keyword", "keywords",
        "filter", "filters", "where", "find",
        
        // Sorting & Ordering
        "sort", "sortBy", "sort_by", "order", "orderBy", "order_by",
        "direction", "dir", "asc", "desc",
        
        // Categories & Types
        "category", "cat", "categories", "type", "kind",
        "group", "groupId", "group_id", "tag", "tags",
        "status", "state", "stage", "phase",
        
        // Files & Resources
        "file", "filename", "fileName", "path", "filepath", "filePath",
        "url", "uri", "link", "href", "src", "source",
        "resource", "asset", "media", "image", "document",
        
        // User data
        "email", "mail", "username", "user_name", "userName",
        "name", "first_name", "firstName", "last_name", "lastName",
        "phone", "mobile", "address", "zip", "country",
        
        // Dates & Times
        "date", "datetime", "time", "timestamp",
        "from", "to", "start", "end", "begin",
        "created", "created_at", "createdAt",
        "updated", "updated_at", "updatedAt",
        "modified", "modified_at", "modifiedAt",
        "expires", "expires_at", "expiresAt", "ttl",
        
        // Localization
        "lang", "language", "locale", "region", "country", "timezone",
        "currency", "unit",
        
        // Callbacks & Redirects
        "callback", "redirect", "redirect_uri", "redirectUri",
        "return", "return_url", "returnUrl", "next",
        "success_url", "successUrl", "error_url", "errorUrl",
        
        // Output formatting
        "format", "output", "response", "contentType", "content_type",
        "accept", "encoding", "charset",
        
        // Flags & Options
        "include", "exclude", "expand", "fields", "select",
        "embed", "populate", "join", "relations",
        "debug", "verbose", "trace", "pretty",
        "force", "override", "validate",
        
        // Versioning
        "version", "v", "api_version", "apiVersion",
        
        // Business logic
        "action", "method", "operation", "command",
        "mode", "context", "scope", "namespace",
        "role", "permission", "access", "level",
        "priority", "weight", "score",
        "value", "data", "payload", "body",
        "meta", "metadata", "info", "details",
        "options", "config", "settings", "params",
        "ref", "reference", "relation", "parent",
        "batch", "bulk", "multiple",
    ]
}

/// Extract parameters from URL query strings
pub fn extract_params_from_url(url: &str) -> HashSet<String> {
    let mut params = HashSet::new();
    
    if let Some(query_start) = url.find('?') {
        let query = &url[query_start + 1..];
        for pair in query.split('&') {
            if let Some(eq_pos) = pair.find('=') {
                let param_name = &pair[..eq_pos];
                if !param_name.is_empty() {
                    params.insert(param_name.to_string());
                }
            } else if !pair.is_empty() {
                params.insert(pair.to_string());
            }
        }
    }
    
    params
}

/// Extract parameter patterns from JavaScript code
pub fn extract_params_from_js(js_content: &str) -> HashSet<String> {
    let mut params = HashSet::new();
    
    // Match patterns like: ?id=, &user=, params.set('key', ...), url += 'name='
    let patterns = vec![
        Regex::new(r#"[?&]([a-zA-Z_][a-zA-Z0-9_]*)\s*="#).unwrap(),
        Regex::new(r#"params\.(?:set|append)\s*\(\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]"#).unwrap(),
        Regex::new(r#"\.searchParams\.set\s*\(\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]"#).unwrap(),
        Regex::new(r#"\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*"#).unwrap(), // Object keys in query builders
    ];
    
    for pattern in patterns {
        for cap in pattern.captures_iter(js_content) {
            if let Some(m) = cap.get(1) {
                let param = m.as_str().to_string();
                // Filter out common false positives
                if param.len() > 1 && param.len() < 30 {
                    params.insert(param);
                }
            }
        }
    }
    
    params
}

/// Extract parameters from API response bodies (JSON)
pub fn extract_params_from_json(json_str: &str) -> HashSet<String> {
    let mut params = HashSet::new();
    
    // Simple key extraction - look for "key": pattern
    let key_pattern = Regex::new(r#""([a-zA-Z_][a-zA-Z0-9_]*)"\s*:"#).unwrap();
    
    for cap in key_pattern.captures_iter(json_str) {
        if let Some(m) = cap.get(1) {
            let key = m.as_str().to_string();
            if key.len() > 1 && key.len() < 30 {
                params.insert(key);
            }
        }
    }
    
    params
}

/// Detect if a URL path contains potential ID-like segments
pub fn detect_path_ids(url: &str) -> Vec<(usize, String)> {
    let mut ids = Vec::new();
    
    // Parse URL to extract path
    if let Ok(parsed) = url::Url::parse(url) {
        let path = parsed.path();
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        
        for (idx, segment) in segments.iter().enumerate() {
            // Check if segment looks like an ID (numeric, UUID, alphanumeric hash)
            if is_id_like(segment) {
                ids.push((idx, segment.to_string()));
            }
        }
    }
    
    ids
}

/// Check if a string looks like an ID value
fn is_id_like(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    
    // Pure numeric (common ID pattern)
    if s.chars().all(|c| c.is_ascii_digit()) && s.len() >= 1 {
        return true;
    }
    
    // UUID pattern
    if s.len() == 36 && s.chars().filter(|&c| c == '-').count() == 4 {
        return true;
    }
    
    // Alphanumeric hash-like (e.g., MongoDB ObjectId)
    if s.len() >= 8 && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric()) {
        // Check if it's not a common word (has mixed case or numbers)
        let has_digit = s.chars().any(|c| c.is_ascii_digit());
        let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
        
        if has_digit || (has_upper && has_lower) {
            return true;
        }
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_params_from_url() {
        let url = "https://api.example.com/users?id=123&name=test&page=1";
        let params = extract_params_from_url(url);
        assert!(params.contains("id"));
        assert!(params.contains("name"));
        assert!(params.contains("page"));
    }

    #[test]
    fn test_is_id_like() {
        assert!(is_id_like("123"));
        assert!(is_id_like("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_id_like("507f1f77bcf86cd799439011"));
        assert!(!is_id_like("users"));
        assert!(!is_id_like("api"));
    }
}
