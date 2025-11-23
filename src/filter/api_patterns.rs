use regex::Regex;

/// Basic heuristic: returns true if URL looks like an API endpoint.
pub fn is_api_candidate(u: &str) -> bool {
    // Exclude common static extensions
    let lower = u.to_lowercase();
    for ext in [
        ".css", ".woff", ".woff2", ".png", ".jpg", ".svg", ".ico", ".map",
    ] {
        if lower.ends_with(ext) {
            return false;
        }
    }

    // Quick tokens
    if lower.contains("/api/")
        || lower.contains("/graphql")
        || lower.contains("/rest/")
        || lower.contains("wp-json")
    {
        return true;
    }

    // ends with .json
    if lower.ends_with(".json") {
        return true;
    }

    // detect versioned api paths
    let re = Regex::new(r"/v\d+(/|$)").unwrap();
    if re.is_match(u) {
        return true;
    }

    // js-discovered endpoints often contain fetch/axios patterns; here just check presence of common verbs
    if lower.contains("/login") || lower.contains("/token") || lower.contains("/auth") {
        return true;
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
