use api_hunter::filter::api_patterns;

#[test]
fn filter_detects_api() {
    assert!(api_patterns::is_api_candidate("https://example.com/api/v1/users"));
    assert!(api_patterns::is_api_candidate("https://example.com/v2/items"));
    assert!(!api_patterns::is_api_candidate("https://example.com/style.css"));
}
