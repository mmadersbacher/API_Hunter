use api_hunter::enrich::json_shape::detect_keys;
use serde_json::json;

#[test]
fn detect_keys_simple() {
    let v = json!({"id":1, "email":"a@b.com", "user":{"token":"xxx"}});
    let keys = detect_keys(&v);
    assert!(keys.iter().any(|k| k.contains("email")));
    assert!(keys.iter().any(|k| k.contains("token")));
}
