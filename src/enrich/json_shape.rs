use serde_json::Value;

/// Detect common keys in a JSON value that indicate user/token/email fields.
pub fn detect_keys(v: &Value) -> Vec<String> {
    let mut found = Vec::new();
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                let lk = k.to_lowercase();
                if lk.contains("token") || lk.contains("auth") {
                    found.push(k.clone());
                }
                if lk.contains("email") || lk.contains("mail") {
                    found.push(k.clone());
                }
                if lk == "id" || lk.ends_with("_id") {
                    found.push(k.clone());
                }
                if lk.contains("user") || lk.contains("account") {
                    found.push(k.clone());
                }
                // Recurse
                let sub = detect_keys(val);
                for s in sub {
                    found.push(format!("{}.{}", k, s));
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter().take(3) {
                let sub = detect_keys(item);
                for s in sub {
                    found.push(s);
                }
            }
        }
        _ => {}
    }
    found.sort();
    found.dedup();
    found
}
