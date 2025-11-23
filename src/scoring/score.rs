use crate::output::writer_jsonl::RawEvent;

/// Return an integer score (1 highest interest) based on event heuristics.
pub fn score_event(e: &RawEvent) -> i32 {
    // Default low interest
    let mut score = 5;

    // High interest: 2xx + JSON
    if e.status >= 200 && e.status < 300 {
        if let Some(ct) = &e.content_type {
            if ct.contains("application/json") || ct.contains("application/graphql") {
                score = 1;
            } else if e.final_url.contains("/api/") || e.final_url.contains("/v") {
                score = std::cmp::min(score, 2);
            }
        } else {
            // If body sample contains json_sample, prefer 2
            if e.json_sample.is_some() {
                score = 1;
            }
        }
    }

    // Auth gated
    if e.status == 401 || e.status == 403 {
        score = std::cmp::min(score, 3);
    }

    // Redirects
    if e.status >= 300 && e.status < 400 {
        score = std::cmp::min(score, 4);
    }

    // 5xx
    if e.status >= 500 {
        score = std::cmp::max(6, score);
    }

    // Boosts for path keywords
    let path = e.final_url.to_lowercase();
    if path.contains("token") || path.contains("auth") || path.contains("login") || path.contains("admin") {
        score = std::cmp::max(1, score - 1);
    }

    // Penalize static assets
    if path.ends_with(".css") || path.ends_with(".woff") || path.ends_with(".png") || path.ends_with(".jpg") {
        score = 99;
    }

    score
}
