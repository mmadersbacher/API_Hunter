use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TechnologyFingerprint {
    pub server: Option<String>,
    pub framework: Vec<String>,
    pub cdn: Option<String>,
    pub language: Option<String>,
    pub database_hints: Vec<String>,
    pub technologies: Vec<String>,
}

impl TechnologyFingerprint {
    pub fn analyze(headers: &HashMap<String, String>, body: &str) -> Self {
        let mut framework = Vec::new();
        let mut technologies = Vec::new();
        let mut database_hints = Vec::new();

        // Server detection
        let server = headers.get("server").cloned();

        // CDN detection
        let cdn = detect_cdn(headers);

        // Framework detection from headers
        if headers.contains_key("x-powered-by") {
            if let Some(powered) = headers.get("x-powered-by") {
                technologies.push(format!("X-Powered-By: {}", powered));
                
                if powered.contains("Express") {
                    framework.push("Express.js".to_string());
                } else if powered.contains("ASP.NET") {
                    framework.push("ASP.NET".to_string());
                } else if powered.contains("PHP") {
                    framework.push("PHP".to_string());
                }
            }
        }

        // Next.js detection
        if headers.contains_key("x-nextjs-cache") || headers.contains_key("x-nextjs-page") {
            framework.push("Next.js".to_string());
        }

        // Vercel detection
        if headers.contains_key("x-vercel-id") || headers.contains_key("x-vercel-cache") {
            technologies.push("Vercel".to_string());
        }

        // Framework detection from body
        if body.contains("__NEXT_DATA__") {
            framework.push("Next.js".to_string());
        }
        if body.contains("wp-content") || body.contains("wp-includes") {
            framework.push("WordPress".to_string());
        }
        if body.contains("drupal") || body.contains("Drupal") {
            framework.push("Drupal".to_string());
        }
        if body.contains("_nuxt") {
            framework.push("Nuxt.js".to_string());
        }
        if body.contains("ng-version") {
            framework.push("Angular".to_string());
        }
        if body.contains("react") || body.contains("React") {
            framework.push("React".to_string());
        }
        if body.contains("Vue") || body.contains("vue") {
            framework.push("Vue.js".to_string());
        }

        // Language detection
        let language = detect_language(headers, body);

        // Database hints from error messages or patterns
        if body.contains("MySQL") || body.contains("mysql") {
            database_hints.push("MySQL".to_string());
        }
        if body.contains("PostgreSQL") || body.contains("postgres") {
            database_hints.push("PostgreSQL".to_string());
        }
        if body.contains("MongoDB") || body.contains("mongodb") {
            database_hints.push("MongoDB".to_string());
        }
        if body.contains("Redis") || body.contains("redis") {
            database_hints.push("Redis".to_string());
        }
        if body.contains("Oracle") {
            database_hints.push("Oracle".to_string());
        }

        // Additional technologies
        if body.contains("graphql") || body.contains("GraphQL") {
            technologies.push("GraphQL".to_string());
        }
        if body.contains("swagger") || body.contains("openapi") {
            technologies.push("OpenAPI/Swagger".to_string());
        }

        TechnologyFingerprint {
            server,
            framework,
            cdn,
            language,
            database_hints,
            technologies,
        }
    }
}

fn detect_cdn(headers: &HashMap<String, String>) -> Option<String> {
    // Cloudflare
    if headers.contains_key("cf-ray") || headers.contains_key("cf-cache-status") {
        return Some("Cloudflare".to_string());
    }
    
    // Fastly
    if headers.contains_key("fastly-debug-digest") || headers.contains_key("x-fastly-request-id") {
        return Some("Fastly".to_string());
    }
    
    // Akamai
    if headers.contains_key("x-akamai-transformed") || headers.contains_key("x-cache-key") {
        return Some("Akamai".to_string());
    }
    
    // Amazon CloudFront
    if headers.contains_key("x-amz-cf-id") || headers.contains_key("x-amz-cf-pop") {
        return Some("Amazon CloudFront".to_string());
    }
    
    // Azure CDN
    if headers.contains_key("x-azure-ref") {
        return Some("Azure CDN".to_string());
    }
    
    None
}

fn detect_language(headers: &HashMap<String, String>, body: &str) -> Option<String> {
    // From headers
    if let Some(powered) = headers.get("x-powered-by") {
        if powered.contains("PHP") {
            return Some("PHP".to_string());
        }
        if powered.contains("ASP.NET") {
            return Some("C#/.NET".to_string());
        }
    }
    
    // From content-type
    if let Some(ct) = headers.get("content-type") {
        if ct.contains("application/json") && body.contains("\"") {
            // Could be many languages, check body for hints
            if body.contains("__class__") || body.contains("'str'") {
                return Some("Python".to_string());
            }
        }
    }
    
    // From patterns
    if body.contains("<?php") {
        return Some("PHP".to_string());
    }
    if body.contains("<%@") {
        return Some("JSP/Java".to_string());
    }
    
    None
}
