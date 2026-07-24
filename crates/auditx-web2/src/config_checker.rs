use std::path::Path;
use walkdir::WalkDir;
use auditx_core::{Web2Finding, Severity};

pub fn check_configs(dir: &Path) -> anyhow::Result<Vec<Web2Finding>> {
    let mut findings = Vec::new();

    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let path_str = path.to_string_lossy().to_string();

        // Skip build/dependency paths
        if path_str.contains("node_modules") || path_str.contains(".git") || path_str.contains("target") || path_str.contains("dist") {
            continue;
        }

        // 1. Check Express / Next.js / server config files
        if name == "server.js" || name == "app.js" || name == "index.js" || name == "next.config.js" || name == "next.config.mjs" {
            if let Ok(content) = std::fs::read_to_string(path) {
                // CORS wildcard *
                if content.contains("Access-Control-Allow-Origin") && (content.contains("*") || content.contains("'*'") || content.contains("\"*\"")) {
                    let line = find_line_containing(&content, "Access-Control-Allow-Origin");
                    let id = format!("web2-config-cors-wildcard-{}", line.unwrap_or(0));
                    findings.push(Web2Finding {
                        id,
                        tool: "config".to_string(),
                        owasp_id: Some("A01".to_string()),
                        severity: Severity::Medium,
                        cvss: 6.5,
                        title: "CORS Wildcard Allowed in Production".to_string(),
                        description: "The API configures Access-Control-Allow-Origin with an unrestricted wildcard (*), exposing endpoints to cross-origin requests from arbitrary sites.".to_string(),
                        file: path_str.clone(),
                        line,
                        remediation: "Restrict Access-Control-Allow-Origin headers to verified, white-listed source domains in production.".to_string(),
                    });
                }

                // Missing helmet or Rate Limiting on server files
                if (name == "server.js" || name == "app.js") && !content.contains("rateLimit") && !content.contains("express-rate-limit") {
                    let line = find_line_containing(&content, "listen");
                    let id = format!("web2-config-rate-limiting-{}", line.unwrap_or(0));
                    findings.push(Web2Finding {
                        id,
                        tool: "config".to_string(),
                        owasp_id: Some("A05".to_string()),
                        severity: Severity::Medium,
                        cvss: 5.3,
                        title: "Missing Rate Limiter on API Entrypoint".to_string(),
                        description: "The backend server starts a listener but does not set up a rate-limiter middleware. This exposes the API to Denial of Service (DoS) and brute-force resource exhausting.".to_string(),
                        file: path_str.clone(),
                        line,
                        remediation: "Configure express-rate-limit or similar rate-limiting middleware globally on API routes.".to_string(),
                    });
                }
            }
        }

        // 2. Check environment config files (.env)
        if name.starts_with(".env") {
            if let Ok(content) = std::fs::read_to_string(path) {
                if content.contains("DEBUG=true") || content.contains("NODE_ENV=development") {
                    let line = find_line_containing(&content, "DEBUG");
                    let id = format!("web2-config-debug-mode-{}", line.unwrap_or(0));
                    findings.push(Web2Finding {
                        id,
                        tool: "config".to_string(),
                        owasp_id: Some("A05".to_string()),
                        severity: Severity::Medium,
                        cvss: 5.0,
                        title: "Debug / Development Mode Active".to_string(),
                        description: "Configuration file specifies debug mode or development environment. Running in debug mode in production prints detailed stack traces which aids reverse engineering.".to_string(),
                        file: path_str.clone(),
                        line,
                        remediation: "Disable debug flags and enforce NODE_ENV=production in staging and production deployments.".to_string(),
                    });
                }
            }
        }
    }

    Ok(findings)
}

fn find_line_containing(content: &str, term: &str) -> Option<u32> {
    for (idx, line) in content.lines().enumerate() {
        if line.contains(term) {
            return Some((idx + 1) as u32);
        }
    }
    None
}
