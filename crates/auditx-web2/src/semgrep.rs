use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use anyhow::Result;
use tracing::warn;
use auditx_core::{Web2Finding, Severity};

pub struct SemgrepEngine {
    pub configs: Vec<String>,
    pub timeout_secs: u64,
}

impl SemgrepEngine {
    pub fn new(configs: Vec<String>, timeout_secs: u64) -> Self {
        Self { configs, timeout_secs }
    }

    pub async fn run(&self, dir: &Path) -> Result<Vec<Web2Finding>> {
        let path_str = dir.to_string_lossy().to_string();
        let mut all_findings = Vec::new();

        for config in &self.configs {
            let child = Command::new("semgrep")
                .arg(format!("--config={}", config))
                .arg("--json")
                .arg(&path_str)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();

            let mut child = match child {
                Ok(c) => c,
                Err(e) => {
                    warn!("Semgrep binary not found or failed to spawn: {}. Degrading gracefully.", e);
                    return Ok(vec![]);
                }
            };

            let run_res = timeout(Duration::from_secs(self.timeout_secs), child.wait_with_output()).await;

            let output = match run_res {
                Ok(Ok(out)) => out,
                Ok(Err(e)) => {
                    warn!("Semgrep execution failed for config {}: {}", config, e);
                    continue;
                }
                Err(_) => {
                    warn!("Semgrep execution timed out for config {} after {} seconds.", config, self.timeout_secs);
                    let _ = child.kill().await;
                    continue;
                }
            };

            let stdout_str = String::from_utf8_lossy(&output.stdout);
            let parsed_json: serde_json::Value = match serde_json::from_str(&stdout_str) {
                Ok(json) => json,
                Err(_) => {
                    warn!("Semgrep output was not valid JSON for config {}.", config);
                    continue;
                }
            };

            if let Some(results) = parsed_json.get("results").and_then(|r| r.as_array()) {
                for res in results {
                    let tool = "semgrep".to_string();
                    let rule_id = res.get("extra").and_then(|e| e.get("metadata")).and_then(|m| m.get("semgrep.rule_id")).and_then(|id| id.as_str()).unwrap_or("");
                    let rule_id_str = if rule_id.is_empty() {
                        res.get("check_id").and_then(|id| id.as_str()).unwrap_or("")
                    } else {
                        rule_id
                    };

                    let message = res.get("extra").and_then(|e| e.get("message")).and_then(|m| m.as_str()).unwrap_or("").to_string();
                    let file = res.get("path").and_then(|p| p.as_str()).unwrap_or(&path_str).to_string();
                    let line = res.get("start").and_then(|s| s.get("line")).and_then(|l| l.as_u64()).map(|l| l as u32);
                    
                    let semgrep_severity = res.get("extra").and_then(|e| e.get("severity")).and_then(|s| s.as_str()).unwrap_or("INFO");

                    let (severity, cvss) = match semgrep_severity {
                        "ERROR" => (Severity::High, 8.0),
                        "WARNING" => (Severity::Medium, 5.5),
                        _ => (Severity::Low, 2.0),
                    };

                    let owasp_id = extract_owasp_category(rule_id_str);
                    
                    let id = format!("web2-{}-{}-{}", tool, rule_id_str.replace(".", "-").to_lowercase(), line.unwrap_or(0));

                    all_findings.push(Web2Finding {
                        id,
                        tool,
                        owasp_id,
                        severity,
                        cvss,
                        title: rule_id_str.to_string(),
                        description: message,
                        file,
                        line,
                        remediation: "Apply standard security fixes recommended by Semgrep for this rule.".to_string(),
                    });
                }
            }
        }

        Ok(all_findings)
    }
}

fn extract_owasp_category(rule_id: &str) -> Option<String> {
    if rule_id.contains("sqli") {
        Some("A03".to_string())
    } else if rule_id.contains("xss") {
        Some("A03".to_string())
    } else if rule_id.contains("jwt") || rule_id.contains("auth") {
        Some("A07".to_string())
    } else if rule_id.contains("secrets") || rule_id.contains("crypto") {
        Some("A02".to_string())
    } else {
        None
    }
}
