use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use anyhow::Result;
use tracing::warn;
use auditx_core::{DependencyFinding, Severity};

pub struct CargoAuditEngine;

impl CargoAuditEngine {
    pub fn new() -> Self {
        Self
    }

    pub async fn run(&self, project_dir: &Path) -> Result<Vec<DependencyFinding>> {
        let child = Command::new("cargo")
            .arg("audit")
            .arg("--json")
            .current_dir(project_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                warn!("cargo-audit binary not found or failed to spawn: {}. Degrading gracefully.", e);
                return Ok(vec![]);
            }
        };

        let run_res = timeout(Duration::from_secs(60), child.wait_with_output()).await;

        let output = match run_res {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                warn!("cargo-audit execution failed: {}", e);
                return Ok(vec![]);
            }
            Err(_) => {
                warn!("cargo-audit execution timed out.");
                let _ = child.kill().await;
                return Ok(vec![]);
            }
        };

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let parsed_json: serde_json::Value = match serde_json::from_str(&stdout_str) {
            Ok(json) => json,
            Err(_) => {
                return Ok(vec![]);
            }
        };

        let mut findings = Vec::new();

        if let Some(vulnerabilities) = parsed_json.get("vulnerabilities").and_then(|v| v.get("list")).and_then(|l| l.as_array()) {
            for vuln in vulnerabilities {
                let package = vuln.get("package").and_then(|p| p.get("name")).and_then(|n| n.as_str()).unwrap_or("unknown").to_string();
                let version = vuln.get("package").and_then(|p| p.get("version")).and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                let cve = vuln.get("advisory").and_then(|a| a.get("id")).and_then(|i| i.as_str()).unwrap_or("unknown").to_string();

                let cvss = vuln.get("advisory")
                    .and_then(|a| a.get("cvss"))
                    .and_then(|c| c.as_str())
                    .and_then(|s| s.parse::<f32>().ok())
                    .unwrap_or(5.0);

                let fixed_in = vuln.get("versions")
                    .and_then(|v| v.get("patched"))
                    .and_then(|p| p.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|first| first.as_str())
                    .map(|s| s.to_string());

                let severity = match cvss {
                    score if score >= 9.0 => Severity::Critical,
                    score if score >= 7.0 => Severity::High,
                    score if score >= 4.0 => Severity::Medium,
                    _ => Severity::Low,
                };

                findings.push(DependencyFinding {
                    package,
                    version,
                    severity,
                    cve,
                    cvss,
                    fixed_in,
                    exploit_available: false, // Default fallback
                });
            }
        }

        Ok(findings)
    }
}
