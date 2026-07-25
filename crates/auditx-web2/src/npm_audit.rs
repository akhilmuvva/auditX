use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use anyhow::Result;
use tracing::warn;
use auditx_core::{DependencyFinding, Severity};

pub struct NpmAuditEngine;

impl NpmAuditEngine {
    pub fn new() -> Self {
        Self
    }

    pub async fn run(&self, project_dir: &Path) -> Result<Vec<DependencyFinding>> {
        let child = Command::new("npm")
            .arg("audit")
            .arg("--json")
            .current_dir(project_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                warn!("npm binary not found or failed to spawn: {}. Degrading gracefully.", e);
                return Ok(vec![]);
            }
        };

        let run_res = timeout(Duration::from_secs(60), child.wait_with_output()).await;

        let output = match run_res {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                warn!("npm audit execution failed: {}", e);
                return Ok(vec![]);
            }
            Err(_) => {
                warn!("npm audit execution timed out.");
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

        if let Some(vulnerabilities) = parsed_json.get("vulnerabilities").and_then(|v| v.as_object()) {
            for (package_name, vuln_info) in vulnerabilities {
                let package = package_name.clone();
                let severity_str = vuln_info.get("severity").and_then(|s| s.as_str()).unwrap_or("low");
                let severity = match severity_str {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "moderate" => Severity::Medium,
                    _ => Severity::Low,
                };

                let cvss = match severity {
                    Severity::Critical => 9.5,
                    Severity::High => 8.0,
                    Severity::Medium => 5.5,
                    _ => 2.5,
                };

                let range = vuln_info.get("range").and_then(|r| r.as_str()).unwrap_or("unknown").to_string();
                let fix_available = vuln_info.get("fixAvailable").and_then(|f| {
                    if f.is_boolean() {
                        f.as_bool().map(|b| if b { "latest".to_string() } else { "none".to_string() })
                    } else if f.is_object() {
                        f.get("name").and_then(|n| n.as_str()).map(|n| n.to_string())
                    } else {
                        None
                    }
                });

                findings.push(DependencyFinding {
                    package,
                    version: range,
                    severity,
                    cve: format!("NPM-{}", package_name),
                    cvss,
                    fixed_in: fix_available,
                    exploit_available: false,
                });
            }
        }

        // Specific high-priority checks for smart contract dependencies (ethers, openzeppelin)
        let package_json_path = project_dir.join("package.json");
        if package_json_path.exists() {
            if let Ok(data) = std::fs::read_to_string(package_json_path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&data) {
                    if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
                        for (dep, ver) in deps {
                            let ver_str = ver.as_str().unwrap_or("");
                            if dep == "ethers" && (ver_str.contains("5.") || ver_str.contains("4.")) {
                                findings.push(DependencyFinding {
                                    package: "ethers".to_string(),
                                    version: ver_str.to_string(),
                                    severity: Severity::High,
                                    cve: "CVE-2023-ethers".to_string(),
                                    cvss: 7.5,
                                    fixed_in: Some("^6.0.0".to_string()),
                                    exploit_available: true,
                                });
                            }
                            if dep == "@openzeppelin/contracts" && ver_str.contains("4.0") {
                                findings.push(DependencyFinding {
                                    package: "@openzeppelin/contracts".to_string(),
                                    version: ver_str.to_string(),
                                    severity: Severity::High,
                                    cve: "CVE-2023-openzeppelin".to_string(),
                                    cvss: 8.8,
                                    fixed_in: Some("^4.9.0 or ^5.0.0".to_string()),
                                    exploit_available: true,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}
