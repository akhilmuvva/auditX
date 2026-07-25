use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use anyhow::{Result, Context};
use tracing::warn;
use auditx_core::{Web3Finding, Severity};

pub struct SlitherEngine {
    pub timeout_secs: u64,
}

impl SlitherEngine {
    pub fn new(timeout_secs: u64) -> Self {
        Self { timeout_secs }
    }

    pub async fn run(&self, contract_path: &Path) -> Result<Vec<Web3Finding>> {
        let path_str = contract_path.to_string_lossy().to_string();

        let child = Command::new("slither")
            .arg(&path_str)
            .arg("--json")
            .arg("-")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                warn!("Slither binary not found or failed to spawn: {}. Degrading gracefully.", e);
                return Ok(vec![]);
            }
        };

        let run_res = timeout(Duration::from_secs(self.timeout_secs), child.wait_with_output()).await;

        let output = match run_res {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                warn!("Slither execution failed: {}", e);
                return Ok(vec![]);
            }
            Err(_) => {
                warn!("Slither execution timed out after {} seconds.", self.timeout_secs);
                return Ok(vec![]);
            }
        };

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let parsed_json: serde_json::Value = match serde_json::from_str(&stdout_str) {
            Ok(json) => json,
            Err(_) => {
                if let Some(json_start) = stdout_str.find('{') {
                    if let Some(json_end) = stdout_str.rfind('}') {
                        if let Ok(json) = serde_json::from_str(&stdout_str[json_start..=json_end]) {
                            json
                        } else {
                            warn!("Slither output was not valid JSON.");
                            return Ok(vec![]);
                        }
                    } else {
                        return Ok(vec![]);
                    }
                } else {
                    return Ok(vec![]);
                }
            }
        };

        let mut findings = Vec::new();

        if let Some(results) = parsed_json.get("results") {
            if let Some(detectors) = results.get("detectors") {
                if let Some(detectors_arr) = detectors.as_array() {
                    for det in detectors_arr {
                        let tool = "slither".to_string();
                        let check = det.get("check").and_then(|c| c.as_str()).unwrap_or("unknown");
                        let description = det.get("description").and_then(|d| d.as_str()).unwrap_or("");
                        let impact = det.get("impact").and_then(|i| i.as_str()).unwrap_or("Informational");

                        let severity = match impact {
                            "High" => Severity::High,
                            "Medium" => Severity::Medium,
                            "Low" => Severity::Low,
                            _ => Severity::Informational,
                        };

                        let cvss = match severity {
                            Severity::Critical => 9.0,
                            Severity::High => 7.5,
                            Severity::Medium => 5.0,
                            Severity::Low => 2.5,
                            Severity::Informational => 0.0,
                        };

                        let mut file = path_str.clone();
                        let mut line = None;

                        if let Some(first_element) = det.get("elements").and_then(|e| e.as_array()).and_then(|a| a.first()) {
                            if let Some(source_mapping) = first_element.get("source_mapping") {
                                if let Some(filename) = source_mapping.get("filename_relative").and_then(|f| f.as_str()) {
                                    file = filename.to_string();
                                }
                                if let Some(lines) = source_mapping.get("lines").and_then(|l| l.as_array()) {
                                    if let Some(first_line) = lines.first().and_then(|val| val.as_u64()) {
                                        line = Some(first_line as u32);
                                    }
                                }
                            }
                        }

                        let title = check.to_string();
                        let id = format!("web3-{}-{}-{}", tool, title.replace(" ", "-").to_lowercase(), line.unwrap_or(0));

                        findings.push(Web3Finding {
                            id,
                            tool,
                            swc_id: None,
                            severity,
                            cvss,
                            title,
                            description: description.to_string(),
                            file,
                            line,
                            remediation: "See slither recommendations for this check type.".to_string(),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }
}
