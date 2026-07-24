use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tokio::io::AsyncReadExt;
use anyhow::{Result, Context};
use tracing::warn;
use auditx_core::{Web3Finding, Severity};

pub struct MythrilEngine {
    pub timeout_secs: u64,
    pub enabled: bool,
}

impl MythrilEngine {
    pub fn new(timeout_secs: u64, enabled: bool) -> Self {
        Self { timeout_secs, enabled }
    }

    pub async fn run(&self, contract_path: &Path) -> Result<Vec<Web3Finding>> {
        if !self.enabled {
            return Ok(vec![]);
        }

        let path_str = contract_path.to_string_lossy().to_string();

        let mut child = Command::new("myth")
            .arg("analyze")
            .arg(&path_str)
            .arg("-o")
            .arg("json")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn Mythril")?;

        let mut stdout = child.stdout.take().ok_or_else(|| anyhow::anyhow!("Failed to open Mythril stdout"))?;
        let mut stdout_data = Vec::new();

        // Read stdout asynchronously to capture partial results on timeout
        let run_res = timeout(Duration::from_secs(self.timeout_secs), async {
            let mut buf = [0; 1024];
            while let Ok(n) = stdout.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                stdout_data.extend_from_slice(&buf[..n]);
            }
            child.wait().await
        }).await;

        if run_res.is_err() {
            warn!("Mythril execution timed out after {} seconds. Collecting partial results.", self.timeout_secs);
            let _ = child.kill().await;
        }

        let stdout_str = String::from_utf8_lossy(&stdout_data);
        if stdout_str.trim().is_empty() {
            return Ok(vec![]);
        }

        let parsed_json: serde_json::Value = match serde_json::from_str(&stdout_str) {
            Ok(json) => json,
            Err(_) => {
                // Try to find a JSON array in whatever was printed so far
                if let Some(start) = stdout_str.find('[') {
                    if let Some(end) = stdout_str.rfind(']') {
                        if let Ok(json) = serde_json::from_str(&stdout_str[start..=end]) {
                            json
                        } else {
                            warn!("Mythril output was not valid JSON.");
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
        let issues = if parsed_json.is_array() {
            parsed_json.as_array()
        } else {
            parsed_json.get("issues").and_then(|i| i.as_array())
        };

        if let Some(issues_arr) = issues {
            for issue in issues_arr {
                let tool = "mythril".to_string();
                let swc_id = issue.get("swc-id").and_then(|s| s.as_str()).map(|s| s.to_string());
                let title = issue.get("title").and_then(|t| t.as_str()).unwrap_or("unknown").to_string();
                let description = issue.get("description").and_then(|d| d.as_str()).unwrap_or("").to_string();
                let severity_str = issue.get("severity").and_then(|s| s.as_str()).unwrap_or("Informational");
                let file = issue.get("filename").and_then(|f| f.as_str()).unwrap_or(&path_str).to_string();
                let line = issue.get("lineno").and_then(|l| l.as_u64()).map(|l| l as u32);

                let severity = match severity_str {
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

                let id = format!("web3-{}-{}-{}", tool, title.replace(" ", "-").to_lowercase(), line.unwrap_or(0));

                findings.push(Web3Finding {
                    id,
                    tool,
                    swc_id,
                    severity,
                    cvss,
                    title,
                    description,
                    file,
                    line,
                    remediation: "See SWC registry recommendations for this issue ID.".to_string(),
                });
            }
        }

        Ok(findings)
    }
}
