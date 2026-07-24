use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use anyhow::{Result, Context};
use tracing::warn;
use auditx_core::SecretFinding;

pub struct GitleaksEngine;

impl GitleaksEngine {
    pub fn new() -> Self {
        Self
    }

    pub async fn run(&self, dir: &Path) -> Result<Vec<SecretFinding>> {
        let path_str = dir.to_string_lossy().to_string();
        let temp_report_path = dir.join("gitleaks-report.json");
        let temp_report_str = temp_report_path.to_string_lossy().to_string();

        let child = Command::new("gitleaks")
            .arg("detect")
            .arg("--source")
            .arg(&path_str)
            .arg("--no-git")
            .arg("--report-format")
            .arg("json")
            .arg("--report-path")
            .arg(&temp_report_str)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                warn!("Gitleaks binary not found or failed to spawn: {}. Degrading gracefully.", e);
                return Ok(vec![]);
            }
        };

        let run_res = timeout(Duration::from_secs(30), child.wait_with_output()).await;

        match run_res {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                warn!("Gitleaks execution failed: {}", e);
                let _ = tokio::fs::remove_file(&temp_report_path).await;
                return Ok(vec![]);
            }
            Err(_) => {
                warn!("Gitleaks execution timed out.");
                let _ = child.kill().await;
                let _ = tokio::fs::remove_file(&temp_report_path).await;
                return Ok(vec![]);
            }
        };

        if !temp_report_path.exists() {
            return Ok(vec![]);
        }

        let report_data = match tokio::fs::read_to_string(&temp_report_path).await {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to read Gitleaks report file: {}", e);
                return Ok(vec![]);
            }
        };

        let _ = tokio::fs::remove_file(&temp_report_path).await;

        let parsed_json: serde_json::Value = match serde_json::from_str(&report_data) {
            Ok(json) => json,
            Err(_) => {
                warn!("Gitleaks report was not valid JSON.");
                return Ok(vec![]);
            }
        };

        let mut findings = Vec::new();

        if let Some(leaks_arr) = parsed_json.as_array() {
            for leak in leaks_arr {
                let description = leak.get("Description").and_then(|d| d.as_str()).unwrap_or("Secret detected").to_string();
                let file = leak.get("File").and_then(|f| f.as_str()).unwrap_or("").to_string();
                let line = leak.get("StartLine").and_then(|l| l.as_u64()).map(|l| l as u32).unwrap_or(0);
                let commit = leak.get("Commit").and_then(|c| c.as_str()).map(|c| c.to_string());
                let entropy = leak.get("Entropy").and_then(|e| e.as_f64()).unwrap_or(0.0);

                // CRITICAL: NEVER store actual secret values in SecretFinding struct
                findings.push(SecretFinding {
                    description,
                    file,
                    line,
                    commit,
                    entropy,
                });
            }
        }

        Ok(findings)
    }
}
