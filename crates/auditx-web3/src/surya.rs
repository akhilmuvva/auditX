use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;
use anyhow::{Result, Context};
use tracing::warn;

pub struct SuryaEngine;

impl SuryaEngine {
    pub fn new() -> Self {
        Self
    }

    pub async fn run(&self, contract_path: &Path) -> Result<String> {
        let path_str = contract_path.to_string_lossy().to_string();

        let mut surya_child = Command::new("surya")
            .arg("graph")
            .arg(&path_str)
            .stdout(Stdio::piped())
            .spawn();

        let mut surya_child = match surya_child {
            Ok(c) => c,
            Err(e) => {
                warn!("Surya binary not found or failed to spawn: {}. Returning empty callgraph.", e);
                return Ok(String::from("<svg></svg>"));
            }
        };

        let surya_stdout = surya_child.stdout.take().ok_or_else(|| anyhow::anyhow!("Failed to open surya graph stdout"))?;

        let dot_child = Command::new("dot")
            .arg("-Tsvg")
            .stdin(Stdio::from(surya_stdout.into_owned_fd().unwrap()))
            .stdout(Stdio::piped())
            .spawn();

        let dot_child = match dot_child {
            Ok(c) => c,
            Err(e) => {
                warn!("Graphviz (dot) not found or failed to spawn: {}. Returning empty callgraph.", e);
                return Ok(String::from("<svg></svg>"));
            }
        };

        let output = dot_child.wait_with_output().await.context("Failed to run dot pipeline")?;
        let svg = String::from_utf8_lossy(&output.stdout).into_owned();

        Ok(svg)
    }
}
