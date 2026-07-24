use std::path::Path;
use anyhow::Result;
use auditx_core::Web3Finding;

pub mod slither;
pub mod mythril;
pub mod surya;
pub mod detectors;

use slither::SlitherEngine;
use mythril::MythrilEngine;
use surya::SuryaEngine;

pub struct Web3Options {
    pub timeout_secs: u64,
    pub mythril_enabled: bool,
}

impl Default for Web3Options {
    fn default() -> Self {
        Self {
            timeout_secs: 120,
            mythril_enabled: false,
        }
    }
}

pub async fn run_web3_engine(
    path: &Path,
    opts: &Web3Options,
) -> Result<Vec<Web3Finding>> {
    let slither_engine = SlitherEngine::new(opts.timeout_secs);
    let mythril_engine = MythrilEngine::new(opts.timeout_secs, opts.mythril_enabled);
    let surya_engine = SuryaEngine::new();

    // Run subprocess tools in parallel
    let (slither_res, mythril_res, surya_res) = tokio::join!(
        slither_engine.run(path),
        mythril_engine.run(path),
        surya_engine.run(path),
    );

    // Surya callgraph result can be logged/handled, but doesn't produce findings
    if let Err(e) = surya_res {
        tracing::debug!("Surya callgraph generation failed: {}", e);
    }

    let mut all_findings = Vec::new();

    if let Ok(findings) = slither_res {
        all_findings.extend(findings);
    }
    if let Ok(findings) = mythril_res {
        all_findings.extend(findings);
    }

    // Run pure-Rust detectors (no subprocess, instant)
    let filename = path.to_string_lossy().to_string();
    if let Ok(source) = tokio::fs::read_to_string(path).await {
        all_findings.extend(detectors::flash_loan::detect(&source, &filename));
        all_findings.extend(detectors::signature_replay::detect(&source, &filename));
        all_findings.extend(detectors::mev::detect(&source, &filename));
        all_findings.extend(detectors::governance::detect(&source, &filename));
        all_findings.extend(detectors::reentrancy::detect(&source, &filename));
        all_findings.extend(detectors::surya_graph::analyze_graph(&source, &filename));
    }

    // Deduplicate findings by (file, line, title)
    // Keep the one with the highest CVSS score
    let mut unique_findings: Vec<Web3Finding> = Vec::new();
    for f in all_findings {
        let existing_idx = unique_findings.iter().position(|uf| {
            uf.file == f.file && uf.line == f.line && uf.title == f.title
        });

        if let Some(idx) = existing_idx {
            if f.cvss > unique_findings[idx].cvss {
                // Merge tool name and update score
                let mut merged_f = f.clone();
                merged_f.tool = format!("{}, {}", unique_findings[idx].tool, f.tool);
                unique_findings[idx] = merged_f;
            }
        } else {
            unique_findings.push(f);
        }
    }

    // Sort by severity (Critical first)
    unique_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    Ok(unique_findings)
}
