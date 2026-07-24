use std::path::Path;
use anyhow::Result;
use serde::{Serialize, Deserialize};

pub mod semgrep;
pub mod gitleaks;
pub mod secrets;
pub mod cargo_audit;
pub mod npm_audit;
pub mod config_checker;

use semgrep::SemgrepEngine;
use gitleaks::GitleaksEngine;
use cargo_audit::CargoAuditEngine;
use npm_audit::NpmAuditEngine;

use auditx_core::{Web2Finding, SecretFinding, DependencyFinding};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web2Options {
    pub semgrep_configs: Vec<String>,
    pub timeout_secs: u64,
}

impl Default for Web2Options {
    fn default() -> Self {
        Self {
            semgrep_configs: vec![
                "p/javascript".to_string(),
                "p/typescript".to_string(),
                "p/nodejs-security".to_string(),
                "p/jwt".to_string(),
                "p/secrets".to_string(),
            ],
            timeout_secs: 120,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web2EngineOutput {
    pub web2_findings: Vec<Web2Finding>,
    pub secret_findings: Vec<SecretFinding>,
    pub dependency_findings: Vec<DependencyFinding>,
}

pub async fn run_web2_engine(
    dir: &Path,
    opts: &Web2Options,
) -> Result<Web2EngineOutput> {
    let semgrep_engine = SemgrepEngine::new(opts.semgrep_configs.clone(), opts.timeout_secs);
    let gitleaks_engine = GitleaksEngine::new();
    let cargo_audit_engine = CargoAuditEngine::new();
    let npm_audit_engine = NpmAuditEngine::new();

    // Run Web2 scans in parallel
    let (semgrep_res, gitleaks_res, cargo_audit_res, npm_audit_res) = tokio::join!(
        semgrep_engine.run(dir),
        gitleaks_engine.run(dir),
        cargo_audit_engine.run(dir),
        npm_audit_engine.run(dir),
    );

    let mut web2_findings = Vec::new();
    let mut secret_findings = Vec::new();
    let mut dependency_findings = Vec::new();

    if let Ok(findings) = semgrep_res {
        web2_findings.extend(findings);
    }
    if let Ok(findings) = gitleaks_res {
        secret_findings.extend(findings);
    }
    if let Ok(findings) = cargo_audit_res {
        dependency_findings.extend(findings);
    }
    if let Ok(findings) = npm_audit_res {
        dependency_findings.extend(findings);
    }

    // Run fallback Shannon-entropy secrets detector
    if let Ok(entropy_secrets) = secrets::detect_secrets(dir) {
        for secret in entropy_secrets {
            // Deduplicate secrets: avoid duplicate files + line numbers
            if !secret_findings.iter().any(|sf| sf.file == secret.file && sf.line == secret.line) {
                secret_findings.push(secret);
            }
        }
    }

    // Run config checker rules
    if let Ok(config_findings) = config_checker::check_configs(dir) {
        web2_findings.extend(config_findings);
    }

    // Deduplicate Web2 findings
    let mut unique_web2 = Vec::new();
    for f in web2_findings {
        let existing = unique_web2.iter().position(|uf: &Web2Finding| {
            uf.file == f.file && uf.line == f.line && uf.title == f.title
        });
        if let Some(idx) = existing {
            if f.cvss > unique_web2[idx].cvss {
                let mut merged = f.clone();
                merged.tool = format!("{}, {}", unique_web2[idx].tool, f.tool);
                unique_web2[idx] = merged;
            }
        } else {
            unique_web2.push(f);
        }
    }

    // Sort findings by severity (Critical first)
    unique_web2.sort_by(|a, b| b.severity.cmp(&a.severity));
    dependency_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    Ok(Web2EngineOutput {
        web2_findings: unique_web2,
        secret_findings,
        dependency_findings,
    })
}
