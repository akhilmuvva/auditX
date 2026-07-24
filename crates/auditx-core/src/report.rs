use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Layer {
    Web2,
    Web3,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Likelihood {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web3Finding {
    pub id: String,
    pub tool: String, // "slither" | "mythril" | "surya" | "custom"
    pub swc_id: Option<String>,
    pub severity: Severity,
    pub cvss: f32,
    pub title: String,
    pub description: String,
    pub file: String,
    pub line: Option<u32>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web2Finding {
    pub id: String,
    pub tool: String, // "semgrep" | "gitleaks" | "cargo-audit" | "npm-audit" | "config"
    pub owasp_id: Option<String>,
    pub severity: Severity,
    pub cvss: f32,
    pub title: String,
    pub description: String,
    pub file: String,
    pub line: Option<u32>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub description: String,
    pub file: String,
    pub line: u32,
    pub commit: Option<String>,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyFinding {
    pub package: String,
    pub version: String,
    pub severity: Severity,
    pub cve: String,
    pub cvss: f32,
    pub fixed_in: Option<String>,
    pub exploit_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    pub layer: Layer,
    pub finding_ref: String,
    pub description: String,
    pub enables_next: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    pub chain_id: String,
    pub title: String,
    pub steps: Vec<AttackStep>,
    pub combined_cvss: f32,
    pub likelihood: Likelihood,
    pub web2_remediation: String,
    pub web3_remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditXReport {
    pub project_name: String,
    pub audit_date: String,
    pub web3_cvss: f32,
    pub web2_cvss: f32,
    pub combined_cvss: f32,
    pub web3_findings: Vec<Web3Finding>,
    pub web2_findings: Vec<Web2Finding>,
    pub secret_findings: Vec<SecretFinding>,
    pub dependency_findings: Vec<DependencyFinding>,
    pub attack_chains: Vec<AttackChain>,
    pub total_critical: u32,
    pub total_high: u32,
    pub total_medium: u32,
    pub total_low: u32,
    pub ipfs_cid: Option<String>,
    pub eas_attestation: Option<String>,
    pub badge_token_id: Option<u64>,
    pub pipeline_duration_ms: u64,
}
