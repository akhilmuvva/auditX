use auditx_core::{Web3Finding, Web2Finding, SecretFinding, DependencyFinding};

pub fn build_fusion_prompt(
    web3_findings: &[Web3Finding],
    web2_findings: &[Web2Finding],
    secret_findings: &[SecretFinding],
    dependency_findings: &[DependencyFinding],
) -> String {
    format!(
        r#"
You are a full-stack Web3 + Web2 security expert.

WEB3 FINDINGS (from Slither/Mythril/custom detectors):
{}

WEB2 FINDINGS (from Semgrep/Gitleaks/npm-audit/config):
{}

SECRET FINDINGS:
{}

DEPENDENCY FINDINGS:
{}

Tasks:
1. Deduplicate findings across all tools. Remove exact duplicates (same file + line + vulnerability type).
2. Score each unique finding with CVSS 3.1 (0.0-10.0).
3. Identify CROSS-LAYER ATTACK CHAINS where a Web2 vulnerability enables or amplifies a Web3 exploit. Common patterns:
   - Leaked private key -> privileged contract call
   - XSS -> wallet signature hijack -> unauthorized tx
   - SSRF -> internal RPC -> contract state manipulation
   - Compromised dependency -> malicious tx signing
4. For each chain output steps[], combined_cvss, likelihood, web2_remediation, web3_remediation.
5. Compute combined_system_cvss for the entire project (not just the contract — the full system risk).
6. For each finding provide exact remediation with code snippet.

Severity escalation rule:
  If Web2 finding enables Web3 finding:
  combinedCvss = min(10.0, max(web2Cvss, web3Cvss) + 2.0)

Respond ONLY in valid JSON. No preamble. No markdown.
Schema:
{{
  "deduped_web3": [
    {{
      "id": "string",
      "tool": "string",
      "swc_id": "string or null",
      "severity": "Critical" | "High" | "Medium" | "Low" | "Informational",
      "cvss": 0.0,
      "title": "string",
      "description": "string",
      "file": "string",
      "line": 0,
      "remediation": "string"
    }}
  ],
  "deduped_web2": [
    {{
      "id": "string",
      "tool": "string",
      "owasp_id": "string or null",
      "severity": "Critical" | "High" | "Medium" | "Low" | "Informational",
      "cvss": 0.0,
      "title": "string",
      "description": "string",
      "file": "string",
      "line": 0,
      "remediation": "string"
    }}
  ],
  "attack_chains": [
    {{
      "chain_id": "string",
      "title": "string",
      "steps": [
        {{
          "layer": "Web2" | "Web3",
          "finding_ref": "string reference to finding title",
          "description": "string",
          "enables_next": "string"
        }}
      ],
      "combined_cvss": 0.0,
      "likelihood": "High" | "Medium" | "Low",
      "web2_remediation": "string",
      "web3_remediation": "string"
    }}
  ],
  "combined_system_cvss": 0.0,
  "executive_summary": "string"
}}
"#,
        serde_json::to_string_pretty(web3_findings).unwrap_or_default(),
        serde_json::to_string_pretty(web2_findings).unwrap_or_default(),
        serde_json::to_string_pretty(secret_findings).unwrap_or_default(),
        serde_json::to_string_pretty(dependency_findings).unwrap_or_default()
    )
}
