use auditx_core::report::{Web3Finding, Severity};
use regex::Regex;
use uuid::Uuid;

pub fn detect(source: &str, filename: &str) -> Vec<Web3Finding> {
    let mut findings = vec![];

    let has_call = Regex::new(r"\.call\s*\{[^}]*value").unwrap();
    let has_nonreentrant = Regex::new(r"nonReentrant").unwrap();

    if has_call.is_match(source) && !has_nonreentrant.is_match(source) {
        let line = find_line(source, ".call");
        findings.push(Web3Finding {
            id: format!("detector-reentrancy-{}", Uuid::new_v4()),
            tool: "auditx-detector".to_string(),
            swc_id: Some("SWC-107".to_string()),
            severity: Severity::High,
            cvss: 8.5,
            title: "Reentrancy vulnerability".to_string(),
            description: format!(
                "External call transferring value via .call at line {} before state resolution or without nonReentrant guard.",
                line.unwrap_or(0)
            ),
            file: filename.to_string(),
            line,
            remediation: "Apply checks-effects-interactions pattern or add OpenZeppelin nonReentrant modifier.".to_string(),
        });
    }

    findings
}

fn find_line(source: &str, pattern: &str) -> Option<u32> {
    source.lines().enumerate()
        .find(|(_, l)| l.contains(pattern))
        .map(|(i, _)| (i + 1) as u32)
}
