use auditx_core::{Web3Finding, Web2Finding};

pub fn deduplicate_web3(findings: Vec<Web3Finding>) -> Vec<Web3Finding> {
    let mut unique_findings: Vec<Web3Finding> = Vec::new();

    for f in findings {
        let existing_idx = unique_findings.iter().position(|uf| {
            uf.file == f.file && uf.line == f.line && uf.title == f.title
        });

        if let Some(idx) = existing_idx {
            if f.cvss > unique_findings[idx].cvss {
                let mut merged = f.clone();
                merged.tool = format!("{}, {}", unique_findings[idx].tool, f.tool);
                unique_findings[idx] = merged;
            } else {
                let mut merged = unique_findings[idx].clone();
                if !merged.tool.contains(&f.tool) {
                    merged.tool = format!("{}, {}", merged.tool, f.tool);
                }
                unique_findings[idx] = merged;
            }
        } else {
            unique_findings.push(f);
        }
    }

    // Sort by severity (highest first)
    unique_findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    unique_findings
}

pub fn deduplicate_web2(findings: Vec<Web2Finding>) -> Vec<Web2Finding> {
    let mut unique_findings: Vec<Web2Finding> = Vec::new();

    for f in findings {
        let existing_idx = unique_findings.iter().position(|uf| {
            uf.file == f.file && uf.line == f.line && uf.title == f.title
        });

        if let Some(idx) = existing_idx {
            if f.cvss > unique_findings[idx].cvss {
                let mut merged = f.clone();
                merged.tool = format!("{}, {}", unique_findings[idx].tool, f.tool);
                unique_findings[idx] = merged;
            } else {
                let mut merged = unique_findings[idx].clone();
                if !merged.tool.contains(&f.tool) {
                    merged.tool = format!("{}, {}", merged.tool, f.tool);
                }
                unique_findings[idx] = merged;
            }
        } else {
            unique_findings.push(f);
        }
    }

    // Sort by severity (highest first)
    unique_findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    unique_findings
}
