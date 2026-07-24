use auditx_core::{Web3Finding, Severity};
use regex::Regex;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct GraphNode {
    pub name: String,
    pub visibility: String,
    pub is_payable: bool,
    pub is_delegatecall: bool,
    pub modifiers: Vec<String>,
    pub calls: Vec<String>,
}

pub fn analyze_graph(source: &str, filename: &str) -> Vec<Web3Finding> {
    let mut findings = Vec::new();
    let nodes = parse_nodes(source);

    for node in &nodes {
        // Rule 1: Unrestricted Delegatecall in public/external function
        if node.is_delegatecall && (node.visibility == "public" || node.visibility == "external") {
            let has_admin_guard = node.modifiers.iter().any(|m| m.contains("onlyOwner") || m.contains("onlyAdmin") || m.contains("auth"));
            if !has_admin_guard {
                findings.push(Web3Finding {
                    id: format!("surya-delegatecall-{}", Uuid::new_v4()),
                    tool: "surya-graph".to_string(),
                    swc_id: Some("SWC-112".to_string()),
                    severity: Severity::Critical,
                    cvss: 9.8,
                    title: "Unrestricted Delegatecall in Subgraph".to_string(),
                    description: format!(
                        "Public/External function '{}' in {} executes delegatecall without access control guards. Attacker can hijack contract storage.",
                        node.name, filename
                    ),
                    file: filename.to_string(),
                    line: find_line(source, &node.name),
                    remediation: "Add onlyOwner or authorized modifier to delegatecall execution paths or use a static implementation proxy.".to_string(),
                });
            }
        }

        // Rule 2: Unprotected State Modification Entry Path
        if (node.visibility == "public" || node.visibility == "external") && !node.is_payable {
            let modifies_state = source.contains(&format!("function {}", node.name)) && 
                (source.contains("owner =") || source.contains("admin =") || source.contains("selfdestruct"));
            let has_guard = node.modifiers.iter().any(|m| m.contains("onlyOwner") || m.contains("onlyAdmin") || m.contains("require"));
            
            if modifies_state && !has_guard {
                findings.push(Web3Finding {
                    id: format!("surya-unprotected-entry-{}", Uuid::new_v4()),
                    tool: "surya-graph".to_string(),
                    swc_id: Some("SWC-106".to_string()),
                    severity: Severity::High,
                    cvss: 8.2,
                    title: "Unprotected Admin Pathway in Call Graph".to_string(),
                    description: format!(
                        "Entry path to function '{}' permits unauthenticated caller to modify critical contract state.",
                        node.name
                    ),
                    file: filename.to_string(),
                    line: find_line(source, &node.name),
                    remediation: "Enforce strict caller verification using OpenZeppelin Ownable or AccessControl.".to_string(),
                });
            }
        }

        // Rule 3: Circular / Reentrant Call Loop in Graph
        for callee_name in &node.calls {
            if let Some(callee) = nodes.iter().find(|n| &n.name == callee_name) {
                if callee.calls.contains(&node.name) {
                    findings.push(Web3Finding {
                        id: format!("surya-circular-loop-{}", Uuid::new_v4()),
                        tool: "surya-graph".to_string(),
                        swc_id: Some("SWC-107".to_string()),
                        severity: Severity::High,
                        cvss: 7.5,
                        title: "Circular Protocol Call Graph Loop".to_string(),
                        description: format!(
                            "Circular call graph dependency detected between function '{}' and '{}'. High risk of state corruption or reentrancy.",
                            node.name, callee.name
                        ),
                        file: filename.to_string(),
                        line: find_line(source, &node.name),
                        remediation: "Break circular function calls into distinct linear execution steps.".to_string(),
                    });
                }
            }
        }
    }

    findings
}

fn parse_nodes(source: &str) -> Vec<GraphNode> {
    let mut nodes = Vec::new();
    let fn_re = Regex::new(r"function\s+(\w+)\s*\([^)]*\)\s*([^{]*)").unwrap();

    for cap in fn_re.captures_iter(source) {
        let name = cap.get(1).map_or("", |m| m.as_str()).to_string();
        let specifiers = cap.get(2).map_or("", |m| m.as_str());

        let visibility = if specifiers.contains("external") {
            "external".to_string()
        } else if specifiers.contains("public") {
            "public".to_string()
        } else if specifiers.contains("internal") {
            "internal".to_string()
        } else {
            "private".to_string()
        };

        let is_payable = specifiers.contains("payable");

        let mut modifiers = Vec::new();
        for word in specifiers.split_whitespace() {
            if !["external", "public", "internal", "private", "pure", "view", "payable", "returns", "virtual", "override"].contains(&word) {
                modifiers.push(word.to_string());
            }
        }

        // Extract body calls
        let mut calls = Vec::new();
        let is_delegatecall = source.contains(&format!("function {}", name)) && source.contains("delegatecall");

        // Match internal function invocations
        let call_re = Regex::new(r"(\w+)\s*\(").unwrap();
        if let Some(start) = source.find(&format!("function {}", name)) {
            let body = &source[start..source.len().min(start + 500)];
            for c_cap in call_re.captures_iter(body) {
                let called_fn = c_cap.get(1).map_or("", |m| m.as_str());
                if called_fn != name && !["require", "assert", "emit", "revert", "keccak256", "abi"].contains(&called_fn) {
                    calls.push(called_fn.to_string());
                }
            }
        }

        nodes.push(GraphNode {
            name,
            visibility,
            is_payable,
            is_delegatecall,
            modifiers,
            calls,
        });
    }

    nodes
}

fn find_line(source: &str, func_name: &str) -> Option<u32> {
    source.lines().enumerate()
        .find(|(_, l)| l.contains("function") && l.contains(func_name))
        .map(|(i, _)| (i + 1) as u32)
}
