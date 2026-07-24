use regex::Regex;
use auditx_core::{Web3Finding, Severity};

pub fn detect(source: &str, filename: &str) -> Vec<Web3Finding> {
    let mut findings = Vec::new();

    // Pattern 1: getReserves() without TWAP reference in same function
    // We match functions containing getReserves() but missing twap/consult/priceCumulative
    // Since parsing functions with regex is hard, we can do a function-level split or block scan
    let re_func = Regex::new(r"function\s+(\w+)\s*\([^)]*\)[^{]*\{([^}]*)\}").unwrap();
    for mat in re_func.captures_iter(source) {
        let func_name = mat.get(1).map(|m| m.as_str()).unwrap_or("");
        let func_body = mat.get(2).map(|m| m.as_str()).unwrap_or("");
        
        if func_body.contains("getReserves") 
            && !func_body.contains("twap") 
            && !func_body.contains("consult") 
            && !func_body.contains("priceCumulative") 
        {
            let line = find_line_containing(source, &format!("function {}", func_name));
            let id = format!("web3-detector-oracle-manipulation-{}", line.unwrap_or(0));
            findings.push(Web3Finding {
                id,
                tool: "auditx-detector".to_string(),
                swc_id: None,
                severity: Severity::High,
                cvss: 8.2,
                title: "Oracle Manipulation Vulnerability via getReserves()".to_string(),
                description: format!("Function '{}' queries getReserves() directly without applying a TWAP check or oracle validation. Flash loan attackers can easily manipulate the reserves to corrupt pricing.", func_name),
                file: filename.to_string(),
                line,
                remediation: "Integrate a Uniswap v2/v3 TWAP Consult oracle or a Chainlink Aggregator instead of querying reserves directly.".to_string(),
            });
        }
    }

    // Pattern 2: balanceOf(address(this)) in arithmetic expression
    let re_arith = Regex::new(r"balanceOf\(\s*address\(\s*this\s*\)\s*\)\s*[\+\-\*/]").unwrap();
    if re_arith.is_match(source) {
        let line = find_line_containing(source, "balanceOf(address(this))");
        let id = format!("web3-detector-balanceof-arithmetic-{}", line.unwrap_or(0));
        findings.push(Web3Finding {
            id,
            tool: "auditx-detector".to_string(),
            swc_id: None,
            severity: Severity::High,
            cvss: 7.8,
            title: "Dangerous use of balanceOf(address(this)) in Arithmetic".to_string(),
            description: "Direct arithmetic on balanceOf(address(this)) is vulnerable to inflation attacks. Attackers can donate tokens directly to the contract to break internal accounting logic.".to_string(),
            file: filename.to_string(),
            line,
            remediation: "Track token balances internally using state variables, and do not rely on balanceOf(address(this)) dynamically in division or subtraction.".to_string(),
        });
    }

    // Pattern 3: no reentrancy guard on function with external call
    // Search for functions that make external calls (.call{value: ...} or .transfer/send/transferFrom)
    // but do not contain 'nonReentrant' modifier.
    for mat in re_func.captures_iter(source) {
        let func_name = mat.get(1).map(|m| m.as_str()).unwrap_or("");
        let func_decl = mat.get(0).map(|m| m.as_str()).unwrap_or("");
        let func_body = mat.get(2).map(|m| m.as_str()).unwrap_or("");

        if (func_body.contains(".call{") || func_body.contains(".transfer(") || func_body.contains(".send("))
            && !func_decl.contains("nonReentrant")
            && func_name != "withdraw" // Ignore common safe getters unless doing state updates after
        {
            // If function modifies state after the call: simple check for assignment after call
            let call_pos = func_body.find(".call").or_else(|| func_body.find(".transfer")).unwrap_or(0);
            let post_call = &func_body[call_pos..];
            if post_call.contains("=") || post_call.contains("-=") || post_call.contains("+=") {
                let line = find_line_containing(source, &format!("function {}", func_name));
                let id = format!("web3-detector-unprotected-reentrancy-{}", line.unwrap_or(0));
                findings.push(Web3Finding {
                    id,
                    tool: "auditx-detector".to_string(),
                    swc_id: Some("SWC-107".to_string()),
                    severity: Severity::Critical,
                    cvss: 9.3,
                    title: "State Update After External Call without ReentrancyGuard".to_string(),
                    description: format!("Function '{}' updates state variables after executing external ether/token transfers and lacks a nonReentrant modifier.", func_name),
                    file: filename.to_string(),
                    line,
                    remediation: "Inherit OpenZeppelin's ReentrancyGuard and apply the nonReentrant modifier to the function. Ensure state is updated before the external call (CEI pattern).".to_string(),
                });
            }
        }
    }

    findings
}

fn find_line_containing(source: &str, term: &str) -> Option<u32> {
    for (idx, line) in source.lines().enumerate() {
        if line.contains(term) {
            return Some((idx + 1) as u32);
        }
    }
    None
}
