use regex::Regex;
use auditx_core::{Web3Finding, Severity};

pub fn detect_flash_loan_patterns(source: &str, filename: &str) -> Vec<Web3Finding> {
    let mut findings = Vec::new();

    // Pattern 1: getReserves() without TWAP (Price Oracle manipulation risk)
    if source.contains("getReserves()") && !source.contains("consult") && !source.contains("twap") && !source.contains("price0CumulativeLast") {
        findings.push(Web3Finding {
            tool: "auditx-detector".to_string(),
            swc_id: Some("SWC-120".to_string()), // Weak Randomness / dependency on oracle
            severity: Severity::High,
            cvss: 8.2,
            title: "Potential Price Oracle Manipulation Risk".to_string(),
            description: "The contract uses getReserves() directly without TWAP (Time-Weighted Average Price) checks. This makes it susceptible to flash-loan funded oracle manipulation attacks.".to_string(),
            file: filename.to_string(),
            line: find_line_containing(source, "getReserves"),
            remediation: "Implement a Uniswap v2/v3 TWAP oracle or use a decentralized oracle network like Chainlink for asset price feeds.".to_string(),
        });
    }

    // Pattern 2: balanceOf(address(this)) in arithmetic (Inflation Attack)
    let re_bal = Regex::new(r"balanceOf\(\s*address\(\s*this\s*\)\s*\)\s*[\+\-\*/]").unwrap();
    if re_bal.is_match(source) {
        findings.push(Web3Finding {
            tool: "auditx-detector".to_string(),
            swc_id: Some("SWC-101".to_string()), // Integer Overflow/Underflow or logic error
            severity: Severity::High,
            cvss: 7.8,
            title: "Dangerous use of balanceOf(address(this)) in Arithmetic".to_string(),
            description: "Direct use of balanceOf(address(this)) in mathematical operations is sensitive to token inflation or donation attacks. Attackers can artificially inflate your contract balance in a flash loan to corrupt math calculations.".to_string(),
            file: filename.to_string(),
            line: find_line_containing(source, "balanceOf(address(this))"),
            remediation: "Track internal token balances via a state variable instead of relying on balanceOf(address(this)) dynamically.".to_string(),
        });
    }

    // Pattern 3: same-tx borrow without reentrancy guard
    if (source.contains("flashLoan") || source.contains("borrow") || source.contains("executeOperation")) 
       && !source.contains("nonReentrant") && !source.contains("ReentrancyGuard") {
        findings.push(Web3Finding {
            tool: "auditx-detector".to_string(),
            swc_id: Some("SWC-107".to_string()), // Reentrancy
            severity: Severity::Critical,
            cvss: 9.3,
            title: "Flash Loan / Callback interface without ReentrancyGuard".to_string(),
            description: "The contract defines a flash loan receiver or borrow entrypoint but does not protect it with a ReentrancyGuard. Attackers can hijack execution flow during callbacks to drain funds.".to_string(),
            file: filename.to_string(),
            line: find_line_containing(source, "executeOperation"),
            remediation: "Inherit OpenZeppelin's ReentrancyGuard and apply the nonReentrant modifier to all callback/entrypoint functions.".to_string(),
        });
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
