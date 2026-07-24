use regex::Regex;
use auditx_core::{Web3Finding, Severity};

pub fn detect_mev_patterns(source: &str, filename: &str) -> Vec<Web3Finding> {
    let mut findings = Vec::new();

    // Pattern 1: block.timestamp used for randomness
    let re_rand = Regex::new(r"keccak256\s*\(\s*abi\.encode(Packed)?\s*\([^)]*block\.timestamp").unwrap();
    if re_rand.is_match(source) || (source.contains("block.timestamp") && (source.contains("random") || source.contains("rand"))) {
        findings.push(Web3Finding {
            tool: "auditx-detector".to_string(),
            swc_id: Some("SWC-120".to_string()), // Weak Randomness
            severity: Severity::Medium,
            cvss: 5.5,
            title: "Weak Randomness: block.timestamp dependency".to_string(),
            description: "The contract relies on block.timestamp or block hash for random number generation. Miners can influence block parameters to manipulate execution outcomes to their advantage.".to_string(),
            file: filename.to_string(),
            line: find_line_containing(source, "block.timestamp"),
            remediation: "Use a verifiable random function (VRF) like Chainlink VRF for secure on-chain randomness.".to_string(),
        });
    }

    // Pattern 2: Swaps without slippage limits or deadlines (front-running risk)
    if source.contains("swapExactTokensForTokens") && !source.contains("amountOutMin") && !source.contains("minAmountOut") {
        findings.push(Web3Finding {
            tool: "auditx-detector".to_string(),
            swc_id: None,
            severity: Severity::High,
            cvss: 7.5,
            title: "Slippage Vulnerability in Token Swaps".to_string(),
            description: "Token swaps appear to be executed with zero/undefined slippage boundaries (e.g. mapping amountOutMin to 0). Frontrunners (sandwich bots) can manipulate Uniswap pools in the same block, yielding heavy losses.".to_string(),
            file: filename.to_string(),
            line: find_line_containing(source, "swapExactTokensForTokens"),
            remediation: "Calculate a minimum output value off-chain or dynamically based on current pool reserves with a maximum acceptable tolerance (e.g. 0.5%).".to_string(),
        });
    }

    // Pattern 3: tx.gasprice checks (MEV signals)
    if source.contains("tx.gasprice") {
        findings.push(Web3Finding {
            tool: "auditx-detector".to_string(),
            swc_id: None,
            severity: Severity::Low,
            cvss: 3.5,
            title: "Use of tx.gasprice for logic enforcement".to_string(),
            description: "The contract contains logic bound to tx.gasprice. This value varies dynamically due to gas markets and EIP-1559 and can be exploited or broken by miners or MEV searchers.".to_string(),
            file: filename.to_string(),
            line: find_line_containing(source, "tx.gasprice"),
            remediation: "Avoid restricting execution flow based on tx.gasprice, as gas price auction dynamics are highly volatile and easily gameable.".to_string(),
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
