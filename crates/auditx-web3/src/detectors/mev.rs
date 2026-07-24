use regex::Regex;
use auditx_core::{Web3Finding, Severity};

pub fn detect(source: &str, filename: &str) -> Vec<Web3Finding> {
    let mut findings = Vec::new();

    // 1. block.timestamp in randomness or deadline logic
    let re_rand = Regex::new(r"keccak256\s*\(\s*abi\.encode(Packed)?\s*\([^)]*block\.timestamp").unwrap();
    if re_rand.is_match(source) || (source.contains("block.timestamp") && (source.contains("random") || source.contains("rand"))) {
        let line = find_line_containing(source, "block.timestamp");
        let id = format!("web3-detector-mev-randomness-{}", line.unwrap_or(0));
        findings.push(Web3Finding {
            id,
            tool: "auditx-detector".to_string(),
            swc_id: Some("SWC-120".to_string()),
            severity: Severity::Medium,
            cvss: 5.5,
            title: "Weak Randomness via block.timestamp".to_string(),
            description: "The contract uses block.timestamp for random number generation. Miners/validators can manipulate block timestamps slightly to game the randomness outcome.".to_string(),
            file: filename.to_string(),
            line,
            remediation: "Use Chainlink VRF (Verifiable Random Function) to request secure, tamper-proof randomness on-chain.".to_string(),
        });
    }

    // 2. Swap calls without deadline / amountOutMin parameters
    if source.contains("swapExact") {
        let line = find_line_containing(source, "swapExact");
        // Check if Uniswap/Sushiswap style swap is called with a static '0' for amountOutMin or missing params
        if source.contains(", 0,") || source.contains("amountOutMin: 0") {
            let id = format!("web3-detector-mev-slippage-{}", line.unwrap_or(0));
            findings.push(Web3Finding {
                id,
                tool: "auditx-detector".to_string(),
                swc_id: None,
                severity: Severity::High,
                cvss: 7.5,
                title: "Slippage limits set to 0 in token swap".to_string(),
                description: "The contract executes a decentralized exchange swap setting amountOutMin to 0. Frontrunning bots can sandwich the transaction, causing massive slippage and draining token values.".to_string(),
                file: filename.to_string(),
                line,
                remediation: "Calculate dynamic minimum amountOutMin based on price feeds or input thresholds with a slippage percentage check (e.g. 0.5%).".to_string(),
            });
        }
    }

    // 3. tx.gasprice used in conditional
    if source.contains("tx.gasprice") {
        let line = find_line_containing(source, "tx.gasprice");
        let id = format!("web3-detector-mev-gasprice-{}", line.unwrap_or(0));
        findings.push(Web3Finding {
            id,
            tool: "auditx-detector".to_string(),
            swc_id: None,
            severity: Severity::Low,
            cvss: 3.5,
            title: "Conditional logic dependency on tx.gasprice".to_string(),
            description: "Enforcing logic bound to tx.gasprice makes transactions susceptible to MEV searcher manipulation and gas auction gaming.".to_string(),
            file: filename.to_string(),
            line,
            remediation: "Avoid relying on tx.gasprice for transaction eligibility checks or access control logic.".to_string(),
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
