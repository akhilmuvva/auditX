use regex::Regex;
use auditx_core::{Web3Finding, Severity};

pub fn detect_signature_replay(source: &str, filename: &str) -> Vec<Web3Finding> {
    let mut findings = Vec::new();

    // Pattern 1: ecrecover() without nonce mapping
    if source.contains("ecrecover") && !source.contains("nonces") && !source.contains("nonce") {
        findings.push(Web3Finding {
            tool: "auditx-detector".to_string(),
            swc_id: Some("SWC-121".to_string()), // Missing Protection against Signature Replay Attacks
            severity: Severity::High,
            cvss: 8.5,
            title: "Potential Signature Replay: ecrecover used without nonces".to_string(),
            description: "The contract calls ecrecover to verify signatures but does not appear to track nonces. This allows signatures to be replayed multiple times to execute actions.".to_string(),
            file: filename.to_string(),
            line: find_line_containing(source, "ecrecover"),
            remediation: "Maintain a mapping(address => uint256) public nonces and include the current nonce in the signature hash, incrementing it upon validation.".to_string(),
        });
    }

    // Pattern 2: missing chainId in struct hash or EIP-712
    if source.contains("ecrecover") && !source.contains("block.chainid") && !source.contains("chainId") {
        findings.push(Web3Finding {
            tool: "auditx-detector".to_string(),
            swc_id: Some("SWC-121".to_string()),
            severity: Severity::High,
            cvss: 7.5,
            title: "Cross-Chain Signature Replay: missing chainId verification".to_string(),
            description: "The signature validation does not bind the chainId. An attacker can intercept a valid signature on one chain (e.g. Sepolia) and replay it on another chain (e.g. Mainnet).".to_string(),
            file: filename.to_string(),
            line: find_line_containing(source, "ecrecover"),
            remediation: "Incorporate block.chainid into the hash calculation, ideally by implementing the EIP-712 standard with a valid domain separator.".to_string(),
        });
    }

    // Pattern 3: missing address(this) in struct hash
    if source.contains("ecrecover") && !source.contains("address(this)") && !source.contains("DOMAIN_SEPARATOR") {
        findings.push(Web3Finding {
            tool: "auditx-detector".to_string(),
            swc_id: Some("SWC-121".to_string()),
            severity: Severity::High,
            cvss: 7.2,
            title: "Cross-Contract Signature Replay: missing contract address binding".to_string(),
            description: "The signature verification does not bind the verifying contract address. An attacker can intercept a signature intended for contract A and replay it against contract B if both are deployed by the same user or share key states.".to_string(),
            file: filename.to_string(),
            line: find_line_containing(source, "ecrecover"),
            remediation: "Bind address(this) into the signed digest, or implement EIP-712 where DOMAIN_SEPARATOR includes the verifyingContract address parameter.".to_string(),
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
