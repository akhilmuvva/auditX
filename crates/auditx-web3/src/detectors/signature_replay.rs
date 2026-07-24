use auditx_core::{Web3Finding, Severity};

pub fn detect(source: &str, filename: &str) -> Vec<Web3Finding> {
    let mut findings = Vec::new();

    if source.contains("ecrecover") {
        let line = find_line_containing(source, "ecrecover");
        
        // 1. ecrecover without nonce tracking
        if !source.contains("nonces") && !source.contains("nonce") {
            let id = format!("web3-detector-sig-replay-nonce-{}", line.unwrap_or(0));
            findings.push(Web3Finding {
                id,
                tool: "auditx-detector".to_string(),
                swc_id: Some("SWC-121".to_string()),
                severity: Severity::High,
                cvss: 8.5,
                title: "Signature Replay vulnerability: missing nonces".to_string(),
                description: "The contract utilizes ecrecover() for signature validation but does not track nonces. Attacker can capture a signed message and replay it multiple times.".to_string(),
                file: filename.to_string(),
                line,
                remediation: "Maintain a nonces mapping(address => uint) and include the incrementing nonce in the signed digest.".to_string(),
            });
        }

        // 2. missing chainId in signed hash
        if !source.contains("block.chainid") && !source.contains("chainId") {
            let id = format!("web3-detector-sig-replay-chainid-{}", line.unwrap_or(0));
            findings.push(Web3Finding {
                id,
                tool: "auditx-detector".to_string(),
                swc_id: Some("SWC-121".to_string()),
                severity: Severity::High,
                cvss: 7.5,
                title: "Cross-Chain Signature Replay: missing chainId".to_string(),
                description: "The signature digest does not incorporate block.chainid. Attacker can replay a signature signed on a testnet (e.g. Sepolia) on the mainnet.".to_string(),
                file: filename.to_string(),
                line,
                remediation: "Incorporate block.chainid into the hash or implement full EIP-712 standard support.".to_string(),
            });
        }

        // 3. missing EIP-712 domain separator
        if !source.contains("DOMAIN_SEPARATOR") && !source.contains("domainSeparator") {
            let id = format!("web3-detector-sig-replay-domain-{}", line.unwrap_or(0));
            findings.push(Web3Finding {
                id,
                tool: "auditx-detector".to_string(),
                swc_id: Some("SWC-121".to_string()),
                severity: Severity::Medium,
                cvss: 6.8,
                title: "Missing EIP-712 Domain Separator".to_string(),
                description: "The contract uses raw signature verification rather than EIP-712 structured signing. This makes signatures harder for users to read and verify during wallet approval, increasing phishing risks.".to_string(),
                file: filename.to_string(),
                line,
                remediation: "Adopt OpenZeppelin's EIP712 contract and use _hashTypedDataV4() to hash structured messages securely.".to_string(),
            });
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
