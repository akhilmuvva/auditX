use auditx_core::{Web3Finding, Severity};

pub fn detect(source: &str, filename: &str) -> Vec<Web3Finding> {
    let mut findings = Vec::new();

    // 1. proposal execution without TimelockController
    if source.contains("propose") && source.contains("execute") && !source.contains("timelock") && !source.contains("Timelock") {
        let line = find_line_containing(source, "propose");
        let id = format!("web3-detector-gov-timelock-{}", line.unwrap_or(0));
        findings.push(Web3Finding {
            id,
            tool: "auditx-detector".to_string(),
            swc_id: None,
            severity: Severity::High,
            cvss: 7.6,
            title: "Governance Action Execution without Timelock".to_string(),
            description: "The governance system allows executing proposals instantly upon passing. This exposes the protocol to flash-loan funded vote hijacking attacks where a proposal is voted and executed in the same block/transaction.".to_string(),
            file: filename.to_string(),
            line,
            remediation: "Require all governance proposals to queue inside a TimelockController for a minimum of 24-48 hours before execution.".to_string(),
        });
    }

    // 2. votes read from current block not snapshot
    if source.contains("getVotes") && !source.contains("getPastVotes") {
        let line = find_line_containing(source, "getVotes");
        let id = format!("web3-detector-gov-flashvote-{}", line.unwrap_or(0));
        findings.push(Web3Finding {
            id,
            tool: "auditx-detector".to_string(),
            swc_id: None,
            severity: Severity::High,
            cvss: 8.0,
            title: "Governance Flash-Voting Risk: votes checked at current block".to_string(),
            description: "Governance reads voting power from getVotes() (current balance) instead of getPastVotes() (historic block number). Attackers can buy/borrow tokens in a flash loan, vote, and sell them back in the same transaction.".to_string(),
            file: filename.to_string(),
            line,
            remediation: "Query token voting power at the proposal creation block or snapshot block using getPastVotes(account, blockNumber) instead of live checkpoints.".to_string(),
        });
    }

    // 3. no quorum check before execution
    if source.contains("execute") && !source.contains("quorum") && !source.contains("Quorum") {
        let line = find_line_containing(source, "execute");
        let id = format!("web3-detector-gov-quorum-{}", line.unwrap_or(0));
        findings.push(Web3Finding {
            id,
            tool: "auditx-detector".to_string(),
            swc_id: None,
            severity: Severity::Medium,
            cvss: 6.5,
            title: "Governance Execution lacking Quorum enforcement".to_string(),
            description: "The proposal execution function does not explicitly verify that a quorum (minimum number of votes) was reached. A proposal could pass with a trivial number of votes if opposition is absent.".to_string(),
            file: filename.to_string(),
            line,
            remediation: "Enforce a strict quorum check (e.g. require total votes >= quorumThreshold()) in the proposal execution checks.".to_string(),
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
