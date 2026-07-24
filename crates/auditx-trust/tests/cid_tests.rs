use auditx_core::report::AuditXReport;
use auditx_trust::ipfs::IpfsClient;

#[test]
fn test_offline_cid_matches_ipfs_format() {
    let client = IpfsClient::new(None);
    let report = AuditXReport {
        project_name: "Test".to_string(),
        audit_date: "2026-07-03".to_string(),
        web3_cvss: 0.0,
        web2_cvss: 0.0,
        combined_cvss: 0.0,
        web3_findings: vec![],
        web2_findings: vec![],
        secret_findings: vec![],
        dependency_findings: vec![],
        attack_chains: vec![],
        ipfs_cid: None,
        eas_attestation: None,
        badge_token_id: None,
        total_critical: 0,
        total_high: 0,
        total_medium: 0,
        total_low: 0,
    };
    
    let cid = client.generate_offline_cid(&report);
    assert!(cid.starts_with("Qm"), "CIDv0 should start with Qm");
    assert_eq!(cid.len(), 46, "CIDv0 should be exactly 46 characters long");
}

#[test]
fn test_cid_deterministic() {
    let client = IpfsClient::new(None);
    let report1 = AuditXReport {
        project_name: "Test".to_string(),
        audit_date: "2026-07-03".to_string(),
        web3_cvss: 0.0,
        web2_cvss: 0.0,
        combined_cvss: 0.0,
        web3_findings: vec![],
        web2_findings: vec![],
        secret_findings: vec![],
        dependency_findings: vec![],
        attack_chains: vec![],
        ipfs_cid: None,
        eas_attestation: None,
        badge_token_id: None,
        total_critical: 0,
        total_high: 0,
        total_medium: 0,
        total_low: 0,
    };
    
    let report2 = report1.clone();
    
    let cid1 = client.generate_offline_cid(&report1);
    let cid2 = client.generate_offline_cid(&report2);
    
    assert_eq!(cid1, cid2, "Offline CID generation must be deterministic");
}
