use auditx_core::report::AuditXReport;
use auditx_trust::generate_cid_v0;

#[test]
fn test_offline_cid_format() {
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
        pipeline_duration_ms: 0,
    };
    
    let serialized = serde_json::to_vec(&report).unwrap();
    let cid = generate_cid_v0(&serialized);
    assert!(cid.starts_with("Qm"), "CIDv0 should start with Qm");
    assert_eq!(cid.len(), 46, "CIDv0 should be exactly 46 characters long");
}

#[test]
fn test_offline_cid_deterministic() {
    let data = b"some audit report json payload";
    let cid1 = generate_cid_v0(data);
    let cid2 = generate_cid_v0(data);
    assert_eq!(cid1, cid2, "CID generation must be deterministic");
}
