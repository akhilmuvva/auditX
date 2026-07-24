use criterion::{criterion_group, criterion_main, Criterion};
use std::path::PathBuf;
use auditx_core::report::AuditXReport;
use auditx_trust::generate_cid_v0;

fn bench_offline_cid(c: &mut Criterion) {
    let report = AuditXReport {
        project_name: "Benchmark Project".to_string(),
        audit_date: "2026-07-03".to_string(),
        web3_cvss: 5.0,
        web2_cvss: 4.2,
        combined_cvss: 7.2,
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
    
    let data = serde_json::to_vec(&report).unwrap();
    
    c.bench_function("generate_cid_v0", |b| b.iter(|| {
        generate_cid_v0(&data);
    }));
}

criterion_group!(benches, bench_offline_cid);
criterion_main!(benches);
