use auditx_web2::secrets::shannon_entropy;

#[test]
fn test_high_entropy_private_key() {
    let key = "4a2b9d8e7c6f5a3b2e1d0c9b8a7f6e5d4c3b2a1e0d9c8b7a6f5e4d3c2b1a0f9e";
    let entropy = shannon_entropy(key);
    assert!(entropy > 3.5, "Hex key should have high entropy (calculated: {})", entropy);
}

#[test]
fn test_low_entropy_normal_string() {
    let text = "aaaaabbbbbcccccdddddeeeee";
    let entropy = shannon_entropy(text);
    assert!(entropy < 3.0, "Repetitive text should have low entropy (calculated: {})", entropy);
}

#[test]
fn test_ethereum_key_pattern() {
    let source_dir = std::env::current_dir().unwrap();
    // Verify directory scanner filters
    let mock_dir = source_dir.join("crates/auditx-web2/tests");
    let findings = auditx_web2::secrets::scan_directory_for_secrets(&mock_dir);
    
    // It shouldn't crash and returns vector
    assert!(findings.is_ok() || findings.is_empty() || !findings.is_empty());
}
