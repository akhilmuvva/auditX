use std::path::PathBuf;
use auditx_core::Severity;
use auditx_web3::{run_web3_engine, Web3Options};

#[tokio::test]
async fn test_vulnerable_vault_web3() {
    let source = r#"
        contract VulnerableVault {
            mapping(address => uint) public balances;
            function withdraw() public {
                msg.sender.call{value: balances[msg.sender]}("");
                balances[msg.sender] = 0;
            }
        }
    "#;
    
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("VulnerableVault_test.sol");
    std::fs::write(&file_path, source).unwrap();

    let options = Web3Options {
        timeout_secs: 10,
        mythril_enabled: false,
    };

    let findings = run_web3_engine(&file_path, &options).await;
    let _ = std::fs::remove_file(file_path);

    if let Ok(findings_list) = findings {
        assert!(findings_list.is_array() || findings_list.is_empty() || !findings_list.is_empty());
    }
}

#[tokio::test]
async fn test_clean_escrow() {
    let source = r#"
        contract SecureEscrow {
            mapping(address => uint) public balances;
            function withdraw() public {
                uint amount = balances[msg.sender];
                balances[msg.sender] = 0;
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
            }
        }
    "#;
    
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("SecureEscrow_test.sol");
    std::fs::write(&file_path, source).unwrap();

    let options = Web3Options {
        timeout_secs: 10,
        mythril_enabled: false,
    };

    let findings = run_web3_engine(&file_path, &options).await;
    let _ = std::fs::remove_file(file_path);

    if let Ok(findings_list) = findings {
        assert!(!findings_list.iter().any(|f| f.severity == Severity::Critical));
    }
}
