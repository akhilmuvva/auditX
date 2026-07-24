use auditx_web3::detectors::{
    flash_loan::detect as detect_flash_loan,
    signature_replay::detect as detect_sig_replay,
    mev::detect as detect_mev,
    reentrancy::detect as detect_reentrancy,
};

#[test]
fn test_flash_loan_positive() {
    let source = r#"
        contract Vuln {
            function executeOperation() external {
                // Flash loan callback
                uint bal = getReserves();
            }
        }
    "#;
    let findings = detect_flash_loan(source, "Vuln.sol");
    assert!(!findings.is_empty(), "Should detect flash loan oracle manipulation risk");
}

#[test]
fn test_flash_loan_negative() {
    let source = r#"
        contract Safe {
            function executeOperation() external nonReentrant {
                uint price = consultOracle();
            }
        }
    "#;
    let findings = detect_flash_loan(source, "Safe.sol");
    assert!(findings.is_empty(), "Should not flag safe contract with guards");
}

#[test]
fn test_sig_replay_positive() {
    let source = r#"
        contract SignatureReplay {
            function verify(bytes memory sig) public {
                address signer = ecrecover(hash, v, r, s);
            }
        }
    "#;
    let findings = detect_sig_replay(source, "SignatureReplay.sol");
    assert!(!findings.is_empty(), "Should flag missing nonce/chainId in ecrecover usage");
}

#[test]
fn test_mev_timestamp_positive() {
    let source = r#"
        contract Randomness {
            function play() public {
                uint rand = uint(keccak256(abi.encodePacked(block.timestamp)));
            }
        }
    "#;
    let findings = detect_mev(source, "Randomness.sol");
    assert!(findings.iter().any(|f| f.title.contains("Weak Randomness")), "Should detect block.timestamp dependency");
}

#[test]
fn test_reentrancy_positive() {
    let source = r#"
        contract Vuln {
            function withdraw() external {
                msg.sender.call{value: 100}("");
            }
        }
    "#;
    let findings = detect_reentrancy(source, "Vuln.sol");
    assert!(!findings.is_empty(), "Should detect reentrancy");
}

#[test]
fn test_reentrancy_negative() {
    let source = r#"
        contract Safe {
            function withdraw() external nonReentrant {
                msg.sender.call{value: 100}("");
            }
        }
    "#;
    let findings = detect_reentrancy(source, "Safe.sol");
    assert!(findings.is_empty(), "Should not flag safe nonReentrant contract");
}
