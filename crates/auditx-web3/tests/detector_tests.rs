use auditx_web3::{
    flash_loan::detect_flash_loan_patterns,
    signature_replay::detect_signature_replay,
    mev::detect_mev_patterns,
};

#[test]
fn test_flash_loan_detection_positive() {
    let source = r#"
        contract Vuln {
            function executeOperation() external {
                // Flash loan callback
                uint bal = getReserves();
            }
        }
    "#;
    let findings = detect_flash_loan_patterns(source, "Vuln.sol");
    assert!(!findings.is_empty(), "Should detect flash loan reentrancy / TWAP oracle manipulation risks");
}

#[test]
fn test_flash_loan_detection_negative() {
    let source = r#"
        contract Safe {
            // Uses ReentrancyGuard and consults TWAP
            function executeOperation() external nonReentrant {
                uint price = consultOracle();
            }
        }
    "#;
    let findings = detect_flash_loan_patterns(source, "Safe.sol");
    assert!(findings.is_empty(), "Should not flag safe contract with guards");
}

#[test]
fn test_signature_replay_detection() {
    let source = r#"
        contract SignatureReplay {
            function verify(bytes memory sig) public {
                address signer = ecrecover(hash, v, r, s);
            }
        }
    "#;
    let findings = detect_signature_replay(source, "SignatureReplay.sol");
    assert!(!findings.is_empty(), "Should flag missing nonce/chainId in ecrecover usage");
}

#[test]
fn test_mev_detection() {
    let source = r#"
        contract Randomness {
            function play() public {
                uint rand = uint(keccak256(abi.encodePacked(block.timestamp)));
            }
        }
    "#;
    let findings = detect_mev_patterns(source, "Randomness.sol");
    assert!(findings.iter().any(|f| f.title.contains("Weak Randomness")), "Should detect block.timestamp dependency");
}
