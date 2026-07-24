use std::collections::HashMap;
use std::path::Path;
use regex::Regex;
use walkdir::WalkDir;
use auditx_core::SecretFinding;

pub fn detect_secrets(dir: &Path) -> anyhow::Result<Vec<SecretFinding>> {
    let mut findings = Vec::new();

    let re_eth_key = Regex::new(r"\b0x[0-9a-fA-F]{64}\b").unwrap();
    let re_env_key = Regex::new(r"\b(ANTHROPIC_API_KEY|PRIVATE_KEY|MNEMONIC|API_KEY|SECRET|PASSWORD)\b").unwrap();
    let re_hex_key = Regex::new(r"\b[0-9a-fA-F]{32,64}\b").unwrap();
    let re_b64_key = Regex::new(r"\b[A-Za-z0-9+/]{40,}=*\b").unwrap();

    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let file_path = entry.path();
        let path_str = file_path.to_string_lossy().to_string();
        
        // Skip common build/dependency folders
        if path_str.contains("node_modules") || path_str.contains(".git") || path_str.contains("target") || path_str.contains("dist") {
            continue;
        }

        if let Ok(content) = std::fs::read_to_string(file_path) {
            for (line_idx, line) in content.lines().enumerate() {
                let line_num = (line_idx + 1) as u32;

                // 1. Ethereum Private Key Pattern (0x + 64 hex)
                if re_eth_key.is_match(line) {
                    findings.push(SecretFinding {
                        description: "Ethereum Private Key pattern detected".to_string(),
                        file: path_str.clone(),
                        line: line_num,
                        commit: None,
                        entropy: shannon_entropy(line),
                    });
                    continue;
                }

                // 2. Sensitive Environment Variables in config/.env
                if re_env_key.is_match(line) && line.contains('=') {
                    findings.push(SecretFinding {
                        description: "Possible plaintext credential/secret in configuration file".to_string(),
                        file: path_str.clone(),
                        line: line_num,
                        commit: None,
                        entropy: shannon_entropy(line),
                    });
                    continue;
                }

                // 3. High Entropy Strings (Hex and Base64)
                for mat in re_hex_key.find_iter(line) {
                    let s = mat.as_str();
                    let entropy = shannon_entropy(s);
                    if entropy > 4.5 && s.len() > 20 {
                        findings.push(SecretFinding {
                            description: format!("High entropy hex string (entropy: {:.2})", entropy),
                            file: path_str.clone(),
                            line: line_num,
                            commit: None,
                            entropy,
                        });
                    }
                }

                for mat in re_b64_key.find_iter(line) {
                    let s = mat.as_str();
                    let entropy = shannon_entropy(s);
                    if entropy > 4.5 && s.len() > 40 {
                        findings.push(SecretFinding {
                            description: format!("High entropy base64 string (entropy: {:.2})", entropy),
                            file: path_str.clone(),
                            line: line_num,
                            commit: None,
                            entropy,
                        });
                    }
                }
            }
        }
    }

    Ok(findings)
}

pub fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    freq.values()
        .map(|&f| {
            let p = f as f64 / len;
            -p * p.log2()
        })
        .sum()
}
