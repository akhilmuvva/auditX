use std::path::Path;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectType {
    Web3Only,
    Web2Only,
    FullStack,
    Unknown,
}

pub fn detect(dir: &Path) -> ProjectType {
    let mut has_web3 = false;
    let mut has_web2 = false;

    // Direct check for common web2 files at the root
    if dir.join("package.json").exists() 
        || dir.join("requirements.txt").exists() 
        || dir.join("Cargo.toml").exists() 
        || dir.join("go.mod").exists()
        || dir.join("pyproject.toml").exists() 
    {
        has_web2 = true;
    }

    // Helper recursive function to scan files
    fn scan_dir(p: &Path, has_web3: &mut bool, has_web2: &mut bool) {
        if *has_web3 && *has_web2 {
            return;
        }

        if let Ok(entries) = std::fs::read_dir(p) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    // Skip build/dependency directories
                    if name != "node_modules" && name != "target" && name != ".git" && name != "dist" {
                        scan_dir(&path, has_web3, has_web2);
                    }
                } else if path.is_file() {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if ext == "sol" {
                            *has_web3 = true;
                        } else if ext == "js" || ext == "ts" || ext == "py" || ext == "rs" || ext == "go" {
                            *has_web2 = true;
                        }
                    }
                }
            }
        }
    }

    scan_dir(dir, &mut has_web3, &mut has_web2);

    match (has_web3, has_web2) {
        (true, true) => ProjectType::FullStack,
        (true, false) => ProjectType::Web3Only,
        (false, true) => ProjectType::Web2Only,
        _ => ProjectType::Unknown,
    }
}
