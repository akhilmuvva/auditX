use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;
use clap::{Parser, Subcommand, ValueEnum};
use glob::glob;
use anyhow::{Result, Context};
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;
use dotenv::dotenv;

use auditx_core::{
    AuditXReport, Web3Finding, Web2Finding, SecretFinding, DependencyFinding, 
    Severity, AttackChain, AttackStep, Likelihood, Layer, ProjectType, detect
};
use auditx_web3::{run_web3_engine, Web3Options};
use auditx_web2::{run_web2_engine, Web2Options};
use auditx_ai::GeminiClient;
use auditx_trust::{EasClient, IpfsClient, mint_badge};

#[derive(Parser)]
#[command(name = "auditx", about = "Full-stack Web3+Web2 security agent", version = "2.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Audit {
        #[arg(short, long, help = "Path to single Solidity contract file")]
        file: Option<PathBuf>,
        
        #[arg(short, long, help = "Path to full project directory")]
        dir: Option<PathBuf>,
        
        #[arg(long, help = "Run only Web3 scans")]
        web3_only: bool,
        
        #[arg(long, help = "Run only Web2 scans")]
        web2_only: bool,
        
        #[arg(long, help = "Skip slow Mythril symbolic execution")]
        no_mythril: bool,
        
        #[arg(long, help = "Pin generated report to IPFS")]
        ipfs: bool,
        
        #[arg(long, help = "Mint Ethereum Attestation Service proof")]
        eas: bool,
        
        #[arg(long, help = "Recipient wallet address to mint SVG Security Badge NFT")]
        mint: Option<String>,
        
        #[arg(long, help = "Enable CI mode (exits non-zero on High/Critical findings)")]
        ci: bool,
        
        #[arg(long, help = "Custom output path for JSON report")]
        output: Option<PathBuf>,

        #[arg(long, value_enum, help = "Run a demo scenario (Clean | Reentrancy | FullStack)")]
        demo: Option<DemoScenario>,
    },
    Demo {
        #[arg(value_enum)]
        scenario: DemoScenario,
    },
    Secrets {
        #[arg(short, long)]
        dir: PathBuf,
    },
    Deps {
        #[arg(short, long)]
        dir: PathBuf,
    },
    Client {
        #[command(subcommand)]
        subcommand: ClientCommands,
    },
}

#[derive(Subcommand)]
enum ClientCommands {
    Register {
        #[arg(long, help = "Name of the client application (e.g. polylance)")]
        name: String,
        
        #[arg(long, help = "Webhook URL to receive HMAC-signed alert notifications")]
        webhook_url: String,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DemoScenario {
    Clean,
    Reentrancy,
    FullStack,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    // Set up logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set tracing subscriber")?;

    let args = Cli::parse();

    match args.command {
        Commands::Audit {
            file,
            dir,
            web3_only,
            web2_only,
            no_mythril,
            ipfs,
            eas,
            mint,
            ci,
            output,
            demo,
        } => {
            let start_time = Instant::now();

            // Handle Demo Scenario inside Audit if requested
            if let Some(scenario) = demo {
                run_demo_scenario(scenario, output, ci, start_time).await?;
                return Ok(());
            }

            // Run standard audit pipeline
            let target_dir = match (&file, &dir) {
                (Some(f), None) => f.parent().unwrap_or(Path::new(".")).to_path_buf(),
                (None, Some(d)) => d.clone(),
                _ => {
                    warn!("Please specify either a file (-f) or a directory (-d).");
                    process::exit(1);
                }
            };

            let proj_type = detect(&target_dir);
            info!("Detected project type: {:?}", proj_type);

            let mut web3_findings = Vec::new();
            let mut web2_findings = Vec::new();
            let mut secret_findings = Vec::new();
            let mut dependency_findings = Vec::new();

            let run_web3 = !web2_only && (proj_type == ProjectType::Web3Only || proj_type == ProjectType::FullStack);
            let run_web2 = !web3_only && (proj_type == ProjectType::Web2Only || proj_type == ProjectType::FullStack);

            if run_web3 {
                let web3_opts = Web3Options {
                    timeout_secs: 120,
                    mythril_enabled: !no_mythril,
                };
                let search_target = file.as_ref().unwrap_or(&target_dir);
                info!("Running Web3 security engine against: {:?}", search_target);
                web3_findings = run_web3_engine(search_target, &web3_opts).await?;
            }

            if run_web2 {
                let web2_opts = Web2Options::default();
                info!("Running Web2 security engine against: {:?}", target_dir);
                let web2_res = run_web2_engine(&target_dir, &web2_opts).await?;
                web2_findings = web2_res.web2_findings;
                secret_findings = web2_res.secret_findings;
                dependency_findings = web2_res.dependency_findings;
            }

            // AI Triage
            let api_key = std::env::var("GEMINI_API_KEY").unwrap_or_default();
            let mut report = if !api_key.is_empty() {
                info!("Sending findings to Gemini AI for deduplication and analysis...");
                let gemini = GeminiClient::new(api_key, "gemini-2.5-pro".to_string());
                let analysis = gemini.analyze(&web3_findings, &web2_findings, &secret_findings, &dependency_findings).await?;
                
                AuditXReport {
                    project_name: target_dir.file_name().and_then(|n| n.to_str()).unwrap_or("AuditX Project").to_string(),
                    audit_date: chrono::Utc::now().to_rfc3339(),
                    web3_cvss: analysis.deduped_web3.iter().map(|f| f.cvss).fold(0.0, f32::max),
                    web2_cvss: analysis.deduped_web2.iter().map(|f| f.cvss).fold(0.0, f32::max),
                    combined_cvss: analysis.combined_system_cvss,
                    web3_findings: analysis.deduped_web3,
                    web2_findings: analysis.deduped_web2,
                    secret_findings,
                    dependency_findings,
                    attack_chains: analysis.attack_chains,
                    ipfs_cid: None,
                    eas_attestation: None,
                    badge_token_id: None,
                    total_critical: 0,
                    total_high: 0,
                    total_medium: 0,
                    total_low: 0,
                    pipeline_duration_ms: start_time.elapsed().as_millis() as u64,
                }
            } else {
                warn!("ANTHROPIC_API_KEY env variable not set. Skipping AI fusion layer.");
                let combined_cvss = f32::max(
                    web3_findings.iter().map(|f| f.cvss).fold(0.0, f32::max),
                    web2_findings.iter().map(|f| f.cvss).fold(0.0, f32::max),
                );

                AuditXReport {
                    project_name: target_dir.file_name().and_then(|n| n.to_str()).unwrap_or("AuditX Project").to_string(),
                    audit_date: chrono::Utc::now().to_rfc3339(),
                    web3_cvss: web3_findings.iter().map(|f| f.cvss).fold(0.0, f32::max),
                    web2_cvss: web2_findings.iter().map(|f| f.cvss).fold(0.0, f32::max),
                    combined_cvss,
                    web3_findings,
                    web2_findings,
                    secret_findings,
                    dependency_findings,
                    attack_chains: vec![],
                    ipfs_cid: None,
                    eas_attestation: None,
                    badge_token_id: None,
                    total_critical: 0,
                    total_high: 0,
                    total_medium: 0,
                    total_low: 0,
                    pipeline_duration_ms: start_time.elapsed().as_millis() as u64,
                }
            };

            // Calculate totals
            let all_severities: Vec<&Severity> = report.web3_findings.iter().map(|f| &f.severity)
                .chain(report.web2_findings.iter().map(|f| &f.severity))
                .chain(report.secret_findings.iter().map(|_| &Severity::High))
                .chain(report.dependency_findings.iter().map(|f| &f.severity))
                .collect();

            for sev in all_severities {
                match sev {
                    Severity::Critical => report.total_critical += 1,
                    Severity::High => report.total_high += 1,
                    Severity::Medium => report.total_medium += 1,
                    Severity::Low | Severity::Informational => report.total_low += 1,
                }
            }

            // Trust Layer: IPFS Upload
            let ipfs_client = IpfsClient::new(std::env::var("PINATA_JWT").ok());
            if ipfs {
                let cid = ipfs_client.upload(&report).await?;
                info!("IPFS Upload successful. CID: {}", cid);
                report.ipfs_cid = Some(cid);
            } else {
                report.ipfs_cid = Some(ipfs_client.generate_offline_cid(&report));
            }

            // Trust Layer: EAS Attestation
            if eas {
                let rpc_url = std::env::var("RPC_URL").unwrap_or_default();
                let priv_key = std::env::var("PRIVATE_KEY").unwrap_or_default();
                let schema_uid = std::env::var("SCHEMA_UID").unwrap_or_default().parse().unwrap_or_default();
                let eas_contract = std::env::var("EAS_CONTRACT").unwrap_or_default().parse().unwrap_or_default();

                if !rpc_url.is_empty() && !priv_key.is_empty() {
                    let eas_client = EasClient::new(rpc_url, priv_key, schema_uid, eas_contract);
                    let attestation = eas_client.attest(&report).await?;
                    info!("EAS Attestation successful. UID/TxHash: {}", attestation);
                    report.eas_attestation = Some(attestation);
                } else {
                    warn!("RPC_URL or PRIVATE_KEY not found in env, skipping EAS attestation.");
                }
            }

            // Trust Layer: Badge Minting
            if let Some(recipient_str) = mint {
                let rpc_url = std::env::var("RPC_URL").unwrap_or_default();
                let priv_key = std::env::var("PRIVATE_KEY").unwrap_or_default();
                let badge_contract = std::env::var("BADGE_CONTRACT").unwrap_or_default().parse().unwrap_or_default();
                let recipient = recipient_str.parse().unwrap_or_default();

                if !rpc_url.is_empty() && !priv_key.is_empty() {
                    let signer: alloy::signers::local::PrivateKeySigner = priv_key.parse()?;
                    let wallet = alloy::network::EthereumWallet::from(signer);
                    let provider = alloy::providers::ProviderBuilder::new()
                        .with_recommended_fillers()
                        .wallet(wallet)
                        .on_builtin(&rpc_url)
                        .await?;

                    let badge_id = mint_badge(
                        &provider,
                        badge_contract,
                        recipient,
                        &report.project_name,
                        report.combined_cvss,
                        report.ipfs_cid.as_ref().unwrap_or(&"".to_string()),
                        true,
                    ).await?;

                    report.badge_token_id = badge_id;
                } else {
                    warn!("RPC_URL or PRIVATE_KEY not found in env, skipping Badge minting.");
                }
            }

            // Update final duration
            report.pipeline_duration_ms = start_time.elapsed().as_millis() as u64;

            // Write report output
            let output_path = output.unwrap_or(PathBuf::from("./auditx-report.json"));
            let json_str = serde_json::to_string_pretty(&report)?;
            tokio::fs::write(&output_path, json_str).await?;
            info!("Final report saved to: {:?}", output_path);

            print_summary_box(&report);

            // CI Mode Check
            if ci {
                if report.total_critical > 0 {
                    info!("CI Gate: {} critical vulnerabilities found. Exiting with code 2.", report.total_critical);
                    process::exit(2);
                } else if report.total_high > 0 {
                    info!("CI Gate: {} high vulnerabilities found. Exiting with code 1.", report.total_high);
                    process::exit(1);
                } else {
                    info!("CI Gate: Clean audit. Exiting with code 0.");
                    process::exit(0);
                }
            }
        }
        Commands::Demo { scenario } => {
            run_demo_scenario(scenario, None, false, Instant::now()).await?;
        }
        Commands::Secrets { dir } => {
            info!("Scanning directory {:?} for secrets...", dir);
            let secrets = auditx_web2::secrets::detect_secrets(&dir).unwrap_or_default();
            println!("{}", serde_json::to_string_pretty(&secrets)?);
        }
        Commands::Deps { dir } => {
            info!("Scanning directory {:?} for package dependencies...", dir);
            let cargo_audit = auditx_web2::cargo_audit::CargoAuditEngine::new();
            let npm_audit = auditx_web2::npm_audit::NpmAuditEngine::new();
            
            let mut deps = Vec::new();
            if let Ok(c_findings) = cargo_audit.run(&dir).await {
                deps.extend(c_findings);
            }
            if let Ok(n_findings) = npm_audit.run(&dir).await {
                deps.extend(n_findings);
            }
            println!("{}", serde_json::to_string_pretty(&deps)?);
        }
        Commands::Client { subcommand } => {
            match subcommand {
                ClientCommands::Register { name, webhook_url } => {
                    let registry = auditx_core::MultiTenantRegistry::new();
                    let (client, raw_api_key, webhook_secret) = registry.register_client(&name, &webhook_url);
                    println!(r#"
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 AuditX SIEM Client Registration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Client Name:    {}
 Client ID:      {}
 Webhook URL:    {}
 Created At:     {}

 🔑 API KEY (save now, never shown again):
    {}

 🔐 WEBHOOK SECRET (use to verify X-AuditX-Signature):
    {}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"#,
                        client.name,
                        client.id,
                        client.webhook_url,
                        client.created_at,
                        raw_api_key,
                        webhook_secret
                    );
                }
            }
        }
    }

    Ok(())
}

fn print_summary_box(report: &AuditXReport) {
    let severity_name = if report.combined_cvss >= 9.0 {
        "Critical"
    } else if report.combined_cvss >= 7.0 {
        "High"
    } else if report.combined_cvss >= 4.0 {
        "Medium"
    } else {
        "Low"
    };

    let total_secs = report.pipeline_duration_ms / 1000;
    let mins = total_secs / 60;
    let secs = total_secs % 60;

    let badge_type = if report.combined_cvss >= 7.0 {
        "Amber Guard (CVSS ≥ 7.0 — fix issues for Emerald)".to_string()
    } else {
        match report.badge_token_id {
            Some(id) => format!("Emerald Guard (Token ID: {})", id),
            None => "Emerald Guard (Mint Skipped/Eligible)".to_string(),
        }
    };

    println!(r#"
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 AuditX v2.0 — Audit Complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Project:      {}
 System CVSS:  {:.1} ({})
 Web3 CVSS:    {:.1}
 Web2 CVSS:    {:.1}
 Critical:     {}  High: {}  Medium: {}  Low: {}
 Attack chains: {} detected
 Badge:        {}
 IPFS:         {}
 EAS:          {}
 Duration:     {}m {}s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"#,
        report.project_name,
        report.combined_cvss,
        severity_name,
        report.web3_cvss,
        report.web2_cvss,
        report.total_critical,
        report.total_high,
        report.total_medium,
        report.total_low,
        report.attack_chains.len(),
        badge_type,
        report.ipfs_cid.as_ref().unwrap_or(&"None".to_string()),
        report.eas_attestation.as_ref().unwrap_or(&"None".to_string()),
        mins,
        secs
    );
}

async fn run_demo_scenario(scenario: DemoScenario, output: Option<PathBuf>, ci: bool, start_time: Instant) -> Result<()> {
    info!("Running Demo Scenario: {:?}", scenario);
    
    let mut report = AuditXReport {
        project_name: format!("Demo Project ({:?})", scenario),
        audit_date: chrono::Utc::now().to_rfc3339(),
        web3_cvss: 0.0,
        web2_cvss: 0.0,
        combined_cvss: 0.0,
        web3_findings: vec![],
        web2_findings: vec![],
        secret_findings: vec![],
        dependency_findings: vec![],
        attack_chains: vec![],
        ipfs_cid: Some("QmDemoOfflineCID00000000000000".to_string()),
        eas_attestation: None,
        badge_token_id: None,
        total_critical: 0,
        total_high: 0,
        total_medium: 0,
        total_low: 0,
        pipeline_duration_ms: 0,
    };

    match scenario {
        DemoScenario::Clean => {
            report.combined_cvss = 1.8;
            report.web3_findings.push(Web3Finding {
                id: "web3-custom-gas-opt-1".to_string(),
                tool: "custom".to_string(),
                swc_id: None,
                severity: Severity::Low,
                cvss: 1.8,
                title: "Gas Optimization: public vs external".to_string(),
                description: "State read functions can be declared external to reduce deployment gas.".to_string(),
                file: "CleanContract.sol".to_string(),
                line: Some(12),
                remediation: "Change public visibility to external for read-only view calls.".to_string(),
            });
            report.total_low = 1;
            report.badge_token_id = Some(42); // Simulated mint
        }
        DemoScenario::Reentrancy => {
            report.combined_cvss = 8.5;
            report.web3_findings.push(Web3Finding {
                id: "web3-slither-reentrancy-1".to_string(),
                tool: "slither".to_string(),
                swc_id: Some("SWC-107".to_string()),
                severity: Severity::High,
                cvss: 8.5,
                title: "Reentrancy vulnerability".to_string(),
                description: "Unchecked call sends ether to recipient before resolving internal state balance updates.".to_string(),
                file: "VulnerableVault.sol".to_string(),
                line: Some(42),
                remediation: "Update balances before executing transfer calls (checks-effects-interactions pattern).".to_string(),
            });
            report.total_high = 1;
        }
        DemoScenario::FullStack => {
            report.combined_cvss = 9.8;
            report.web3_findings.push(Web3Finding {
                id: "web3-custom-replay-1".to_string(),
                tool: "custom".to_string(),
                swc_id: Some("SWC-121".to_string()),
                severity: Severity::High,
                cvss: 8.0,
                title: "Cross-Contract Signature Replay".to_string(),
                description: "Missing contract address in signed hashes allows execution replaying.".to_string(),
                file: "Escrow.sol".to_string(),
                line: Some(90),
                remediation: "Bind address(this) into signed digest.".to_string(),
            });
            report.web2_findings.push(Web2Finding {
                id: "web2-semgrep-cmd-injection-1".to_string(),
                tool: "semgrep".to_string(),
                owasp_id: Some("OWASP A03:2021-Injection".to_string()),
                severity: Severity::Critical,
                cvss: 9.8,
                title: "Command Injection in node backend".to_string(),
                description: "User input concatenated directly into child_process.exec call.".to_string(),
                file: "server.js".to_string(),
                line: Some(214),
                remediation: "Avoid command shell executions, parse parameters cleanly or use safe spawn calls.".to_string(),
            });
            report.attack_chains.push(AttackChain {
                chain_id: "CHAIN-01".to_string(),
                title: "Web2 Command Injection yields Web3 contract compromise".to_string(),
                steps: vec![
                    AttackStep {
                        layer: Layer::Web2,
                        finding_ref: "Command Injection in node backend".to_string(),
                        description: "Attacker executes code on Node server".to_string(),
                        enables_next: "Extract private keys stored in server env config".to_string(),
                    },
                    AttackStep {
                        layer: Layer::Web3,
                        finding_ref: "Cross-Contract Signature Replay".to_string(),
                        description: "Attacker replays administrator signature to drain Escrow".to_string(),
                        enables_next: "Complete project vault drainage".to_string(),
                    }
                ],
                combined_cvss: 9.8,
                likelihood: Likelihood::High,
                web2_remediation: "Fix the input validation in Node.js backend server.".to_string(),
                web3_remediation: "Incorporate address(this) into signature check.".to_string(),
            });
            report.total_critical = 1;
            report.total_high = 1;
        }
    }

    report.pipeline_duration_ms = start_time.elapsed().as_millis() as u64;

    let output_path = output.unwrap_or(PathBuf::from("./auditx-report.json"));
    let json_str = serde_json::to_string_pretty(&report)?;
    tokio::fs::write(&output_path, json_str).await?;
    info!("Demo report saved to: {:?}", output_path);

    print_summary_box(&report);

    if ci {
        if report.total_critical > 0 {
            info!("CI Gate: {} critical vulnerabilities found. Exiting with code 2.", report.total_critical);
            process::exit(2);
        } else if report.total_high > 0 {
            info!("CI Gate: {} high vulnerabilities found. Exiting with code 1.", report.total_high);
            process::exit(1);
        } else {
            info!("CI Gate: Clean audit. Exiting with code 0.");
            process::exit(0);
        }
    }

    Ok(())
}
