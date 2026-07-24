use alloy::{
    providers::Provider,
    primitives::{Address, U256},
    sol,
};
use anyhow::{Result, Context, anyhow};
use tracing::info;

sol! {
    #[sol(rpc)]
    interface IAuditBadgeNFT {
        function mintBadge(
            address recipient,
            string calldata contractName,
            uint8 severityScore,
            string calldata ipfsCid,
            bool zkChecksPassed
        ) external returns (uint256);

        event BadgeMinted(address indexed recipient, uint256 indexed tokenId, string contractName, uint8 score, string ipfsCid, bool zkChecksPassed);
    }
}

pub async fn mint_badge(
    provider: &impl Provider,
    contract_address: Address,
    recipient: Address,
    contract_name: &str,
    cvss: f32,
    ipfs_cid: &str,
    zk_checks_passed: bool,
) -> Result<Option<u64>> {
    // Only mint if cvss < 7.0
    if cvss >= 7.0 {
        info!("CVSS {:.1} >= 7.0 — badge mint skipped", cvss);
        return Ok(None);
    }

    let severity_score = (cvss * 10.0) as u8;
    let badge_contract = IAuditBadgeNFT::new(contract_address, provider);

    info!("Minting badge for {} (recipient: {}) on-chain...", contract_name, recipient);

    let tx_receipt = badge_contract.mintBadge(
        recipient,
        contract_name.to_string(),
        severity_score,
        ipfs_cid.to_string(),
        zk_checks_passed,
    )
    .send()
    .await
    .context("Failed to send mintBadge transaction")?
    .get_receipt()
    .await
    .context("Failed to get transaction receipt for mintBadge")?;

    // Parse logs for BadgeMinted event
    for log in &tx_receipt.inner.logs {
        if let Ok(event) = log.log_decode::<IAuditBadgeNFT::BadgeMinted>() {
            let token_id = event.tokenId.to::<u64>();
            info!("Successfully minted badge token ID: {}", token_id);
            return Ok(Some(token_id));
        }
    }

    // Default return if event decoding fails but transaction succeeded
    Ok(Some(0))
}
