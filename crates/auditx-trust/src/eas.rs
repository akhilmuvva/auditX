use alloy::{
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    primitives::{Address, FixedBytes, U256},
    network::EthereumWallet,
    sol,
    sol_types::SolValue,
};
use anyhow::{Result, Context, anyhow};
use auditx_core::report::AuditXReport;

sol! {
    #[sol(rpc)]
    interface IEAS {
        struct AttestationRequestData {
            address recipient;
            uint64 expirationTime;
            bool revocable;
            bytes32 refUID;
            bytes data;
            uint256 value;
        }

        struct AttestationRequest {
            bytes32 schema;
            AttestationRequestData data;
        }

        function attest(AttestationRequest calldata request) external payable returns (bytes32);
    }
}

pub struct EasClient {
    pub rpc_url: String,
    pub private_key: String,
    pub schema_uid: FixedBytes<32>,
    pub eas_contract: Address,
}

impl EasClient {
    pub fn new(rpc_url: String, private_key: String, schema_uid: FixedBytes<32>, eas_contract: Address) -> Self {
        Self { rpc_url, private_key, schema_uid, eas_contract }
    }

    pub async fn attest(&self, report: &AuditXReport) -> Result<String> {
        let signer: PrivateKeySigner = self.private_key.parse()
            .map_err(|e| anyhow!("Failed to parse private key: {}", e))?;
        
        let wallet = EthereumWallet::from(signer);
        
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_builtin(&self.rpc_url)
            .await
            .context("Failed to construct provider")?;

        // ABI-encode: (string target, uint256 web3Cvss, uint256 web2Cvss, uint256 systemCvss, string ipfsCid, uint256 ts)
        // Scale float CVSS scores to uint256 (e.g. multiplied by 100 for decimals)
        let web3_cvss_u = U256::from((report.web3_cvss * 100.0) as u64);
        let web2_cvss_u = U256::from((report.web2_cvss * 100.0) as u64);
        let system_cvss_u = U256::from((report.combined_cvss * 100.0) as u64);
        let ts = U256::from(chrono::Utc::now().timestamp());

        let payload = (
            report.project_name.clone(),
            web3_cvss_u,
            web2_cvss_u,
            system_cvss_u,
            report.ipfs_cid.clone().unwrap_or_default(),
            ts,
        );
        let encoded_data = payload.abi_encode();

        let req_data = IEAS::AttestationRequestData {
            recipient: Address::ZERO,
            expirationTime: 0,
            revocable: true,
            refUID: FixedBytes::ZERO,
            data: encoded_data.into(),
            value: U256::ZERO,
        };

        let request = IEAS::AttestationRequest {
            schema: self.schema_uid,
            data: req_data,
        };

        let eas_contract = IEAS::new(self.eas_contract, &provider);
        
        let tx_receipt = eas_contract.attest(request)
            .send()
            .await
            .context("Failed to send EAS attest transaction")?
            .get_receipt()
            .await
            .context("Failed to get EAS attest transaction receipt")?;

        let tx_hash_str = format!("{:?}", tx_receipt.transaction_hash);
        Ok(tx_hash_str)
    }
}
