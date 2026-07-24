use reqwest::Client;
use serde_json::Value;
use anyhow::{Result, Context, anyhow};
use auditx_core::report::AuditXReport;
use crate::cid::generate_cid_v0;

pub struct IpfsClient {
    pub pinata_jwt: Option<String>,  // None = offline mode
}

impl IpfsClient {
    pub fn new(pinata_jwt: Option<String>) -> Self {
        Self { pinata_jwt }
    }

    pub async fn upload(&self, report: &AuditXReport) -> Result<String> {
        match &self.pinata_jwt {
            Some(jwt) => self.upload_pinata(report, jwt).await,
            None => Ok(self.generate_offline_cid(report)),
        }
    }

    async fn upload_pinata(&self, report: &AuditXReport, jwt: &str) -> Result<String> {
        let client = Client::new();
        let payload = serde_json::to_value(report).context("Failed to serialize report to JSON")?;

        let response = client
            .post("https://api.pinata.cloud/pinning/pinJSONToIPFS")
            .bearer_auth(jwt)
            .json(&payload)
            .send()
            .await
            .context("Failed to send request to Pinata API")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Pinata API error status {}: {}", status, text));
        }

        let res_json: Value = response.json().await.context("Failed to parse Pinata response JSON")?;
        let cid = res_json.get("IpfsHash")
            .and_then(|h| h.as_str())
            .ok_or_else(|| anyhow!("IpfsHash not found in Pinata response"))?
            .to_string();

        Ok(cid)
    }

    pub fn generate_offline_cid(&self, report: &AuditXReport) -> String {
        let serialized = serde_json::to_vec(report).unwrap_or_default();
        generate_cid_v0(&serialized)
    }
}
