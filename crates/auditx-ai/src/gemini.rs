use reqwest::Client;
use serde::{Serialize, Deserialize};
use anyhow::{Result, Context, anyhow};
use auditx_core::{Web3Finding, Web2Finding, SecretFinding, DependencyFinding, AttackChain};
use crate::prompt::build_fusion_prompt;

pub struct GeminiClient {
    pub api_key: String,
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiAnalysis {
    pub deduped_web3: Vec<Web3Finding>,
    pub deduped_web2: Vec<Web2Finding>,
    pub attack_chains: Vec<AttackChain>,
    pub combined_system_cvss: f32,
    pub executive_summary: String,
}

impl GeminiClient {
    pub fn new(api_key: String, model: String) -> Self {
        Self { api_key, model }
    }

    pub async fn analyze(
        &self,
        web3_findings: &[Web3Finding],
        web2_findings: &[Web2Finding],
        secret_findings: &[SecretFinding],
        dependency_findings: &[DependencyFinding],
    ) -> Result<GeminiAnalysis> {
        let prompt = build_fusion_prompt(
            web3_findings,
            web2_findings,
            secret_findings,
            dependency_findings,
        );

        let body = serde_json::json!({
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
        });

        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.model, self.api_key
        );

        let response = Client::new()
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("Failed to send request to Gemini API")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Gemini API error status {}: {}", status, text));
        }

        let res_json: serde_json::Value = response.json().await.context("Failed to parse Gemini API response JSON")?;
        
        let content_text = res_json.get("candidates")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|f| f.get("content"))
            .and_then(|c| c.get("parts"))
            .and_then(|p| p.as_array())
            .and_then(|arr| arr.first())
            .and_then(|f| f.get("text"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| anyhow!("Unexpected Gemini response structure: candidates content text not found"))?;

        // Extract JSON from output
        let start = content_text.find('{').unwrap_or(0);
        let end = content_text.rfind('}').unwrap_or(content_text.len() - 1);
        let json_str = &content_text[start..=end];

        let analysis: GeminiAnalysis = serde_json::from_str(json_str)
            .context("Failed to deserialize Gemini response into GeminiAnalysis struct")?;

        Ok(analysis)
    }
}
