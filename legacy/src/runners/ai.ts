import fs from 'fs';
import { emitStep } from '../events.js';
import { writeIncrementalReport, delay } from '../utils/helpers.js';
import fetch from 'node-fetch';
import { ZKCheckResult } from '../analysis/zkChecks.js';

export async function runAIAnalysis(findings: any[], contractFiles: string[], reportDir: string, zkResults: ZKCheckResult[] = []) {
  emitStep('ai-triage', 'active', { message: `Packaging heuristics for AI Triage (Claude Sonnet)...` });

  const API_KEY = process.env.ANTHROPIC_API_KEY;
  if (!API_KEY) {
    emitStep('ai-triage', 'error', { message: `No ANTHROPIC_API_KEY found, skipping AI triage.` });
    return { summary: "Skipped", riskLevel: "unknown", detailedFindings: [] };
  }

  let contractSource = '';
  for (const file of contractFiles) {
    if (fs.existsSync(file)) {
      contractSource += `\n--- ${file} ---\n` + fs.readFileSync(file, 'utf-8');
    }
  }

  const prompt = `
    You are AuditX, an elite smart contract security auditor and SIEM analyst.
    You analyze smart contracts for pre-deploy vulnerabilities AND post-deploy runtime threats.

    ═══════════════════════════════════════════════════════════
    STATIC ANALYSIS TRIAGE
    ═══════════════════════════════════════════════════════════
    Analyze the raw findings from Slither and Mythril, and the provided smart contract source code.
    Filter out false positives, aggregate duplicates, and return a final list of true vulnerabilities.

    ═══════════════════════════════════════════════════════════
    ZK CHECKS INTEGRATION
    ═══════════════════════════════════════════════════════════
    Each FAILED ZK check MUST add +1.5 to the final CVSS score.
    Checks:
      VULN-1 REPLAY  — nullifier must bind chainId + address(this)
      VULN-2 QUALIFIED — _pubSignals[0]==1 must be the FIRST require
      VULN-3 THRESHOLD — _pubSignals[1]>=minimumThreshold must be SECOND
      VULN-4 DOMAIN SEP — chainId + address(this) baked into every nullifier
      VULN-5 TIMELOCK  — 48h delay on verifier upgrades

    ═══════════════════════════════════════════════════════════
    BADGE TIER DECISION RULES
    ═══════════════════════════════════════════════════════════
    Compute finalCvss = min(10.0, baseCvss + zkCvssAdjustment)
    where zkCvssAdjustment = (number of failed ZK checks) * 1.5

    Badge assignment:
      finalCvss >= 9.0  → "RED"    (critical — do not deploy)
      finalCvss >= 7.0  → "AMBER"  (high risk — major fixes required)
      finalCvss >= 4.0  → "AMBER"  (medium risk — fixes required)
      finalCvss <  4.0  → "EMERALD" (low risk — safe to deploy)

    Additionally assign AMBER if any ZK check fails with individual cvss >= 3.0.

    ═══════════════════════════════════════════════════════════
    SIEM RUNTIME CONTEXT
    ═══════════════════════════════════════════════════════════
    You are integrated into a post-deploy SIEM monitoring system.
    When assessing runtime event patterns, watch for:
      • Reentrancy signals: high-gas withdrawals with non-zero ETH value
      • Oracle manipulation: >50% price change in single update
      • Flash loan patterns: gasUsed z-score > 3σ above baseline
      • Governance attacks: rapid proposal creation + execution in one block
      • Upgrade hijacking: BeaconUpgraded/Upgraded events from non-multisig
      • Threat Intelligence: any 'from' or arg address in sanctioned/exploit feeds

    For SIEM-triggered analysis, explain the anomaly and whether it represents
    a live exploit attempt or benign activity.

    ═══════════════════════════════════════════════════════════
    RESPONSE FORMAT
    ═══════════════════════════════════════════════════════════
    Return EXACTLY a JSON object (no markdown, no backticks, just raw JSON):
    {
      "summary": "High level summary",
      "riskLevel": "critical|high|medium|low|safe",
      "cvssScore": 0.0,
      "badge": "RED|AMBER|EMERALD",
      "zkSummary": "Summary of ZK checks — which passed/failed and why",
      "siemInsights": "Runtime threat assessment (empty string if no SIEM context)",
      "detailedFindings": [
        {
          "severity": "critical|high|medium|low|info",
          "title": "Short title",
          "tool": "Slither|Mythril|ZKCheck|SIEM",
          "desc": "Detailed explanation",
          "loc": "ContractName:Line",
          "vulnCode": "The vulnerable lines (empty string if N/A)",
          "fixCode": "How to fix it"
        }
      ]
    }

    Raw Static Findings:
    ${JSON.stringify(findings, null, 2).substring(0, 5000)}

    ZK Check Results:
    ${JSON.stringify(zkResults, null, 2)}

    Source Code:
    ${contractSource.substring(0, 10000)}
  `;

  const requestBody = {
    model: "claude-3-sonnet-20240229",
    max_tokens: 2000,
    messages: [{ role: "user", content: prompt }]
  };

  let attempt = 0;
  const maxRetries = 3;
  let backoffDelay = 2000;

  while (attempt < maxRetries) {
    attempt++;
    try {
      emitStep('ai-triage', 'active', { message: `Calling Anthropic API (Attempt ${attempt}/${maxRetries})...` });
      
      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "x-api-key": API_KEY,
          "anthropic-version": "2023-06-01",
          "content-type": "application/json"
        },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw new Error(`Anthropic API error: ${response.status} ${response.statusText}`);
      }

      const data: any = await response.json();
      const rawText = data.content[0].text.trim();
      
      const jsonStart = rawText.indexOf('{');
      const jsonEnd = rawText.lastIndexOf('}');
      if (jsonStart === -1 || jsonEnd === -1) throw new Error("No JSON object found in response");
      
      const cleanJson = rawText.substring(jsonStart, jsonEnd + 1);
      const result = JSON.parse(cleanJson);
      
      emitStep('ai-triage', 'complete', { message: `AI Triage complete. Assessed Risk: ${result.riskLevel.toUpperCase()}, CVSS: ${result.cvssScore}` });
      writeIncrementalReport(reportDir, { aiAnalysis: result });
      return result;

    } catch (error: any) {
      emitStep('ai-triage', 'error', { message: `AI API Error: ${error.message}` });
      if (attempt >= maxRetries) {
        emitStep('ai-triage', 'error', { message: `Max retries reached for AI Triage. Falling back to raw findings.` });
        writeIncrementalReport(reportDir, { aiAnalysisError: error.message });
        return { summary: "AI Triage Failed", riskLevel: "unknown", cvssScore: 0.0, detailedFindings: [] };
      }
      emitStep('ai-triage', 'active', { message: `Retrying in ${backoffDelay}ms...` });
      await delay(backoffDelay);
      backoffDelay *= 2;
    }
  }
}
