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
    You are AuditX, an elite smart contract security auditor.
    Analyze the following raw findings from Slither and Mythril, and the provided smart contract code.
    Filter out false positives, aggregate duplicates, and return a final list of true vulnerabilities.
    
    Return EXACTLY a JSON object with this structure (no markdown, no backticks, just raw JSON):
    {
      "summary": "High level summary",
      "riskLevel": "critical|high|medium|low|safe",
      "cvssScore": 0.0,
      "zkSummary": "Summary of ZK checks",
      "detailedFindings": [
        {
          "severity": "high",
          "title": "Short title",
          "tool": "Slither/Mythril",
          "desc": "Detailed explanation",
          "loc": "ContractName:Line",
          "vulnCode": "The vulnerable lines",
          "fixCode": "How to fix it"
        }
      ]
    }

    Raw Findings:
    ${JSON.stringify(findings, null, 2).substring(0, 5000)}

    ZK Check Results (Each failed ZK check MUST add +1.5 to the final CVSS score):
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
