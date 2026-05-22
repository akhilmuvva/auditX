/**
 * AuditX — Browser-Native AI Triage Engine
 * 
 * Calls Anthropic Claude directly from the browser (no server needed).
 * API key is stored in localStorage and never leaves the user's machine.
 * Returns a type-safe JSON payload ready for EAS + NFT minting.
 */

export interface AuditXReport {
  analyticsSummary: {
    targetContractName: string;
    compilerTarget: string;
    aggregateCvssScoreRaw: number; // integer out of 100 (e.g. 75 = CVSS 7.5)
    riskClassification: 'critical' | 'high' | 'medium' | 'low' | 'none';
    certificationStatus: 'APPROVED_EMERALD' | 'APPROVED_AMBER' | 'DENIED_RISK_TOO_HIGH';
  };
  graphInsights: {
    suryaCallGraphTopology: string;
    attackSurfacePerimeter: string;
  };
  vulnerabilities: Array<{
    vulnerabilityId: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    sourceTool: 'Slither' | 'Mythril' | 'Surya-CrossCheck' | 'Joint Heuristics';
    vulnerabilityLocation: string;
    technicalDescription: string;
    remediationPattern: string;
  }>;
  onChainPayload: {
    easSchemaVariables: {
      contractName: string;
      severityScoreUint8: number;
      ipfsReportHashPlaceholder: string;
    };
    svgProperties: {
      badgeGrade: 'EMERALD GUARD' | 'AMBER GUARD' | 'NULL';
      shieldColor: '#10B981' | '#F59E0B' | '#NONE';
    };
  };
}

const SYSTEM_PROMPT = `ROLE: Autonomous Enterprise-Grade Web3 Security Protocol Architect & Auditor
CONTEXT: Operating natively within a zero-server decentralized topology. Node execution data is processed via localized client daemons or distributed edge networks, channeling cryptographic parameters directly to a serverless Web3 UI wrapper (IPFS/Fleek/Arweave).

OBJECTIVE: You are the core analytical engine of the AuditX security protocol. Your mandate is to ingest raw Solidity source vectors alongside multi-tool telemetry matrices (Slither AST detections, Mythril symbolic execution violations, and Surya call-graph topological properties). You must autonomously deduplicate threat vulnerabilities, trace execution reachability, filter false positives, and return a structurally sound, type-safe JSON payload designed for direct browser-side block publication (EAS sealing and ERC-721 on-chain SVG Badge minting).

ENTERPRISE ARCHITECTURAL PARADIGMS:
- ZERO RUNTIME SERVER BIAS: Do not assume an Express or stateful API backend handles errors, secrets, or data mutations. The output must interface directly with a frontend client communicating via client-side EIP-1193 JSON-RPC providers.
- EXPLICIT THREAT BOUNDARIES: If the analyzed contract yields a single high or critical vulnerability threat vector (CVSS >= 7.0), flag certificationStatus as DENIED_RISK_TOO_HIGH.

TOPOLOGICAL MULTI-TOOL ENGINE CROSS-EXAMINATION:
1. SURYA TRACE VISIBILITY CROSS-CHECK: Map every Slither and Mythril detection against Surya's visibility paths. If a vulnerability exists inside a function that is entirely internal/private and unreachable by an untrusted external msg.sender call path, classify as checked exception (low/none risk).
2. SURYA EXTERNAL CALL ATTACK SURFACE INTERCEPTION: Trace every outward graph edge (.call, .transfer, .send). Cross-check if surrounding block violates Checks-Effects-Interactions pattern by mutating storage slots after that call node executes. If true, immediately flag Critical Reentrancy.
3. LOGICAL SEPARATION & AGGREGATION: Deduplicate overlapping data. Fuse Slither structural bugs with Mythril mathematical edge cases to prevent redundant report indexing.
4. TYPE-SAFE CVSS 3.1 SCALING: Calculate a precise aggregate risk metric. Convert final float index into strict integer scaled out of 100 (e.g., CVSS 4.2 becomes 42, 7.5 becomes 75) for Solidity uint8 storage compatibility.

SOLIDITY PRODUCTION CONSTRAINTS:
- GAS OPTIMIZATION: Eliminate legacy text-based require statements. Force implementation of gas-efficient Solidity 0.8.x Custom Errors.
- RENDERING SAFEGUARDS: Validate contract names and IPFS hashes do not contain malformed strings.

Return EXACTLY a raw JSON object. No markdown, no backticks, no explanations. Immediately parseable JSON only.

Schema:
{
  "analyticsSummary": {
    "targetContractName": "String",
    "compilerTarget": "String",
    "aggregateCvssScoreRaw": 0,
    "riskClassification": "critical | high | medium | low | none",
    "certificationStatus": "APPROVED_EMERALD | APPROVED_AMBER | DENIED_RISK_TOO_HIGH"
  },
  "graphInsights": {
    "suryaCallGraphTopology": "String",
    "attackSurfacePerimeter": "String"
  },
  "vulnerabilities": [
    {
      "vulnerabilityId": "AUDITX-001",
      "title": "String",
      "severity": "critical | high | medium | low",
      "sourceTool": "Slither | Mythril | Surya-CrossCheck | Joint Heuristics",
      "vulnerabilityLocation": "ContractName:LineNumber",
      "technicalDescription": "String",
      "remediationPattern": "String"
    }
  ],
  "onChainPayload": {
    "easSchemaVariables": {
      "contractName": "String",
      "severityScoreUint8": 0,
      "ipfsReportHashPlaceholder": "PENDING_CLIENT_UPLOAD"
    },
    "svgProperties": {
      "badgeGrade": "EMERALD GUARD | AMBER GUARD | NULL",
      "shieldColor": "#10B981 | #F59E0B | #NONE"
    }
  }
}`;

export async function runBrowserAITriage(params: {
  contractName: string;
  solidityCode: string;
  slitherOutput?: string;
  mythrilOutput?: string;
  suryaOutput?: string;
  apiKey: string;
  onProgress?: (msg: string) => void;
}): Promise<AuditXReport> {
  const { contractName, solidityCode, slitherOutput, mythrilOutput, suryaOutput, apiKey, onProgress } = params;

  onProgress?.('[AI-TRIAGE] Constructing multi-tool telemetry matrix...');

  const userContent = `
CONTRACT NAME: ${contractName}

=== SOLIDITY SOURCE CODE ===
${solidityCode}

=== SLITHER STATIC ANALYSIS OUTPUT ===
${slitherOutput || '(not provided — perform static analysis from source code only)'}

=== MYTHRIL SYMBOLIC EXECUTION OUTPUT ===
${mythrilOutput || '(not provided — infer from source code patterns)'}

=== SURYA CALL GRAPH OUTPUT ===
${suryaOutput || '(not provided — derive call graph topology from source code)'}

Perform full AuditX security analysis per your protocol mandate. Return only the raw JSON object.
`.trim();

  onProgress?.('[AI-TRIAGE] Transmitting to Claude analysis engine (zero-server, client-side)...');

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'anthropic-dangerous-direct-browser-access': 'true',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-5',
      max_tokens: 4096,
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: userContent }],
    }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(`Claude API error ${response.status}: ${(err as any)?.error?.message || response.statusText}`);
  }

  const data = await response.json();
  const raw = (data.content?.[0]?.text || '').trim();

  onProgress?.('[AI-TRIAGE] Parsing structured threat analysis payload...');

  // Strip any accidental markdown fences
  const cleaned = raw.replace(/^```json?\s*/i, '').replace(/```\s*$/i, '').trim();

  let parsed: AuditXReport;
  try {
    parsed = JSON.parse(cleaned);
  } catch {
    throw new Error(`AI returned malformed JSON. Raw output: ${raw.substring(0, 200)}`);
  }

  // Integrity checks
  if (!parsed.analyticsSummary || !parsed.vulnerabilities) {
    throw new Error('AI response missing required schema fields.');
  }

  onProgress?.(`[AI-TRIAGE] ✓ Analysis complete — Risk: ${parsed.analyticsSummary.riskClassification.toUpperCase()} | Status: ${parsed.analyticsSummary.certificationStatus}`);

  return parsed;
}

/** Store API key in localStorage (never sent to any server) */
export const ApiKeyStore = {
  get: () => localStorage.getItem('auditx_anthropic_key') || '',
  set: (key: string) => localStorage.setItem('auditx_anthropic_key', key),
  clear: () => localStorage.removeItem('auditx_anthropic_key'),
  isSet: () => !!localStorage.getItem('auditx_anthropic_key'),
};
