/**
 * AuditX — Browser-Native AI Triage Engine (Google Gemini)
 *
 * Calls Google Gemini API directly from the browser — zero server needed.
 * API key stored in localStorage only, never leaves the user's machine.
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
    mermaidGraph: string;
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
CONTEXT: Operating natively within a zero-server decentralized topology.

OBJECTIVE: You are the core analytical engine of the AuditX security protocol. Ingest raw Solidity source vectors alongside multi-tool telemetry matrices (Slither AST detections, Mythril symbolic execution violations, Surya call-graph topological properties). Autonomously deduplicate threat vulnerabilities, trace execution reachability, filter false positives, and return a structurally sound, type-safe JSON payload for browser-side EAS sealing and ERC-721 SVG Badge minting.

ENTERPRISE RULES:
- ZERO RUNTIME SERVER BIAS: Output interfaces directly with EIP-1193 JSON-RPC providers.
- EXPLICIT THREAT BOUNDARIES: If CVSS >= 7.0, set certificationStatus = DENIED_RISK_TOO_HIGH.

ANALYSIS STEPS:
1. SURYA TRACE VISIBILITY CROSS-CHECK: Map Slither/Mythril detections against Surya visibility paths. If a vulnerable function is entirely internal/private and unreachable by external msg.sender, classify as low/none risk.
2. SURYA EXTERNAL CALL ATTACK SURFACE: Trace every .call/.transfer/.send edge. If surrounding block mutates storage AFTER the call (violates CEI pattern), flag Critical Reentrancy.
3. DEDUPLICATION: Merge overlapping Slither + Mythril findings. No redundant report entries.
4. CVSS SCALING: Convert CVSS float to strict integer × 10 (e.g. CVSS 7.5 → 75) for Solidity uint8 compatibility.
5. MERMAID GENERATION: Create a concise, professional Mermaid.js flowchart representing the primary control flow of the contract.

SOLIDITY REMEDIATION RULES:
- Replace ALL require("string") with Solidity 0.8.x Custom Errors.
- All remediation code must be gas-optimized.

CRITICAL: Return ONLY a raw JSON object. No markdown fences, no backticks, no explanations. Pure JSON only.

JSON Schema to return:
{
  "analyticsSummary": {
    "targetContractName": "String",
    "compilerTarget": "String",
    "aggregateCvssScoreRaw": 0,
    "riskClassification": "critical | high | medium | low | none",
    "certificationStatus": "APPROVED_EMERALD | APPROVED_AMBER | DENIED_RISK_TOO_HIGH"
  },
  "graphInsights": {
    "suryaCallGraphTopology": "string (Textual summary of the call graph architecture)",
    "attackSurfacePerimeter": "string (Analysis of public/external entry points)",
    "mermaidGraph": "string (A valid Mermaid.js graph code e.g. 'graph TD\\\\n A-->B' representing the contract's topological function call graph. Keep it clean and visually professional. No markdown code blocks like [mermaid] just the raw syntax.)"
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

// Use gemini-flash-latest (fastest, confirmed working)
const GEMINI_MODEL = 'gemini-flash-latest';
const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';

export async function runAiTriage(
  files: { contractName: string; sol: string; slither?: string; mythril?: string; surya?: string },
  onProgress?: (msg: string, type?: 'info' | 'success' | 'warning' | 'error') => void
): Promise<AuditXReport> {
  const apiKey = import.meta.env.VITE_GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('Server misconfiguration: VITE_GEMINI_API_KEY is not set in environment variables.');
  }

  const { contractName, sol, slither, mythril, surya } = files;

  onProgress?.('[GEMINI] Constructing multi-tool telemetry matrix...');

  const userContent = `
CONTRACT NAME: ${contractName}

=== SOLIDITY SOURCE CODE ===
${sol}

=== SLITHER STATIC ANALYSIS OUTPUT ===
${slither || '(not provided — perform static analysis from source code only)'}

=== MYTHRIL SYMBOLIC EXECUTION OUTPUT ===
${mythril || '(not provided — infer from source code patterns)'}

=== SURYA CALL GRAPH OUTPUT ===
${surya || '(not provided — derive call graph topology from source code)'}

Perform full AuditX security analysis. Return ONLY the raw JSON object matching the schema — no markdown, no extra text.
`.trim();

  onProgress?.('[GEMINI] Transmitting to Gemini analysis engine (browser-native, zero-server)...');

  const url = `${GEMINI_API_BASE}/${GEMINI_MODEL}:generateContent`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-goog-api-key': apiKey,
    },
    body: JSON.stringify({
      system_instruction: {
        parts: [{ text: SYSTEM_PROMPT }]
      },
      contents: [
        {
          role: 'user',
          parts: [{ text: userContent }],
        },
      ],
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens: 8192,
        responseMimeType: 'application/json',
      },
    }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    const msg = (err as any)?.error?.message || response.statusText;
    throw new Error(`Gemini API error ${response.status}: ${msg}`);
  }

  const data = await response.json();

  // Extract text from Gemini response structure
  const raw = data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';

  if (!raw) {
    throw new Error('Gemini returned an empty response. Check your API key and model quota.');
  }

  onProgress?.('[GEMINI] Parsing structured threat analysis payload...');

  // Strip accidental markdown fences if model ignored responseMimeType
  const cleaned = raw.replace(/^```json?\s*/i, '').replace(/```\s*$/i, '').trim();

  let parsed: AuditXReport;
  try {
    parsed = JSON.parse(cleaned);
  } catch {
    throw new Error(`Gemini returned malformed JSON. Preview: ${raw.substring(0, 300)}`);
  }

  if (!parsed.analyticsSummary || !parsed.vulnerabilities) {
    throw new Error('Gemini response is missing required AuditX schema fields.');
  }

  onProgress?.(
    `[GEMINI] ✓ Analysis complete — Risk: ${parsed.analyticsSummary.riskClassification.toUpperCase()} | Status: ${parsed.analyticsSummary.certificationStatus}`
  );

  return parsed;
}
