import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { ethers } from 'ethers';
import { emitStep, emitProgress } from './events.js';
import { runSlither } from './runners/slither.js';
import { runSurya } from './runners/surya.js';
import { runMythril } from './runners/mythril.js';
import { runZKChecks } from './analysis/zkChecks.js';
import { runAIAnalysis } from './runners/ai.js';
import { ipfsUpload, easAttest, badgeMint } from './runners/onchain.js';
import { queryAuditsByContract } from './storage/theGraph.js';

dotenv.config();

export interface PipelineOptions {
  mythril?: boolean;
  ai?: boolean;
  ipfs?: boolean;
  eas?: boolean;
  mint?: string;
  force?: boolean;
  monitor?: boolean;
  contractAddress?: string;
  chainId?: number;
  generateBot?: boolean;
  contractName?: string;
}

export async function lookupAttestation(contractHash: string) {
  try {
    const existing = await queryAuditsByContract(contractHash);
    if (existing && existing.length > 0) {
      return existing[0];
    }
  } catch (e: any) {
    console.warn('[AuditX] Caching lookup failed:', e.message);
  }
  return null;
}

export async function runPipeline(targetFile: string, opts: PipelineOptions = {}) {
  const code = fs.readFileSync(targetFile, 'utf8');
  const contractHash = ethers.keccak256(ethers.toUtf8Bytes(code));

  // Check cached EAS attestation unless --force flag is present
  const existing = await lookupAttestation(contractHash);
  if (existing && !opts.force) {
    console.log('[AuditX] Using cached attestation. Use --force to re-audit.');
    emitProgress('COMPLETED');
    emitStep('parse', 'complete', {
      message: 'Audit Pipeline Complete (Cached).',
      report: {
        summary: "Using cached attestation.",
        riskLevel: existing.riskLevel || "safe",
        cvssScore: Number(existing.cvssScore) / 10,
        badge: Number(existing.cvssScore) >= 90 ? "RED" : Number(existing.cvssScore) >= 40 ? "AMBER" : "EMERALD",
        detailedFindings: []
      },
      cvssScore: existing.cvssScore.toString(),
      ipfsCid: existing.ipfsCID,
      easUid: existing.id,
      reportDir: null,
    });
    return {
      finalReport: {
        summary: "Using cached attestation.",
        riskLevel: existing.riskLevel || "safe",
        cvssScore: Number(existing.cvssScore) / 10,
        badge: Number(existing.cvssScore) >= 90 ? "RED" : Number(existing.cvssScore) >= 40 ? "AMBER" : "EMERALD",
        detailedFindings: []
      },
      score: existing.cvssScore.toString(),
      ipfsCid: existing.ipfsCID,
      easUid: existing.id,
      reportDir: null
    };
  }
  if (existing && opts.force) {
    console.log('[AuditX] --force flag set. Running fresh analysis...');
  }

  const reportDir = path.join(process.cwd(), 'auditx-reports', `scan_${Date.now()}`);
  fs.mkdirSync(reportDir, { recursive: true });

  emitProgress('RUNNING');
  emitStep('parse', 'active', { message: `Starting audit pipeline on ${path.basename(targetFile)}` });

  // 1. Static Scan
  const slitherFindings = await runSlither(targetFile, reportDir);

  // 2. Symbolic Execution (optional)
  let mythrilFindings: any[] = [];
  if (opts.mythril) {
    mythrilFindings = await runMythril([targetFile], reportDir);
  }

  // 3. Surya Call-Graph
  const suryaData = await runSurya([targetFile], reportDir);

  // 3.5 ZK Checks
  const zkResults = runZKChecks(targetFile);
  const zkChecksPassed = zkResults.length === 5 && zkResults.every(r => r.passed);

  // 4. AI Triage
  let finalReport: any = { findings: slitherFindings.concat(mythrilFindings), suryaData, zkResults };
  if (opts.ai !== false) {
    const aiResult = await runAIAnalysis(finalReport.findings, [targetFile], reportDir, zkResults);
    finalReport = { ...aiResult, suryaData, zkResults };
  }

  // 4.5 Forta post-deploy monitoring (optional)
  let fortaMonitorResult: any = null;
  if (opts.monitor && opts.contractAddress) {
    console.log('\n[AuditX] 🔭 Fetching post-deploy Forta intelligence...');
    console.log(`[AuditX]    Contract: ${opts.contractAddress}`);
    console.log(`[AuditX]    Chain ID: ${opts.chainId || 1}`);

    try {
      const { analyzeDeployedContract } = await import('./forta/index.js');
      const fortaAnalysis = await analyzeDeployedContract(opts.contractAddress, opts.chainId || 1);

      fortaMonitorResult = {
        contractAddress: opts.contractAddress,
        status:          fortaAnalysis.status,
        overallRisk:     fortaAnalysis.overallRisk,
      };

      const s = fortaAnalysis.status;
      console.log(`[AuditX] ✅ Forta: ${s.totalAlerts} alerts found`);
      console.log(`[AuditX]    Risk: ${fortaAnalysis.overallRisk}`);
      if (fortaAnalysis.scamCheck.isScammer) {
        console.log(`[AuditX] 🚨 SCAM DETECTOR: This address is flagged!`);
      }

      // Auto-generate Forta bot if requested
      if (opts.generateBot && finalReport.detailedFindings?.length > 0) {
        console.log('[AuditX] 🤖 Generating custom Forta monitoring bot...');
        const { generateFortaBot, saveFortaBot } = await import('./forta/index.js');
        const bot = await generateFortaBot(
          finalReport.detailedFindings,
          opts.contractAddress,
          opts.contractName || path.basename(targetFile, '.sol')
        );

        if (bot) {
          const botPath = await saveFortaBot(bot, reportDir);
          fortaMonitorResult.generatedBot = bot;
          fortaMonitorResult.botSavedAt = botPath;
          console.log(`[AuditX] ✅ Bot generated: ${botPath}`);
          console.log('[AuditX]    Deploy with: cd ' + botPath + ' && npm install && npx forta-agent@latest push');
        } else {
          console.log('[AuditX]    No monitorable patterns found for bot generation');
        }
      }

      finalReport.fortaMonitor = fortaMonitorResult;

    } catch (err: any) {
      console.warn('[AuditX] ⚠️  Forta analysis failed:', err.message);
      console.warn('[AuditX]    Continuing without Forta data.');
    }
  }

  // Populate Forta metadata fields for EAS / local schemas
  finalReport.fortaRiskScore = finalReport.fortaMonitor?.status?.riskScore ?? 0;
  finalReport.fortaAlertCount = finalReport.fortaMonitor?.status?.totalAlerts ?? 0;
  finalReport.fortaOverallRisk = finalReport.fortaMonitor?.overallRisk ?? 'NOT_MONITORED';
  finalReport.fortaBotGenerated = finalReport.fortaMonitor?.generatedBot ? 'true' : 'false';

  // 5. On-chain (optional)
  let ipfsCid: string | null = null;
  let easUid: string | null = null;
  let mintTx: string | null = null;

  if (opts.ipfs || opts.eas || opts.mint) {
    ipfsCid = await ipfsUpload(finalReport, reportDir);
  }

  // Calculate CVSS properly for on-chain badge (scale up to 100)
  const baseScore = finalReport.cvssScore !== undefined ? finalReport.cvssScore : 
    (finalReport.riskLevel === 'critical' ? 9.5
    : finalReport.riskLevel === 'high' ? 7.5
    : finalReport.riskLevel === 'medium' ? 5.0
    : 1.5);
  
  const scaledScoreStr = Math.round(baseScore * 10).toString();

  if (opts.eas) {
    easUid = await easAttest(path.basename(targetFile), scaledScoreStr, ipfsCid || '', reportDir);
    
    // Explicitly write the custom Forta parameters to the local report folder if EAS is minted
    try {
      const reportPath = path.join(reportDir, 'audit_report.json');
      if (fs.existsSync(reportPath)) {
        const currentReport = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
        const updated = {
          ...currentReport,
          fortaRiskScore: finalReport.fortaRiskScore,
          fortaAlertCount: finalReport.fortaAlertCount,
          fortaOverallRisk: finalReport.fortaOverallRisk,
          fortaBotGenerated: finalReport.fortaBotGenerated
        };
        fs.writeFileSync(reportPath, JSON.stringify(updated, null, 2));
      }
    } catch {}
  }

  if (opts.mint) {
    mintTx = await badgeMint(opts.mint, path.basename(targetFile), scaledScoreStr, ipfsCid || '', zkChecksPassed, reportDir);
  }

  // 6. Generate static HTML dashboard report
  try {
    const templatePath = path.resolve(process.cwd(), 'dashboard/audit-dashboard.html');
    if (fs.existsSync(templatePath)) {
      let html = fs.readFileSync(templatePath, 'utf8');
      
      const counts = {
        CRITICAL: finalReport.detailedFindings?.filter((f: any) => f.severity?.toUpperCase() === 'CRITICAL').length || 0,
        HIGH: finalReport.detailedFindings?.filter((f: any) => f.severity?.toUpperCase() === 'HIGH').length || 0,
        MEDIUM: finalReport.detailedFindings?.filter((f: any) => f.severity?.toUpperCase() === 'MEDIUM').length || 0,
        LOW: finalReport.detailedFindings?.filter((f: any) => f.severity?.toUpperCase() === 'LOW').length || 0,
        INFO: finalReport.detailedFindings?.filter((f: any) => f.severity?.toUpperCase() === 'INFO').length || 0
      };

      const summaryData = {
        counts,
        riskScore: parseInt(scaledScoreStr) || 0,
        riskLevel: finalReport.riskLevel || 'SAFE',
        total: finalReport.detailedFindings?.length || 0
      };

      // Inject data
      html = html.replace('const findings = [];', `const findings = ${JSON.stringify(finalReport.detailedFindings || [])};`);
      html = html.replace(
        'const summary = {"counts":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0},"riskScore":0,"riskLevel":"SAFE","total":0};',
        `const summary = ${JSON.stringify(summaryData)};`
      );
      // Inject whole auditData for Forta dashboards
      html = html.replace('const auditData = null;', `const auditData = ${JSON.stringify(finalReport)};`);
      // Update target name dynamically
      html = html.replace('VulnerableVault.sol', path.basename(targetFile));

      fs.writeFileSync(path.join(reportDir, 'audit-dashboard.html'), html, 'utf8');
      console.log(`[AuditX] 📊 HTML Report Generated → ${reportDir}/audit-dashboard.html`);
    }
  } catch (err: any) {
    console.warn('[AuditX] ⚠️  HTML dashboard generation failed:', err.message);
  }

  emitProgress('COMPLETED');
  emitStep('parse', 'complete', {
    message: 'Audit Pipeline Complete.',
    report: finalReport,
    cvssScore: scaledScoreStr,
    ipfsCid,
    easUid,
    mintTx,
    reportDir,
  });

  return { finalReport, score: scaledScoreStr, ipfsCid, easUid, mintTx, reportDir };
}
