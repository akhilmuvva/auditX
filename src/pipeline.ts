import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { emitStep, emitProgress } from './events.js';
import { runSlither } from './runners/slither.js';
import { runSurya } from './runners/surya.js';
import { runZKChecks } from './analysis/zkChecks.js';
import { runAIAnalysis } from './runners/ai.js';
import { ipfsUpload, easAttest, badgeMint } from './runners/onchain.js';

dotenv.config();

export interface PipelineOptions {
  mythril?: boolean;
  ai?: boolean;
  ipfs?: boolean;
  eas?: boolean;
  mint?: string;
}

export async function runPipeline(targetFile: string, opts: PipelineOptions = {}) {
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
  }

  if (opts.mint) {
    mintTx = await badgeMint(opts.mint, path.basename(targetFile), scaledScoreStr, ipfsCid || '', zkChecksPassed, reportDir);
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
