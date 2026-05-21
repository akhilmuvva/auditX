import { Command } from 'commander';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { emitStep, emitProgress } from './events.js';
import { startServer } from './server.js';
import { runSlither } from './runners/slither.js';
import { runMythril } from './runners/mythril.js';
import { runSurya } from './runners/surya.js';
import { runAIAnalysis } from './runners/ai.js';
import { ipfsUpload, easAttest, badgeMint } from './runners/onchain.js';
import { writeIncrementalReport } from './utils/helpers.js';

dotenv.config();

const program = new Command();
program
  .name('auditx')
  .description('AuditX — Autonomous Smart Contract Security Agent')
  .version('1.0.0')
  .option('-t, --target <path>', 'Path to solidity file or directory')
  .option('-m, --mythril', 'Enable Mythril symbolic execution (slower)')
  .option('--ai', 'Enable Claude Sonnet AI Triage', true)
  .option('--no-ai', 'Disable AI Triage')
  .option('--ipfs', 'Pin report metadata to IPFS via Pinata')
  .option('--eas', 'Mint on-chain EAS attestation on Base Sepolia')
  .option('--mint <address>', 'Mint SVG NFT Badge to wallet address')
  .option('--server', 'Run SSE server for dashboard telemetry')
  .option('--port <number>', 'Port for SSE server', '3000')
  .parse(process.argv);

const opts = program.opts();

async function resolveTarget(targetPath: string) {
  const absolutePath = path.resolve(targetPath);
  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Target path not found: ${absolutePath}`);
  }
  const stat = fs.statSync(absolutePath);
  if (stat.isDirectory()) {
    const files = fs.readdirSync(absolutePath).filter(f => f.endsWith('.sol')).map(f => path.join(absolutePath, f));
    return { isDir: true, files };
  }
  return { isDir: false, files: [absolutePath] };
}

async function main() {
  if (opts.server) {
    startServer(parseInt(opts.port, 10));
  }

  emitProgress('RUNNING');
  console.log('\n' + '═'.repeat(60));
  console.log('  AuditX — Automated Smart Contract Auditor v1.0.0');
  console.log('═'.repeat(60) + '\n');

  if ((opts.eas || opts.mint) && !process.env.PRIVATE_KEY) {
    emitStep('error', 'Missing PRIVATE_KEY in .env required for --eas or --mint');
    process.exit(1);
  }
  if (opts.ai && !process.env.ANTHROPIC_API_KEY && !process.env.OPENAI_API_KEY) {
    emitStep('error', 'Missing ANTHROPIC_API_KEY in .env for AI triage');
    process.exit(1);
  }

  const targetArg = opts.target || './contracts';
  const targetInfo = await resolveTarget(targetArg);
  
  if (targetInfo.files.length === 0) {
    emitStep('error', 'No .sol files found in target.');
    process.exit(1);
  }

  const reportDir = path.join(process.cwd(), 'auditx-reports', `scan_${Date.now()}`);
  fs.mkdirSync(reportDir, { recursive: true });
  emitStep('system', `Report directory created: ${reportDir}`);

  // 1. Static Scan
  const slitherFindings = await runSlither(targetInfo.files[0], reportDir);

  // 2. Symbolic Execution
  let mythrilFindings: any[] = [];
  if (opts.mythril) {
    mythrilFindings = await runMythril(targetInfo.files, reportDir);
  }

  // 3. Surya Call-Graph
  const suryaData = await runSurya(targetInfo.files, reportDir);

  // 4. AI Triage
  let finalReport: any = { findings: slitherFindings.concat(mythrilFindings) };
  if (opts.ai) {
    const aiResult = await runAIAnalysis(finalReport.findings, targetInfo.files, reportDir);
    finalReport = aiResult;
  }

  // 5. On-chain Attestations
  let ipfsCid = null;
  let easUid = null;
  let mintTx = null;

  if (opts.ipfs || opts.eas || opts.mint) {
    ipfsCid = await ipfsUpload(finalReport, reportDir);
  }
  
  const score = finalReport.riskLevel === 'critical' ? '0.0' : finalReport.riskLevel === 'high' ? '3.0' : '9.5';

  if (opts.eas) {
    easUid = await easAttest('TargetContract', score, ipfsCid || '', reportDir);
  }
  
  if (opts.mint) {
    mintTx = await badgeMint(opts.mint, 'TargetContract', score, ipfsCid || '', reportDir);
  }

  emitProgress('COMPLETED');
  emitStep('success', 'Audit Pipeline Complete.');
  
  // Keep alive if server is running
  if (!opts.server) {
    process.exit(0);
  }
}

main().catch(err => {
  emitStep('error', `Fatal Pipeline Error: ${err.message}`);
  emitProgress('ERROR');
  console.error(err);
  if (!opts.server) process.exit(1);
});
