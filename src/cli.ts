#!/usr/bin/env node
/**
 * AuditX — Local CLI Runner (Zero-Server / Decentralized Mode)
 * 
 * Runs Slither, Mythril, and Surya locally and writes JSON outputs
 * to ./auditx-output/<contractName>/ for upload to the dashboard.
 * 
 * Usage:
 *   node dist/cli.js --target ./contracts/MyContract.sol
 *   node dist/cli.js --target ./contracts/MyContract.sol --mythril
 * 
 * No server. No API. The dashboard does AI triage directly in the browser.
 */

import { Command } from 'commander';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { runSlither } from './runners/slither.js';
import { runMythril } from './runners/mythril.js';
import { runSurya } from './runners/surya.js';

dotenv.config();

const program = new Command();
program
  .name('auditx')
  .description('AuditX — Local static analysis runner. Upload outputs to the dashboard for AI triage.')
  .version('2.0.0')
  .requiredOption('-t, --target <path>', 'Path to Solidity file or directory')
  .option('-m, --mythril', 'Enable Mythril symbolic execution (slower, requires mythril installed)')
  .option('-o, --out <dir>', 'Output directory for JSON results', './auditx-output')
  .parse(process.argv);

const opts = program.opts();

function banner() {
  console.log('\n' + '═'.repeat(60));
  console.log('  AuditX v2 — Decentralized Security Protocol');
  console.log('  Zero-Server Local Runner');
  console.log('═'.repeat(60) + '\n');
}

async function resolveTarget(targetPath: string): Promise<string[]> {
  const abs = path.resolve(targetPath);
  if (!fs.existsSync(abs)) throw new Error(`Path not found: ${abs}`);
  const stat = fs.statSync(abs);
  if (stat.isDirectory()) {
    return fs.readdirSync(abs)
      .filter(f => f.endsWith('.sol'))
      .map(f => path.join(abs, f));
  }
  return [abs];
}

async function main() {
  banner();

  const files = await resolveTarget(opts.target);
  if (files.length === 0) {
    console.error('❌ No .sol files found at the given path.');
    process.exit(1);
  }

  const contractName = path.basename(files[0], '.sol');
  const outDir = path.resolve(opts.out, contractName);
  fs.mkdirSync(outDir, { recursive: true });

  console.log(`📂 Contract:  ${files[0]}`);
  console.log(`📁 Output:    ${outDir}\n`);

  // 1. Slither static analysis
  console.log('🔍 Running Slither static analysis…');
  try {
    const slitherFindings = await runSlither(files[0], outDir);
    const slitherOut = path.join(outDir, 'slither.json');
    fs.writeFileSync(slitherOut, JSON.stringify(slitherFindings, null, 2));
    console.log(`   ✓ Slither: ${slitherFindings.length} finding(s) → ${slitherOut}`);
  } catch (e: any) {
    console.warn(`   ⚠  Slither skipped: ${e.message}`);
  }

  // 2. Mythril (optional)
  if (opts.mythril) {
    console.log('🔬 Running Mythril symbolic execution…');
    try {
      const mythrilFindings = await runMythril(files, outDir);
      const mythrilOut = path.join(outDir, 'mythril.json');
      fs.writeFileSync(mythrilOut, JSON.stringify(mythrilFindings, null, 2));
      console.log(`   ✓ Mythril: ${mythrilFindings.length} finding(s) → ${mythrilOut}`);
    } catch (e: any) {
      console.warn(`   ⚠  Mythril skipped: ${e.message}`);
    }
  }

  // 3. Surya call graph
  console.log('📊 Running Surya call-graph analysis…');
  try {
    const suryaData = await runSurya(files, outDir);
    const suryaOut = path.join(outDir, 'surya.json');
    fs.writeFileSync(suryaOut, JSON.stringify(suryaData, null, 2));
    console.log(`   ✓ Surya: call graph written → ${suryaOut}`);
  } catch (e: any) {
    console.warn(`   ⚠  Surya skipped: ${e.message}`);
  }

  console.log('\n' + '─'.repeat(60));
  console.log('✅ Local analysis complete!');
  console.log('\nNext steps:');
  console.log(`  1. Open the AuditX dashboard`);
  console.log(`  2. Upload: ${files[0]}`);
  console.log(`  3. Optionally upload: ${outDir}/slither.json, mythril.json, surya.json`);
  console.log(`  4. Enter your Anthropic API key in the dashboard`);
  console.log(`  5. Click "Run Decentralized Audit" — AI runs in your browser`);
  console.log('─'.repeat(60) + '\n');
}

main().catch((err) => {
  console.error('\n❌ Fatal error:', err.message);
  process.exit(1);
});
