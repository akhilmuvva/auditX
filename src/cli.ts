#!/usr/bin/env node
/**
 * AuditX — CLI Runner
 *
 * Sub-commands:
 *   audit   — Run Slither/Mythril/Surya locally on a .sol file
 *   monitor — Start the SIEM monitor (ingest events, stream alerts)
 *   server  — Start the AuditX API + SIEM WebSocket server
 */

import { Command } from 'commander';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import readline from 'readline';
import { runSlither } from './runners/slither.js';
import { runMythril } from './runners/mythril.js';
import { runSurya } from './runners/surya.js';
import { SIEMEngine } from './siem/index.js';
import type { ChainEvent } from './siem/types.js';

dotenv.config();

// ─── Shared banner ───────────────────────────────────────────────────────────

function banner(subtitle?: string) {
  console.log('\n' + '═'.repeat(60));
  console.log('  AuditX — Decentralized Smart Contract SIEM');
  if (subtitle) console.log('  ' + subtitle);
  console.log('═'.repeat(60) + '\n');
}

// ─── Program ─────────────────────────────────────────────────────────────────

const program = new Command();
program
  .name('auditx')
  .description('AuditX — Decentralized Smart Contract Security Toolkit')
  .version('2.0.0');

// ─── audit sub-command ───────────────────────────────────────────────────────

program
  .command('audit')
  .description('Run static analysis (Slither / Mythril / Surya) on a Solidity file')
  .requiredOption('-t, --target <path>', 'Path to Solidity file or directory')
  .option('-m, --mythril', 'Enable Mythril symbolic execution (slower)')
  .option('-o, --out <dir>', 'Output directory for JSON results', './auditx-output')
  .action(async (opts) => {
    banner('Local Static Analysis Runner');

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

    // 1. Slither
    console.log('🔍 Running Slither static analysis…');
    try {
      const findings = await runSlither(files[0], outDir);
      fs.writeFileSync(path.join(outDir, 'slither.json'), JSON.stringify(findings, null, 2));
      console.log(`   ✓ Slither: ${findings.length} finding(s) → ${outDir}/slither.json`);
    } catch (e: any) { console.warn(`   ⚠  Slither skipped: ${e.message}`); }

    // 2. Mythril (optional)
    if (opts.mythril) {
      console.log('🔬 Running Mythril symbolic execution…');
      try {
        const findings = await runMythril(files, outDir);
        fs.writeFileSync(path.join(outDir, 'mythril.json'), JSON.stringify(findings, null, 2));
        console.log(`   ✓ Mythril: ${findings.length} finding(s) → ${outDir}/mythril.json`);
      } catch (e: any) { console.warn(`   ⚠  Mythril skipped: ${e.message}`); }
    }

    // 3. Surya
    console.log('📊 Running Surya call-graph analysis…');
    try {
      const data = await runSurya(files, outDir);
      fs.writeFileSync(path.join(outDir, 'surya.json'), JSON.stringify(data, null, 2));
      console.log(`   ✓ Surya: call graph → ${outDir}/surya.json`);
    } catch (e: any) { console.warn(`   ⚠  Surya skipped: ${e.message}`); }

    console.log('\n' + '─'.repeat(60));
    console.log('✅ Local analysis complete!');
    console.log('\nNext steps:');
    console.log(`  1. Open the AuditX dashboard`);
    console.log(`  2. Upload: ${files[0]}`);
    console.log('─'.repeat(60) + '\n');
  });

// ─── monitor sub-command ─────────────────────────────────────────────────────

program
  .command('monitor')
  .description('Start the SIEM monitor — ingest chain events from JSONL and stream alerts')
  .option('-f, --file <path>',   'JSONL file of ChainEvent[] to ingest (one JSON per line)')
  .option('-t, --threshold <s>', 'Alert severity threshold: INFO|LOW|MEDIUM|HIGH|CRITICAL', 'LOW')
  .option('--watch',             'Watch the file for new events (tail -f mode)')
  .action(async (opts) => {
    banner('SIEM Monitor — Real-Time Threat Detection');

    const engine = new SIEMEngine({
      alertThreshold: opts.threshold as any,
    });

    // Wire alert output to console
    engine.alertManager.on('alert', (alert: any) => {
      const icon = alert.severity === 'CRITICAL' ? '🚨' : alert.severity === 'HIGH' ? '⚠️ ' : 'ℹ️ ';
      console.log(`${icon} [${alert.severity}] ${alert.title}`);
      console.log(`   ${alert.description}`);
      console.log(`   ID: ${alert.id} | Contract: ${alert.event.contractAddress}`);
      console.log();
    });

    // Train with cold-start (no historical data needed to start)
    await engine.train([]);
    const b = engine.getBaseline();
    console.log(`✅ SIEM ready. Gas baseline: μ=${b.gasUsed.mean.toFixed(0)} σ=${b.gasUsed.stdDev.toFixed(0)} (${b.syntheticSamples} synthetic samples)`);
    console.log(`   Threat feeds loaded: 6 built-in addresses\n`);

    if (!opts.file) {
      // Interactive stdin mode
      console.log('📡 Listening for ChainEvents on stdin (paste JSON and press Enter)…');
      console.log('   Format: { "id": "...", "eventName": "Transfer", "gasUsed": 65000, ... }');
      console.log('   Ctrl+C to exit\n');

      const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
      for await (const line of rl) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('//')) continue;
        try {
          const event: ChainEvent = JSON.parse(trimmed);
          const { alert } = await engine.processSingle(event);
          if (!alert) {
            console.log(`   ✓ Event "${event.eventName}" processed — no alert triggered`);
          }
        } catch (e: any) {
          console.warn(`   ❌ Parse error: ${e.message}`);
        }
      }
      return;
    }

    // File ingestion mode
    const filePath = path.resolve(opts.file);
    if (!fs.existsSync(filePath)) {
      console.error(`❌ File not found: ${filePath}`);
      process.exit(1);
    }

    const ingestFile = async () => {
      const lines = fs.readFileSync(filePath, 'utf8').split('\n').filter(l => l.trim());
      const events: ChainEvent[] = [];
      for (const line of lines) {
        try { events.push(JSON.parse(line)); } catch { /* skip malformed */ }
      }
      const result = await engine.process(events);
      console.log(`📥 Ingested ${events.length} events → ${result.alerts.length} alert(s)`);
      const baseline = engine.getBaseline();
      console.log(`   Baseline updated: μ=${baseline.gasUsed.mean.toFixed(0)} σ=${baseline.gasUsed.stdDev.toFixed(0)}\n`);
    };

    await ingestFile();

    if (opts.watch) {
      console.log(`👁  Watching ${filePath} for changes…\n`);
      fs.watchFile(filePath, { interval: 1000 }, ingestFile);
      // Keep process alive
      process.stdin.resume();
    }
  });

// ─── server sub-command ──────────────────────────────────────────────────────

program
  .command('server')
  .description('Start the AuditX API + SIEM WebSocket server')
  .option('-p, --port <n>', 'Port to listen on', '3000')
  .action(async (opts) => {
    banner('API + SIEM Server');
    const { startServer } = await import('./server.js');
    startServer(Number(opts.port));
  });

// ─── Legacy default behaviour (no sub-command) ───────────────────────────────

// Allow old usage: `auditx --target <path>` to run audit directly
program
  .option('-t, --target <path>', '[Legacy] Shortcut for: auditx audit --target <path>')
  .option('--server', '[Legacy] Shortcut for: auditx server')
  .hook('preAction', async (thisCommand) => {
    const opts = thisCommand.opts();
    if (opts.server) {
      banner('API + SIEM Server');
      const { startServer } = await import('./server.js');
      startServer(3000);
      return;
    }
    if (opts.target) {
      // Delegate to audit sub-command behaviour inline
      const files = await resolveTarget(opts.target);
      console.log(`\nℹ  Running audit on: ${files[0]}\n`);
    }
  });

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function resolveTarget(targetPath: string): Promise<string[]> {
  const abs = path.resolve(targetPath);
  if (!fs.existsSync(abs)) throw new Error(`Path not found: ${abs}`);
  const stat = fs.statSync(abs);
  if (stat.isDirectory()) {
    return fs.readdirSync(abs).filter(f => f.endsWith('.sol')).map(f => path.join(abs, f));
  }
  return [abs];
}

// ─── Run ─────────────────────────────────────────────────────────────────────

program.parseAsync(process.argv).catch((err) => {
  console.error('\n❌ Fatal error:', err.message);
  process.exit(1);
});
