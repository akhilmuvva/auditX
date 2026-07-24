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
import { runPipeline } from './pipeline.js';
import { SIEMEngine } from './siem/index.js';
import type { ChainEvent } from './siem/types.js';
import { parseGithubImport, findSolFiles } from './utils/github.js';

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
  .version('2.0.0')
  .enablePositionalOptions();

// ─── audit sub-command ───────────────────────────────────────────────────────

program
  .command('audit')
  .description('Run smart contract audit pipeline (static checks, ZK, AI, EAS, Forta, Badge mint)')
  .requiredOption('-t, --target <path>', 'Path to Solidity file or directory')
  .option('-m, --mythril', 'Enable Mythril symbolic execution (slower)')
  .option('-o, --out <dir>', 'Output directory for JSON results', './auditx-reports')
  .option('--ai', 'Enable Claude AI triage analysis (default: true)', true)
  .option('--no-ai', 'Disable Claude AI triage analysis')
  .option('--ipfs', 'Pin report telemetry to IPFS')
  .option('--eas', 'Mint Ethereum Attestation Service proof on-chain')
  .option('--mint <address>', 'Mint SVG Security Badge NFT to recipient wallet address')
  .option('--force', 'Bypass all caches, run fresh analysis')
  .option('--monitor', 'Fetch live Forta alerts for deployed contract (requires --address)')
  .option('--address <addr>', 'Deployed contract address to monitor')
  .option('--chain <id>', 'Chain ID for monitoring (default: 1)')
  .option('--gen-bot', 'Auto-generate custom Forta detection bot from findings')
  .option('--name <string>', 'Contract name for bot generation')
  .action(async (opts) => {
    banner('Audit & Lifecycle Security Pipeline');

    // Validations
    if (opts.monitor && !opts.address) {
      console.error('❌ [AuditX] --monitor requires --address <deployedContractAddress>');
      process.exit(1);
    }

    if (opts.address && !/^0x[0-9a-fA-F]{40}$/.test(opts.address)) {
      console.error('❌ [AuditX] Invalid --address format. Expected: 0x followed by 40 hex chars');
      process.exit(1);
    }

    if (opts.genBot && !opts.monitor) {
      console.warn('⚠️ [AuditX] --gen-bot works best with --monitor. Running without Forta alerts.');
    }

    const files = await resolveTarget(opts.target);
    if (files.length === 0) {
      console.error('❌ No .sol files found at the given path.');
      process.exit(1);
    }

    const targetFile = files[0];
    const chainId = opts.chain ? Number(opts.chain) : 1;

    console.log(`📂 Contract Target: ${targetFile}`);
    if (opts.address) {
      console.log(`📡 Deployed Addr:   ${opts.address} (Chain: ${chainId})`);
    }

    try {
      const pipelineOpts = {
        mythril: !!opts.mythril,
        ai: opts.ai !== false,
        ipfs: !!opts.ipfs,
        eas: !!opts.eas,
        mint: opts.mint,
        force: !!opts.force,
        monitor: !!opts.monitor,
        contractAddress: opts.address,
        chainId,
        generateBot: !!opts.genBot,
        contractName: opts.name || path.basename(targetFile, '.sol'),
      };

      const result = await runPipeline(targetFile, pipelineOpts);
      
      console.log('\n' + '─'.repeat(60));
      console.log('✅ Audit & Lifecycle Security Pipeline Complete!');
      if (result.reportDir) {
        console.log(`📂 Saved Report Folder: ${result.reportDir}`);
      }
      console.log('─'.repeat(60) + '\n');

    } catch (err: any) {
      console.error(`\n❌ Pipeline execution failed: ${err.message}`);
      process.exit(1);
    }
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
  const gitInfo = parseGithubImport(targetPath);
  if (gitInfo) {
    const cacheDir = path.join(process.cwd(), 'cache', 'github');
    fs.mkdirSync(cacheDir, { recursive: true });
    const repoDest = path.join(cacheDir, gitInfo.repoName);

    // Re-clone fresh to ensure the latest contract state is audited
    if (fs.existsSync(repoDest)) {
      console.log(`[GitHub] 🧹 Clearing stale cached copy of: ${gitInfo.repoName}`);
      fs.rmSync(repoDest, { recursive: true, force: true });
    }

    console.log(`[GitHub] 📥 Importing repository: ${gitInfo.repoUrl}`);
    const { execSync } = await import('child_process');
    try {
      execSync(`git clone --depth 1 ${gitInfo.repoUrl} "${repoDest}"`, { stdio: 'pipe' });
      console.log(`[GitHub] ✅ Repository cloned successfully to cache.`);
    } catch (err: any) {
      throw new Error(`Failed to clone GitHub repository: ${err.message}`);
    }

    if (gitInfo.filePath) {
      const fullPath = path.join(repoDest, gitInfo.filePath);
      if (!fs.existsSync(fullPath)) {
        throw new Error(`Specified contract file not found in repository: ${gitInfo.filePath}`);
      }
      return [fullPath];
    } else {
      const solFiles = findSolFiles(repoDest);
      if (solFiles.length === 0) {
        throw new Error(`No Solidity (.sol) files found in the cloned repository.`);
      }
      console.log(`[GitHub] 🔎 Found ${solFiles.length} Solidity files recursively.`);
      return solFiles;
    }
  }

  // Local fallback
  const abs = path.resolve(targetPath);
  if (!fs.existsSync(abs)) throw new Error(`Path not found: ${abs}`);
  const stat = fs.statSync(abs);
  if (stat.isDirectory()) {
    return findSolFiles(abs);
  }
  return [abs];
}

// ─── Run ─────────────────────────────────────────────────────────────────────

program.parseAsync(process.argv).catch((err) => {
  console.error('\n❌ Fatal error:', err.message);
  process.exit(1);
});
