import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { auditEmitter } from './events.js';
import { runPipeline } from './pipeline.js';

// Track ongoing scans per client session
const activeSessions = new Map<string, boolean>();

export function startServer(port: number = 3000) {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '2mb' }));

  // ─── SSE Stream Endpoint ─────────────────────────────────────────
  // Frontend connects here to receive live StepEvent + status events
  app.get('/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.flushHeaders();

    // Heartbeat to keep connection alive
    const heartbeat = setInterval(() => {
      res.write(': ping\n\n');
    }, 15000);

    const onStep = (data: any) => {
      res.write(`event: step\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    const onStatus = (data: any) => {
      res.write(`event: status\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    auditEmitter.on('step', onStep);
    auditEmitter.on('status', onStatus);

    req.on('close', () => {
      clearInterval(heartbeat);
      auditEmitter.off('step', onStep);
      auditEmitter.off('status', onStatus);
    });
  });

  // ─── Upload & Audit Endpoint ──────────────────────────────────────
  // Accepts: { filename: string, code: string } JSON body
  // Saves the code as a temp .sol file and runs the real pipeline
  app.post('/api/audit', async (req, res) => {
    const { filename, code } = req.body as { filename?: string; code?: string };

    if (!code || typeof code !== 'string') {
      res.status(400).json({ error: 'Missing "code" field in request body.' });
      return;
    }

    const safeName = (filename || 'UserContract.sol').replace(/[^a-zA-Z0-9._-]/g, '_');
    if (!safeName.endsWith('.sol')) {
      res.status(400).json({ error: 'Only .sol files are supported.' });
      return;
    }

    // Write uploaded code to a temp directory
    const uploadDir = path.join(process.cwd(), 'auditx-uploads');
    fs.mkdirSync(uploadDir, { recursive: true });
    const targetFile = path.join(uploadDir, safeName);
    fs.writeFileSync(targetFile, code, 'utf8');

    // Acknowledge immediately — results stream via SSE
    res.json({ ok: true, file: safeName, message: 'Audit started. Connect to /stream for live telemetry.' });

    // Run the pipeline asynchronously (events emit over SSE)
    runPipeline(targetFile, { ai: false }).catch((err) => {
      console.error('[Pipeline Error]', err.message);
    });
  });

  // ─── Report Endpoint ──────────────────────────────────────────────
  // Returns the latest generated report JSON if it exists
  app.get('/api/reports/latest', (_req, res) => {
    const reportsDir = path.join(process.cwd(), 'auditx-reports');
    if (!fs.existsSync(reportsDir)) {
      res.status(404).json({ error: 'No reports found.' });
      return;
    }
    const scans = fs.readdirSync(reportsDir)
      .filter(d => d.startsWith('scan_'))
      .sort()
      .reverse();
    if (scans.length === 0) {
      res.status(404).json({ error: 'No scans found.' });
      return;
    }
    const reportPath = path.join(reportsDir, scans[0], 'audit_report.json');
    if (!fs.existsSync(reportPath)) {
      res.status(404).json({ error: 'Report file not found.' });
      return;
    }
    res.json(JSON.parse(fs.readFileSync(reportPath, 'utf8')));
  });

  app.listen(port, () => {
    console.log(`📡 AuditX API + SSE server running on http://localhost:${port}`);
    console.log(`   POST /api/audit    — Upload .sol code for real audit`);
    console.log(`   GET  /stream       — SSE telemetry stream`);
    console.log(`   GET  /api/reports/latest — Latest audit report`);
  });
}
