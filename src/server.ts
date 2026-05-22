import express from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { WebSocketServer, WebSocket } from 'ws';
import { createServer } from 'http';
import { auditEmitter } from './events.js';
import { runPipeline } from './pipeline.js';
import { SIEMEngine } from './siem/index.js';
import type { Alert } from './siem/types.js';
import type { ChainEvent } from './siem/types.js';

// ─── SIEM Engine (singleton, shared across all routes) ───────────────────────
const siemEngine = new SIEMEngine({ alertThreshold: 'LOW', uploadToIpfs: false });
siemEngine.train([]).then(() => {
  console.log('[SIEM] Engine trained and ready.');
  console.log(`[SIEM] Baseline: ${JSON.stringify(siemEngine.getBaseline().gasUsed)}`);
});

// Track ongoing scans per client session
const activeSessions = new Map<string, boolean>();

export function startServer(port: number = 3000) {
  const app = express();
  const httpServer = createServer(app);

  // ─── WebSocket Server (for SIEM live alerts) ─────────────────────────────
  const wss = new WebSocketServer({ server: httpServer, path: '/ws/siem' });

  /** Broadcast an alert to all connected SIEM dashboard clients */
  function broadcastAlert(alert: Alert) {
    const payload = JSON.stringify({ type: 'alert', data: alert });
    for (const client of wss.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(payload);
      }
    }
  }

  /** Broadcast baseline stats to all connected clients */
  function broadcastBaseline() {
    const payload = JSON.stringify({ type: 'baseline', data: siemEngine.getBaseline() });
    for (const client of wss.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(payload);
      }
    }
  }

  // Wire AlertManager → WebSocket broadcast
  siemEngine.alertManager.on('alert', (alert: Alert) => {
    broadcastAlert(alert);
  });

  wss.on('connection', (ws) => {
    console.log('[SIEM] WebSocket client connected');

    // Send current open alerts on connect
    const openAlerts = siemEngine.getOpenAlerts();
    ws.send(JSON.stringify({ type: 'init', data: { openAlerts, baseline: siemEngine.getBaseline() } }));

    ws.on('message', async (raw) => {
      try {
        const msg = JSON.parse(raw.toString());

        // Accept: { type: 'ingest', events: ChainEvent[] }
        if (msg.type === 'ingest' && Array.isArray(msg.events)) {
          const result = await siemEngine.process(msg.events as ChainEvent[]);
          ws.send(JSON.stringify({ type: 'processed', data: {
            classified: result.classified.length,
            anomalies: result.scored.filter(e => e.anomaly.isAnomaly).length,
            threatMatches: result.enriched.filter(e => e.threatMatches.length > 0).length,
            alerts: result.alerts.length,
          }}));
          broadcastBaseline();
          return;
        }

        // Accept: { type: 'acknowledge', alertId: string }
        if (msg.type === 'acknowledge' && msg.alertId) {
          const ok = siemEngine.acknowledgeAlert(msg.alertId);
          ws.send(JSON.stringify({ type: 'ack_result', alertId: msg.alertId, ok }));
          return;
        }

        // Accept: { type: 'resolve', alertId: string }
        if (msg.type === 'resolve' && msg.alertId) {
          const ok = siemEngine.resolveAlert(msg.alertId);
          ws.send(JSON.stringify({ type: 'resolve_result', alertId: msg.alertId, ok }));
          return;
        }

        // Accept: { type: 'get_baseline' }
        if (msg.type === 'get_baseline') {
          ws.send(JSON.stringify({ type: 'baseline', data: siemEngine.getBaseline() }));
          return;
        }

      } catch (err: any) {
        ws.send(JSON.stringify({ type: 'error', message: err.message }));
      }
    });

    ws.on('close', () => console.log('[SIEM] WebSocket client disconnected'));
  });

  app.use(cors());
  app.use(express.json({ limit: '2mb' }));

  // ─── SSE Stream Endpoint ────────────────────────────────────────────────
  app.get('/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.flushHeaders();

    const heartbeat = setInterval(() => { res.write(': ping\n\n'); }, 15000);
    const onStep = (data: any) => res.write(`event: step\ndata: ${JSON.stringify(data)}\n\n`);
    const onStatus = (data: any) => res.write(`event: status\ndata: ${JSON.stringify(data)}\n\n`);

    auditEmitter.on('step', onStep);
    auditEmitter.on('status', onStatus);

    req.on('close', () => {
      clearInterval(heartbeat);
      auditEmitter.off('step', onStep);
      auditEmitter.off('status', onStatus);
    });
  });

  // ─── Upload & Audit Endpoint ─────────────────────────────────────────────
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

    const uploadDir = path.join(process.cwd(), 'auditx-uploads');
    fs.mkdirSync(uploadDir, { recursive: true });
    const targetFile = path.join(uploadDir, safeName);
    fs.writeFileSync(targetFile, code, 'utf8');

    res.json({ ok: true, file: safeName, message: 'Audit started. Connect to /stream for live telemetry.' });

    runPipeline(targetFile, { ai: false }).catch((err) => {
      console.error('[Pipeline Error]', err.message);
    });
  });

  // ─── SIEM REST Endpoints ─────────────────────────────────────────────────

  /** GET /api/siem/alerts — returns open alerts */
  app.get('/api/siem/alerts', (_req, res) => {
    res.json({
      ok: true,
      alerts: siemEngine.getOpenAlerts(),
      total: siemEngine.alertManager.totalCount,
    });
  });

  /** GET /api/siem/baseline — current anomaly detector baseline */
  app.get('/api/siem/baseline', (_req, res) => {
    res.json({ ok: true, baseline: siemEngine.getBaseline() });
  });

  /** POST /api/siem/ingest — ingest an array of ChainEvents */
  app.post('/api/siem/ingest', async (req, res) => {
    const events: ChainEvent[] = req.body?.events;
    if (!Array.isArray(events) || events.length === 0) {
      res.status(400).json({ error: 'Expected { events: ChainEvent[] }' });
      return;
    }

    try {
      const result = await siemEngine.process(events);
      result.alerts.forEach(broadcastAlert);
      broadcastBaseline();
      res.json({
        ok: true,
        processed: events.length,
        classified: result.classified.length,
        anomalies: result.scored.filter(e => e.anomaly.isAnomaly).length,
        threatMatches: result.enriched.filter(e => e.threatMatches.length > 0).length,
        alerts: result.alerts.map(a => ({ id: a.id, title: a.title, severity: a.severity })),
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  /** PATCH /api/siem/alerts/:id/acknowledge */
  app.patch('/api/siem/alerts/:id/acknowledge', (req, res) => {
    const ok = siemEngine.acknowledgeAlert(req.params.id);
    res.json({ ok });
  });

  /** PATCH /api/siem/alerts/:id/resolve */
  app.patch('/api/siem/alerts/:id/resolve', (req, res) => {
    const ok = siemEngine.resolveAlert(req.params.id);
    res.json({ ok });
  });

  // ─── Report Endpoint ─────────────────────────────────────────────────────
  app.get('/api/reports/latest', (_req, res) => {
    const reportsDir = path.join(process.cwd(), 'auditx-reports');
    if (!fs.existsSync(reportsDir)) { res.status(404).json({ error: 'No reports found.' }); return; }
    const scans = fs.readdirSync(reportsDir).filter(d => d.startsWith('scan_')).sort().reverse();
    if (scans.length === 0) { res.status(404).json({ error: 'No scans found.' }); return; }
    const reportPath = path.join(reportsDir, scans[0], 'audit_report.json');
    if (!fs.existsSync(reportPath)) { res.status(404).json({ error: 'Report file not found.' }); return; }
    res.json(JSON.parse(fs.readFileSync(reportPath, 'utf8')));
  });

  // ─── Start ───────────────────────────────────────────────────────────────
  httpServer.listen(port, () => {
    console.log(`📡 AuditX API + SSE + SIEM server running on http://localhost:${port}`);
    console.log(`   POST /api/audit              — Upload .sol code for real audit`);
    console.log(`   GET  /stream                 — SSE telemetry stream`);
    console.log(`   GET  /api/reports/latest     — Latest audit report`);
    console.log(`   GET  /api/siem/alerts        — Open SIEM alerts`);
    console.log(`   GET  /api/siem/baseline      — Anomaly detector baseline`);
    console.log(`   POST /api/siem/ingest        — Ingest chain events`);
    console.log(`   WS   /ws/siem                — Real-time SIEM WebSocket`);
  });
}
