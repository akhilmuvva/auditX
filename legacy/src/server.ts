import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { WebSocketServer, WebSocket } from 'ws';
import { timingSafeEqual } from 'crypto';
import { createServer } from 'http';
import { auditEmitter } from './events.js';
import { SIEMEngine } from './siem/index.js';
import type { Alert } from './siem/types.js';
import type { ChainEvent } from './siem/types.js';
import { parseGithubImport, findSolFiles } from './utils/github.js';
import {
  bootstrapPolyLance,
  eventMatchesMonitoredAddress,
  TenantRegistry,
  type IssuedClientCredentials,
  type MonitoredAddress,
} from './tenantRegistry.js';

// ─── SIEM Engine (singleton, shared across all routes) ───────────────────────
const siemEngine = new SIEMEngine({ alertThreshold: 'LOW', uploadToIpfs: false });
siemEngine.train([]).then(() => {
  console.log('[SIEM] Engine trained and ready.');
  console.log(`[SIEM] Baseline: ${JSON.stringify(siemEngine.getBaseline().gasUsed)}`);
});

// Track ongoing scans per client session
const activeSessions = new Map<string, boolean>();
const tenantRegistry = new TenantRegistry();
bootstrapPolyLance(tenantRegistry);

function hasApiAccess(req: Pick<Request, 'headers'> & { url?: string }): boolean {
  const expected = process.env.AUDITX_API_TOKEN;
  if (!expected) return false;
  const authorization = Array.isArray(req.headers.authorization)
    ? req.headers.authorization[0]
    : req.headers.authorization;
  const apiKey = Array.isArray(req.headers['x-api-key'])
    ? req.headers['x-api-key'][0]
    : req.headers['x-api-key'];
  const websocketProtocol = typeof req.headers['sec-websocket-protocol'] === 'string'
    ? req.headers['sec-websocket-protocol'].split(',').map((value) => value.trim())
      .find((value) => value.startsWith('auditx-api-key.'))?.slice('auditx-api-key.'.length)
    : undefined;
  const supplied = authorization?.startsWith('Bearer ')
    ? authorization.slice(7)
    : apiKey || websocketProtocol || undefined;
  if (!supplied) return false;
  if (tenantRegistry.authenticate(supplied)) return true;
  if (!expected) return false;
  const expectedBuffer = Buffer.from(expected);
  const suppliedBuffer = Buffer.from(supplied);
  return expectedBuffer.length === suppliedBuffer.length && timingSafeEqual(expectedBuffer, suppliedBuffer);
}

async function dispatchMatchingWebhooks(alerts: Alert[]): Promise<void> {
  for (const alert of alerts) {
    const monitored = tenantRegistry.lookupAddress(alert.event.contractAddress);
    for (const registration of monitored) {
      if (registration.owningApp === 'PolyLance' && eventMatchesMonitoredAddress(alert.event, registration)) {
        try {
          await tenantRegistry.dispatchAlert(registration, alert);
        } catch (error) {
          console.error(`[SIEM] Webhook delivery failed for ${registration.owningApp}:`, error instanceof Error ? error.message : 'unknown error');
        }
      }
    }
  }
}

function requireApiAccess(req: Request, res: Response, next: NextFunction) {
  if (!hasApiAccess(req)) {
    res.status(401).json({ error: 'SIEM API authentication required.' });
    return;
  }
  next();
}

function isValidChainEvent(value: unknown): value is ChainEvent {
  if (!value || typeof value !== 'object') return false;
  const event = value as Partial<ChainEvent>;
  return typeof event.id === 'string' && event.id.length <= 256
    && Number.isSafeInteger(event.timestamp) && typeof event.chainId === 'number'
    && typeof event.contractAddress === 'string' && typeof event.txHash === 'string'
    && Number.isSafeInteger(event.blockNumber) && typeof event.eventName === 'string'
    && typeof event.args === 'object' && event.args !== null
    && typeof event.gasUsed === 'number' && typeof event.callValue === 'string'
    && typeof event.from === 'string';
}

function validateEvents(events: unknown): events is ChainEvent[] {
  return Array.isArray(events) && events.length > 0 && events.length <= 1000 && events.every(isValidChainEvent);
}

export function startServer(port: number = 3000) {
  const app = express();
  const httpServer = createServer(app);

  // ─── WebSocket Server (for SIEM live alerts) ─────────────────────────────
  const wss = new WebSocketServer({
    server: httpServer,
    path: '/ws/siem',
    handleProtocols: (protocols) => [...protocols].find((protocol) => protocol.startsWith('auditx-api-key.')) || '',
  });

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

  wss.on('connection', (ws, request) => {
    if (!hasApiAccess(request)) {
      ws.close(1008, 'Authentication required');
      return;
    }
    console.log('[SIEM] WebSocket client connected');

    // Send current open alerts on connect
    const openAlerts = siemEngine.getOpenAlerts();
    ws.send(JSON.stringify({ type: 'init', data: { openAlerts, baseline: siemEngine.getBaseline() } }));

    ws.on('message', async (raw) => {
      try {
        const msg = JSON.parse(raw.toString());

        // Accept: { type: 'ingest', events: ChainEvent[] }
        if (msg.type === 'ingest' && validateEvents(msg.events)) {
          const result = await siemEngine.process(msg.events as ChainEvent[]);
          await dispatchMatchingWebhooks(result.alerts);
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
        if (msg.type === 'acknowledge' && typeof msg.alertId === 'string' && msg.alertId.length <= 256) {
          const ok = siemEngine.acknowledgeAlert(msg.alertId);
          ws.send(JSON.stringify({ type: 'ack_result', alertId: msg.alertId, ok }));
          return;
        }

        // Accept: { type: 'resolve', alertId: string }
        if (msg.type === 'resolve' && typeof msg.alertId === 'string' && msg.alertId.length <= 256) {
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
  app.use('/api/siem', requireApiAccess);

  app.post('/api/siem/clients', (req, res) => {
    if (req.headers.authorization !== `Bearer ${process.env.AUDITX_API_TOKEN}`) {
      res.status(403).json({ error: 'Admin authorization required.' });
      return;
    }
    const { name, webhook_url: webhookUrl } = req.body as { name?: string; webhook_url?: string };
    if (!name || !webhookUrl) {
      res.status(400).json({ error: 'name and webhook_url are required' });
      return;
    }
    let credentials: IssuedClientCredentials;
    try {
      credentials = tenantRegistry.registerClient(name, webhookUrl);
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : 'Invalid client registration' });
      return;
    }
    res.status(201).json({
      client: credentials.client,
      api_key: credentials.apiKey,
      hmac_secret: credentials.hmacSecret,
    });
  });

  app.post('/api/siem/monitored-addresses', (req, res) => {
    const apiKey = typeof req.headers['x-api-key'] === 'string' ? req.headers['x-api-key'] : '';
    const { address, chain, watch_config: watchConfig } = req.body as {
      address?: string; chain?: string; watch_config?: string[];
    };
    if (!apiKey || !address || !chain || !watchConfig) {
      res.status(400).json({ error: 'x-api-key, address, chain, and watch_config are required' });
      return;
    }
    let monitored: MonitoredAddress;
    try {
      monitored = tenantRegistry.registerMonitoredAddress(apiKey, address, chain, watchConfig);
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : 'Invalid monitored address' });
      return;
    }
    res.status(201).json({ registration: monitored });
  });

  // ─── SSE Stream Endpoint ────────────────────────────────────────────────
  app.get('/stream', requireApiAccess, (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
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

    import('./pipeline.js').then(({ runPipeline }) => runPipeline(targetFile, { ai: false })).catch((err) => {
      console.log('[Pipeline Error]', err.message);
    });
  });

  // ─── GitHub Import & Audit Endpoint ──────────────────────────────────────
  app.post('/api/audit/github', async (req, res) => {
    const { target } = req.body as { target?: string };

    if (!target || typeof target !== 'string') {
      res.status(400).json({ error: 'Missing required "target" field in request body.' });
      return;
    }

    const gitInfo = parseGithubImport(target);
    if (!gitInfo) {
      res.status(400).json({ error: 'Invalid GitHub repository or target format.' });
      return;
    }

    const cacheDir = path.join(process.cwd(), 'cache', 'github');
    fs.mkdirSync(cacheDir, { recursive: true });
    const repoDest = path.join(cacheDir, `${gitInfo.repoName}_${Date.now()}`);

    // Immediately respond to avoid HTTP timeout issues during cloning
    res.json({
      ok: true,
      message: `GitHub repository import initiated for ${gitInfo.repoName}. Connect to /stream for live audit telemetry.`
    });

    // Execute cloning and audit pipeline in background
    (async () => {
      try {
        const { exec } = await import('child_process');
        console.log(`[GitHub API] 📥 Cloning ${gitInfo.repoUrl} in background...`);
        
        await new Promise<void>((resolve, reject) => {
          exec(`git clone --depth 1 ${gitInfo.repoUrl} "${repoDest}"`, (err) => {
            if (err) reject(new Error(`Git clone failed: ${err.message}`));
            else resolve();
          });
        });

        console.log(`[GitHub API] ✅ Repository cloned successfully to cache.`);

        let targetFiles: string[] = [];
        if (gitInfo.filePath) {
          const fullPath = path.join(repoDest, gitInfo.filePath);
          if (fs.existsSync(fullPath)) {
            targetFiles = [fullPath];
          } else {
            throw new Error(`Target file ${gitInfo.filePath} not found in the cloned repository.`);
          }
        } else {
          targetFiles = findSolFiles(repoDest);
        }

        if (targetFiles.length === 0) {
          throw new Error('No Solidity (.sol) files found in the repository.');
        }

        console.log(`[GitHub API] Starting audit pipeline on primary file: ${targetFiles[0]}`);
        const { runPipeline } = await import('./pipeline.js');
        await runPipeline(targetFiles[0], { ai: false });
      } catch (err: any) {
        console.error('[GitHub API Audit Error]', err.message);
      }
    })();
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
    if (!validateEvents(events)) {
      res.status(400).json({ error: 'Expected { events: ChainEvent[] }' });
      return;
    }

    try {
      const result = await siemEngine.process(events);
      await dispatchMatchingWebhooks(result.alerts);
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
  return httpServer;
}
