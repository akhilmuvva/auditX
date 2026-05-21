import express from 'express';
import cors from 'cors';
import { auditEmitter } from './events.js';

export function startServer(port: number = 3000) {
  const app = express();
  app.use(cors());

  app.get('/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

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
      auditEmitter.off('step', onStep);
      auditEmitter.off('status', onStatus);
    });
  });

  app.listen(port, () => {
    console.log(`📡 SSE Telemetry server running on port ${port}`);
  });
}
