// @ts-nocheck
import { createServer, type Server } from 'http';
import { once } from 'events';
import { WalletRiskClient } from '../legacy/src/identity/walletRiskClient.js';

const servers: Server[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) server.close();
});

describe('Phase 6: Wallet Login SIWE Scorer Fail-Safe Contract', () => {
  it('yields STEP_UP and requires extra challenge when scorer response exceeds 250ms', async () => {
    // Mock a slow server that delays 400ms
    const slowServer = createServer((req, res) => {
      setTimeout(() => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ decision: 'ALLOW', trust_score: 95 }));
      }, 400);
    }).listen(0);
    servers.push(slowServer);
    await once(slowServer, 'listening');
    const port = (slowServer.address() as { port: number }).port;

    const client = new WalletRiskClient(`http://127.0.0.1:${port}/assess-wallet-login`, undefined, 250);
    const assessment = await client.assessLogin({
      wallet_address: '0x1111111111111111111111111111111111111111',
      message: 'Sign In With Ethereum',
      signature: '0xsig',
      ip_address: '1.2.3.4',
      user_agent: 'Mozilla',
      device_fingerprint: 'fp123',
    });

    expect(assessment.decision).toBe('STEP_UP');
    expect(assessment.decision).not.toBe('ALLOW');
    expect(assessment.requires_extra_challenge).toBe(true);
    expect(assessment.trust_score).toBe(50);
    expect(assessment.risk_flags).toContain('SCORER_TIMEOUT_EXCEEDED');
  });

  it('yields STEP_UP when scorer returns HTTP 500 error', async () => {
    const errorServer = createServer((req, res) => {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }).listen(0);
    servers.push(errorServer);
    await once(errorServer, 'listening');
    const port = (errorServer.address() as { port: number }).port;

    const client = new WalletRiskClient(`http://127.0.0.1:${port}/assess-wallet-login`, undefined, 250);
    const assessment = await client.assessLogin({
      wallet_address: '0x2222222222222222222222222222222222222222',
      message: 'Sign In With Ethereum',
      signature: '0xsig',
      ip_address: '1.2.3.4',
      user_agent: 'Mozilla',
      device_fingerprint: 'fp123',
    });

    expect(assessment.decision).toBe('STEP_UP');
    expect(assessment.decision).not.toBe('ALLOW');
    expect(assessment.requires_extra_challenge).toBe(true);
    expect(assessment.risk_flags).toContain('HTTP_ERROR_500');
  });

  it('yields STEP_UP when scorer is unreachable (connection refused)', async () => {
    const client = new WalletRiskClient('http://127.0.0.1:49991/assess-wallet-login', undefined, 250);
    const assessment = await client.assessLogin({
      wallet_address: '0x3333333333333333333333333333333333333333',
      message: 'Sign In With Ethereum',
      signature: '0xsig',
      ip_address: '1.2.3.4',
      user_agent: 'Mozilla',
      device_fingerprint: 'fp123',
    });

    expect(assessment.decision).toBe('STEP_UP');
    expect(assessment.decision).not.toBe('ALLOW');
    expect(assessment.requires_extra_challenge).toBe(true);
  });
});
