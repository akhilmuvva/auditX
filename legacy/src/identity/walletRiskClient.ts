import { setTimeout as sleep } from 'timers/promises';

export interface WalletLoginRiskAssessment {
  wallet_address: string;
  trust_score: number;
  decision: 'ALLOW' | 'STEP_UP' | 'DENY';
  risk_flags: string[];
  latency_ms: number;
  requires_extra_challenge: boolean;
}

export interface WalletLoginRequest {
  wallet_address: string;
  message: string;
  signature: string;
  ip_address: string;
  user_agent: string;
  device_fingerprint: string;
}

export class WalletRiskClient {
  private serviceUrl: string;
  private serviceKey?: string;
  private timeoutMs: number;

  constructor(
    serviceUrl = process.env.IDENTITY_SERVICE_URL || 'http://127.0.0.1:8088/assess-wallet-login',
    serviceKey = process.env.IDENTITY_SERVICE_KEY,
    timeoutMs = 250
  ) {
    this.serviceUrl = serviceUrl;
    this.serviceKey = serviceKey;
    this.timeoutMs = timeoutMs;
  }

  async assessLogin(req: WalletLoginRequest): Promise<WalletLoginRiskAssessment> {
    const startTime = performance.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers: Record<string, string> = {
        'content-type': 'application/json',
      };
      if (this.serviceKey) {
        headers['x-service-key'] = this.serviceKey;
      }

      const res = await fetch(this.serviceUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(req),
        signal: controller.signal,
      });

      const elapsed = performance.now() - startTime;

      if (!res.ok) {
        // SECURITY-DECISION: Fail-Safe StepUp on HTTP error
        return {
          wallet_address: req.wallet_address.toLowerCase(),
          trust_score: 50,
          decision: 'STEP_UP',
          risk_flags: [`HTTP_ERROR_${res.status}`],
          latency_ms: elapsed,
          requires_extra_challenge: true,
        };
      }

      const data = await res.json();
      return {
        wallet_address: data.wallet_address || req.wallet_address.toLowerCase(),
        trust_score: data.trust_score ?? 50,
        decision: data.decision || 'STEP_UP',
        risk_flags: data.risk_flags || [],
        latency_ms: elapsed,
        requires_extra_challenge: data.decision !== 'ALLOW',
      };
    } catch (err: any) {
      const elapsed = performance.now() - startTime;
      const isTimeout = err.name === 'AbortError' || elapsed >= this.timeoutMs;

      // SECURITY-DECISION: Strict fail-safe. On timeout or connection drop, ALWAYS STEP_UP, NEVER ALLOW.
      return {
        wallet_address: req.wallet_address.toLowerCase(),
        trust_score: 50,
        decision: 'STEP_UP',
        risk_flags: [isTimeout ? 'SCORER_TIMEOUT_EXCEEDED' : 'SCORER_UNREACHABLE'],
        latency_ms: elapsed,
        requires_extra_challenge: true,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}
