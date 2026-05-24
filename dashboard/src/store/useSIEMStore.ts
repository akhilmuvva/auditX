import { create } from 'zustand';
import type { Alert } from '../types/siem';

// ─── Types ────────────────────────────────────────────────────────────────────

export type WsStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

export interface Baseline {
  gasUsed: { mean: number; stdDev: number; n: number };
  callValue: { mean: number; stdDev: number; n: number };
  syntheticSamples: number;
}

interface SIEMStore {
  // Connection
  wsStatus: WsStatus;
  ws: WebSocket | null;

  // Data
  alerts: Alert[];
  baseline: Baseline | null;
  eventCount: number;
  anomalyCount: number;
  threatCount: number;

  // Actions
  connect: (url?: string) => void;
  disconnect: () => void;
  acknowledge: (alertId: string) => void;
  resolve: (alertId: string) => void;
  clearResolved: () => void;
  ingestEvents: (events: any[]) => void;
}

// ─── Default WS URL ───────────────────────────────────────────────────────────

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';
const DEFAULT_WS_URL = `${API_URL.replace(/^http/, 'ws')}/ws/siem`;

// ─── Store ────────────────────────────────────────────────────────────────────

export const useSIEMStore = create<SIEMStore>((set, get) => ({
  wsStatus: 'disconnected',
  ws: null,
  alerts: [],
  baseline: null,
  eventCount: 0,
  anomalyCount: 0,
  threatCount: 0,

  connect: (url = DEFAULT_WS_URL) => {
    const existing = get().ws;
    if (existing && existing.readyState < 2) existing.close();

    set({ wsStatus: 'connecting' });

    const ws = new WebSocket(url);

    ws.onopen = () => set({ wsStatus: 'connected' });

    ws.onclose = () => set({ wsStatus: 'disconnected', ws: null });

    ws.onerror = () => set({ wsStatus: 'error' });

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);

        if (msg.type === 'init') {
          set({
            alerts: msg.data.openAlerts ?? [],
            baseline: msg.data.baseline ?? null,
          });
        }

        if (msg.type === 'alert') {
          set((s) => ({ alerts: [msg.data, ...s.alerts].slice(0, 200) }));
        }

        if (msg.type === 'baseline') {
          set({ baseline: msg.data });
        }

        if (msg.type === 'processed') {
          const d = msg.data;
          set((s) => ({
            eventCount: s.eventCount + (d.classified ?? 0),
            anomalyCount: s.anomalyCount + (d.anomalies ?? 0),
            threatCount: s.threatCount + (d.threatMatches ?? 0),
          }));
        }
      } catch {
        // ignore malformed
      }
    };

    set({ ws });
  },

  disconnect: () => {
    get().ws?.close();
    set({ wsStatus: 'disconnected', ws: null });
  },

  acknowledge: (alertId) => {
    const ws = get().ws;
    if (ws?.readyState === 1) ws.send(JSON.stringify({ type: 'acknowledge', alertId }));
    set((s) => ({
      alerts: s.alerts.map((a) => a.id === alertId ? { ...a, status: 'ACKNOWLEDGED' as const } : a),
    }));
  },

  resolve: (alertId) => {
    const ws = get().ws;
    if (ws?.readyState === 1) ws.send(JSON.stringify({ type: 'resolve', alertId }));
    set((s) => ({
      alerts: s.alerts.map((a) => a.id === alertId ? { ...a, status: 'RESOLVED' as const } : a),
    }));
  },

  clearResolved: () => {
    set((s) => ({ alerts: s.alerts.filter((a) => a.status !== 'RESOLVED') }));
  },

  ingestEvents: (events) => {
    const ws = get().ws;
    if (ws?.readyState === 1) {
      ws.send(JSON.stringify({ type: 'ingest', events }));
    }
  },
}));
