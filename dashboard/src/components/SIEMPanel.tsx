import React, { useEffect, useState, useRef } from 'react';
import { useSIEMStore } from '../store/useSIEMStore';
import {
  Shield, Wifi, WifiOff, AlertTriangle, CheckCircle2,
  Activity, Zap, Eye, RefreshCw, ChevronDown, ChevronUp, Skull,
  Radio, BarChart3, Info,
} from 'lucide-react';
import type { Alert } from '../../../src/siem/types';

// ─── Severity helpers ─────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'text-rose-400 border-rose-500/40 bg-rose-500/8',
  HIGH:     'text-orange-400 border-orange-500/40 bg-orange-500/8',
  MEDIUM:   'text-amber-400 border-amber-500/40 bg-amber-500/8',
  LOW:      'text-blue-400 border-blue-500/40 bg-blue-500/8',
  INFO:     'text-gray-400 border-white/10 bg-white/4',
};

const SEV_ICON: Record<string, React.ReactNode> = {
  CRITICAL: <Skull className="w-3 h-3" />,
  HIGH:     <AlertTriangle className="w-3 h-3" />,
  MEDIUM:   <Zap className="w-3 h-3" />,
  LOW:      <Eye className="w-3 h-3" />,
  INFO:     <Info className="w-3 h-3" />,
};

// ─── Alert row ────────────────────────────────────────────────────────────────

const AlertRow: React.FC<{ alert: Alert }> = ({ alert }) => {
  const { acknowledge, resolve } = useSIEMStore();
  const [expanded, setExpanded] = useState(false);
  const sevClass = SEV_COLOR[alert.severity] ?? SEV_COLOR.INFO;

  const isResolved = alert.status === 'RESOLVED';
  const isAcknowledged = alert.status === 'ACKNOWLEDGED';

  return (
    <div
      className={`rounded-xl border transition-all duration-300 ${
        isResolved ? 'opacity-40' : ''
      } ${sevClass}`}
    >
      {/* Header row */}
      <div
        className="flex items-start gap-3 p-3 cursor-pointer select-none"
        onClick={() => setExpanded((e) => !e)}
      >
        <div className={`mt-0.5 flex-shrink-0 ${SEV_COLOR[alert.severity]?.split(' ')[0]}`}>
          {SEV_ICON[alert.severity]}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[11px] font-bold font-outfit truncate">{alert.title}</span>
            <span className={`text-[9px] font-fira font-bold px-1.5 py-0.5 rounded-md border ${sevClass}`}>
              {alert.severity}
            </span>
            {isAcknowledged && (
              <span className="text-[9px] font-fira text-indigo-400 border border-indigo-500/30 bg-indigo-500/10 px-1.5 py-0.5 rounded-md">
                ACK
              </span>
            )}
          </div>
          <div className="text-[10px] text-gray-500 font-fira mt-0.5 truncate">
            {new Date(alert.timestamp).toLocaleTimeString()} · {alert.event.contractAddress.slice(0, 18)}…
          </div>
        </div>

        <div className="flex-shrink-0 text-gray-600">
          {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-3 pb-3 border-t border-white/5 pt-3 space-y-2">
          <p className="text-[11px] text-gray-300 leading-relaxed">{alert.description}</p>

          <div className="grid grid-cols-2 gap-2 text-[10px] font-fira text-gray-500">
            <div><span className="text-gray-600">Event:</span> {alert.event.eventName}</div>
            <div><span className="text-gray-600">Block:</span> #{alert.event.blockNumber}</div>
            <div><span className="text-gray-600">Gas:</span> {alert.event.gasUsed.toLocaleString()}</div>
            <div><span className="text-gray-600">Anomaly:</span> {(alert.event.anomaly.score * 100).toFixed(1)}%</div>
          </div>

          {/* Threat matches */}
          {alert.event.threatMatches?.length > 0 && (
            <div className="rounded-lg bg-rose-500/10 border border-rose-500/20 p-2 space-y-1">
              {alert.event.threatMatches.map((m, i) => (
                <div key={i} className="text-[10px] font-fira text-rose-300">
                  ☠ {m.feed.label} · {m.feed.category} · Score: {m.feed.riskScore}/10
                </div>
              ))}
            </div>
          )}

          {/* Actions */}
          {!isResolved && (
            <div className="flex gap-2 pt-1">
              {!isAcknowledged && (
                <button
                  onClick={(e) => { e.stopPropagation(); acknowledge(alert.id); }}
                  className="text-[10px] font-fira font-bold px-3 py-1.5 rounded-lg border border-indigo-500/30 bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 transition-colors"
                >
                  Acknowledge
                </button>
              )}
              <button
                onClick={(e) => { e.stopPropagation(); resolve(alert.id); }}
                className="text-[10px] font-fira font-bold px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 transition-colors"
              >
                Resolve
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ─── Stat card ────────────────────────────────────────────────────────────────

const StatCard: React.FC<{ label: string; value: string | number; icon: React.ReactNode; color?: string }> = ({
  label, value, icon, color = 'text-indigo-400',
}) => (
  <div className="rounded-xl border border-white/8 bg-white/[0.03] p-3">
    <div className={`flex items-center gap-2 mb-1 ${color}`}>
      {icon}
      <span className="text-[10px] font-fira font-bold uppercase tracking-widest">{label}</span>
    </div>
    <div className="text-xl font-extrabold font-outfit text-white">{value}</div>
  </div>
);

// ─── Animated gas gauge ───────────────────────────────────────────────────────

const GasGauge: React.FC<{ mean: number; stdDev: number }> = ({ mean, stdDev }) => {
  const pct = Math.min(100, (mean / 200_000) * 100);
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[10px] font-fira text-gray-500">
        <span>Gas Baseline μ</span>
        <span className="text-white font-bold">{mean.toFixed(0)}</span>
      </div>
      <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
        <div
          className="h-full rounded-full bg-gradient-to-r from-indigo-500 to-purple-500 transition-all duration-700"
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="flex justify-between text-[9px] font-fira text-gray-700">
        <span>21k</span>
        <span>σ={stdDev.toFixed(0)}</span>
        <span>200k</span>
      </div>
    </div>
  );
};

// ─── Mini alert frequency chart ───────────────────────────────────────────────

const AlertFreqChart: React.FC<{ alerts: Alert[] }> = ({ alerts }) => {
  // Build last-60-second buckets (10 × 6s buckets)
  const now = Date.now();
  const buckets = Array(10).fill(0);
  for (const a of alerts) {
    const age = (now - a.timestamp) / 1000;
    const bucket = Math.floor(age / 6);
    if (bucket >= 0 && bucket < 10) buckets[9 - bucket]++;
  }
  const max = Math.max(...buckets, 1);

  return (
    <div className="space-y-1">
      <div className="text-[10px] font-fira text-gray-500">Alert frequency (last 60s)</div>
      <div className="flex items-end gap-1 h-10">
        {buckets.map((count, i) => (
          <div
            key={i}
            className="flex-1 rounded-sm bg-gradient-to-t from-indigo-500/60 to-purple-500/40 transition-all duration-500"
            style={{ height: `${(count / max) * 100}%`, minHeight: count > 0 ? '4px' : '2px' }}
          />
        ))}
      </div>
    </div>
  );
};

// ─── Connection pill ──────────────────────────────────────────────────────────

const ConnectPill: React.FC = () => {
  const { wsStatus, connect, disconnect } = useSIEMStore();
  const [url] = useState('ws://localhost:3000/ws/siem');

  return (
    <div className="flex items-center gap-2">
      <div className={`flex items-center gap-1.5 text-[10px] font-fira font-bold px-2.5 py-1.5 rounded-full border transition-colors ${
        wsStatus === 'connected'    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400' :
        wsStatus === 'connecting'   ? 'border-amber-500/40 bg-amber-500/10 text-amber-400' :
        wsStatus === 'error'        ? 'border-rose-500/40 bg-rose-500/10 text-rose-400' :
                                      'border-white/10 bg-white/5 text-gray-500'
      }`}>
        {wsStatus === 'connected'  ? <Wifi className="w-3 h-3" />   : <WifiOff className="w-3 h-3" />}
        {wsStatus.toUpperCase()}
      </div>

      {wsStatus !== 'connected' ? (
        <button
          onClick={() => connect(url)}
          className="text-[10px] font-fira font-bold px-3 py-1.5 rounded-lg border border-indigo-500/40 bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 transition-colors flex items-center gap-1.5"
        >
          <Radio className="w-3 h-3" /> Connect
        </button>
      ) : (
        <button
          onClick={disconnect}
          className="text-[10px] font-fira font-bold px-3 py-1.5 rounded-lg border border-white/10 bg-white/5 text-gray-400 hover:text-rose-400 hover:border-rose-500/30 transition-colors"
        >
          Disconnect
        </button>
      )}
    </div>
  );
};

// ─── Main SIEMPanel ───────────────────────────────────────────────────────────

export const SIEMPanel: React.FC = () => {
  const {
    wsStatus, alerts, baseline, eventCount, anomalyCount, threatCount,
    clearResolved,
  } = useSIEMStore();

  const [filter, setFilter] = useState<'ALL' | 'OPEN' | 'CRITICAL' | 'HIGH'>('ALL');
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to top when new alert arrives
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  }, [alerts.length]);

  const filtered = alerts.filter((a) => {
    if (filter === 'OPEN')     return a.status === 'OPEN';
    if (filter === 'CRITICAL') return a.severity === 'CRITICAL';
    if (filter === 'HIGH')     return a.severity === 'HIGH' || a.severity === 'CRITICAL';
    return true;
  });

  const openCount     = alerts.filter(a => a.status === 'OPEN').length;
  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL' && a.status === 'OPEN').length;

  return (
    <div className="space-y-5">
      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-rose-500/20 to-orange-500/20 border border-rose-500/20 flex items-center justify-center">
            <Shield className="w-4 h-4 text-rose-400" />
          </div>
          <div>
            <h2 className="text-base font-extrabold font-outfit text-white">SIEM Monitor</h2>
            <p className="text-[10px] text-gray-500 font-fira">Real-time post-deploy threat detection</p>
          </div>
          {criticalCount > 0 && (
            <div className="flex items-center gap-1.5 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-[10px] font-fira font-bold px-2.5 py-1 rounded-full animate-pulse">
              <AlertTriangle className="w-3 h-3" />
              {criticalCount} CRITICAL
            </div>
          )}
        </div>
        <ConnectPill />
      </div>

      {/* ── Stats grid ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Events"   value={eventCount}   icon={<Activity className="w-3 h-3" />}  color="text-indigo-400" />
        <StatCard label="Alerts"   value={openCount}    icon={<AlertTriangle className="w-3 h-3" />} color="text-amber-400" />
        <StatCard label="Anomalies" value={anomalyCount} icon={<BarChart3 className="w-3 h-3" />} color="text-purple-400" />
        <StatCard label="Threats"   value={threatCount}  icon={<Skull className="w-3 h-3" />}    color="text-rose-400" />
      </div>

      {/* ── Baseline + chart row ── */}
      {baseline && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 rounded-xl border border-white/8 bg-white/[0.02] p-4">
          <GasGauge mean={baseline.gasUsed.mean} stdDev={baseline.gasUsed.stdDev} />
          <AlertFreqChart alerts={alerts} />
        </div>
      )}

      {/* ── Alert list ── */}
      <div className="rounded-xl border border-white/8 bg-white/[0.02] overflow-hidden">
        {/* Filter tabs */}
        <div className="flex items-center justify-between border-b border-white/5 px-4 py-2">
          <div className="flex gap-1">
            {(['ALL', 'OPEN', 'CRITICAL', 'HIGH'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`text-[10px] font-fira font-bold px-3 py-1 rounded-lg transition-colors ${
                  filter === f
                    ? 'bg-indigo-500/20 border border-indigo-500/30 text-indigo-300'
                    : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
          <button
            onClick={clearResolved}
            className="flex items-center gap-1.5 text-[10px] font-fira text-gray-600 hover:text-gray-400 transition-colors"
          >
            <RefreshCw className="w-3 h-3" /> Clear resolved
          </button>
        </div>

        {/* Alert scroll area */}
        <div ref={scrollRef} className="max-h-[480px] overflow-y-auto p-3 space-y-2">
          {wsStatus === 'disconnected' && (
            <div className="text-center py-12 space-y-3">
              <WifiOff className="w-8 h-8 text-gray-700 mx-auto" />
              <p className="text-sm text-gray-600 font-outfit">Not connected to SIEM server</p>
              <p className="text-[11px] text-gray-700 font-fira">
                Start the server with <code className="bg-white/5 px-1.5 py-0.5 rounded">npm run dev</code> then click Connect
              </p>
            </div>
          )}

          {wsStatus === 'connected' && filtered.length === 0 && (
            <div className="text-center py-12 space-y-3">
              <CheckCircle2 className="w-8 h-8 text-emerald-500/40 mx-auto" />
              <p className="text-sm text-gray-500 font-outfit">No alerts · All clear</p>
              <p className="text-[11px] text-gray-700 font-fira">
                Monitoring {eventCount} events processed
              </p>
            </div>
          )}

          {filtered.map((alert) => (
            <AlertRow key={alert.id} alert={alert} />
          ))}
        </div>

        {/* Footer */}
        <div className="border-t border-white/5 px-4 py-2 flex items-center justify-between">
          <span className="text-[10px] font-fira text-gray-700">
            {filtered.length} of {alerts.length} alerts shown
          </span>
          <span className="text-[10px] font-fira text-gray-700">
            {baseline ? `Baseline n=${baseline.gasUsed.n} (${baseline.syntheticSamples} synthetic)` : 'Baseline loading…'}
          </span>
        </div>
      </div>
    </div>
  );
};
