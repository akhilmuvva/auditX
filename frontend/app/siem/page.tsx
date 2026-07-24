'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { 
  ShieldAlert, ShieldCheck, Activity, Zap, Play, Filter, 
  Search, RefreshCw, AlertTriangle, Cpu, Terminal, Eye, Layers 
} from 'lucide-react';

export default function SIEMDashboard() {
  const [events, setEvents] = useState<any[]>([]);
  const [rules, setRules] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<any>({
    total_events: 0,
    critical_threats: 0,
    high_threats: 0,
    active_rules: 0,
    status: 'SECURE',
  });

  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [fortaAlerts, setFortaAlerts] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState<'stream' | 'rules' | 'forta'>('stream');
  const [selectedEvent, setSelectedEvent] = useState<any>(null);

  const fetchSIEMData = async () => {
    try {
      const res = await fetch('/api/siem');
      const fortaRes = await fetch('/api/forta/alerts');
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events || []);
        setRules(data.rules || []);
        setMetrics(data.metrics || {});
      }
      if (fortaRes.ok) {
        const fortaData = await fortaRes.json();
        setFortaAlerts(fortaData.alerts || []);
      }
    } catch (e) {
      console.error('Failed to fetch SIEM data:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSIEMData();
    const interval = setInterval(fetchSIEMData, 4000); // 4s live polling loop
    return () => clearInterval(interval);
  }, []);

  const triggerSimulation = async (scenario: string) => {
    setSimulating(true);
    try {
      const res = await fetch('/api/siem', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario }),
      });
      if (res.ok) {
        await fetchSIEMData();
      }
    } catch (e) {
      console.error(e);
    } finally {
      setSimulating(false);
    }
  };

  const filteredEvents = events.filter((evt) => {
    if (selectedCategory !== 'ALL' && evt.category !== selectedCategory) return false;
    if (selectedSeverity !== 'ALL' && evt.severity !== selectedSeverity) return false;
    if (searchQuery.trim() !== '') {
      const q = searchQuery.toLowerCase();
      const matchAddr = evt.contract_address.toLowerCase().includes(q);
      const matchCaller = evt.caller.toLowerCase().includes(q);
      const matchTx = evt.tx_hash.toLowerCase().includes(q);
      const matchRule = evt.rule_matched.toLowerCase().includes(q);
      const matchDesc = evt.description.toLowerCase().includes(q);
      if (!matchAddr && !matchCaller && !matchTx && !matchRule && !matchDesc) return false;
    }
    return true;
  });

  const getSevPill = (sev: string) => {
    switch (sev) {
      case 'Critical':
        return 'bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] px-2 py-0.5 rounded font-extrabold uppercase';
      case 'High':
        return 'bg-orange-500/10 text-orange-400 border border-orange-500/20 text-[10px] px-2 py-0.5 rounded font-extrabold uppercase';
      case 'Medium':
        return 'bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[10px] px-2 py-0.5 rounded font-extrabold uppercase';
      case 'Low':
        return 'bg-blue-500/10 text-blue-400 border border-blue-500/20 text-[10px] px-2 py-0.5 rounded font-extrabold uppercase';
      default:
        return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] px-2 py-0.5 rounded font-extrabold uppercase';
    }
  };

  return (
    <div className="min-h-screen bg-[#030303] text-white flex flex-col font-sans relative selection:bg-indigo-500 selection:text-white pb-16">
      {/* Background radial glow */}
      <div className="absolute top-0 right-1/4 w-[45%] h-[40%] rounded-full bg-indigo-500/5 blur-[140px] pointer-events-none" />

      {/* Header */}
      <header className="border-b border-white/[0.06] bg-black/40 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-indigo-500 to-emerald-500 flex items-center justify-center font-bold text-black text-lg">
              A
            </div>
            <span className="font-extrabold text-xl tracking-tight bg-gradient-to-r from-white to-white/70 bg-clip-text text-transparent">
              Audit<span className="text-indigo-400">X</span>
            </span>
          </Link>

          <nav className="hidden md:flex items-center gap-8 text-sm font-medium text-white/60">
            <Link href="/dashboard" className="hover:text-white transition-colors">Dashboard</Link>
            <Link href="/audit" className="hover:text-white transition-colors">New Audit</Link>
            <Link href="/siem" className="text-white font-bold transition-colors flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-emerald-400 animate-pulse" /> Web3 SIEM
            </Link>
          </nav>

          <div className="flex items-center gap-3">
            <span className="text-[11px] font-semibold px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
              SIEM Agent Active
            </span>
          </div>
        </div>
      </header>

      {/* Main Body */}
      <main className="max-w-7xl w-full mx-auto px-6 py-8 flex flex-col gap-8 flex-1">
        {/* Title Banner */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-white/[0.06] pb-6">
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <h1 className="text-3xl font-black tracking-tight">Web3 SIEM Security Toolkit</h1>
              <span className="bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 text-[10px] font-bold px-2 py-0.5 rounded">
                Real-Time
              </span>
            </div>
            <p className="text-white/60 text-xs sm:text-sm max-w-2xl">
              Live threat telemetry stream, event logging, and rule evaluation for smart contracts, cross-layer Web2 exposures, and EVM transactions.
            </p>
          </div>

          <button
            onClick={() => fetchSIEMData()}
            disabled={loading}
            className="self-start md:self-auto bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] text-xs font-semibold px-4 py-2.5 rounded-xl flex items-center gap-2 transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Stream
          </button>
        </div>

        {/* SIEM Metrics Cards Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          <div className="p-5 rounded-2xl bg-white/[0.01] border border-white/[0.06] flex flex-col gap-1 relative overflow-hidden">
            <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">Total Telemetry Ingested</span>
            <span className="text-3xl font-black">{metrics.total_events || 0}</span>
            <span className="text-[10px] text-emerald-400 mt-1 font-semibold flex items-center gap-1">
              <Activity className="w-3 h-3" /> Live Event Pipeline
            </span>
          </div>

          <div className="p-5 rounded-2xl bg-white/[0.01] border border-white/[0.06] flex flex-col gap-1 relative overflow-hidden">
            <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">Critical Threat Alerts</span>
            <span className="text-3xl font-black text-rose-500">{metrics.critical_threats || 0}</span>
            <span className="text-[10px] text-rose-400/80 mt-1 font-semibold">Immediate Remediation Required</span>
          </div>

          <div className="p-5 rounded-2xl bg-white/[0.01] border border-white/[0.06] flex flex-col gap-1 relative overflow-hidden">
            <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">High Severity Intrusions</span>
            <span className="text-3xl font-black text-orange-500">{metrics.high_threats || 0}</span>
            <span className="text-[10px] text-orange-400/80 mt-1 font-semibold">Ownership & Access Anomalies</span>
          </div>

          <div className="p-5 rounded-2xl bg-white/[0.01] border border-white/[0.06] flex flex-col gap-1 relative overflow-hidden">
            <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">Active Rule Matchers</span>
            <span className="text-3xl font-black text-indigo-400">{metrics.active_rules || 5}</span>
            <span className="text-[10px] text-indigo-300 mt-1 font-semibold">Flash Loan / Reentrancy / OWASP</span>
          </div>
        </div>

        {/* Real-Time Security Test Simulator */}
        <div className="p-6 rounded-2xl bg-gradient-to-r from-indigo-950/20 via-black to-emerald-950/20 border border-white/[0.08] flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Zap className="w-5 h-5 text-indigo-400" />
              <h3 className="font-extrabold text-sm uppercase tracking-wide">Real-Time Threat Test Simulator</h3>
            </div>
            <span className="text-[10px] text-white/40 font-mono">Trigger Security Telemetry Events</span>
          </div>
          <p className="text-xs text-white/60">
            Click any attack scenario button below to simulate an incoming EVM transaction event and test live SIEM threat rule evaluation:
          </p>

          <div className="flex flex-wrap gap-3 pt-2">
            <button
              onClick={() => triggerSimulation('flashloan')}
              disabled={simulating}
              className="bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-300 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all flex items-center gap-1.5"
            >
              <Play className="w-3 h-3 fill-current" /> Simulate Flash Loan Drain
            </button>

            <button
              onClick={() => triggerSimulation('reentrancy')}
              disabled={simulating}
              className="bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/30 text-orange-300 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all flex items-center gap-1.5"
            >
              <Play className="w-3 h-3 fill-current" /> Simulate Reentrancy Loop
            </button>

            <button
              onClick={() => triggerSimulation('ownership')}
              disabled={simulating}
              className="bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-300 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all flex items-center gap-1.5"
            >
              <Play className="w-3 h-3 fill-current" /> Simulate Admin Hijack
            </button>

            <button
              onClick={() => triggerSimulation('crosslayer')}
              disabled={simulating}
              className="bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/30 text-purple-300 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all flex items-center gap-1.5"
            >
              <Play className="w-3 h-3 fill-current" /> Simulate Web2 Secret Leak
            </button>

            <button
              onClick={() => triggerSimulation('gasspike')}
              disabled={simulating}
              className="bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 text-blue-300 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all flex items-center gap-1.5"
            >
              <Play className="w-3 h-3 fill-current" /> Simulate Gas Spike
            </button>

            <button
              onClick={() => triggerSimulation('normal')}
              disabled={simulating}
              className="bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all flex items-center gap-1.5"
            >
              <Play className="w-3 h-3 fill-current" /> Simulate Compliant Tx
            </button>
          </div>
        </div>

        {/* Tab Links: Telemetry Stream vs Detection Rules */}
        <div className="flex border-b border-white/[0.06] gap-8 text-sm font-semibold">
          <button
            onClick={() => setActiveTab('stream')}
            className={`pb-3 relative transition-colors ${activeTab === 'stream' ? 'text-white' : 'text-white/40 hover:text-white/60'}`}
          >
            Live Security Stream ({filteredEvents.length})
            {activeTab === 'stream' && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500" />}
          </button>

          <button
            onClick={() => setActiveTab('rules')}
            className={`pb-3 relative transition-colors ${activeTab === 'rules' ? 'text-white' : 'text-white/40 hover:text-white/60'}`}
          >
            SIEM Rule Matchers ({rules.length})
            {activeTab === 'rules' && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500" />}
          </button>

          <button
            onClick={() => setActiveTab('forta')}
            className={`pb-3 relative transition-colors ${activeTab === 'forta' ? 'text-white' : 'text-white/40 hover:text-white/60'}`}
          >
            Forta Bot Alerts ({fortaAlerts.length})
            {activeTab === 'forta' && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500" />}
          </button>
        </div>

        {/* Stream Tab Content */}
        {activeTab === 'stream' && (
          <div className="flex flex-col gap-6">
            {/* Filter Bar */}
            <div className="flex flex-col md:flex-row items-center justify-between gap-4 bg-white/[0.01] p-4 rounded-xl border border-white/[0.06]">
              {/* Search input */}
              <div className="relative w-full md:w-80">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-white/40" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search tx hash, contract, rule..."
                  className="w-full bg-white/[0.03] border border-white/[0.08] rounded-xl pl-9 pr-4 py-2 text-xs outline-none focus:border-indigo-500/50 text-white/80 placeholder:text-white/20"
                />
              </div>

              {/* Category Dropdown */}
              <div className="flex items-center gap-4 w-full md:w-auto">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-white/40 font-bold uppercase">Category:</span>
                  <select
                    value={selectedCategory}
                    onChange={(e) => setSelectedCategory(e.target.value)}
                    className="bg-black border border-white/[0.08] text-xs rounded-xl px-3 py-2 outline-none text-white/80"
                  >
                    <option value="ALL">All Categories</option>
                    <option value="FlashLoan">Flash Loan</option>
                    <option value="Reentrancy">Reentrancy</option>
                    <option value="OwnershipHijack">Ownership Hijack</option>
                    <option value="CrossLayerIntrusion">Cross-Layer Leak</option>
                    <option value="GasSpike">Gas Spike</option>
                  </select>
                </div>

                {/* Severity Dropdown */}
                <div className="flex items-center gap-2">
                  <span className="text-xs text-white/40 font-bold uppercase">Severity:</span>
                  <select
                    value={selectedSeverity}
                    onChange={(e) => setSelectedSeverity(e.target.value)}
                    className="bg-black border border-white/[0.08] text-xs rounded-xl px-3 py-2 outline-none text-white/80"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Info">Info</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Events Stream Table */}
            <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="text-white/40 border-b border-white/[0.06]">
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Severity</th>
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Timestamp</th>
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Network & Event</th>
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Target Contract</th>
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Matched SIEM Rule</th>
                    <th className="pb-3 font-bold uppercase tracking-wide text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.map((evt, idx) => (
                    <tr key={idx} className="border-b border-white/[0.04] hover:bg-white/[0.01] transition-colors">
                      <td className="py-4 pr-4">{getSevPill(evt.severity)}</td>
                      <td className="py-4 pr-4 font-mono text-white/50 text-[11px]">
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-4 pr-4">
                        <div className="flex flex-col">
                          <span className="font-bold text-white/90">{evt.event_type}</span>
                          <span className="text-[10px] text-indigo-400 font-mono">{evt.network}</span>
                        </div>
                      </td>
                      <td className="py-4 pr-4 font-mono text-white/60 text-[11px]">
                        {evt.contract_address.slice(0, 10)}...{evt.contract_address.slice(-6)}
                      </td>
                      <td className="py-4 pr-4 font-semibold text-white/80 max-w-xs truncate">
                        {evt.rule_matched}
                      </td>
                      <td className="py-4 text-right">
                        <button
                          onClick={() => setSelectedEvent(evt)}
                          className="bg-white/[0.04] hover:bg-white/[0.08] text-white text-[11px] font-semibold px-3 py-1.5 rounded-lg border border-white/[0.08] transition-all inline-flex items-center gap-1"
                        >
                          <Eye className="w-3 h-3" /> Inspect
                        </button>
                      </td>
                    </tr>
                  ))}

                  {filteredEvents.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-white/40">
                        No security telemetry events match the selected filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Rules Tab Content */}
        {activeTab === 'rules' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {rules.map((rule, idx) => (
              <div key={idx} className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.06] flex flex-col gap-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-indigo-400 font-bold">{rule.id}</span>
                  {getSevPill(rule.severity)}
                </div>
                <h4 className="font-bold text-base">{rule.name}</h4>
                <p className="text-xs text-white/60 leading-relaxed bg-black/40 p-3 rounded-xl border border-white/[0.04] font-mono">
                  {rule.condition_description}
                </p>
                <div className="flex items-center justify-between border-t border-white/[0.04] pt-3 text-xs">
                  <span className="text-white/40">Status: <strong className="text-emerald-400">ENABLED</strong></span>
                  <span className="text-[10px] text-white/40 uppercase tracking-wider">{rule.category}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Forta Bot Alerts Tab Content */}
        {activeTab === 'forta' && (
          <div className="flex flex-col gap-6">
            <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.06] flex flex-col gap-6">
              <div className="flex items-center justify-between">
                <div className="flex flex-col gap-1">
                  <h3 className="font-bold text-sm">Forta Decentralized Security Network Alerts</h3>
                  <p className="text-xs text-white/50">
                    Real-time threat signals emitted by Forta Detection Bots scanning EVM transactions.
                  </p>
                </div>
                <span className="text-[10px] text-emerald-400 font-bold bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded-full uppercase">
                  Forta Network Active
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {fortaAlerts.map((alert, idx) => (
                  <div key={idx} className="p-5 rounded-2xl bg-white/[0.02] border border-white/[0.06] flex flex-col gap-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
                        {alert.bot_name}
                      </span>
                      {getSevPill(alert.severity)}
                    </div>

                    <h4 className="font-extrabold text-sm">{alert.title}</h4>
                    <p className="text-xs text-white/70 leading-relaxed bg-black/40 p-3 rounded-xl border border-white/[0.04]">
                      {alert.description}
                    </p>

                    <div className="flex flex-col gap-1 text-[11px] font-mono border-t border-white/[0.04] pt-3 text-white/60">
                      <div>Target Contract: <span className="text-indigo-300">{alert.contract_address}</span></div>
                      <div>Suggested Action: <span className="text-amber-400">{alert.action_suggested}</span></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Event Detail Modal Drawer */}
        {selectedEvent && (
          <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-6">
            <div className="bg-[#08080c] border border-white/[0.1] max-w-2xl w-full rounded-3xl p-8 flex flex-col gap-6 relative shadow-2xl">
              <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
                <div className="flex items-center gap-3">
                  {getSevPill(selectedEvent.severity)}
                  <h3 className="font-black text-lg">{selectedEvent.event_type}</h3>
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="text-white/40 hover:text-white font-bold text-lg px-2"
                >
                  ✕
                </button>
              </div>

              <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                <div className="flex flex-col gap-1 p-3 rounded-xl bg-white/[0.02] border border-white/[0.04]">
                  <span className="text-[10px] text-white/40">NETWORK</span>
                  <span className="text-indigo-400">{selectedEvent.network}</span>
                </div>
                <div className="flex flex-col gap-1 p-3 rounded-xl bg-white/[0.02] border border-white/[0.04]">
                  <span className="text-[10px] text-white/40">BLOCK NUMBER</span>
                  <span>#{selectedEvent.block_number}</span>
                </div>
                <div className="flex flex-col gap-1 p-3 rounded-xl bg-white/[0.02] border border-white/[0.04] col-span-2">
                  <span className="text-[10px] text-white/40">TRANSACTION HASH</span>
                  <span className="text-white/80 break-all">{selectedEvent.tx_hash}</span>
                </div>
              </div>

              <div className="flex flex-col gap-2">
                <span className="text-xs font-bold text-white/40 uppercase tracking-wider">SIEM Rule Matcher</span>
                <p className="text-xs text-white/80 font-bold bg-white/[0.02] p-3 rounded-xl border border-white/[0.04]">
                  {selectedEvent.rule_matched}
                </p>
              </div>

              <div className="flex flex-col gap-2">
                <span className="text-xs font-bold text-white/40 uppercase tracking-wider">Threat Telemetry Description</span>
                <p className="text-xs text-white/70 leading-relaxed bg-white/[0.02] p-3 rounded-xl border border-white/[0.04]">
                  {selectedEvent.description}
                </p>
              </div>

              <div className="flex flex-col gap-2">
                <span className="text-xs font-bold text-white/40 uppercase tracking-wider">Payload Bytecode Preview</span>
                <pre className="text-[11px] font-mono bg-black p-4 rounded-xl border border-white/[0.08] text-emerald-400 overflow-x-auto">
                  {selectedEvent.payload_preview}
                </pre>
              </div>

              <button
                onClick={() => setSelectedEvent(null)}
                className="w-full bg-white hover:bg-white/90 text-black font-bold py-3 rounded-xl text-xs transition-all mt-2"
              >
                Close Telemetry Inspection
              </button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
