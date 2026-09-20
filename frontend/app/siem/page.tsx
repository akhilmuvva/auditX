'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { 
  ShieldAlert, ShieldCheck, Activity, Zap, Play, Filter, 
  Search, RefreshCw, AlertTriangle, Cpu, Terminal, Eye, Layers, ArrowRight, CheckCircle2 
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
      const matchAddr = evt.contract_address?.toLowerCase().includes(q);
      const matchCaller = evt.caller?.toLowerCase().includes(q);
      const matchTx = evt.tx_hash?.toLowerCase().includes(q);
      const matchRule = evt.rule_matched?.toLowerCase().includes(q);
      const matchDesc = evt.description?.toLowerCase().includes(q);
      if (!matchAddr && !matchCaller && !matchTx && !matchRule && !matchDesc) return false;
    }
    return true;
  });

  const getSevPill = (sev: string) => {
    switch (sev) {
      case 'Critical':
        return 'bg-rose-50 text-rose-700 border border-rose-200 text-[10px] px-2 py-0.5 rounded-full font-bold uppercase';
      case 'High':
        return 'bg-orange-50 text-orange-700 border border-orange-200 text-[10px] px-2 py-0.5 rounded-full font-bold uppercase';
      case 'Medium':
        return 'bg-amber-50 text-amber-700 border border-amber-200 text-[10px] px-2 py-0.5 rounded-full font-bold uppercase';
      case 'Low':
        return 'bg-blue-50 text-blue-700 border border-blue-200 text-[10px] px-2 py-0.5 rounded-full font-bold uppercase';
      default:
        return 'bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] px-2 py-0.5 rounded-full font-bold uppercase';
    }
  };

  return (
    <div className="min-h-screen bg-[#F6F9FC] text-slate-900 flex flex-col font-sans selection:bg-blue-600 selection:text-white pb-16">
      {/* Header */}
      <header className="border-b border-slate-200/80 bg-white/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-blue-600 to-cyan-500 flex items-center justify-center font-bold text-white text-lg shadow-sm shadow-blue-500/20">
              A
            </div>
            <span className="font-extrabold text-xl tracking-tight text-slate-900">
              Audit<span className="text-blue-600">X</span>
            </span>
          </Link>

          <nav className="hidden md:flex items-center gap-8 text-sm font-medium text-slate-600">
            <Link href="/dashboard" className="hover:text-blue-600 transition-colors">Dashboard</Link>
            <Link href="/audit" className="hover:text-blue-600 transition-colors">New Audit</Link>
            <Link href="/siem" className="text-blue-700 font-bold bg-blue-50/80 border border-blue-200/80 px-3 py-1.5 rounded-xl flex items-center gap-1.5 shadow-sm">
              <Activity className="w-4 h-4 text-blue-600" /> Web3 SIEM
            </Link>
          </nav>

          <div className="flex items-center gap-3">
            <span className="text-xs font-semibold px-3 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
              SIEM Stream Active
            </span>
          </div>
        </div>
      </header>

      {/* Main Body */}
      <main className="max-w-7xl w-full mx-auto px-6 py-8 flex flex-col gap-8 flex-1">
        {/* Title Banner */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 border-b border-slate-200/80 pb-6">
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center gap-2.5">
              <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-slate-900">Web3 SIEM Security Gateway</h1>
              <span className="bg-blue-100 text-blue-800 border border-blue-200 text-[11px] font-bold px-2.5 py-0.5 rounded-full">
                Real-Time
              </span>
            </div>
            <p className="text-slate-600 text-xs sm:text-sm max-w-2xl">
              Live threat telemetry stream, event logging, Welford statistical anomaly detection, and automated webhook dispatching for smart contracts.
            </p>
          </div>

          <button
            onClick={() => fetchSIEMData()}
            disabled={loading}
            className="self-start md:self-auto bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold px-4 py-2.5 rounded-xl flex items-center gap-2 shadow-sm transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh Stream
          </button>
        </div>

        {/* SIEM Metrics Cards Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          <div className="p-5 rounded-2xl bg-white border border-slate-200/80 shadow-sm flex flex-col gap-1">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Total Telemetry Ingested</span>
            <span className="text-3xl font-black text-slate-900">{metrics.total_events || 0}</span>
            <span className="text-[11px] text-emerald-600 mt-1 font-semibold flex items-center gap-1">
              <Activity className="w-3.5 h-3.5" /> Ingest Pipeline Live
            </span>
          </div>

          <div className="p-5 rounded-2xl bg-white border border-slate-200/80 shadow-sm flex flex-col gap-1">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Critical Threat Alerts</span>
            <span className="text-3xl font-black text-rose-600">{metrics.critical_threats || 0}</span>
            <span className="text-[11px] text-slate-500 mt-1 font-medium">Immediate Challenge Required</span>
          </div>

          <div className="p-5 rounded-2xl bg-white border border-slate-200/80 shadow-sm flex flex-col gap-1">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">High Severity Intrusions</span>
            <span className="text-3xl font-black text-orange-600">{metrics.high_threats || 0}</span>
            <span className="text-[11px] text-slate-500 mt-1 font-medium">Access & State Anomalies</span>
          </div>

          <div className="p-5 rounded-2xl bg-white border border-slate-200/80 shadow-sm flex flex-col gap-1">
            <span className="text-[10px] text-slate-500 font-bold uppercase tracking-wider">Active Rule Matchers</span>
            <span className="text-3xl font-black text-blue-600">{metrics.active_rules || 5}</span>
            <span className="text-[11px] text-slate-500 mt-1 font-medium">Flash Loan / Reentrancy / SIWE</span>
          </div>
        </div>

        {/* Real-Time Security Threat Test Simulator */}
        <div className="p-6 rounded-2xl bg-gradient-to-r from-blue-50 via-white to-cyan-50 border border-blue-200/80 shadow-sm flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Zap className="w-5 h-5 text-blue-600" />
              <h3 className="font-bold text-sm uppercase tracking-wider text-slate-900">Real-Time Threat Test Simulator</h3>
            </div>
            <span className="text-xs text-slate-500 font-medium">Simulate live attack vectors into the SIEM pipeline</span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => triggerSimulation('reentrancy')}
              disabled={simulating}
              className="bg-white hover:bg-rose-50 text-rose-700 border border-rose-200 hover:border-rose-300 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all shadow-sm flex items-center gap-1.5"
            >
              <Play className="w-3.5 h-3.5 fill-current" /> Trigger Reentrancy Attack
            </button>

            <button
              onClick={() => triggerSimulation('flashloan')}
              disabled={simulating}
              className="bg-white hover:bg-orange-50 text-orange-700 border border-orange-200 hover:border-orange-300 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all shadow-sm flex items-center gap-1.5"
            >
              <Play className="w-3.5 h-3.5 fill-current" /> Trigger Flash Loan Drain
            </button>

            <button
              onClick={() => triggerSimulation('ownership')}
              disabled={simulating}
              className="bg-white hover:bg-amber-50 text-amber-700 border border-amber-200 hover:border-amber-300 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all shadow-sm flex items-center gap-1.5"
            >
              <Play className="w-3.5 h-3.5 fill-current" /> Trigger Admin Ownership Hijack
            </button>

            <button
              onClick={() => triggerSimulation('crosslayer')}
              disabled={simulating}
              className="bg-white hover:bg-purple-50 text-purple-700 border border-purple-200 hover:border-purple-300 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all shadow-sm flex items-center gap-1.5"
            >
              <Play className="w-3.5 h-3.5 fill-current" /> Trigger Web2-Web3 Key Leak
            </button>

            <button
              onClick={() => triggerSimulation('gasspike')}
              disabled={simulating}
              className="bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 hover:border-slate-300 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all shadow-sm flex items-center gap-1.5"
            >
              <Play className="w-3.5 h-3.5 fill-current" /> Trigger Gas Spike Loop
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center justify-between border-b border-slate-200/80 pb-3">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setActiveTab('stream')}
              className={`text-xs font-bold px-4 py-2 rounded-xl transition-all flex items-center gap-2 ${
                activeTab === 'stream'
                  ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/20'
                  : 'text-slate-600 hover:text-slate-900 bg-white border border-slate-200'
              }`}
            >
              <Activity className="w-4 h-4" /> Live Threat Stream ({events.length})
            </button>

            <button
              onClick={() => setActiveTab('rules')}
              className={`text-xs font-bold px-4 py-2 rounded-xl transition-all flex items-center gap-2 ${
                activeTab === 'rules'
                  ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/20'
                  : 'text-slate-600 hover:text-slate-900 bg-white border border-slate-200'
              }`}
            >
              <Terminal className="w-4 h-4" /> Active Rules ({rules.length})
            </button>

            <button
              onClick={() => setActiveTab('forta')}
              className={`text-xs font-bold px-4 py-2 rounded-xl transition-all flex items-center gap-2 ${
                activeTab === 'forta'
                  ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/20'
                  : 'text-slate-600 hover:text-slate-900 bg-white border border-slate-200'
              }`}
            >
              <ShieldAlert className="w-4 h-4" /> Forta Security Feeds ({fortaAlerts.length})
            </button>
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Filter by address, tx or rule..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-white border border-slate-200 rounded-xl pl-9 pr-4 py-1.5 text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-500 w-64 shadow-sm"
            />
          </div>
        </div>

        {/* Live Event Stream View */}
        {activeTab === 'stream' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 flex flex-col gap-3">
              {filteredEvents.length === 0 ? (
                <div className="p-12 text-center bg-white rounded-2xl border border-slate-200/80 shadow-sm text-slate-500 text-xs">
                  No telemetry events match your search query.
                </div>
              ) : (
                filteredEvents.map((evt) => (
                  <div
                    key={evt.id}
                    onClick={() => setSelectedEvent(evt)}
                    className={`p-5 rounded-2xl bg-white border transition-all cursor-pointer shadow-sm hover:shadow-md ${
                      selectedEvent?.id === evt.id
                        ? 'border-blue-500 ring-2 ring-blue-500/10'
                        : 'border-slate-200/80 hover:border-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-4 mb-2">
                      <div className="flex items-center gap-2">
                        <span className={getSevPill(evt.severity)}>{evt.severity}</span>
                        <span className="font-bold text-xs text-slate-900">{evt.event_type}</span>
                        <span className="text-[11px] text-slate-500 bg-slate-100 px-2 py-0.5 rounded font-mono">
                          {evt.network || 'Polygon'}
                        </span>
                      </div>
                      <span className="text-[11px] text-slate-500 font-mono">
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <p className="text-xs text-slate-700 mb-3 leading-relaxed">{evt.description}</p>

                    <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-500 font-mono pt-3 border-t border-slate-100">
                      <span>Contract: <strong className="text-slate-800">{evt.contract_address?.slice(0, 8)}...{evt.contract_address?.slice(-6)}</strong></span>
                      <span>Gas: <strong className="text-slate-800">{evt.gas_used?.toLocaleString()}</strong></span>
                      <span>Value: <strong className="text-slate-800">{evt.value_eth} ETH</strong></span>
                      <span className="text-blue-600 font-semibold ml-auto flex items-center gap-1">
                        Inspect <Eye className="w-3 h-3" />
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Event Detail Drawer */}
            <div className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm flex flex-col gap-4 sticky top-24 self-start">
              <h3 className="font-bold text-sm text-slate-900 pb-3 border-b border-slate-100 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-blue-600" /> Telemetry Payload Inspector
              </h3>

              {selectedEvent ? (
                <div className="flex flex-col gap-3 text-xs">
                  <div>
                    <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1">Rule Matched</span>
                    <span className="font-semibold text-slate-900 bg-slate-50 p-2 rounded-lg border border-slate-200 block">
                      {selectedEvent.rule_matched}
                    </span>
                  </div>

                  <div>
                    <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1">Transaction Hash</span>
                    <span className="font-mono text-[11px] text-slate-800 break-all bg-slate-50 p-2 rounded-lg border border-slate-200 block">
                      {selectedEvent.tx_hash}
                    </span>
                  </div>

                  <div>
                    <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1">Contract Address</span>
                    <span className="font-mono text-[11px] text-slate-800 break-all bg-slate-50 p-2 rounded-lg border border-slate-200 block">
                      {selectedEvent.contract_address}
                    </span>
                  </div>

                  <div>
                    <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1">Payload Signature</span>
                    <pre className="p-3 rounded-lg bg-slate-900 text-emerald-400 font-mono text-[11px] overflow-x-auto">
                      {selectedEvent.payload_preview || 'transfer(address,uint256)'}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center text-slate-500 text-xs">
                  Click on any transaction telemetry row to inspect its decoded call stack and security analysis.
                </div>
              )}
            </div>
          </div>
        )}

        {/* Security Rules Tab */}
        {activeTab === 'rules' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {rules.map((rule) => (
              <div key={rule.id} className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm flex flex-col gap-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold bg-blue-50 text-blue-700 px-2.5 py-1 rounded-md border border-blue-200">
                    {rule.id}
                  </span>
                  <span className={getSevPill(rule.severity)}>{rule.severity}</span>
                </div>
                <h4 className="font-bold text-sm text-slate-900">{rule.name}</h4>
                <p className="text-xs text-slate-600">{rule.condition_description}</p>
                <div className="mt-auto pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
                  <span>Category: <strong className="text-slate-700">{rule.category}</strong></span>
                  <span className="text-emerald-600 font-semibold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Active Enforcer
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Forta Security Feeds Tab */}
        {activeTab === 'forta' && (
          <div className="flex flex-col gap-4">
            {fortaAlerts.map((fa) => (
              <div key={fa.alert_id} className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className={getSevPill(fa.severity)}>{fa.severity}</span>
                  <span className="text-xs font-mono text-slate-500">{new Date(fa.timestamp).toLocaleString()}</span>
                </div>
                <h4 className="font-bold text-sm text-slate-900">{fa.title}</h4>
                <p className="text-xs text-slate-600">{fa.description}</p>
                <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-xs text-amber-900 mt-2 font-medium">
                  <strong>Action Suggested:</strong> {fa.action_suggested}
                </div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
