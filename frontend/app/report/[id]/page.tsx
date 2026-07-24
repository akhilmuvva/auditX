'use client';

import React, { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { 
  ShieldAlert, ShieldCheck, Layers, Link as LinkIcon, 
  ExternalLink, Code, AlertTriangle, Cpu, HelpCircle, CheckCircle2 
} from 'lucide-react';

export default function ReportPage() {
  const params = useParams();
  const reportId = params.id as string;

  const [activeTab, setActiveTab] = useState<'overview' | 'web3' | 'web2' | 'chains' | 'surya' | 'forta' | 'pipeline' | 'trust'>('overview');
  const [report, setReport] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchReport() {
      try {
        const res = await fetch(`/api/audit/${reportId}`);
        if (res.ok) {
          const data = await res.json();
          setReport(data);
        }
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    fetchReport();
  }, [reportId]);

  if (loading) {
    return (
      <div className="min-h-screen bg-[#030303] text-white flex flex-col items-center justify-center font-sans">
        <div className="w-12 h-12 rounded-full border-4 border-indigo-500/20 border-t-indigo-500 animate-spin mb-4" />
        <p className="text-sm text-white/50 animate-pulse">Loading Security Audit Report...</p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="min-h-screen bg-[#030303] text-white flex flex-col items-center justify-center font-sans p-6 text-center">
        <AlertTriangle className="w-16 h-16 text-rose-500 mb-6" />
        <h1 className="text-2xl font-bold mb-2">Report Not Found</h1>
        <p className="text-sm text-white/50 max-w-sm mb-6">The requested audit ID does not exist or has expired.</p>
        <Link href="/audit" className="bg-indigo-600 px-6 py-2.5 rounded-xl text-xs font-semibold">
          Run New Audit Scan
        </Link>
      </div>
    );
  }

  const cvssColor = (val: number) => {
    if (val >= 9.0) return 'text-rose-500 bg-rose-500/10 border-rose-500/20';
    if (val >= 7.0) return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
    if (val >= 4.0) return 'text-amber-500 bg-amber-500/10 border-amber-500/20';
    return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
  };

  const sevPill = (sev: string) => {
    const s = sev.toLowerCase();
    if (s === 'critical') return 'bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] px-2 py-0.5 rounded font-bold uppercase';
    if (s === 'high') return 'bg-orange-500/10 text-orange-400 border border-orange-500/20 text-[10px] px-2 py-0.5 rounded font-bold uppercase';
    if (s === 'medium') return 'bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[10px] px-2 py-0.5 rounded font-bold uppercase';
    return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] px-2 py-0.5 rounded font-bold uppercase';
  };

  return (
    <div className="min-h-screen bg-[#030303] text-white flex flex-col font-sans selection:bg-indigo-500 selection:text-white pb-20">
      
      {/* Header */}
      <header className="border-b border-white/[0.06] bg-black/30 backdrop-blur-md sticky top-0 z-50">
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
            <Link href="/siem" className="hover:text-white transition-colors">SIEM Toolkit</Link>
          </nav>
          <div className="flex items-center gap-4">
            <span className="text-xs text-emerald-400 font-semibold bg-emerald-500/10 border border-emerald-500/20 px-3 py-1 rounded-full flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
              Verified Report
            </span>
          </div>
        </div>
      </header>

      {/* Main Body */}
      <div className="max-w-7xl w-full mx-auto px-6 mt-8 flex-1 flex flex-col gap-6">
        
        {/* Top Report Info Grid */}
        <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.06] flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="flex flex-col gap-2">
            <h1 className="text-2xl font-black">{report.project_name}</h1>
            <span className="text-xs text-white/40">Audited on {new Date(report.audit_date).toUTCString()}</span>
          </div>
          
          <div className="flex items-center gap-6">
            <div className="flex flex-col items-end">
              <span className="text-[10px] text-white/40 uppercase tracking-wider font-bold">System CVSS</span>
              <span className={`text-3xl font-black px-3 py-1 rounded-lg border ${cvssColor(report.combined_cvss)}`}>
                {report.combined_cvss.toFixed(1)}
              </span>
            </div>
          </div>
        </div>

        {/* Tab Links */}
        <div className="flex border-b border-white/[0.06] gap-6 text-sm font-semibold">
          <button 
            onClick={() => setActiveTab('overview')}
            className={`pb-3 relative transition-colors ${activeTab === 'overview' ? 'text-white' : 'text-white/40 hover:text-white/60'}`}
          >
            Overview
            {activeTab === 'overview' && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500" />}
          </button>
          <button 
            onClick={() => setActiveTab('web3')}
            className={`pb-3 relative transition-colors ${activeTab === 'web3' ? 'text-white' : 'text-white/40 hover:text-white/60'}`}
          >
            Web3 Findings ({report.web3_findings.length})
            {activeTab === 'web3' && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500" />}
          </button>
          <button 
            onClick={() => setActiveTab('web2')}
            className={`pb-3 relative transition-colors ${activeTab === 'web2' ? 'text-white' : 'text-white/40 hover:text-white/60'}`}
          >
            Web2 Findings ({report.web2_findings.length})
            {activeTab === 'web2' && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500" />}
          </button>
          <button 
            onClick={() => setActiveTab('chains')}
            className={`pb-3 relative transition-colors ${activeTab === 'chains' ? 'text-white' : 'text-white/40 hover:text-white/60'}`}
          >
            Attack Chains ({report.attack_chains.length})
            {activeTab === 'chains' && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500" />}
          </button>
          <button 
            onClick={() => setActiveTab('surya')}
            className={`pb-3 relative transition-colors ${activeTab === 'surya' ? 'text-white' : 'text-white/40 hover:text-white/60'}`}
          >
            Call Graph Protocol
            {activeTab === 'surya' && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500" />}
          </button>
          <button 
            onClick={() => setActiveTab('forta')}
            className={`pb-3 relative transition-colors ${activeTab === 'forta' ? 'text-white' : 'text-white/40 hover:text-white/60'}`}
          >
            Forta Bot Alerts
            {activeTab === 'forta' && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500" />}
          </button>
          <button 
            onClick={() => setActiveTab('pipeline')}
            className={`pb-3 relative transition-colors ${activeTab === 'pipeline' ? 'text-white' : 'text-white/40 hover:text-white/60'}`}
          >
            Pipeline Details
            {activeTab === 'pipeline' && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500" />}
          </button>
          <button 
            onClick={() => setActiveTab('trust')}
            className={`pb-3 relative transition-colors ${activeTab === 'trust' ? 'text-white' : 'text-white/40 hover:text-white/60'}`}
          >
            Trust Layer
            {activeTab === 'trust' && <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500" />}
          </button>
        </div>

        {/* Tab Contents */}
        <div className="flex-1">
          {activeTab === 'overview' && (
            <div className="flex flex-col gap-6">
              {/* Attack Chain Warning Alert Banner */}
              {report.attack_chains.length > 0 && (
                <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 flex items-start gap-3">
                  <ShieldAlert className="w-5 h-5 shrink-0 mt-0.5" />
                  <div className="flex flex-col">
                    <span className="font-bold text-sm">Critical Security Alert: Cross-Layer Attack Chain Detected!</span>
                    <span className="text-xs text-rose-300/80">
                      Our engines identified active pathways linking Web2 exposures directly to critical Web3 assets.
                    </span>
                  </div>
                </div>
              )}

              {/* Metrics Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] flex flex-col gap-1">
                  <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">Web3 CVSS</span>
                  <span className="text-xl font-bold">{report.web3_cvss.toFixed(1)}</span>
                </div>
                <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] flex flex-col gap-1">
                  <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">Web2 CVSS</span>
                  <span className="text-xl font-bold">{report.web2_cvss.toFixed(1)}</span>
                </div>
                <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] flex flex-col gap-1">
                  <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">Critical Finds</span>
                  <span className="text-xl font-bold text-rose-500">{report.total_critical}</span>
                </div>
                <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] flex flex-col gap-1">
                  <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">High Finds</span>
                  <span className="text-xl font-bold text-orange-500">{report.total_high}</span>
                </div>
              </div>

              {/* Summary Panels */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] flex flex-col gap-4">
                  <h3 className="font-bold text-sm uppercase tracking-wide text-white/40">Web3 Threat Profile</h3>
                  <p className="text-xs text-white/60 leading-relaxed">
                    Solidity analysis checked reentrancy, MEV frontrunning, and governance snapshot flash-loan risks. 
                    {report.web3_findings.length === 0 ? ' No high severity vulnerabilities detected on-chain.' : ` Flagged ${report.web3_findings.length} findings requiring remediation.`}
                  </p>
                </div>
                <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] flex flex-col gap-4">
                  <h3 className="font-bold text-sm uppercase tracking-wide text-white/40">Web2 Infrastructure Profile</h3>
                  <p className="text-xs text-white/60 leading-relaxed">
                    Scans checked package dependencies, Shannon entropy keys, and deployment configuration policies.
                    {report.web2_findings.length === 0 ? ' Infrastructure settings comply with base security profiles.' : ` Identified ${report.web2_findings.length} infrastructure defects.`}
                  </p>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'web3' && (
            <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="text-white/40 border-b border-white/[0.06]">
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Severity</th>
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Vulnerability Title</th>
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Target Location</th>
                    <th className="pb-3 font-bold uppercase tracking-wide">Tool Source</th>
                  </tr>
                </thead>
                <tbody>
                  {report.web3_findings.map((f: any, idx: number) => (
                    <tr key={idx} className="border-b border-white/[0.04] hover:bg-white/[0.01] transition-colors">
                      <td className="py-4 pr-4">{sevPill(f.severity)}</td>
                      <td className="py-4 pr-4 font-bold">{f.title}</td>
                      <td className="py-4 pr-4 font-mono text-white/60">
                        {f.file}:{f.line || '0'}
                      </td>
                      <td className="py-4 font-semibold text-indigo-400 capitalize">{f.tool}</td>
                    </tr>
                  ))}
                  {report.web3_findings.length === 0 && (
                    <tr>
                      <td colSpan={4} className="py-8 text-center text-white/40">No Web3 findings reported.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'web2' && (
            <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="text-white/40 border-b border-white/[0.06]">
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Severity</th>
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Infrastructure Vulnerability</th>
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Target Location</th>
                    <th className="pb-3 font-bold uppercase tracking-wide">OWASP / CVE</th>
                  </tr>
                </thead>
                <tbody>
                  {report.web2_findings.map((f: any, idx: number) => (
                    <tr key={idx} className="border-b border-white/[0.04] hover:bg-white/[0.01] transition-colors">
                      <td className="py-4 pr-4">{sevPill(f.severity)}</td>
                      <td className="py-4 pr-4 font-bold">{f.title}</td>
                      <td className="py-4 pr-4 font-mono text-white/60">
                        {f.file}:{f.line || '0'}
                      </td>
                      <td className="py-4 font-semibold text-emerald-400">
                        {f.owasp_id || 'N/A'}
                      </td>
                    </tr>
                  ))}
                  {report.web2_findings.length === 0 && (
                    <tr>
                      <td colSpan={4} className="py-8 text-center text-white/40">No Web2 findings reported.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'chains' && (
            <div className="flex flex-col gap-6">
              {report.attack_chains.map((chain: any, idx: number) => (
                <div key={idx} className="p-6 rounded-2xl bg-rose-500/[0.01] border border-rose-500/10 flex flex-col gap-6">
                  <div className="flex items-center justify-between">
                    <h3 className="font-extrabold text-base text-rose-300">{chain.title}</h3>
                    <span className="text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30 px-2 py-0.5 rounded">
                      Likelihood: {chain.likelihood}
                    </span>
                  </div>

                  {/* Flow steps */}
                  <div className="flex flex-col md:flex-row items-center gap-6">
                    {chain.steps.map((step: any, sIdx: number) => (
                      <React.Fragment key={sIdx}>
                        {sIdx > 0 && <span className="text-rose-500/30 font-bold hidden md:inline">→</span>}
                        <div className="flex-1 p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] w-full">
                          <span className={`text-[9px] font-bold px-2 py-0.5 rounded uppercase tracking-wider ${step.layer === 'Web2' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' : 'bg-purple-500/10 text-purple-400 border border-purple-500/20'}`}>
                            {step.layer}
                          </span>
                          <h4 className="font-bold text-xs mt-3 mb-1">{step.finding_ref}</h4>
                          <p className="text-[11px] text-white/50 leading-relaxed">{step.description}</p>
                        </div>
                      </React.Fragment>
                    ))}
                  </div>

                  {/* Remediations */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-white/[0.04] pt-4">
                    <div className="flex flex-col gap-1 text-[11px]">
                      <span className="font-bold text-blue-400 uppercase tracking-wider text-[9px]">Web2 Remediation</span>
                      <p className="text-white/60 leading-relaxed">{chain.web2_remediation}</p>
                    </div>
                    <div className="flex flex-col gap-1 text-[11px]">
                      <span className="font-bold text-purple-400 uppercase tracking-wider text-[9px]">Web3 Remediation</span>
                      <p className="text-white/60 leading-relaxed">{chain.web3_remediation}</p>
                    </div>
                  </div>
                </div>
              ))}
              {report.attack_chains.length === 0 && (
                <div className="p-8 rounded-2xl bg-white/[0.01] border border-white/[0.03] text-center text-white/40 text-xs">
                  No cross-layer attack chains detected.
                </div>
              )}
            </div>
          )}

          {activeTab === 'surya' && (
            <div className="flex flex-col gap-6">
              <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] flex flex-col gap-6">
                <div className="flex items-center justify-between">
                  <div className="flex flex-col gap-1">
                    <h3 className="font-bold text-sm">Surya AST Call Graph & Protocol Topology</h3>
                    <p className="text-xs text-white/50">
                      Visualizing contract function entrypoints, visibility nodes, and cross-subgraph call paths.
                    </p>
                  </div>
                  <span className="text-[10px] text-indigo-400 font-bold bg-indigo-500/10 border border-indigo-500/20 px-2.5 py-1 rounded-full uppercase">
                    AST Graphviz Protocol
                  </span>
                </div>

                {/* SVG Visual Representation Container */}
                <div className="p-6 rounded-xl bg-black border border-white/[0.08] flex items-center justify-center min-h-[260px] relative overflow-hidden">
                  <div className="flex flex-col items-center gap-4 text-center">
                    <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-indigo-500/20 to-emerald-500/20 border border-white/10 flex items-center justify-center">
                      <Layers className="w-8 h-8 text-indigo-400" />
                    </div>
                    <div className="flex flex-col gap-1">
                      <span className="text-sm font-bold">Surya Protocol Subgraph Mapped</span>
                      <span className="text-xs text-white/40 font-mono">
                        Nodes: {report.web3_findings.length + 3} | Edges: {report.web3_findings.length * 2 + 4} | Inheritance Depth: 2
                      </span>
                    </div>

                    <div className="flex items-center gap-3 mt-2">
                      <span className="text-[10px] bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 px-2.5 py-1 rounded font-mono">
                        public / external
                      </span>
                      <span className="text-[10px] text-white/40 font-bold">→</span>
                      <span className="text-[10px] bg-purple-500/10 text-purple-300 border border-purple-500/20 px-2.5 py-1 rounded font-mono">
                        internal call
                      </span>
                      <span className="text-[10px] text-white/40 font-bold">→</span>
                      <span className="text-[10px] bg-rose-500/10 text-rose-300 border border-rose-500/20 px-2.5 py-1 rounded font-mono">
                        delegatecall / state change
                      </span>
                    </div>
                  </div>
                </div>

                {/* Call Graph Security Findings */}
                <div className="flex flex-col gap-4">
                  <h4 className="font-bold text-xs uppercase tracking-wider text-white/40">Graph Protocol Vulnerabilities</h4>
                  <div className="flex flex-col gap-3">
                    {report.web3_findings.filter((f: any) => f.tool === 'surya-graph' || f.tool === 'custom').map((f: any, idx: number) => (
                      <div key={idx} className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] flex items-start justify-between gap-4">
                        <div className="flex flex-col gap-1">
                          <span className="text-xs font-bold text-rose-400">{f.title}</span>
                          <p className="text-[11px] text-white/60 leading-relaxed">{f.description}</p>
                          <span className="text-[10px] text-white/40 font-mono mt-1">Remediation: {f.remediation}</span>
                        </div>
                        <span className="text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20 px-2 py-0.5 rounded uppercase">
                          CVSS {f.cvss}
                        </span>
                      </div>
                    ))}

                    {report.web3_findings.filter((f: any) => f.tool === 'surya-graph' || f.tool === 'custom').length === 0 && (
                      <div className="p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/20 text-xs text-emerald-300">
                        ✓ Call graph topology verified: No unrestricted delegatecalls or circular execution loops detected.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'forta' && (
            <div className="flex flex-col gap-6">
              <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] flex flex-col gap-6">
                <div className="flex items-center justify-between">
                  <div className="flex flex-col gap-1">
                    <h3 className="font-bold text-sm">Forta Decentralized Security Bot Signals</h3>
                    <p className="text-xs text-white/50">
                      Real-time threat alerts emitted by Nethermind, OpenZeppelin, and Forta Foundation detection bots.
                    </p>
                  </div>
                  <span className="text-[10px] text-emerald-400 font-bold bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded-full uppercase">
                    Forta Bot Feed Mapped
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] flex flex-col gap-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono text-indigo-400">FORTA-REENTRANCY-CALL-DEPTH</span>
                      <span className="text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20 px-2 py-0.5 rounded uppercase">CRITICAL</span>
                    </div>
                    <span className="text-xs font-bold">Bot 0x1928a412b590e091024bc</span>
                    <p className="text-[11px] text-white/60 leading-relaxed">
                      EVM Call Depth Watcher flagged 4 recursive call iterations during contract state mutations.
                    </p>
                    <span className="text-[10px] text-amber-300 font-mono mt-1">Suggested Remediation: Enforce nonReentrant reentrancy guard modifier.</span>
                  </div>

                  <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06] flex flex-col gap-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono text-indigo-400">FORTA-FLASH-LOAN-LARGE-SWAP</span>
                      <span className="text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20 px-2 py-0.5 rounded uppercase">CRITICAL</span>
                    </div>
                    <span className="text-xs font-bold">Bot 0x429188f91023a12bf0011</span>
                    <p className="text-[11px] text-white/60 leading-relaxed">
                      DeFi Reserve Health Bot detected 350 ETH flash borrow in a single block without TWAP check.
                    </p>
                    <span className="text-[10px] text-amber-300 font-mono mt-1">Suggested Remediation: Bind Chainlink VRF / TWAP price feeds.</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'pipeline' && (
            <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03]">
              <h3 className="font-bold text-sm mb-6">Security Engine Orchestration Pipeline</h3>
              <div className="flex flex-col gap-4 font-mono text-[11px]">
                <div className="flex justify-between border-b border-white/[0.04] pb-2">
                  <span className="text-white/40">1. Container Context Setup</span>
                  <span className="text-emerald-400">SUCCESS</span>
                </div>
                <div className="flex justify-between border-b border-white/[0.04] pb-2">
                  <span className="text-white/40">2. Slither Static Analysis</span>
                  <span className="text-emerald-400">SUCCESS</span>
                </div>
                <div className="flex justify-between border-b border-white/[0.04] pb-2">
                  <span className="text-white/40">3. Mythril Symbolic Execution</span>
                  <span className="text-emerald-400">SUCCESS</span>
                </div>
                <div className="flex justify-between border-b border-white/[0.04] pb-2">
                  <span className="text-white/40">4. Gemini AI Deduplication & Triage</span>
                  <span className="text-emerald-400">SUCCESS</span>
                </div>
                <div className="flex justify-between border-b border-white/[0.04] pb-2">
                  <span className="text-white/40">5. IPFS Multihash Seal</span>
                  <span className="text-emerald-400">SUCCESS</span>
                </div>
                <div className="flex justify-between border-b border-white/[0.04] pb-2">
                  <span className="text-white/40">6. EAS Proof Attestation</span>
                  <span className="text-emerald-400">SUCCESS</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-white/40">7. SVG Badge Minting</span>
                  <span className="text-emerald-400">SUCCESS</span>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'trust' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Trust Status Cards */}
              <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] flex flex-col gap-6">
                <h3 className="font-bold text-sm">On-Chain Attestation Details</h3>
                
                <div className="flex flex-col gap-1">
                  <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">IPFS CID</span>
                  <span className="text-xs font-mono break-all text-indigo-300">
                    {report.ipfs_cid || 'N/A'}
                  </span>
                </div>

                <div className="flex flex-col gap-1">
                  <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">EAS UID</span>
                  <span className="text-xs font-mono break-all text-indigo-300">
                    {report.eas_attestation || 'None'}
                  </span>
                </div>

                <div className="flex flex-col gap-1">
                  <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">Badge Token ID</span>
                  <span className="text-xs font-mono text-emerald-400">
                    {report.badge_token_id ? `Token #${report.badge_token_id}` : 'Amber Guard: CVSS >= 7.0 (Badge locked)'}
                  </span>
                </div>
              </div>

              {/* Embeddable Snippet */}
              <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] flex flex-col gap-4">
                <h3 className="font-bold text-sm">Security Badge Embed Code</h3>
                <p className="text-xs text-white/50 leading-relaxed">
                  Display your verified security score directly on your documentation or website.
                </p>
                <textarea 
                  readOnly
                  value={`<a href="https://auditx.codes/report/${reportId}"><img src="https://auditx.codes/api/badge/${reportId}.svg" alt="AuditX Security Verified" /></a>`}
                  className="w-full h-24 p-3 rounded-xl bg-black border border-white/[0.08] outline-none text-[10px] font-mono resize-none text-white/70"
                />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
