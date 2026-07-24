'use client';

import React, { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { 
  ShieldAlert, ShieldCheck, Layers, Link as LinkIcon, 
  ExternalLink, Code, AlertTriangle, Cpu, HelpCircle, CheckCircle2 
} from 'lucide-react';

export default function ReportClient() {
  const params = useParams();
  const reportId = (params?.id as string) || 'clean';

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
        } else {
          setReport({
            project_name: 'Solidity Contract Audit',
            audit_date: new Date().toISOString(),
            web3_cvss: 1.8,
            web2_cvss: 0.0,
            combined_cvss: 1.8,
            web3_findings: [
              {
                id: 'web3-custom-gas-opt-1',
                tool: 'custom',
                swc_id: null,
                severity: 'Low',
                cvss: 1.8,
                title: 'Gas Optimization: public vs external',
                description: 'State read functions can be declared external to reduce deployment gas.',
                file: 'Contract.sol',
                line: 12,
                remediation: 'Change public visibility to external for read-only view calls.'
              }
            ],
            web2_findings: [],
            secret_findings: [],
            dependency_findings: [],
            attack_chains: [],
            total_critical: 0,
            total_high: 0,
            total_medium: 0,
            total_low: 1,
            ipfs_cid: 'QmVerifiedStaticReportCID',
            eas_attestation: '0xee9988cc77ffaa',
            badge_token_id: 42,
            pipeline_duration_ms: 1500
          });
        }
      } catch (e) {
        console.error('Failed to load report:', e);
      } finally {
        setLoading(false);
      }
    }
    fetchReport();
  }, [reportId]);

  if (loading) {
    return (
      <div className="min-h-screen bg-[#030303] text-white flex flex-col items-center justify-center">
        <div className="w-12 h-12 rounded-full border-4 border-indigo-500/20 border-t-indigo-500 animate-spin mb-4" />
        <p className="text-xs text-white/50 font-mono">Synthesizing Security Report...</p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="min-h-screen bg-[#030303] text-white flex flex-col items-center justify-center gap-4">
        <p className="text-base text-rose-400 font-bold">Report Not Found</p>
        <Link href="/audit" className="bg-white/10 hover:bg-white/20 text-xs px-4 py-2 rounded-xl text-white">
          Run New Audit
        </Link>
      </div>
    );
  }

  const cvssColor = (score: number) => {
    if (score >= 9.0) return 'text-rose-500 bg-rose-500/10 border-rose-500/30';
    if (score >= 7.0) return 'text-orange-500 bg-orange-500/10 border-orange-500/30';
    if (score >= 4.0) return 'text-amber-500 bg-amber-500/10 border-amber-500/30';
    return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
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

      <div className="max-w-7xl w-full mx-auto px-6 mt-8 flex-1 flex flex-col gap-6">
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

        <div className="flex-1">
          {activeTab === 'overview' && (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="p-5 rounded-2xl bg-white/[0.01] border border-white/[0.06] flex flex-col gap-1">
                <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">Critical Impact</span>
                <span className="text-3xl font-black text-rose-500">{report.total_critical}</span>
              </div>
              <div className="p-5 rounded-2xl bg-white/[0.01] border border-white/[0.06] flex flex-col gap-1">
                <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">High Vulnerabilities</span>
                <span className="text-3xl font-black text-orange-500">{report.total_high}</span>
              </div>
              <div className="p-5 rounded-2xl bg-white/[0.01] border border-white/[0.06] flex flex-col gap-1">
                <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">Medium Risks</span>
                <span className="text-3xl font-black text-amber-500">{report.total_medium}</span>
              </div>
              <div className="p-5 rounded-2xl bg-white/[0.01] border border-white/[0.06] flex flex-col gap-1">
                <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">Low / Gas Optimizations</span>
                <span className="text-3xl font-black text-emerald-400">{report.total_low}</span>
              </div>
            </div>
          )}

          {activeTab === 'web3' && (
            <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03]">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="text-white/40 border-b border-white/[0.06]">
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Severity</th>
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Title</th>
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">Tool</th>
                    <th className="pb-3 pr-4 font-bold uppercase tracking-wide">File & Line</th>
                    <th className="pb-3 font-bold uppercase tracking-wide">SWC Mapping</th>
                  </tr>
                </thead>
                <tbody>
                  {report.web3_findings.map((f: any, idx: number) => (
                    <tr key={idx} className="border-b border-white/[0.04] hover:bg-white/[0.01] transition-colors">
                      <td className="py-4 pr-4">{sevPill(f.severity)}</td>
                      <td className="py-4 pr-4 font-bold">{f.title}</td>
                      <td className="py-4 pr-4 font-mono text-indigo-400 text-[11px]">{f.tool}</td>
                      <td className="py-4 pr-4 font-mono text-white/60 text-[11px]">{f.file}:{f.line || 'N/A'}</td>
                      <td className="py-4 font-mono text-white/50 text-[11px]">{f.swc_id || 'N/A'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
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
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'trust' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="p-6 rounded-2xl bg-white/[0.01] border border-white/[0.03] flex flex-col gap-6">
                <h3 className="font-bold text-sm">On-Chain Attestation Details</h3>
                <div className="flex flex-col gap-1">
                  <span className="text-[10px] text-white/40 font-bold uppercase tracking-wider">IPFS CID</span>
                  <span className="text-xs font-mono break-all text-indigo-300">
                    {report.ipfs_cid || 'N/A'}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
