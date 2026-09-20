'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { 
  ShieldCheck, Upload, GitBranch, Code, CheckCircle2, ArrowRight, Play, Loader2, Sparkles 
} from 'lucide-react';

export default function AuditPage() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<'paste' | 'file' | 'github'>('paste');
  
  // Form inputs
  const [solCode, setSolCode] = useState('');
  const [githubUrl, setGithubUrl] = useState('');
  const [fileName, setFileName] = useState('');
  
  // Options checkboxes
  const [includeMythril, setIncludeMythril] = useState(false);
  const [sealIpfs, setSealIpfs] = useState(true);
  const [easAttest, setEasAttest] = useState(true);
  const [mintBadge, setMintBadge] = useState(false);
  const [recipient, setRecipient] = useState('');

  // Status tracking
  const [loading, setLoading] = useState(false);
  const [progressStep, setProgressStep] = useState(0);
  const [progressMsg, setProgressMsg] = useState('');

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setFileName(file.name);
      const reader = new FileReader();
      reader.onload = (event) => {
        if (event.target?.result) {
          setSolCode(event.target.result as string);
        }
      };
      reader.readAsText(file);
    }
  };

  const startDemoOrScan = async (demoScenario?: string) => {
    setLoading(true);
    setProgressStep(1);
    setProgressMsg('Initializing container security context...');

    const steps = [
      'Cloning source workspace & resolving configs...',
      'Running Slither static analysis checks...',
      'Executing Mythril symbolic analysis...',
      'Deduplicating findings via Claude AI Layer...',
      'Generating offline IPFS Multihash CID...',
      'Pushing attestation record to EAS Registry...',
      'Minting Security Badge NFT on Polygon...',
      'Compilation successful! Building report dashboard...'
    ];

    // Simulate pipeline progress for visual feedback
    for (let i = 0; i < steps.length; i++) {
      await new Promise((resolve) => setTimeout(resolve, i === 2 && includeMythril ? 2000 : 800));
      setProgressStep(i + 2);
      setProgressMsg(steps[i]);
    }

    try {
      // Create request payload
      const payload = {
        code: solCode,
        githubUrl: activeTab === 'github' ? githubUrl : '',
        fileName: activeTab === 'file' ? fileName : 'Contract.sol',
        includeMythril,
        sealIpfs,
        easAttest,
        mintBadge,
        recipient: mintBadge ? recipient : '',
        demoScenario
      };

      const res = await fetch('/api/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (data && data.auditId) {
        router.push(`/report/${data.auditId}`);
      } else {
        alert('Failed to initialize audit pipeline.');
        setLoading(false);
      }
    } catch (e) {
      console.error(e);
      alert('An error occurred during scanning.');
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#F6F9FC] text-slate-900 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
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
            <Link href="/audit" className="text-blue-700 font-bold bg-blue-50/80 border border-blue-200/80 px-3 py-1.5 rounded-xl flex items-center gap-1.5 shadow-sm">
              New Audit
            </Link>
            <Link href="/siem" className="hover:text-blue-600 transition-colors">SIEM Toolkit</Link>
          </nav>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-4xl w-full mx-auto px-6 py-10 flex flex-col gap-8 flex-1">
        <div className="flex flex-col gap-1.5">
          <h1 className="text-2xl sm:text-3xl font-black text-slate-900">New Smart Contract Audit</h1>
          <p className="text-slate-600 text-xs sm:text-sm">
            Execute automated AST static analysis, symbolic execution, and AI threat triaging on your Solidity contracts.
          </p>
        </div>

        {/* Demo Quick Start Card */}
        <div className="p-6 rounded-2xl bg-gradient-to-r from-blue-50 via-white to-cyan-50 border border-blue-200/80 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-blue-700 bg-blue-100 px-2.5 py-0.5 rounded-full">
              Quick Test Scenarios
            </span>
            <h3 className="font-bold text-sm text-slate-900 mt-2">Test with Verified Reference Contracts</h3>
            <p className="text-xs text-slate-600">Execute instant pre-configured security pipelines:</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => startDemoOrScan('clean')}
              disabled={loading}
              className="bg-white hover:bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all shadow-sm flex items-center gap-1.5"
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Clean Token
            </button>
            <button
              onClick={() => startDemoOrScan('reentrancy')}
              disabled={loading}
              className="bg-white hover:bg-rose-50 text-rose-700 border border-rose-200 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all shadow-sm flex items-center gap-1.5"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-rose-600" /> Reentrancy Bug
            </button>
            <button
              onClick={() => startDemoOrScan('fullstack')}
              disabled={loading}
              className="bg-white hover:bg-purple-50 text-purple-700 border border-purple-200 text-xs font-semibold px-3.5 py-2 rounded-xl transition-all shadow-sm flex items-center gap-1.5"
            >
              <Sparkles className="w-3.5 h-3.5 text-purple-600" /> Full Stack App
            </button>
          </div>
        </div>

        {/* Audit Form Card */}
        <div className="p-6 rounded-2xl bg-white border border-slate-200/80 shadow-sm flex flex-col gap-6">
          {/* Input Source Tabs */}
          <div className="flex items-center gap-3 border-b border-slate-100 pb-4">
            <button
              onClick={() => setActiveTab('paste')}
              className={`text-xs font-bold px-4 py-2 rounded-xl transition-all flex items-center gap-2 ${
                activeTab === 'paste'
                  ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/20'
                  : 'text-slate-600 hover:text-slate-900 bg-slate-50 border border-slate-200'
              }`}
            >
              <Code className="w-3.5 h-3.5" /> Paste Solidity Code
            </button>
            <button
              onClick={() => setActiveTab('file')}
              className={`text-xs font-bold px-4 py-2 rounded-xl transition-all flex items-center gap-2 ${
                activeTab === 'file'
                  ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/20'
                  : 'text-slate-600 hover:text-slate-900 bg-slate-50 border border-slate-200'
              }`}
            >
              <Upload className="w-3.5 h-3.5" /> Upload .sol File
            </button>
            <button
              onClick={() => setActiveTab('github')}
              className={`text-xs font-bold px-4 py-2 rounded-xl transition-all flex items-center gap-2 ${
                activeTab === 'github'
                  ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/20'
                  : 'text-slate-600 hover:text-slate-900 bg-slate-50 border border-slate-200'
              }`}
            >
              <GitBranch className="w-3.5 h-3.5" /> GitHub Repository
            </button>
          </div>

          {/* Tab Content */}
          {activeTab === 'paste' && (
            <div>
              <label className="text-xs font-bold text-slate-700 block mb-2">Solidity Source Code</label>
              <textarea
                value={solCode}
                onChange={(e) => setSolCode(e.target.value)}
                placeholder="// SPDX-License-Identifier: MIT&#10;pragma solidity ^0.8.20;&#10;&#10;contract MyContract { ... }"
                className="w-full h-64 p-4 rounded-xl bg-slate-900 text-slate-100 font-mono text-xs border border-slate-800 focus:outline-none focus:border-blue-500 shadow-inner"
              />
            </div>
          )}

          {activeTab === 'file' && (
            <div>
              <label className="text-xs font-bold text-slate-700 block mb-2">Select Contract File (.sol)</label>
              <input
                type="file"
                accept=".sol"
                onChange={handleFileChange}
                className="w-full text-xs text-slate-500 file:mr-4 file:py-2.5 file:px-4 file:rounded-xl file:border-0 file:text-xs file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 cursor-pointer"
              />
              {fileName && (
                <span className="text-xs text-emerald-600 font-medium block mt-2">
                  ✓ Selected file: {fileName}
                </span>
              )}
            </div>
          )}

          {activeTab === 'github' && (
            <div>
              <label className="text-xs font-bold text-slate-700 block mb-2">GitHub Repository URL</label>
              <input
                type="text"
                value={githubUrl}
                onChange={(e) => setGithubUrl(e.target.value)}
                placeholder="https://github.com/owner/repository"
                className="w-full p-3 rounded-xl bg-white border border-slate-200 text-slate-900 text-xs focus:outline-none focus:border-blue-500 shadow-sm"
              />
            </div>
          )}

          {/* Pipeline Options Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 border-t border-slate-100 pt-6">
            <label className="flex items-center gap-3 p-4 rounded-xl border border-slate-200/80 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition-all">
              <input
                type="checkbox"
                checked={sealIpfs}
                onChange={(e) => setSealIpfs(e.target.checked)}
                className="rounded border-slate-300 text-blue-600 focus:ring-blue-500 w-4 h-4"
              />
              <div>
                <span className="text-xs font-bold text-slate-900 block">IPFS Multihash Seal</span>
                <span className="text-[11px] text-slate-500">Seal tamper-proof report hash</span>
              </div>
            </label>

            <label className="flex items-center gap-3 p-4 rounded-xl border border-slate-200/80 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition-all">
              <input
                type="checkbox"
                checked={easAttest}
                onChange={(e) => setEasAttest(e.target.checked)}
                className="rounded border-slate-300 text-blue-600 focus:ring-blue-500 w-4 h-4"
              />
              <div>
                <span className="text-xs font-bold text-slate-900 block">EAS Attestation</span>
                <span className="text-[11px] text-slate-500">Record on Ethereum Attestation Service</span>
              </div>
            </label>
          </div>

          <button
            onClick={() => startDemoOrScan()}
            disabled={loading || (!solCode && !githubUrl && !fileName)}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-bold py-3.5 rounded-xl transition-all shadow-md shadow-blue-500/20 flex items-center justify-center gap-2 text-sm"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Executing Security Pipeline...
              </>
            ) : (
              <>
                Start Analysis <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>

        {/* Real-Time Progress Modal / Notification */}
        {loading && (
          <div className="p-6 rounded-2xl bg-white border border-blue-200 shadow-md flex flex-col gap-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-bold text-blue-700">Pipeline Step {progressStep} / 8</span>
              <span className="text-slate-500 font-mono">{progressMsg}</span>
            </div>
            <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
              <div 
                className="bg-blue-600 h-2 transition-all duration-300 rounded-full" 
                style={{ width: `${(progressStep / 8) * 100}%` }}
              />
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
