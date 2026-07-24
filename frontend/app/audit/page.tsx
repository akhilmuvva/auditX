'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

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
      await new Promise((resolve) => setTimeout(resolve, i === 2 && includeMythril ? 4000 : 1500));
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
    <div className="min-h-screen bg-[#030303] text-white flex flex-col font-sans relative selection:bg-indigo-500 selection:text-white">
      <div className="absolute top-0 right-0 w-[40%] h-[40%] rounded-full bg-indigo-500/5 blur-[120px] pointer-events-none" />

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
            <Link href="/siem" className="hover:text-white transition-colors">SIEM Toolkit</Link>
          </nav>
          <span className="text-xs text-white/40 font-semibold bg-white/[0.03] border border-white/[0.08] px-3 py-1 rounded-full">
            Console Mode
          </span>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-4xl w-full mx-auto px-6 py-12 flex flex-col justify-center">
        {loading ? (
          /* Loading & Progress Pipeline screen */
          <div className="p-8 rounded-2xl bg-white/[0.01] border border-white/[0.06] text-center max-w-md w-full mx-auto relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-b from-indigo-500/5 to-transparent pointer-events-none" />
            
            <div className="w-16 h-16 rounded-full border-4 border-indigo-500/20 border-t-indigo-500 animate-spin mx-auto mb-8" />
            
            <h2 className="text-xl font-bold mb-2">Analyzing Project Security</h2>
            <p className="text-sm text-white/50 mb-6">Pipeline Step {progressStep}/9</p>

            <div className="w-full bg-white/[0.06] h-1.5 rounded-full overflow-hidden mb-6">
              <div 
                className="bg-gradient-to-r from-indigo-500 to-emerald-500 h-full transition-all duration-500" 
                style={{ width: `${(progressStep / 9) * 100}%` }}
              />
            </div>

            <p className="text-xs font-mono text-indigo-400 tracking-wider h-6 animate-pulse">
              {progressMsg}
            </p>
          </div>
        ) : (
          /* Input Console Form */
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="md:col-span-2 flex flex-col gap-6">
              <h1 className="text-3xl font-black tracking-tight">Run On-Chain Security Audit</h1>
              <p className="text-white/60 text-sm">
                Submit your Solidity source files or link a repository to scan with Slither, Mythril, and our custom MEV/Reentrancy detectors.
              </p>

              {/* Tab Switcher */}
              <div className="flex bg-white/[0.03] p-1 rounded-xl border border-white/[0.08]">
                <button 
                  onClick={() => setActiveTab('paste')}
                  className={`flex-1 py-2 text-xs font-semibold rounded-lg transition-all ${activeTab === 'paste' ? 'bg-white/10 text-white shadow-md' : 'text-white/40 hover:text-white/60'}`}
                >
                  Paste Code
                </button>
                <button 
                  onClick={() => setActiveTab('file')}
                  className={`flex-1 py-2 text-xs font-semibold rounded-lg transition-all ${activeTab === 'file' ? 'bg-white/10 text-white shadow-md' : 'text-white/40 hover:text-white/60'}`}
                >
                  Upload File
                </button>
                <button 
                  onClick={() => setActiveTab('github')}
                  className={`flex-1 py-2 text-xs font-semibold rounded-lg transition-all ${activeTab === 'github' ? 'bg-white/10 text-white shadow-md' : 'text-white/40 hover:text-white/60'}`}
                >
                  GitHub Link
                </button>
              </div>

              {/* Console Input Areas */}
              <div className="flex-1 min-h-[300px] flex flex-col">
                {activeTab === 'paste' && (
                  <textarea
                    value={solCode}
                    onChange={(e) => setSolCode(e.target.value)}
                    placeholder="// Paste your Solidity source contract here..."
                    className="flex-1 w-full p-4 rounded-2xl bg-white/[0.02] border border-white/[0.08] focus:border-indigo-500/50 outline-none text-xs font-mono resize-none text-white/80 placeholder:text-white/20"
                  />
                )}

                {activeTab === 'file' && (
                  <div className="flex-1 border-2 border-dashed border-white/[0.08] rounded-2xl flex flex-col items-center justify-center p-8 bg-white/[0.01]">
                    <input 
                      type="file" 
                      accept=".sol" 
                      onChange={handleFileChange}
                      id="sol-file-upload" 
                      className="hidden" 
                    />
                    <label htmlFor="sol-file-upload" className="cursor-pointer bg-white/[0.04] border border-white/[0.08] hover:bg-white/[0.08] text-xs px-4 py-2 rounded-xl transition-all mb-3 font-semibold">
                      Select Contract (.sol)
                    </label>
                    <span className="text-xs text-white/40">
                      {fileName ? `Loaded: ${fileName}` : 'Maximum size 2MB'}
                    </span>
                  </div>
                )}

                {activeTab === 'github' && (
                  <div className="flex-1 flex flex-col justify-center p-8 rounded-2xl bg-white/[0.02] border border-white/[0.08]">
                    <label className="text-xs text-white/40 font-bold mb-2 uppercase tracking-wide">Repository URL</label>
                    <input 
                      type="text"
                      value={githubUrl}
                      onChange={(e) => setGithubUrl(e.target.value)}
                      placeholder="https://github.com/username/project"
                      className="w-full h-11 bg-white/[0.04] border border-white/[0.08] rounded-xl px-4 text-sm outline-none focus:border-indigo-500/50 text-white/80 placeholder:text-white/20"
                    />
                  </div>
                )}
              </div>
            </div>

            {/* Sidebar Options Panel */}
            <div className="flex flex-col gap-6 p-6 rounded-2xl bg-white/[0.01] border border-white/[0.06] self-start w-full">
              <h3 className="font-bold text-sm uppercase tracking-wide text-white/50">Pipeline Options</h3>

              {/* Mythril */}
              <label className="flex items-center justify-between cursor-pointer border-b border-white/[0.04] pb-4">
                <div className="flex flex-col">
                  <span className="text-xs font-semibold">Include Mythril</span>
                  <span className="text-[10px] text-white/40">Slower symbolic execution</span>
                </div>
                <input 
                  type="checkbox" 
                  checked={includeMythril} 
                  onChange={(e) => setIncludeMythril(e.target.checked)}
                  className="rounded border-white/20 bg-black text-indigo-600 focus:ring-indigo-500 w-4 h-4" 
                />
              </label>

              {/* IPFS */}
              <label className="flex items-center justify-between cursor-pointer border-b border-white/[0.04] pb-4">
                <div className="flex flex-col">
                  <span className="text-xs font-semibold">Seal to IPFS</span>
                  <span className="text-[10px] text-white/40">Pin reports on Pinata nodes</span>
                </div>
                <input 
                  type="checkbox" 
                  checked={sealIpfs} 
                  onChange={(e) => setSealIpfs(e.target.checked)}
                  className="rounded border-white/20 bg-black text-indigo-600 focus:ring-indigo-500 w-4 h-4" 
                />
              </label>

              {/* EAS */}
              <label className="flex items-center justify-between cursor-pointer border-b border-white/[0.04] pb-4">
                <div className="flex flex-col">
                  <span className="text-xs font-semibold">EAS Attestation</span>
                  <span className="text-[10px] text-white/40">On-chain Ethereum credentials</span>
                </div>
                <input 
                  type="checkbox" 
                  checked={easAttest} 
                  onChange={(e) => setEasAttest(e.target.checked)}
                  className="rounded border-white/20 bg-black text-indigo-600 focus:ring-indigo-500 w-4 h-4" 
                />
              </label>

              {/* Mint Badge */}
              <div className="flex flex-col gap-3">
                <label className="flex items-center justify-between cursor-pointer">
                  <div className="flex flex-col">
                    <span className="text-xs font-semibold">Mint Security Badge</span>
                    <span className="text-[10px] text-white/40">Polygon ERC-721 SVG Badge</span>
                  </div>
                  <input 
                    type="checkbox" 
                    checked={mintBadge} 
                    onChange={(e) => setMintBadge(e.target.checked)}
                    className="rounded border-white/20 bg-black text-indigo-600 focus:ring-indigo-500 w-4 h-4" 
                  />
                </label>
                
                {mintBadge && (
                  <input 
                    type="text" 
                    value={recipient}
                    onChange={(e) => setRecipient(e.target.value)}
                    placeholder="Recipient Wallet (0x...)"
                    className="w-full h-9 bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 text-xs outline-none focus:border-indigo-500/50"
                  />
                )}
              </div>

              {/* Run Scan Button */}
              <button 
                onClick={() => startDemoOrScan()}
                className="w-full h-11 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-xl transition-all shadow-[0_0_15px_rgba(79,70,229,0.3)] mt-4 text-xs"
              >
                Execute Pipeline Scan
              </button>

              <div className="text-center text-[10px] text-white/30 border-t border-white/[0.04] pt-4">
                Want to test? Run a{' '}
                <button 
                  onClick={() => startDemoOrScan('Reentrancy')}
                  className="text-indigo-400 hover:underline inline-block font-semibold"
                >
                  Demo Reentrancy Scan
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
