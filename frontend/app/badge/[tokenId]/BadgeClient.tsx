'use client';

import React, { useMemo } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { ShieldCheck, Award, ArrowLeft, CheckCircle2 } from 'lucide-react';

export default function BadgeClient() {
  const params = useParams();
  const tokenId = useMemo(() => {
    const rawTokenId = Array.isArray(params?.tokenId) ? params.tokenId[0] : params?.tokenId;
    return /^\d{1,10}$/.test(rawTokenId || '') ? Number(rawTokenId) : null;
  }, [params]);

  if (tokenId === null || !Number.isSafeInteger(tokenId)) {
    return <div className="min-h-screen bg-[#F6F9FC] text-slate-700 flex items-center justify-center font-medium">Invalid badge token ID.</div>;
  }

  return (
    <div className="min-h-screen bg-[#F6F9FC] text-slate-900 flex flex-col items-center justify-center p-6 font-sans selection:bg-blue-600 selection:text-white">
      <div className="max-w-md w-full flex flex-col gap-6">
        <div className="text-center flex flex-col gap-2">
          <Link href="/dashboard" className="text-xs text-slate-500 hover:text-blue-600 inline-flex items-center justify-center gap-1 mb-2">
            <ArrowLeft className="w-3.5 h-3.5" /> Back to Dashboard
          </Link>
          <div className="w-12 h-12 rounded-2xl bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600 mx-auto shadow-sm">
            <Award className="w-6 h-6" />
          </div>
          <h1 className="text-2xl font-black text-slate-900">Soulbound Security Badge</h1>
          <p className="text-xs text-slate-500">Verified Token ID: #{tokenId}</p>
        </div>

        <div className="w-full aspect-[4/5] rounded-3xl overflow-hidden border border-slate-200 shadow-md bg-white p-4">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 500" width="100%" height="100%" style={{ background: '#ffffff', fontFamily: 'sans-serif' }}>
            <defs>
              <linearGradient id="badgeGlow" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#10B981" stopOpacity="0.15"/>
                <stop offset="100%" stopColor="#ffffff" stopOpacity="0"/>
              </linearGradient>
            </defs>
            <rect width="400" height="500" rx="30" fill="#ffffff" stroke="#E2E8F0" strokeWidth="2"/>
            <circle cx="200" cy="200" r="140" fill="url(#badgeGlow)" />
            <polygon points="200,80 320,140 320,300 200,420 80,300 80,140" fill="#F0FDF4" stroke="#16A34A" strokeWidth="3" />
            <path d="M170 180l20 20 40-40" fill="none" stroke="#16A34A" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round"/>
            <text x="200" y="270" fill="#0F172A" fontSize="22" fontWeight="800" textAnchor="middle">EMERALD GUARD</text>
            <text x="200" y="305" fill="#16A34A" fontSize="12" fontWeight="700" textAnchor="middle">SECURITY CERTIFIED</text>
            <text x="200" y="350" fill="#2563EB" fontSize="11" fontWeight="600" textAnchor="middle">TOKEN ID: #{tokenId}</text>
          </svg>
        </div>

        <div className="p-5 rounded-2xl bg-white border border-slate-200 shadow-sm text-xs flex flex-col gap-3">
          <div className="flex justify-between items-center">
            <span className="text-slate-500">Contract Compliance</span>
            <span className="text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-0.5 rounded-full font-bold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> PASSED
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-slate-500">On-Chain Registrar</span>
            <span className="text-blue-700 font-bold font-mono">Polygon PoS</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-slate-500">Audit Agency</span>
            <span className="text-slate-900 font-bold">AuditX Master Agent</span>
          </div>
        </div>
      </div>
    </div>
  );
}
