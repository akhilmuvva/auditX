'use client';

import React, { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { ShieldCheck, Award } from 'lucide-react';

export default function BadgeClient() {
  const params = useParams();
  const tokenId = (params?.tokenId as string) || '1';
  const [svgContent, setSvgContent] = useState<string>('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const mockSvg = `
      <svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 400 500' width='100%' height='100%' style='background:#050508;font-family:sans-serif;'>
        <defs>
          <linearGradient id='glow' x1='0%' y1='0%' x2='100%' y2='100%'>
            <stop offset='0%' stop-color='#10B981' stop-opacity='0.4'/>
            <stop offset='100%' stop-color='#0a0b10' stop-opacity='0'/>
          </linearGradient>
        </defs>
        <rect width='400' height='500' rx='30' fill='#0a0b10' stroke='rgba(255,255,255,0.08)' stroke-width='1.5'/>
        <circle cx='200' cy='200' r='140' fill='url(#glow)' filter='blur(30px)'/>
        <polygon points='200,80 320,140 320,300 200,420 80,300 80,140' fill='none' stroke='#10B981' stroke-width='2' />
        <path d='M170 180l20 20 40-40' fill='none' stroke='#10B981' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/>
        <text x='200' y='270' fill='#ffffff' font-size='22' font-weight='800' text-anchor='middle'>EMERALD GUARD</text>
        <text x='200' y='305' fill='rgba(255,255,255,0.6)' font-size='11' font-weight='700' text-anchor='middle'>SECURITY CERTIFIED</text>
        <text x='200' y='350' fill='#818cf8' font-size='10' text-anchor='middle'>TOKEN ID: #${tokenId}</text>
      </svg>
    `;
    setSvgContent(mockSvg);
    setLoading(false);
  }, [tokenId]);

  if (loading) {
    return (
      <div className="min-h-screen bg-[#030303] text-white flex flex-col items-center justify-center">
        <div className="w-12 h-12 rounded-full border-4 border-indigo-500/20 border-t-indigo-500 animate-spin mb-4" />
        <p className="text-xs text-white/50">Fetching Badge Metadata...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#030303] text-white flex flex-col items-center justify-center p-6 font-sans">
      <div className="max-w-md w-full flex flex-col gap-6">
        
        <div className="text-center flex flex-col gap-2">
          <Award className="w-10 h-10 text-emerald-400 mx-auto" />
          <h1 className="text-2xl font-black">Security Badge Verification</h1>
          <p className="text-xs text-white/40">Verified Token ID: #{tokenId}</p>
        </div>

        <div 
          className="w-full aspect-[4/5] rounded-3xl overflow-hidden border border-white/[0.08] shadow-[0_0_50px_rgba(16,185,129,0.1)] bg-[#050508]"
          dangerouslySetInnerHTML={{ __html: svgContent }}
        />

        <div className="p-4 rounded-xl bg-white/[0.01] border border-white/[0.06] text-xs flex flex-col gap-3">
          <div className="flex justify-between">
            <span className="text-white/40">Contract Compliance</span>
            <span className="text-emerald-400 font-bold flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5" /> PASSED
            </span>
          </div>
          <div className="flex justify-between">
            <span className="text-white/40">On-Chain Registrar</span>
            <span className="text-indigo-400 font-bold font-mono">Polygon PoS</span>
          </div>
          <div className="flex justify-between">
            <span className="text-white/40">Audit Agency</span>
            <span className="text-white/80 font-bold">AuditX Master Agent</span>
          </div>
        </div>

        <div className="flex gap-4">
          <Link href="/audit" className="flex-1 bg-white hover:bg-white/90 text-black font-bold h-11 flex items-center justify-center rounded-xl text-xs transition-all">
            Scan My Code
          </Link>
        </div>
      </div>
    </div>
  );
}
