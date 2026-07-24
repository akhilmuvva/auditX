import { NextResponse } from 'next/server';

export const dynamic = 'force-static';

export function generateStaticParams() {
  return [{ id: 'clean' }, { id: 'reentrancy' }, { id: 'fullstack' }];
}

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const cleanId = id.replace('.svg', '').toLowerCase();

  let cvss = 0.0;
  let label = 'EMERALD GUARD';
  let color = '#10B981'; // green

  if (cleanId === 'reentrancy') {
    cvss = 8.5;
    label = 'AMBER GUARD';
    color = '#F59E0B'; // amber
  } else if (cleanId === 'fullstack') {
    cvss = 9.8;
    label = 'AMBER GUARD';
    color = '#F59E0B';
  } else if (cleanId === 'clean') {
    cvss = 1.8;
    label = 'EMERALD GUARD';
    color = '#10B981';
  } else {
    cvss = 5.5;
    label = 'AMBER GUARD';
    color = '#F59E0B';
  }

  const svg = `
    <svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 400 500' width='400' height='500' style='background:#050508;font-family:sans-serif;'>
      <defs>
        <linearGradient id='glow' x1='0%' y1='0%' x2='100%' y2='100%'>
          <stop offset='0%' stop-color='${color}' stop-opacity='0.4'/>
          <stop offset='100%' stop-color='#0a0b10' stop-opacity='0'/>
        </linearGradient>
      </defs>
      <rect width='400' height='500' rx='30' fill='#0a0b10' stroke='rgba(255,255,255,0.08)' stroke-width='1.5'/>
      <circle cx='200' cy='200' r='140' fill='url(#glow)' filter='blur(30px)'/>
      <polygon points='200,80 320,140 320,300 200,420 80,300 80,140' fill='none' stroke='${color}' stroke-width='2' />
      <path d='M170 180l20 20 40-40' fill='none' stroke='${color}' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/>
      <text x='200' y='270' fill='#ffffff' font-size='22' font-weight='800' text-anchor='middle'>${label}</text>
      <text x='200' y='305' fill='rgba(255,255,255,0.6)' font-size='11' font-weight='700' text-anchor='middle'>SECURITY CERTIFIED</text>
      <text x='200' y='350' fill='#818cf8' font-size='10' text-anchor='middle'>CVSS IMPACT: ${cvss.toFixed(1)}</text>
    </svg>
  `.trim();

  return new NextResponse(svg, {
    headers: {
      'Content-Type': 'image/svg+xml',
      'Cache-Control': 'public, max-age=86400, s-maxage=86400',
    },
  });
}
