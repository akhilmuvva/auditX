import React, { useEffect, useRef } from 'react';
import mermaid from 'mermaid';

mermaid.initialize({
  startOnLoad: false,
  theme: 'base',
  themeVariables: {
    darkMode: true,
    background: 'transparent',
    primaryColor: '#6366f1', // indigo-500
    primaryTextColor: '#f3f4f6', // gray-100
    primaryBorderColor: '#818cf8', // indigo-400
    lineColor: '#4ade80', // emerald-400
    secondaryColor: '#1e1b4b', // indigo-950
    tertiaryColor: '#0a0d14', // bg color
  },
  flowchart: {
    curve: 'basis'
  }
});

interface MermaidDiagramProps {
  chart: string;
}

export const MermaidDiagram: React.FC<MermaidDiagramProps> = ({ chart }) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current && chart) {
      // Clear previous graph
      containerRef.current.innerHTML = '';
      
      try {
        mermaid.render('mermaid-graph-' + Date.now(), chart).then(({ svg }) => {
          if (containerRef.current) {
            containerRef.current.innerHTML = svg;
          }
        });
      } catch (err) {
        console.error('Mermaid render failed:', err);
        if (containerRef.current) {
          containerRef.current.innerHTML = '<div class="text-rose-400 text-[10px] p-4 border border-rose-500/20 bg-rose-500/10 rounded">Failed to render graph topology.</div>';
        }
      }
    }
  }, [chart]);

  return (
    <div 
      ref={containerRef} 
      className="flex justify-center items-center w-full min-h-[200px] overflow-x-auto overflow-y-hidden"
    />
  );
};
