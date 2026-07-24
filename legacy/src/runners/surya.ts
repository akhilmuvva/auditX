import fs from 'fs';
import path from 'path';
import { emitStep } from '../events.js';
import { spawnAsync, sanitizePath, writeIncrementalReport } from '../utils/helpers.js';

export async function runSurya(contractFiles: string[], reportDir: string) {
  emitStep('surya', 'active', { message: `Mapping Contract Call-Graph AST via Surya...` });
  
  if (!contractFiles || contractFiles.length === 0) return { nodes: [], edges: [] };

  const safePaths = contractFiles.map(sanitizePath);
  
  try {
    const { stdout, code } = await spawnAsync('surya', ['graph', ...safePaths]);
    
    // Convert DOT output to a simplified structure
    const nodes: any[] = [];
    const edges: any[] = [];
    
    const lines = stdout.split('\n');
    lines.forEach(line => {
      // Very basic DOT parsing to extract nodes and edges for the dashboard
      const edgeMatch = line.match(/"?([\w.]+)"?\s*->\s*"?([\w.]+)"?/);
      if (edgeMatch) {
        edges.push({ source: edgeMatch[1], target: edgeMatch[2] });
        if (!nodes.find(n => n.id === edgeMatch[1])) nodes.push({ id: edgeMatch[1], type: 'contract' });
        if (!nodes.find(n => n.id === edgeMatch[2])) nodes.push({ id: edgeMatch[2], type: 'contract' });
      }
    });

    emitStep('surya', 'complete', { message: `Surya AST map generated: ${nodes.length} nodes, ${edges.length} edges` });
    const suryaData = { graphNodes: nodes, graphEdges: edges, rawDot: stdout };
    writeIncrementalReport(reportDir, { surya: suryaData });
    return suryaData;
  } catch (error: any) {
    emitStep('surya', 'error', { message: `Surya execution failed: ${error.message}` });
    writeIncrementalReport(reportDir, { suryaError: error.message });
    return { nodes: [], edges: [] };
  }
}
