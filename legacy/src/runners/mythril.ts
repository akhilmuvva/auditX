import fs from 'fs';
import path from 'path';
import { emitStep } from '../events.js';
import { spawnAsync, sanitizePath, writeIncrementalReport } from '../utils/helpers.js';

export async function runMythril(contractFiles: string[], reportDir: string) {
  emitStep('mythril', 'active', { message: `Booting Mythril symbolic execution solver...` });
  
  if (!contractFiles || contractFiles.length === 0) {
    emitStep('mythril', 'error', { message: 'No solidity files passed to Mythril.' });
    return [];
  }

  const safePath = sanitizePath(contractFiles[0]);
  
  try {
    const { stdout, stderr, code } = await spawnAsync('myth', ['analyze', safePath, '-o', 'json']);
    let output = stdout || stderr;
    
    let parsed = null;
    try {
      const match = output.match(/\{[\s\S]*\}/);
      if (match) parsed = JSON.parse(match[0]);
    } catch (e) {
      emitStep('mythril', 'error', { message: `Failed to parse Mythril JSON output.` });
    }

    if (parsed && parsed.issues) {
      const issues = parsed.issues.length;
      emitStep('mythril', 'complete', { message: `Mythril completed: Found ${issues} constraints/violations` });
      writeIncrementalReport(reportDir, { mythril: parsed.issues });
      return parsed.issues;
    } else {
      emitStep('mythril', 'error', { message: `Mythril ran but no issues array found. Assuming 0 issues.` });
      writeIncrementalReport(reportDir, { mythril: [] });
      return [];
    }
  } catch (error: any) {
    emitStep('mythril', 'error', { message: `Mythril execution failed: ${error.message}` });
    writeIncrementalReport(reportDir, { mythrilError: error.message });
    return [];
  }
}
