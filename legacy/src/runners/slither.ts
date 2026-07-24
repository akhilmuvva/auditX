import fs from 'fs';
import path from 'path';
import { emitStep } from '../events.js';
import { spawnAsync, sanitizePath, writeIncrementalReport } from '../utils/helpers.js';

export async function runSlither(targetPath: string, reportDir: string) {
  emitStep('slither', 'active', { message: `Initializing Slither static analysis on ${path.basename(targetPath)}` });
  const safePath = sanitizePath(targetPath);
  
  try {
    const { stdout, stderr, code } = await spawnAsync('slither', [safePath, '--json', '-']);
    let output = stdout || stderr;
    
    // Attempt to extract JSON from Slither output
    let parsed = null;
    try {
      const match = output.match(/\{[\s\S]*\}/);
      if (match) parsed = JSON.parse(match[0]);
    } catch (e) {
      emitStep('slither', 'error', { message: `Failed to parse Slither JSON output.` });
    }

    if (parsed && parsed.success && parsed.results && parsed.results.detectors) {
      const issues = parsed.results.detectors.length;
      emitStep('slither', 'complete', { message: `Slither completed: Found ${issues} potential vulnerabilities` });
      writeIncrementalReport(reportDir, { slither: parsed.results.detectors });
      return parsed.results.detectors;
    } else {
      emitStep('slither', 'error', { message: `Slither ran but no standard detectors array found. Assuming 0 issues.` });
      writeIncrementalReport(reportDir, { slither: [] });
      return [];
    }
  } catch (error: any) {
    emitStep('slither', 'error', { message: `Slither execution failed: ${error.message}` });
    writeIncrementalReport(reportDir, { slitherError: error.message });
    return [];
  }
}
