import path from 'path';
import { spawn, SpawnOptions } from 'child_process';
import fs from 'fs';
import { emitStep } from '../events.js';

export function sanitizePath(inputPath: string): string {
  const resolved = path.resolve(inputPath);
  if (!/^[a-zA-Z0-9.\\/\-_:]+$/.test(resolved)) {
    throw new Error('Invalid characters in path: ' + inputPath);
  }
  return resolved;
}

export function spawnAsync(command: string, args: string[], options: SpawnOptions = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, options);
    let stdout = '';
    let stderr = '';
    if (child.stdout) {
      child.stdout.on('data', (data) => { stdout += data.toString(); });
    }
    if (child.stderr) {
      child.stderr.on('data', (data) => { stderr += data.toString(); });
    }
    child.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
    child.on('error', (err) => {
      reject(err);
    });
  });
}

// Incremental report writer
export function writeIncrementalReport(reportDir: string, data: any) {
  const reportPath = path.join(reportDir, 'audit_report.json');
  let currentReport = {};
  if (fs.existsSync(reportPath)) {
    try {
      currentReport = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
    } catch (e) {}
  }
  const newReport = { ...currentReport, ...data };
  fs.writeFileSync(reportPath, JSON.stringify(newReport, null, 2));
  emitStep('parse', 'complete', { message: `💾 Incremental report saved to disk` });
}

export const delay = (ms: number) => new Promise(res => setTimeout(res, ms));
