import fs from 'fs';
import path from 'path';

export interface GithubImportInfo {
  repoUrl: string;
  repoName: string;
  filePath?: string;
}

/**
 * Parses a target string to identify if it is a GitHub repository or contract file target.
 * Supports:
 * - Full blob URL: https://github.com/owner/repo/blob/main/contracts/Vault.sol
 * - Full repo URL: https://github.com/owner/repo
 * - Short repo/file syntax: owner/repo/contracts/Vault.sol
 * - Short repo syntax: owner/repo
 */
export function parseGithubImport(target: string): GithubImportInfo | null {
  if (!target || typeof target !== 'string') return null;

  // 1. Check if it's a full https GitHub URL
  // Matches: https://github.com/owner/repo/blob/main/path/file.sol OR https://github.com/owner/repo
  const httpsRegex = /^https:\/\/github\.com\/([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_-]+)(?:\/(?:tree|blob)\/[a-zA-Z0-9._-]+ \/(.+))?$/;
  // Also check a relaxed version that matches branch name and subfolders
  const relaxedHttpsRegex = /^https:\/\/github\.com\/([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_-]+)(?:\/(?:tree|blob)\/[^/]+\/(.+))?$/;
  
  let match = target.match(relaxedHttpsRegex);
  if (match) {
    return {
      repoUrl: `https://github.com/${match[1]}/${match[2]}.git`,
      repoName: match[2],
      filePath: match[3] ? decodeURIComponent(match[3]) : undefined
    };
  }

  // 2. Check if it's a short owner/repo format
  // Matches: owner/repo/path/to/file.sol OR owner/repo
  const shortRegex = /^([a-zA-Z0-9_-]+)\/([a-zA-Z0-9_-]+)(?:\/(.+))?$/;
  const matchShort = target.match(shortRegex);
  if (matchShort) {
    // Crucial: ensure we don't treat an existing local directory or file as a GitHub shortcode!
    if (fs.existsSync(target)) {
      return null;
    }
    return {
      repoUrl: `https://github.com/${matchShort[1]}/${matchShort[2]}.git`,
      repoName: matchShort[2],
      filePath: matchShort[3] ? matchShort[3] : undefined
    };
  }

  return null;
}

/**
 * Recursively searches a directory and returns all found .sol file paths.
 */
export function findSolFiles(dir: string): string[] {
  let results: string[] = [];
  if (!fs.existsSync(dir)) return [];

  const list = fs.readdirSync(dir);
  for (const file of list) {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    if (stat && stat.isDirectory()) {
      // Skip node_modules or standard cache folders to keep audits focused and fast
      if (file !== 'node_modules' && file !== '.git' && file !== 'cache') {
        results = results.concat(findSolFiles(filePath));
      }
    } else if (file.endsWith('.sol')) {
      results.push(filePath);
    }
  }
  return results;
}
