/**
 * Authoritative PolyLance ABI artifacts loaded directly from verified fixtures
 * Provenance: D:\Polylance\artifacts\contracts\ (commit: c4be92d767afec8b4da8cb339f3f7d3b41445c7a)
 */

import fs from 'fs';
import path from 'path';

function loadFixtureAbi(filename: string): any[] {
  const possiblePaths = [
    path.resolve(process.cwd(), 'test/fixtures/polylance-artifacts', filename),
    path.resolve(process.cwd(), '../test/fixtures/polylance-artifacts', filename),
    path.resolve(__dirname, '../../../test/fixtures/polylance-artifacts', filename),
  ];

  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      const json = JSON.parse(fs.readFileSync(p, 'utf8'));
      return json.abi || json;
    }
  }

  throw new Error(`Failed to locate fixture ABI for ${filename}`);
}

export const JOB_FACTORY_ABI = loadFixtureAbi('JobFactory.json');
export const JOB_ESCROW_ABI = loadFixtureAbi('JobEscrow.json');
export const REPUTATION_SBT_ABI = loadFixtureAbi('ReputationSBT.json');
export const MOCK_USDT_ABI = loadFixtureAbi('MockUSDT.json');
