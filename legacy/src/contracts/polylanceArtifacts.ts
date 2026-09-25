/**
 * Authoritative PolyLance ABI artifacts loaded from legacy/src/contracts/abi
 * Included in production build and Docker image
 */

import fs from 'fs';
import path from 'path';

function loadContractAbi(filename: string): any[] {
  const possiblePaths = [
    path.resolve(process.cwd(), 'legacy/src/contracts/abi', filename),
    path.resolve(process.cwd(), 'src/contracts/abi', filename),
    path.resolve(process.cwd(), 'dist/src/contracts/abi', filename),
    path.resolve(process.cwd(), 'legacy/dist/src/contracts/abi', filename),
    path.resolve(process.cwd(), '../legacy/src/contracts/abi', filename),
  ];

  for (const p of possiblePaths) {
    try {
      if (fs.existsSync(p)) {
        const json = JSON.parse(fs.readFileSync(p, 'utf8'));
        return json.abi || json;
      }
    } catch {
      // continue search
    }
  }

  throw new Error(`Failed to locate production ABI for ${filename}`);
}

export const JOB_FACTORY_ABI = loadContractAbi('JobFactory.json');
export const JOB_ESCROW_ABI = loadContractAbi('JobEscrow.json');
export const REPUTATION_SBT_ABI = loadContractAbi('ReputationSBT.json');
export const MOCK_USDT_ABI = loadContractAbi('MockUSDT.json');
