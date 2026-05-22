import { runZKChecks } from '../src/analysis/zkChecks.js';
import path from 'path';
import { describe, it, expect } from '@jest/globals';

describe('ZK Security Checks', () => {
    it('Should fail all checks on a vulnerable contract', () => {
        const targetFile = path.resolve(__dirname, '../contracts/VulnerableVault.sol');
        const results = runZKChecks(targetFile);

        expect(results.length).toBe(5);
        // VulnerableVault doesn't have submitProof, so everything fails
        results.forEach(r => {
            expect(r.passed).toBe(false);
        });
    });

    it('Should pass all checks on the secured ResumeRegistry', () => {
        const targetFile = path.resolve(__dirname, '../contracts/ResumeRegistry.sol');
        const results = runZKChecks(targetFile);

        expect(results.length).toBe(5);
        results.forEach(r => {
            expect(r.passed).toBe(true);
        });
    });
});
