import { parseGithubImport, findSolFiles } from '../src/utils/github.js';
import { describe, it, expect, jest } from '@jest/globals';
import fs from 'fs';
import path from 'path';

describe('GitHub Repository Import & Solidity Discovery', () => {
  describe('GitHub URL Parser', () => {
    it('should parse full https repository URLs', () => {
      const result = parseGithubImport('https://github.com/akhilmuvva/auditX');
      expect(result).not.toBeNull();
      expect(result!.repoUrl).toBe('https://github.com/akhilmuvva/auditX.git');
      expect(result!.repoName).toBe('auditX');
      expect(result!.filePath).toBeUndefined();
    });

    it('should parse full https blob URLs with branch and nested contract file paths', () => {
      const result = parseGithubImport('https://github.com/akhilmuvva/auditX/blob/main/contracts/VulnerableVault.sol');
      expect(result).not.toBeNull();
      expect(result!.repoUrl).toBe('https://github.com/akhilmuvva/auditX.git');
      expect(result!.repoName).toBe('auditX');
      expect(result!.filePath).toBe('contracts/VulnerableVault.sol');
    });

    it('should parse shortowner/repo syntax', () => {
      const result = parseGithubImport('openzepp/contracts');
      expect(result).not.toBeNull();
      expect(result!.repoUrl).toBe('https://github.com/openzepp/contracts.git');
      expect(result!.repoName).toBe('contracts');
      expect(result!.filePath).toBeUndefined();
    });

    it('should parse shortowner/repo/filepath syntax', () => {
      const result = parseGithubImport('openzepp/contracts/contracts/token/ERC20/ERC20.sol');
      expect(result).not.toBeNull();
      expect(result!.repoUrl).toBe('https://github.com/openzepp/contracts.git');
      expect(result!.repoName).toBe('contracts');
      expect(result!.filePath).toBe('contracts/token/ERC20/ERC20.sol');
    });

    it('should return null for local paths that exist to prevent false matching', () => {
      const mockExist = jest.spyOn(fs, 'existsSync').mockReturnValue(true);
      
      const result = parseGithubImport('contracts/VulnerableVault.sol');
      expect(result).toBeNull();
      
      mockExist.mockRestore();
    });
  });

  describe('Recursive Solidity Finder', () => {
    it('should recursively find .sol files and skip cache/node_modules directories', () => {
      const mockReaddir = jest.spyOn(fs, 'readdirSync').mockImplementation(((dirPath: any) => {
        if (dirPath.includes('node_modules') || dirPath.includes('.git')) return [];
        if (dirPath.endsWith('nested')) return ['DeepContract.sol'];
        return ['LocalContract.sol', 'nested', 'node_modules'];
      }) as any);

      const mockStat = jest.spyOn(fs, 'statSync').mockImplementation((filePath: any) => {
        return {
          isDirectory: () => filePath.endsWith('nested') || filePath.endsWith('node_modules')
        } as any;
      });

      const mockExists = jest.spyOn(fs, 'existsSync').mockReturnValue(true);

      const files = findSolFiles('/mock-root');
      expect(files).toContain(path.join('/mock-root', 'LocalContract.sol'));
      expect(files).toContain(path.join('/mock-root', 'nested', 'DeepContract.sol'));
      expect(files.some(f => f.includes('node_modules'))).toBe(false);

      mockReaddir.mockRestore();
      mockStat.mockRestore();
      mockExists.mockRestore();
    });
  });
});
