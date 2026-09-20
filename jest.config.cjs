/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/test/**/*.test.ts'],
  testPathIgnorePatterns: [
    '/node_modules/',
    '/cache/',
    '/AgentRegistry.test.ts',
    '/AuditBadgeNFT.test.ts',
    '/AuditJobQueue.test.ts',
    '/AuditRegistry.test.ts',
    '/ResumeRegistry.test.ts'
  ],
  modulePathIgnorePatterns: ['<rootDir>/cache/'],
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      useESM: true,
      tsconfig: '<rootDir>/tsconfig.json',
    }],
  },
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^@auditx/types$': '<rootDir>/types/index.ts',
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
};
