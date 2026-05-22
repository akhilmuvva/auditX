/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/test/**/*.test.ts'],
  testPathIgnorePatterns: [
    '/node_modules/',
    '/AgentRegistry.test.ts',
    '/AuditBadgeNFT.test.ts',
    '/AuditJobQueue.test.ts',
    '/AuditRegistry.test.ts',
    '/ResumeRegistry.test.ts'
  ],
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      useESM: true,
    }],
  },
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
};
