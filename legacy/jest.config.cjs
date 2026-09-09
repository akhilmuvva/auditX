/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  rootDir: '..',
  moduleDirectories: ['<rootDir>/legacy/node_modules', 'node_modules'],
  testEnvironment: 'node',
  testMatch: ['<rootDir>/test/**/*.test.ts'],
  testPathIgnorePatterns: [
    '/node_modules/',
    '/cache/',
    '/AgentRegistry.test.ts',
    '/AuditBadgeNFT.test.ts',
    '/AuditJobQueue.test.ts',
    '/AuditRegistry.test.ts',
    '/ResumeRegistry.test.ts',
  ],
  transform: {
    '^.+\\.tsx?$': [require.resolve('ts-jest'), { useESM: true, tsconfig: '<rootDir>/legacy/tsconfig.json' }],
  },
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
    '^@auditx/types$': '<rootDir>/legacy/types/index.ts',
    '^@jest/globals$': '<rootDir>/legacy/node_modules/@jest/globals/build/index.js',
  },
};
