const path = require('path');

// Root Jest config to run workspace package tests via `pnpm -w -r test` or direct jest
module.exports = {
  // Centralized root config: run as single project so transforms/mappers apply globally
  preset: 'ts-jest',
  testEnvironment: 'node',
  // Increase timeout to allow integration server startup (in-memory Mongo) to complete
  testTimeout: 20000,
  // transform using absolute tsconfig path so ts-jest always finds repo tsconfig
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', { tsconfig: path.resolve(__dirname, 'tsconfig.json') }],
  },
  // Only run tests under packages/*/src/**/__tests__
  testMatch: ['<rootDir>/packages/*/src/**/__tests__/**/*.ts'],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'json'],
  // Ignore compiled files under dist
  testPathIgnorePatterns: ['/node_modules/', '/packages/.*/dist/'],
  // Map scoped package imports like @kedaruma/revlm-server/server -> packages/revlm-server/src/server
  moduleNameMapper: {
    '^@kedaruma/([^/]+)(.*)$': '<rootDir>/packages/$1/src$2',
  },
};
