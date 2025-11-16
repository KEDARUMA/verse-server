const path = require('path');

module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testTimeout: 20000,
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', {
      tsconfig: {
        module: 'commonjs',
        moduleResolution: 'node',
        esModuleInterop: true,
        isolatedModules: false
      }
    }],
  },
  testMatch: ['<rootDir>/packages/*/src/**/__tests__/**/*.ts'],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'json'],
  testPathIgnorePatterns: ['/node_modules/', '/packages/.*/dist/'],
  moduleNameMapper: {
    '^@kedaruma/([^/]+)(.*)$': '<rootDir>/packages/$1/src$2',
  },
};
