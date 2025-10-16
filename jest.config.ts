import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.ts'],
  globals: {
    'ts-jest': {
      tsconfig: 'tsconfig.json',
    },
  },
  moduleNameMapper: {
    '^verse-shared/(.*)$': '<rootDir>/packages/verse-shared/src/$1',
    '^verse-shared$': '<rootDir>/packages/verse-shared/src/index.ts',
    '^verse-server/(.*)$': '<rootDir>/packages/verse-server/src/$1',
    '^verse-server$': '<rootDir>/packages/verse-server/src/index.ts',
    '^verse-client/(.*)$': '<rootDir>/packages/verse-client/src/$1',
    '^verse-client$': '<rootDir>/packages/verse-client/src/index.ts',
  },
};

export default config;
