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
    '^revlm-shared/(.*)$': '<rootDir>/packages/revlm-shared/src/$1',
    '^revlm-shared$': '<rootDir>/packages/revlm-shared/src/index.ts',
    '^revlm-server/(.*)$': '<rootDir>/packages/revlm-server/src/$1',
    '^revlm-server$': '<rootDir>/packages/revlm-server/src/index.ts',
    '^revlm-client/(.*)$': '<rootDir>/packages/revlm-client/src/$1',
    '^revlm-client$': '<rootDir>/packages/revlm-client/src/index.ts',
  },
};

export default config;
