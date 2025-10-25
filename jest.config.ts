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
    '^@kedaruma/revlm-shared/(.*)$': '<rootDir>/packages/revlm-shared/src/$1',
    '^@kedaruma/revlm-shared$': '<rootDir>/packages/revlm-shared/src/index.ts',
    '^@kedaruma/revlm-server/(.*)$': '<rootDir>/packages/revlm-server/src/$1',
    '^@kedaruma/revlm-server$': '<rootDir>/packages/revlm-server/src/index.ts',
    '^@kedaruma/revlm-client/(.*)$': '<rootDir>/packages/revlm-client/src/$1',
    '^@kedaruma/revlm-client$': '<rootDir>/packages/revlm-client/src/index.ts',
  },
};

export default config;
