/** Jest config for the LANCOM LX plugin's pure-logic unit tests (ts-jest, node env). */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/*.test.ts'],
};
