/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/functions'],
  testMatch: ['**/*.test.ts'],
  clearMocks: true,
  restoreMocks: true,
  transform: {
    '^.+\\.tsx?$': [
      '@swc/jest',
      {
        jsc: {
          parser: {syntax: 'typescript', tsx: false},
          target: 'es2022',
        },
        module: {type: 'commonjs'},
      },
    ],
  },
};
