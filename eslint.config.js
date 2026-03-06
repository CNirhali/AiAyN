const js = require('@eslint/js');
const globals = require('globals');
const eslintPluginSecurity = require('eslint-plugin-security');

/**
 * ESLint Flat Configuration for Sentinel 🛡️
 *
 * This configuration ensures both standard JavaScript best practices (via eslint:recommended)
 * and security-focused linting (via eslint-plugin-security) are enforced.
 *
 * We are using CommonJS because this is a legacy-style Node.js environment.
 *
 * @see https://eslint.org/docs/latest/use/configure/configuration-files
 */
module.exports = [
  // 1. Core recommended JavaScript rules to prevent common bugs
  js.configs.recommended,

  // 2. Security-specific rules from eslint-plugin-security
  eslintPluginSecurity.configs.recommended,

  // 3. Custom language options and global variables
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      // Enable Node.js global variables to prevent "undefined" errors
      globals: {
        ...globals.node,
      },
    },
  },

  // 4. Ignores: Skip non-essential files
  {
    ignores: ['node_modules/**', 'dist/**', 'build/**'],
  },
];
