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
    rules: {
      // Harden against code injection by disallowing dynamic code execution
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',

      // Prevent common JavaScript pitfalls that could lead to logic errors or security gaps
      'no-unsafe-finally': 'error',
      'no-unsafe-negation': 'error',
      'no-caller': 'error',
      'no-proto': 'error',
      'no-delete-var': 'error',

      // Specific security-focused rules for prototype pollution and object injection
      'security/detect-object-injection': 'error',

      // Prevent Trojan Source attacks by disallowing bidirectional control characters
      'security/detect-bidi-characters': 'error',

      // Harden against Regular Expression Denial of Service (ReDoS)
      'security/detect-unsafe-regex': 'error',

      // Prevent command injection by flagging child_process usage with non-literals
      'security/detect-child-process': 'error',

      // Flag eval() with expressions to prevent code injection
      'security/detect-eval-with-expression': 'error',

      // Prevent Remote Code Execution (RCE) via non-literal require() calls
      'security/detect-non-literal-require': 'error',

      // Mitigate path traversal by flagging non-literal file paths in fs operations
      'security/detect-non-literal-fs-filename': 'error',

      // Prevent insecure comparisons that could leak info via timing
      'security/detect-possible-timing-attacks': 'error',

      // Mitigate ReDoS by flagging non-literal values in RegExp constructor
      'security/detect-non-literal-regexp': 'error',

      // Prevent out-of-bounds writes in Buffer operations
      'security/detect-buffer-noassert': 'error',

      // Prevent use of deprecated and unsafe new Buffer()
      'security/detect-new-buffer': 'error',

      // Prevent use of cryptographically weak pseudo-random numbers
      'security/detect-pseudoRandomBytes': 'error',

      // Prevent use of cryptographically weak random numbers
      'no-restricted-properties': [
        'error',
        {
          object: 'Math',
          property: 'random',
          message: 'Use crypto.randomBytes() or crypto.randomInt() for security-sensitive operations.',
        },
      ],

      // Ensure CSRF protection is applied before method override
      'security/detect-no-csrf-before-method-override': 'error',

      // Prevent RCE via dynamic import() and insecure Buffer allocation
      'no-restricted-syntax': [
        'error',
        {
          selector: 'ImportExpression[source.type!="Literal"]',
          message: 'Dynamic imports with non-literal paths can lead to Remote Code Execution (RCE).',
        },
        {
          selector: "CallExpression[callee.object.name='Buffer'][callee.property.name=/^allocUnsafe(Slow)?$/]",
          message: 'Use Buffer.alloc() instead of Buffer.allocUnsafe() to ensure memory is zero-filled and prevent information leakage.',
        },
      ],

      // Prevent disabling of escape in mustache templates
      'security/detect-disable-mustache-escape': 'error',
    },
  },

  // 4. Ignores: Skip non-essential files
  {
    ignores: ['node_modules/**', 'dist/**', 'build/**'],
  },
];
