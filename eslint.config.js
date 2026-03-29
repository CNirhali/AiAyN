const js = require("@eslint/js");
const globals = require("globals");
const eslintPluginSecurity = require("eslint-plugin-security");

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
      ecmaVersion: "latest",
      sourceType: "module",
      // Enable Node.js global variables to prevent "undefined" errors
      globals: {
        ...globals.node,
      },
    },
    rules: {
      // Harden against code injection by disallowing dynamic code execution
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",

      // Prevent common JavaScript pitfalls that could lead to logic errors or security gaps
      "no-unsafe-finally": "error",
      "no-unsafe-negation": "error",
      "no-caller": "error",
      "no-proto": "error",
      "no-delete-var": "error",

      // Specific security-focused rules for prototype pollution and object injection
      "security/detect-object-injection": "error",

      // Prevent Trojan Source attacks by disallowing bidirectional control characters
      "security/detect-bidi-characters": "error",

      // Harden against Regular Expression Denial of Service (ReDoS)
      "security/detect-unsafe-regex": "error",

      // Prevent command injection by flagging child_process usage with non-literals
      "security/detect-child-process": "error",

      // Flag eval() with expressions to prevent code injection
      "security/detect-eval-with-expression": "error",

      // Prevent Remote Code Execution (RCE) via non-literal require() calls
      "security/detect-non-literal-require": "error",

      // Mitigate path traversal by flagging non-literal file paths in fs operations
      "security/detect-non-literal-fs-filename": "error",

      // Prevent insecure comparisons that could leak info via timing
      "security/detect-possible-timing-attacks": "error",

      // Mitigate ReDoS by flagging non-literal values in RegExp constructor
      "security/detect-non-literal-regexp": "error",

      // Prevent out-of-bounds writes in Buffer operations
      "security/detect-buffer-noassert": "error",

      // Prevent use of deprecated and unsafe new Buffer()
      "security/detect-new-buffer": "error",

      // Prevent use of cryptographically weak pseudo-random numbers
      "security/detect-pseudoRandomBytes": "error",

      // Prevent use of cryptographically weak random numbers
      "no-restricted-properties": [
        "error",
        {
          object: "Math",
          property: "random",
          message:
            "Use crypto.randomBytes() or crypto.randomInt() for security-sensitive operations.",
        },
      ],

      // Ensure CSRF protection is applied before method override
      "security/detect-no-csrf-before-method-override": "error",

      // Prevent RCE via dynamic import() and insecure Buffer allocation, and disallow insecure APIs
      "no-restricted-syntax": [
        "error",
        {
          selector: 'ImportExpression[source.type!="Literal"]',
          message:
            "Dynamic imports with non-literal paths can lead to Remote Code Execution (RCE).",
        },
        {
          selector:
            "CallExpression:matches([callee.object.name='Buffer'][callee.property.name=/^allocUnsafe(Slow)?$/], [callee.name='allocUnsafe'], [callee.name='allocUnsafeSlow'])",
          message:
            "Use Buffer.alloc() instead of Buffer.allocUnsafe() to ensure memory is zero-filled and prevent information leakage.",
        },
        {
          selector:
            "CallExpression:matches([callee.name='Buffer'], [callee.object.name='Buffer'][callee.property.name='Buffer'])",
          message:
            "The Buffer() constructor is deprecated and insecure. Use Buffer.alloc(), Buffer.allocUnsafe(), or Buffer.from() instead.",
        },
        {
          selector:
            "CallExpression[callee.name='require'][arguments.0.value=/^(node:)?vm$/]",
          message:
            'The "vm" module is not a secure sandbox. Use "isolated-vm" or a separate process for untrusted code execution.',
        },
        {
          selector: "ImportDeclaration[source.value=/^(node:)?vm$/]",
          message:
            'The "vm" module is not a secure sandbox. Use "isolated-vm" or a separate process for untrusted code execution.',
        },
        {
          selector:
            "CallExpression:matches([callee.object.name='crypto'][callee.property.name=/^create(De)?cipher$/], [callee.name='createCipher'], [callee.name='createDecipher'])",
          message:
            "crypto.createCipher() and crypto.createDecipher() are deprecated and use insecure key derivation. Use crypto.createCipheriv() or crypto.createDecipheriv() instead.",
        },
        {
          selector:
            "CallExpression:matches([callee.name=/^(spawn|spawnSync|exec|execSync|execFile|execFileSync)$/], [callee.property.name=/^(spawn|spawnSync|exec|execSync|execFile|execFileSync)$/], [callee.property.value=/^(spawn|spawnSync|exec|execSync|execFile|execFileSync)$/])[arguments.0.type!='Literal']",
          message:
            "Using non-literal arguments with child_process methods can lead to command injection. Ensure all arguments are sanitized or use literal values.",
        },
        {
          selector:
            "CallExpression:matches([callee.name=/^(spawn|spawnSync|exec|execSync|execFile|execFileSync)$/], [callee.property.name=/^(spawn|spawnSync|exec|execSync|execFile|execFileSync)$/], [callee.property.value=/^(spawn|spawnSync|exec|execSync|execFile|execFileSync)$/]) > ObjectExpression > Property:matches([key.name='shell'], [key.value='shell']):matches([value.value=true], [value.type='Literal'][value.value!=false], [value.type='TemplateLiteral'])",
          message:
            'The "shell" option in child_process methods is dangerous as it executes the command in a shell, increasing the risk of command injection. Avoid using it with unsanitized input.',
        },
      ],

      // Prevent disabling of escape in mustache templates
      "security/detect-disable-mustache-escape": "error",
    },
  },

  // 4. Ignores: Skip non-essential files
  {
    ignores: ["node_modules/**", "dist/**", "build/**"],
  },
];
