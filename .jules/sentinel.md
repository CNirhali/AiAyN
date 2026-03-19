## 2025-03-05 - Missing Automated Security Infrastructure
**Vulnerability:** The repository lacked a `package.json` and associated linting/testing infrastructure, preventing the enforcement of security coding standards and automated vulnerability scanning.
**Learning:** Even small repositories benefit from basic infrastructure like ESLint and Dependabot to catch low-hanging security issues and keep dependencies updated.
**Prevention:** Always initialize a `package.json` with security-focused linting (e.g., `eslint-plugin-security`) and configure Dependabot for all used ecosystems from the start.

## 2025-03-05 - ESLint v10 Flat Config Migration
**Vulnerability:** The codebase used an obsolete `.eslintrc.json` configuration while running ESLint v10, which requires the Flat Config format (`eslint.config.js`). This mismatch would cause security linting (via `eslint-plugin-security`) to be ignored or fail.
**Learning:** Upgrading ESLint beyond v9 requires a complete migration of the configuration format. Relying on legacy configuration in a modern ESLint environment can silently disable security checks.
**Prevention:** When using ESLint v9+, explicitly migrate to `eslint.config.js`, ensuring that both standard (`eslint:recommended`) and security-specific plugins are correctly integrated into the new flat configuration array.

## 2025-03-05 - Suspicious/Hallucinated GitHub Action SHAs
**Vulnerability:** The CI workflow contained GitHub Action references pinned to commit SHAs that did not correspond to any known official releases, accompanied by misleading version comments (e.g., `checkout@v6.0.2` when the latest major is `v4`). This is a high-risk supply chain vulnerability.
**Learning:** Never trust SHAs or version numbers in CI/CD configurations without verifying them against official repository releases. Hallucinated or maliciously injected SHAs can execute arbitrary code in the CI environment.
**Prevention:** Always verify commit SHAs against official tags/releases on the action's primary repository. Use tools or manual verification to ensure that the pinned SHA is a verified, signed commit from the official maintainers.

## 2025-03-05 - Nuanced Security Rule Enforcement in Tests
**Vulnerability:** Programmatic security tests (`security.test.js`) could falsely pass if the "insecure" code snippets don't match the specific heuristic patterns used by `eslint-plugin-security` (e.g., rules like `detect-non-literal-regexp` may only flag if the source is clearly non-literal, like `process.argv`).
**Learning:** Security linters often use heuristic-based AST analysis that requires specific patterns to trigger. For instance, `detect-possible-timing-attacks` prioritizes comparisons inside `if` statements with security-sensitive variable names.
**Prevention:** When writing security infrastructure tests, verify each rule's trigger requirements in the plugin source or documentation. Use robust triggers like `process.argv[2]` to guarantee detection of non-literal injection risks.

## 2025-03-05 - Static Analysis Limitations for Strict Mode Rules
**Vulnerability:** The `no-delete-var` rule, while important for security by preventing the deletion of variables, is difficult to verify programmatically in modern Node.js environments. In strict mode (default for ESM and common in Node.js), deleting a local variable is a syntax error that causes a fatal parsing error, preventing the linter from ever checking the specific rule.
**Learning:** Some security-related linting rules are effectively superseded by language-level enforcements like strict mode. Attempting to programmatically test these rules requires using code that is syntactically valid yet violates the rule, which may not be possible for all rules.
**Prevention:** When adding security rules to the linter, prioritize those that detect logic vulnerabilities (like injection) over those already covered by strict mode syntax errors. If a rule is critical, verify its behavior using non-strict mode snippets if possible, or acknowledge the parser-level protection.

## 2025-03-05 - Insecure Randomness Detection Gap
**Vulnerability:** The standard `eslint-plugin-security` (v4.0.0) configuration flags `crypto.pseudoRandomBytes()` but does not automatically catch the use of `Math.random()`, which is a cryptographically weak pseudo-random number generator (PRNG).
**Learning:** Relying solely on a security plugin's "recommended" configuration may leave gaps for well-known insecure patterns. `Math.random()` is often used by developers for security-sensitive tasks like ID or token generation, creating a significant security risk.
**Prevention:** Explicitly use the core ESLint `no-restricted-properties` rule to disallow `Math.random()` across the codebase. Always provide a clear error message directing developers to secure alternatives like `crypto.randomBytes()` or `crypto.randomInt()`.

## 2025-03-05 - Insecure Dynamic Import Detection
**Vulnerability:** Dynamic `import()` calls with non-literal sources can allow an attacker to execute arbitrary code if they control the source string, leading to Remote Code Execution (RCE). The standard `eslint-plugin-security` (v4.0.0) does not detect this pattern.
**Learning:** Security plugins may have gaps for modern JavaScript features like dynamic imports. Relying on generic security plugins is not enough; custom AST-based rules are necessary to catch modern injection vectors.
**Prevention:** Use the core ESLint `no-restricted-syntax` rule with a selector like `ImportExpression[source.type!="Literal"]` to globally disallow non-literal dynamic imports. This ensures that all dynamic imports use hardcoded, trusted paths.
