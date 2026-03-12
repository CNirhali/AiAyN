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
