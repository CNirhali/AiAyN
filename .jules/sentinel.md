## 2025-03-05 - Missing Automated Security Infrastructure
**Vulnerability:** The repository lacked a `package.json` and associated linting/testing infrastructure, preventing the enforcement of security coding standards and automated vulnerability scanning.
**Learning:** Even small repositories benefit from basic infrastructure like ESLint and Dependabot to catch low-hanging security issues and keep dependencies updated.
**Prevention:** Always initialize a `package.json` with security-focused linting (e.g., `eslint-plugin-security`) and configure Dependabot for all used ecosystems from the start.
