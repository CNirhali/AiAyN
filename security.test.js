import { expect, test } from 'vitest';
import { ESLint } from 'eslint';

test('ESLint should catch critical security vulnerabilities as errors', async () => {
  const eslint = new ESLint();

  const insecureCode = `
    const target = 'user_input';
    eval(target);
    const unsafeRegex = / (a+)+ /;
  `;

  const results = await eslint.lintText(insecureCode, { filePath: 'insecure-demo.js' });
  const messages = results[0].messages;

  const errorRules = messages
    .filter(m => m.severity === 2)
    .map(m => m.ruleId);

  // Verify core and promoted security rules are triggered as errors
  expect(errorRules).toContain('no-eval');
  expect(errorRules).toContain('security/detect-unsafe-regex');
  expect(errorRules).toContain('security/detect-eval-with-expression');
});
