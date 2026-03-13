import { expect, test } from 'vitest';
import { ESLint } from 'eslint';

test('ESLint should catch critical security vulnerabilities as errors', async () => {
  const eslint = new ESLint();

  const insecureCode = `
    const target = 'user_input';
    eval(target);
    const unsafeRegex = / (a+)+ /;

    // Trigger detect-possible-timing-attacks
    if (password == 'secret') { console.log('match'); }

    // Trigger detect-non-literal-regexp
    const pattern = process.argv[2];
    const dynamicRe = new RegExp(pattern);
    console.log(dynamicRe);

    // Trigger detect-buffer-noassert
    const buf = Buffer.alloc(10);
    buf.writeUInt8(0x1, 0, true);

    // Trigger detect-new-buffer
    const oldBuf = new Buffer(process.argv[2]);
    console.log(oldBuf);
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
  expect(errorRules).toContain('security/detect-possible-timing-attacks');
  expect(errorRules).toContain('security/detect-non-literal-regexp');
  expect(errorRules).toContain('security/detect-buffer-noassert');
  expect(errorRules).toContain('security/detect-new-buffer');
});
