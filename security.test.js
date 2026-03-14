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

    // Trigger detect-child-process
    const { exec } = require('child_process');
    exec(process.argv[2]);

    // Trigger detect-object-injection
    const userKey = process.argv[2];
    const obj = {};
    console.log(obj[userKey]);

    // Trigger detect-non-literal-require
    require(process.argv[2]);

    // Trigger detect-pseudoRandomBytes
    const crypto = require('crypto');
    crypto.pseudoRandomBytes(10);

    // Trigger detect-no-csrf-before-method-override
    express.csrf();
    express.methodOverride();

    // Trigger detect-disable-mustache-escape
    const obj2 = {};
    obj2.escapeMarkup = false;

    // Trigger core security rules
    console.log(arguments.caller);
    const myProto = obj.__proto__;
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
  expect(errorRules).toContain('security/detect-child-process');
  expect(errorRules).toContain('security/detect-object-injection');
  expect(errorRules).toContain('security/detect-non-literal-require');
  expect(errorRules).toContain('security/detect-pseudoRandomBytes');
  expect(errorRules).toContain('security/detect-no-csrf-before-method-override');
  expect(errorRules).toContain('security/detect-disable-mustache-escape');
  expect(errorRules).toContain('no-caller');
  expect(errorRules).toContain('no-proto');
});
