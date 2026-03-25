import { expect, test } from "vitest";
import { ESLint } from "eslint";

test("ESLint should catch critical security vulnerabilities as errors", async () => {
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
    const { exec, spawn, spawnSync, execSync, execFile, execFileSync } = require('child_process');
    exec(process.argv[2]);
    spawn(process.argv[2]);
    spawnSync(process.argv[2]);
    execSync(process.argv[2]);
    execFile(process.argv[2]);
    execFileSync(process.argv[2]);

    // Trigger no-restricted-syntax (shell: true)
    spawn('ls', [], { shell: true });
    spawnSync('ls', { shell: true });
    exec('ls', { shell: true });
    execSync('ls', { shell: true });
    execFile('ls', [], { shell: true });
    execFileSync('ls', [], { shell: true });
    require('child_process').exec('ls', { shell: true });
    require('child_process').spawn('ls', [], { shell: true });

    // Trigger detect-object-injection
    const userKey = process.argv[2];
    const obj = {};
    console.log(obj[userKey]);

    // Trigger detect-non-literal-require
    require(process.argv[2]);

    // Trigger detect-pseudoRandomBytes
    const crypto = require('crypto');
    crypto.pseudoRandomBytes(10);

    // Trigger no-restricted-properties (Math.random)
    const insecureRandom = Math.random();
    console.log(insecureRandom);

    // Trigger detect-no-csrf-before-method-override
    express.csrf();
    express.methodOverride();

    // Trigger no-restricted-syntax (dynamic import)
    import(process.argv[2]);

    // Trigger no-restricted-syntax (insecure Buffer allocation)
    Buffer.allocUnsafe(10);
    Buffer.allocUnsafeSlow(10);
    const { allocUnsafe, allocUnsafeSlow } = Buffer;
    allocUnsafe(10);
    allocUnsafeSlow(10);

    // Trigger no-restricted-syntax (insecure vm module)
    const vm = require('vm');
    const nodeVm = require('node:vm');

    // Trigger no-restricted-syntax (deprecated crypto)
    crypto.createCipher('aes-128-cbc', 'password');
    crypto.createDecipher('aes-128-cbc', 'password');
    const { createCipher, createDecipher } = crypto;
    createCipher('aes-128-cbc', 'password');
    createDecipher('aes-128-cbc', 'password');

    // Trigger detect-disable-mustache-escape
    const obj2 = {};
    obj2.escapeMarkup = false;

    // Trigger detect-non-literal-fs-filename
    const fs = require('fs');
    fs.readFileSync(process.argv[2]);

    // Trigger detect-bidi-characters
    const bidi = '\u202E';

    // Trigger no-implied-eval
    setTimeout("console.log(1)", 100);

    // Trigger no-new-func
    const fn = new Function('console.log(1)');

    // Trigger no-unsafe-finally
    function unsafeFinally() {
      try {
        console.log('try');
      } finally {
        return;
      }
    }
    unsafeFinally();

    // Trigger no-unsafe-negation
    if (!'a' in {}) { console.log('negation'); }

    // Trigger no-restricted-syntax (import vm)
    // Note: To test ImportDeclaration, we'd normally need a separate file or a complex lint call,
    // but the require() and crypto triggers already cover the 'no-restricted-syntax' rule verification.

    // Trigger core security rules
    console.log(arguments.caller);
    const myProto = obj.__proto__;
  `;

  const results = await eslint.lintText(insecureCode, {
    filePath: "insecure-demo.js",
  });
  const messages = results[0].messages;

  const errorRules = messages
    .filter((m) => m.severity === 2)
    .map((m) => m.ruleId);

  // Verify core and promoted security rules are triggered as errors
  expect(errorRules).toContain("no-eval");
  expect(errorRules).toContain("security/detect-unsafe-regex");
  expect(errorRules).toContain("security/detect-eval-with-expression");
  expect(errorRules).toContain("security/detect-possible-timing-attacks");
  expect(errorRules).toContain("security/detect-non-literal-regexp");
  expect(errorRules).toContain("security/detect-buffer-noassert");
  expect(errorRules).toContain("security/detect-new-buffer");
  expect(errorRules).toContain("security/detect-child-process");
  expect(errorRules).toContain("security/detect-object-injection");
  expect(errorRules).toContain("security/detect-non-literal-require");
  expect(errorRules).toContain("security/detect-pseudoRandomBytes");
  expect(errorRules).toContain("no-restricted-properties");
  expect(errorRules).toContain(
    "security/detect-no-csrf-before-method-override",
  );
  expect(errorRules).toContain("no-restricted-syntax");
  expect(errorRules).toContain("security/detect-disable-mustache-escape");
  expect(errorRules).toContain("security/detect-non-literal-fs-filename");
  expect(errorRules).toContain("security/detect-bidi-characters");
  expect(errorRules).toContain("no-implied-eval");
  expect(errorRules).toContain("no-new-func");
  expect(errorRules).toContain("no-unsafe-finally");
  expect(errorRules).toContain("no-unsafe-negation");
  expect(errorRules).toContain("no-caller");
  expect(errorRules).toContain("no-proto");
});
