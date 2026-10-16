'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { verifyExit, checkExit } = require('../src/main.js');
const { runAction, startServer } = require('./helpers/run-action');

test('verifyExit: authorCpoaRevoked refuses regardless of fail-on/fail-open', async (t) => {
  const base = { code: 0, verdict: 'verified', degraded: false };

  await t.test('true fails even under fail-on never', () => {
    assert.equal(
      verifyExit({ ...base, authorCpoaRevoked: true }, { failOn: 'never', failOpen: true }),
      2
    );
  });

  await t.test('null (chain unreadable) fails the same as true', () => {
    assert.equal(
      verifyExit({ ...base, authorCpoaRevoked: null }, { failOn: 'never', failOpen: true }),
      2
    );
  });

  await t.test('false does not change the ordinary verified result', () => {
    assert.equal(
      verifyExit({ ...base, authorCpoaRevoked: false }, { failOn: 'never', failOpen: true }),
      0
    );
  });

  await t.test('undefined behaves like false', () => {
    assert.equal(verifyExit(base, { failOn: 'never', failOpen: true }), 0);
  });

  await t.test('a usage error still outranks it', () => {
    assert.equal(
      verifyExit({ code: 3, verdict: 'verified', authorCpoaRevoked: true }, { failOn: 'never', failOpen: true }),
      3
    );
  });

  await t.test('a revoked digest still outranks it', () => {
    assert.equal(
      verifyExit(
        { code: 1, verdict: 'revoked', authorCpoaRevoked: true },
        { failOn: 'revoked', failOpen: true }
      ),
      1
    );
  });
});

test('checkExit: authorCpoaRevoked never fails check', () => {
  const summary = { verified: 2, authorCpoaRevoked: 2 };
  assert.equal(checkExit(summary, { failOn: 'unregistered', failOpen: true }), 0);
});

test('verify mode end to end: a live authorCpoaRevoked response fails the job', async (t) => {
  const portFile = path.join(require('os').tmpdir(), `cr-cpoa-port-${process.pid}`);
  const server = startServer(path.join(__dirname, 'helpers', 'author-cpoa-mock.mjs'), [portFile], portFile);

  t.after(() => server.stop());

  await t.test('authorCpoaRevoked: true fails verify, names the UID, ignores fail-on: never', () => {
    const run = runAction({
      CR_MODE: 'verify',
      CR_HASH: 'sha256:' + 'c'.repeat(64),
      CR_VERIFY_ENDPOINT: server.url,
      CR_FAIL_ON: 'never',
    });
    assert.equal(run.code, 2);
    assert.equal(run.outputs['author-cpoa-revoked'], 'true');
    assert.match(run.summary, /authoring agent's CPoA is revoked/);
    assert.match(run.summary, /0xe1{64}|cpoa/i);
  });

  await t.test('authorCpoaRevoked: null fails verify the same way', () => {
    const run = runAction({
      CR_MODE: 'verify',
      CR_HASH: 'sha256:' + 'd'.repeat(64),
      CR_VERIFY_ENDPOINT: server.url,
      CR_FAIL_ON: 'never',
    });
    assert.equal(run.code, 2);
    assert.equal(run.outputs['author-cpoa-revoked'], 'null');
    assert.match(run.summary, /CPoA is unreadable/);
  });

  await t.test('authorCpoaRevoked: false passes verify normally', () => {
    const run = runAction({
      CR_MODE: 'verify',
      CR_HASH: 'sha256:' + 'a'.repeat(64),
      CR_VERIFY_ENDPOINT: server.url,
    });
    assert.equal(run.code, 0);
    assert.equal(run.outputs['author-cpoa-revoked'], 'false');
  });
});
