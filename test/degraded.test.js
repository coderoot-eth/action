'use strict';

// Release jobs fail, other jobs warn. An answer is
// degraded when verify was unreachable, or when it answered but could not read
// the gate's revocations. `verify` is the deploy-time check and defaults to
// failing; `check` reports on a build and defaults to warning.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { FAIL_OPEN_DEFAULT, verifyExit, checkExit, EXIT } = require('../src/main.js');
const { ATTESTED, UNREACHABLE, runAction, startServer } = require('./helpers/run-action');

const GATE_UNREAD_VERIFIED = 'sha256:' + '9'.repeat(64);
const GATE_UNREAD_UNREGISTERED = 'sha256:' + '8'.repeat(64);
const GATE_UNREAD_REVOKED = 'sha256:' + '7'.repeat(64);

test('fail-open defaults per mode: verify fails, check warns', () => {
  assert.deepEqual(FAIL_OPEN_DEFAULT, { check: true, verify: false });
  const degraded = { code: 4, verdict: 'verified', degraded: true };
  assert.equal(verifyExit(degraded, { failOn: 'unregistered', failOpen: FAIL_OPEN_DEFAULT.verify }), EXIT.ERROR);
  assert.equal(checkExit({ degraded: 1, verified: 1 }, { failOn: 'mismatch', failOpen: FAIL_OPEN_DEFAULT.check }), EXIT.CLEAN);
});

test('verify mode: verify answered but could not read the gate', async (t) => {
  const portFile = path.join(os.tmpdir(), `cr-degraded-port-${process.pid}`);
  const server = startServer(path.join(__dirname, 'helpers', 'degraded-mock.mjs'), [portFile], portFile);
  t.after(() => server.stop());
  const verify = (hash, extra = {}) =>
    runAction({ CR_MODE: 'verify', CR_HASH: hash, CR_VERIFY_ENDPOINT: server.url, ...extra });

  await t.test('a verified answer that is degraded fails the job by default, and says why', () => {
    const run = verify(GATE_UNREAD_VERIFIED);
    assert.equal(run.code, 3);
    assert.equal(run.outputs.verdict, 'verified');
    assert.equal(run.outputs.degraded, 'true');
    // The client's own code for "not fully checked"; the step exits 3 (README, exit-code row).
    assert.equal(run.outputs['exit-code'], '4');
    assert.match(run.summary, /Not fully checked: verify could not read the gate's revocations, so this release job fails/);
    assert.match(run.stderr, /::error::This could not be fully checked \(verify could not read the gate's revocations\)/);
  });

  await t.test('fail-open true lets it pass with a warning', () => {
    const run = verify(GATE_UNREAD_VERIFIED, { CR_FAIL_OPEN: 'true' });
    assert.equal(run.code, 0);
    assert.equal(run.outputs.degraded, 'true');
    assert.match(run.summary, /proceeds with a warning/);
    assert.match(run.stderr, /::warning::This could not be fully checked/);
  });

  await t.test('revoked still exits 1, and is not reported as an outage', () => {
    const run = verify(GATE_UNREAD_REVOKED);
    assert.equal(run.code, 1);
    assert.doesNotMatch(run.stderr, /::error::This could not be fully checked/);
  });

  await t.test('fail-on never still cannot pass a degraded answer by default', () => {
    // Softening applies to verdicts; "could not check" is not a verdict.
    assert.equal(verify(GATE_UNREAD_VERIFIED, { CR_FAIL_ON: 'never' }).code, 3);
  });

  await t.test('an unregistered answer that is degraded fails as degraded', () => {
    assert.equal(verify(GATE_UNREAD_UNREGISTERED).code, 3);
  });

  await t.test('a clean answer is unaffected', () => {
    const run = verify('sha256:' + 'b'.repeat(64));
    assert.equal(run.code, 0);
    assert.equal(run.outputs.degraded, 'false');
  });
});

test('verify mode: verify unreachable', async (t) => {
  await t.test('fails by default (exit 3), naming the outage', () => {
    const run = runAction({ CR_MODE: 'verify', CR_HASH: ATTESTED, CR_VERIFY_ENDPOINT: UNREACHABLE });
    assert.equal(run.code, 3);
    assert.equal(run.outputs.degraded, 'true');
    assert.match(run.summary, /Not fully checked: the verify endpoint was unreachable/);
  });

  await t.test('fail-open true keeps the old warn-and-proceed', () => {
    const run = runAction({
      CR_MODE: 'verify',
      CR_HASH: ATTESTED,
      CR_VERIFY_ENDPOINT: UNREACHABLE,
      CR_FAIL_OPEN: 'true',
    });
    assert.equal(run.code, 0);
    assert.equal(run.outputs.degraded, 'true');
  });
});

test('check mode: degraded components warn by default', async (t) => {
  const portFile = path.join(os.tmpdir(), `cr-degraded-check-port-${process.pid}`);
  const server = startServer(path.join(__dirname, 'helpers', 'degraded-mock.mjs'), [portFile], portFile);
  t.after(() => server.stop());

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-degraded-lock-'));

  // npm's own integrity is queried (an SBOM-declared hash never is). 64 bytes of
  // 0x99 is '9' x 128 in hex, which the mock answers verified but degraded; 64
  // bytes of 0x77 is '7' x 128, which it answers revoked.
  function lockfileWith(components) {
    const file = path.join(dir, `package-lock-${components.join('-')}.json`);
    const byte = { gated: 0x99, recalled: 0x77 };
    const packages = { '': { name: 'app' } };
    for (const name of components) {
      packages[`node_modules/${name}`] = {
        version: '1.0.0',
        resolved: `https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz`,
        integrity: `sha512-${Buffer.alloc(64, byte[name]).toString('base64')}`,
      };
    }
    fs.writeFileSync(file, JSON.stringify({ name: 'app', lockfileVersion: 3, packages }));
    return file;
  }
  const check = (components, extra = {}) =>
    runAction({
      CR_MODE: 'check',
      CR_LOCKFILE: lockfileWith(components),
      CR_VERIFY_ENDPOINT: server.url,
      CR_REPORT_PATH: path.join(dir, `report-${Math.random().toString(36).slice(2)}.json`),
      ...extra,
    });

  await t.test('passes with a warning', () => {
    const run = check(['gated']);
    assert.equal(run.code, 0);
    assert.equal(run.outputs.degraded, 'true');
    assert.match(run.summary, /could not be fully checked.*Warning only/);
    assert.match(run.stderr, /::warning::This could not be fully checked/);
  });

  await t.test('fail-open false makes it fail', () => {
    const run = check(['gated'], { CR_FAIL_OPEN: 'false' });
    assert.equal(run.code, 3);
    assert.match(run.summary, /`fail-open` is false, so this job fails/);
    assert.match(run.stderr, /::error::This could not be fully checked/);
  });

  await t.test('a revoked component fails the job without claiming it proceeds', () => {
    // Degraded components beside a revoked one: the job exits 1, so neither the
    // log nor the summary may say it is proceeding.
    for (const failOpen of ['true', 'false']) {
      const run = check(['gated', 'recalled'], { CR_FAIL_OPEN: failOpen });
      assert.equal(run.code, 1, `fail-open ${failOpen}`);
      assert.equal(run.outputs.degraded, 'true');
      assert.doesNotMatch(run.stderr, /proceeding because `fail-open` is true/, `fail-open ${failOpen}`);
      assert.doesNotMatch(run.summary, /Warning only/, `fail-open ${failOpen}`);
      assert.match(run.summary, /The job fails anyway, on the result above/, `fail-open ${failOpen}`);
    }
  });
});
