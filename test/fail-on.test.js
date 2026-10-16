'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { verifyExit, checkExit, FAIL_ON_DEFAULT } = require('../src/main.js');
const { runAction, ATTESTED, UNREACHABLE } = require('./helpers/run-action');

test('defaults', () => {
  assert.equal(FAIL_ON_DEFAULT.verify, 'unregistered');
  assert.equal(FAIL_ON_DEFAULT.check, 'mismatch');
});

test('verify: exit code by verdict and fail-on', async (t) => {
  // [verdict, unregistered, mismatch, revoked, never]
  const table = [
    ['verified', 0, 0, 0, 0],
    ['unregistered', 2, 0, 0, 0],
    ['attested-bytes-unproven', 2, 0, 0, 0],
    ['revoked', 1, 1, 1, 0],
  ];
  const failOns = ['unregistered', 'mismatch', 'revoked', 'never'];
  for (const [verdict, ...want] of table) {
    await t.test(verdict, () => {
      failOns.forEach((failOn, i) => {
        const code = verdict === 'revoked' ? 1 : verdict === 'verified' ? 0 : 2;
        assert.equal(
          verifyExit({ code, verdict, degraded: false }, { failOn, failOpen: true }),
          want[i],
          `fail-on ${failOn}`
        );
      });
    });
  }

  await t.test('a usage error fails whatever fail-on says', () => {
    assert.equal(verifyExit({ code: 3, verdict: 'verified' }, { failOn: 'never', failOpen: true }), 3);
  });
});

test('verify: fail-open', async (t) => {
  const degraded = { code: 0, verdict: 'attested-bytes-unproven', degraded: true };

  await t.test('an outage passes by default, even under the strictest fail-on', () => {
    assert.equal(verifyExit(degraded, { failOn: 'unregistered', failOpen: true }), 0);
  });

  await t.test('fail-open false fails an outage, even under fail-on never', () => {
    assert.equal(verifyExit(degraded, { failOn: 'never', failOpen: false }), 3);
  });

  await t.test('a cached revocation is not degraded, so fail-open cannot pass it', () => {
    const cached = { code: 1, verdict: 'revoked', degraded: false };
    assert.equal(verifyExit(cached, { failOn: 'unregistered', failOpen: true }), 1);
  });
});

test('check: exit code by summary and fail-on', async (t) => {
  const cases = [
    // [name, summary, unregistered, mismatch, revoked, never]
    ['all verified', { verified: 3 }, 0, 0, 0, 0],
    ['unverifiable by nature', { attestedBytesUnproven: 3 }, 0, 0, 0, 0],
    ['unregistered', { verified: 1, unregistered: 2 }, 2, 0, 0, 0],
    ['mismatch', { attestedBytesUnproven: 1, mismatch: 1 }, 2, 2, 0, 0],
    ['revoked', { revoked: 1, mismatch: 1, unregistered: 1 }, 1, 1, 1, 0],
  ];
  const failOns = ['unregistered', 'mismatch', 'revoked', 'never'];
  for (const [name, summary, ...want] of cases) {
    await t.test(name, () => {
      failOns.forEach((failOn, i) => {
        assert.equal(checkExit(summary, { failOn, failOpen: true }), want[i], `fail-on ${failOn}`);
      });
    });
  }

  await t.test('fail-open false fails a degraded run unless it is already revoked', () => {
    assert.equal(checkExit({ degraded: 1, attestedBytesUnproven: 1 }, { failOn: 'mismatch', failOpen: false }), 3);
    assert.equal(checkExit({ degraded: 1, revoked: 1 }, { failOn: 'mismatch', failOpen: false }), 1);
    assert.equal(checkExit({ degraded: 1 }, { failOn: 'mismatch', failOpen: true }), 0);
  });
});

test('an unknown fail-on is a usage error, before any request', () => {
  const run = runAction({ CR_MODE: 'verify', CR_HASH: ATTESTED, CR_FAIL_ON: 'revokd', CR_VERIFY_ENDPOINT: UNREACHABLE });
  assert.equal(run.code, 3);
  assert.match(run.stderr, /fail-on must be one of/);
  assert.equal(run.outputs.verdict, undefined);
});
