'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { runAction, ATTESTED, REVOKED, UNREACHABLE } = require('./helpers/run-action');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cr-cache-'));
}

function seed(file, digests) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(
    file,
    JSON.stringify({
      schema: 'coderoot.revoked-cache/v1',
      entries: digests.map((digest) => ({ digest, seenAt: '2026-09-20T00:00:00.000Z' })),
    })
  );
}

function cachedDigests(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8')).entries.map((entry) => entry.digest);
}

const outage = { CR_MODE: 'verify', CR_VERIFY_ENDPOINT: UNREACHABLE };

test('a digest seen revoked fails during an outage', async (t) => {
  await t.test('from the working cache, whatever fail-open says', () => {
    const cache = path.join(tmpDir(), 'revoked-cache.json');
    seed(cache, [REVOKED]);
    for (const failOpen of ['true', 'false']) {
      const run = runAction({ ...outage, CR_HASH: REVOKED, CR_FAIL_OPEN: failOpen, CODEROOT_REVOKED_CACHE: cache });
      assert.equal(run.code, 1, `fail-open ${failOpen}`);
      assert.equal(run.outputs.verdict, 'revoked');
      assert.equal(run.outputs.degraded, 'false');
    }
  });

  await t.test('from a cache restored in a new job', () => {
    const dir = tmpDir();
    seed(path.join(dir, 'revoked-cache.json'), [REVOKED]);
    const run = runAction({ ...outage, CR_HASH: REVOKED, CR_REVOKED_CACHE_DIR: dir });
    assert.equal(run.code, 1);
  });

  await t.test('an unknown digest is degraded: verify fails by default, fail-open true lets it through', () => {
    const dir = tmpDir();
    seed(path.join(dir, 'revoked-cache.json'), [REVOKED]);
    const run = runAction({ ...outage, CR_HASH: ATTESTED, CR_REVOKED_CACHE_DIR: dir });
    assert.equal(run.code, 3);
    assert.equal(run.outputs.degraded, 'true');
    const open = runAction({ ...outage, CR_HASH: ATTESTED, CR_REVOKED_CACHE_DIR: dir, CR_FAIL_OPEN: 'true' });
    assert.equal(open.code, 0);
  });

  await t.test('a malformed restored cache is ignored, not fatal', () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, 'revoked-cache.json'), 'not json');
    // fail-open on, so exit 3 here could only mean the bad cache was fatal.
    assert.equal(runAction({ ...outage, CR_HASH: ATTESTED, CR_REVOKED_CACHE_DIR: dir, CR_FAIL_OPEN: 'true' }).code, 0);
  });
});

test('what a run hands back for saving', async (t) => {
  const dir = tmpDir();
  const working = path.join(tmpDir(), 'revoked-cache.json');
  const first = runAction({ CR_MODE: 'verify', CR_HASH: REVOKED, CR_REVOKED_CACHE_DIR: dir, CODEROOT_REVOKED_CACHE: working });

  await t.test('a live revocation grows the cache and names a key', () => {
    assert.equal(first.code, 1);
    assert.equal(first.outputs['revoked-cache-changed'], 'true');
    assert.match(first.outputs['revoked-cache-key'], /^coderoot-revoked-[0-9a-f]{32}$/);
    assert.deepEqual(cachedDigests(path.join(dir, 'revoked-cache.json')), [REVOKED]);
  });

  await t.test('the next job restores it and fails during an outage', () => {
    const run = runAction({ ...outage, CR_HASH: REVOKED, CR_REVOKED_CACHE_DIR: dir });
    assert.equal(run.code, 1);
    assert.equal(run.outputs['revoked-cache-changed'], 'false');
  });

  await t.test('an earlier step in the same job is not lost to a stale restore', () => {
    const stale = tmpDir();
    seed(path.join(stale, 'revoked-cache.json'), []);
    const run = runAction({ ...outage, CR_HASH: REVOKED, CR_REVOKED_CACHE_DIR: stale, CODEROOT_REVOKED_CACHE: working });
    assert.equal(run.code, 1);
    assert.equal(run.outputs['revoked-cache-changed'], 'true', 'saved again, since the restore lacked it');
    assert.equal(run.outputs['revoked-cache-key'], first.outputs['revoked-cache-key'], 'same set, same key');
  });
});
