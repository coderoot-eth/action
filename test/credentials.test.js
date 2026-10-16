'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { runAction, ATTESTED, UNREACHABLE } = require('./helpers/run-action');

const FAKE = 'placeholder-not-a-credential-7f3a';

/**
 * The read-only modes. They warn; they do not stop. The endpoint is unreachable
 * only to keep these tests off the network, so fail-open is on: what is tested
 * here is the credential guard, not the degraded rule (see degraded.test.js).
 */
const verify = { CR_MODE: 'verify', CR_HASH: ATTESTED, CR_VERIFY_ENDPOINT: UNREACHABLE, CR_FAIL_OPEN: 'true' };

function dirWithNpmrc(content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-npmrc-'));
  fs.writeFileSync(path.join(dir, '.npmrc'), content);
  return dir;
}

/** A directory submit can run in: it reads package.json from here. */
function submitDir(npmrc) {
  const dir = dirWithNpmrc(npmrc);
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"x","version":"1.0.0"}');
  return dir;
}

const submit = { CR_MODE: 'submit', CR_FLOW: 'published', CR_SUBMIT_ENDPOINT: UNREACHABLE };

test('a registry credential stops submit', async (t) => {
  // submit reads an artifact and talks to the gate, so a token in scope is the
  // shape of a job that could publish. That is the case worth stopping.
  for (const name of ['NPM_TOKEN', 'NODE_AUTH_TOKEN', 'npm_config_//registry.npmjs.org/:_authToken', 'npm_config__auth']) {
    await t.test(`${name} in the environment`, () => {
      const run = runAction({ ...submit, [name]: FAKE }, submitDir('registry=https://registry.npmjs.org/\n'));
      assert.equal(run.code, 4);
      assert.ok(run.stderr.includes(name), 'the error names the variable');
      assert.ok(!run.stderr.includes(FAKE), 'the value is never printed');
    });
  }

  await t.test('an auth line in the project .npmrc', () => {
    const run = runAction(submit, submitDir('//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n'));
    assert.equal(run.code, 4);
    assert.match(run.stderr, /\.npmrc/);
  });

  await t.test('an auth line in the user .npmrc setup-node writes', () => {
    const dir = submitDir('registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}\n');
    const run = runAction({ ...submit, NPM_CONFIG_USERCONFIG: path.join(dir, '.npmrc') }, dir);
    assert.equal(run.code, 4);
  });

  await t.test('it refuses before building or uploading anything', () => {
    const dir = submitDir('_auth=dXNlcjpwYXNz\n');
    const run = runAction(submit, dir);
    assert.equal(run.code, 4);
    assert.equal(fs.readdirSync(dir).filter((f) => f.endsWith('.tgz')).length, 0, 'nothing was built');
  });

  await t.test('exit 4 is distinct from a usage error', () => {
    // A usage error is the operator holding it wrong; exit 4 is the job being
    // shaped wrongly. A pipeline that retries on 3 should not retry on 4.
    assert.equal(runAction(submit, submitDir('_auth=dXNlcjpwYXNz\n')).code, 4);
    const clean = submitDir('registry=https://registry.npmjs.org/\n');
    assert.equal(runAction({ CR_MODE: 'submit' }, clean).code, 3, 'no flow is a usage error');
  });
});

test('the read-only modes warn and carry on', async (t) => {
  // check and verify only read digests and query the verify endpoint. A token
  // in scope is untidy, not dangerous, and stopping would break pipelines that
  // publish in a later step of the same job.
  await t.test('verify warns', () => {
    const run = runAction({ ...verify, NPM_TOKEN: FAKE });
    assert.equal(run.code, 0, 'the run is not stopped');
    assert.match(run.stderr, /::warning::/);
    assert.ok(run.stderr.includes('NPM_TOKEN'), 'the warning names the variable');
    assert.ok(!run.stderr.includes(FAKE), 'the value is never printed');
  });

  await t.test('check warns', () => {
    const sbom = path.join(__dirname, 'fixtures', 'sample.cyclonedx.json');
    const run = runAction({
      CR_MODE: 'check',
      CR_SBOM: sbom,
      CR_VERIFY_ENDPOINT: UNREACHABLE,
      NODE_AUTH_TOKEN: FAKE,
    });
    assert.match(run.stderr, /::warning::/);
    assert.ok(run.stderr.includes('NODE_AUTH_TOKEN'));
  });

  await t.test('an auth line in .npmrc warns rather than stopping verify', () => {
    const run = runAction(verify, dirWithNpmrc('_auth=dXNlcjpwYXNz\n'));
    assert.equal(run.code, 0);
    assert.match(run.stderr, /::warning::/);
  });
});

test('what is not a credential', async (t) => {
  await t.test('an .npmrc without auth lines', () => {
    const run = runAction(verify, dirWithNpmrc('registry=https://registry.npmjs.org/\n# _authToken=placeholder\n; _auth=x\n'));
    assert.equal(run.code, 0);
    assert.ok(!run.stderr.includes('::warning::A registry credential'), 'no warning either');
  });

  await t.test('an empty NPM_TOKEN, as an unset secret expands', () => {
    const run = runAction({ ...verify, NPM_TOKEN: '' });
    assert.equal(run.code, 0);
    assert.ok(!run.stderr.includes('::warning::A registry credential'));
  });

  await t.test('submit runs normally with no credential in scope', () => {
    const dir = submitDir('registry=https://registry.npmjs.org/\n');
    // The gate is unreachable, so this fails for that reason, not exit 4.
    assert.notEqual(runAction(submit, dir).code, 4);
  });
});
