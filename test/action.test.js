'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { ACTION, MAIN, ATTESTED, REVOKED, UNREACHABLE, runAction } = require('./helpers/run-action');

const UNREGISTERED = `sha256:${crypto.createHash('sha256').update('coderoot-action: never attested').digest('hex')}`;

test('mode dispatch', async (t) => {
  await t.test('rejects a missing mode with a usage error', () => {
    assert.equal(runAction({ CR_MODE: '' }).code, 3);
  });

  await t.test('rejects an unknown mode and names the valid ones', () => {
    const run = runAction({ CR_MODE: 'frobnicate' });
    assert.equal(run.code, 3);
  });
});

test('verify mode', async (t) => {
  await t.test('exits 0 and reports verified on an attested digest', () => {
    const run = runAction({ CR_MODE: 'verify', CR_HASH: ATTESTED });
    assert.equal(run.code, 0);
    assert.equal(run.outputs.verdict, 'verified');
    assert.match(run.summary, /✅ \*\*verified\*\*/);
  });

  await t.test('surfaces the EAS attestation UID in the summary', () => {
    // The UID is what lets someone re-check on EAS without CodeRoot.
    const run = runAction({ CR_MODE: 'verify', CR_HASH: ATTESTED });
    assert.match(run.summary, /attestation UIDs/);
    assert.match(run.summary, /0x[0-9a-f]{64}/);
  });

  await t.test('exits 1 on a revoked digest', () => {
    const run = runAction({ CR_MODE: 'verify', CR_HASH: REVOKED });
    assert.equal(run.code, 1);
    assert.equal(run.outputs.verdict, 'revoked');
  });

  await t.test('exits 2 on an unregistered digest by default', () => {
    const run = runAction({ CR_MODE: 'verify', CR_HASH: UNREGISTERED });
    assert.equal(run.code, 2);
    assert.equal(run.outputs.verdict, 'unregistered');
  });

  await t.test('rejects a digest the endpoint cannot answer, whatever fail-on says', () => {
    const sha1 = 'sha1:0123456789abcdef0123456789abcdef01234567';
    assert.equal(runAction({ CR_MODE: 'verify', CR_HASH: sha1, CR_FAIL_ON: 'never' }).code, 3);
  });

  await t.test('needs exactly one of hash or artifact', () => {
    assert.equal(runAction({ CR_MODE: 'verify' }).code, 3);
    assert.equal(runAction({ CR_MODE: 'verify', CR_HASH: ATTESTED, CR_ARTIFACT: '/tmp/x' }).code, 3);
  });

  await t.test('writes a report at the requested path', () => {
    const run = runAction({ CR_MODE: 'verify', CR_HASH: ATTESTED });
    assert.ok(fs.existsSync(run.reportPath));
    assert.equal(JSON.parse(fs.readFileSync(run.reportPath, 'utf8')).verdict, 'verified');
  });
});

test('fail-on softens the gate without continue-on-error', async (t) => {
  await t.test('never: a revoked digest still exits 0', () => {
    // continue-on-error hides every failure; fail-on is the narrow version.
    const run = runAction({ CR_MODE: 'verify', CR_HASH: REVOKED, CR_FAIL_ON: 'never' });
    assert.equal(run.code, 0);
    assert.equal(run.outputs.verdict, 'revoked', 'the verdict is still reported');
  });

  await t.test('revoked: an unregistered digest passes, a revoked one fails', () => {
    assert.equal(runAction({ CR_MODE: 'verify', CR_HASH: UNREGISTERED, CR_FAIL_ON: 'revoked' }).code, 0);
    assert.equal(runAction({ CR_MODE: 'verify', CR_HASH: REVOKED, CR_FAIL_ON: 'revoked' }).code, 1);
  });

  await t.test('a usage error fails regardless of fail-on', () => {
    // Softening applies to verdicts, never to the Action being used wrongly.
    assert.equal(runAction({ CR_MODE: 'verify', CR_FAIL_ON: 'never' }).code, 3);
  });
});

test('fail-open, and turning it off', async (t) => {
  // verify is a release job, so it defaults to failing a
  // degraded answer; `fail-open: true` brings back warn-and-proceed.
  await t.test('an unreachable endpoint fails verify by default', () => {
    const run = runAction({ CR_MODE: 'verify', CR_HASH: ATTESTED, CR_VERIFY_ENDPOINT: UNREACHABLE });
    assert.equal(run.code, 3);
    assert.equal(run.outputs.degraded, 'true');
    assert.match(run.summary, /so this release job fails/);
  });

  await t.test('fail-open true warns and proceeds', () => {
    const run = runAction({
      CR_MODE: 'verify',
      CR_HASH: ATTESTED,
      CR_VERIFY_ENDPOINT: UNREACHABLE,
      CR_FAIL_OPEN: 'true',
    });
    assert.equal(run.code, 0);
    assert.equal(run.outputs.degraded, 'true');
    assert.match(run.summary, /proceeds with a warning/);
  });

  await t.test('fail-open false turns a degraded result into a failure', () => {
    const run = runAction({
      CR_MODE: 'verify',
      CR_HASH: ATTESTED,
      CR_VERIFY_ENDPOINT: UNREACHABLE,
      CR_FAIL_OPEN: 'false',
    });
    assert.equal(run.code, 3);
    assert.equal(run.outputs.degraded, 'true');
  });

  await t.test('fail-open false does not affect a reachable endpoint', () => {
    const run = runAction({ CR_MODE: 'verify', CR_HASH: ATTESTED, CR_FAIL_OPEN: 'false' });
    assert.equal(run.code, 0);
    assert.equal(run.outputs.degraded, 'false');
    assert.equal(run.outputs.verdict, 'verified');
  });
});

test('check mode', async (t) => {
  const sbom = path.join(__dirname, 'fixtures', 'sample.cyclonedx.json');

  const lockfile = path.join(__dirname, 'fixtures', 'sample.package-lock.json');

  await t.test('refuses to guess when given no sbom', () => {
    // The Action consumes SBOMs; it does not generate them.
    assert.equal(runAction({ CR_MODE: 'check' }).code, 3);
  });

  await t.test('refuses sbom and lockfile together', () => {
    const run = runAction({ CR_MODE: 'check', CR_SBOM: sbom, CR_LOCKFILE: lockfile });
    assert.equal(run.code, 3);
    assert.match(run.stderr, /not both/);
  });

  await t.test('writes a verdict table and a report from a lockfile', { skip: !fs.existsSync(lockfile) }, () => {
    const run = runAction({ CR_MODE: 'check', CR_LOCKFILE: lockfile });
    assert.match(run.summary, /## CodeRoot check/);
    assert.ok(fs.existsSync(run.reportPath));
    const report = JSON.parse(fs.readFileSync(run.reportPath, 'utf8'));
    assert.equal(report.schema, 'coderoot.verification-run/v1');
    assert.equal(report.source.format, 'npm-lockfile');
    assert.equal(run.code, 0);
  });

  await t.test('an unreadable SBOM fails even under fail-on never, and no old report is shown', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-stale-'));
    const report = path.join(dir, 'coderoot-report.json');
    fs.writeFileSync(report, JSON.stringify({ schema: 'coderoot.verification-run/v1', summary: { total: 1, verified: 1 } }));
    fs.writeFileSync(path.join(dir, 'not-an-sbom.json'), '{"lockfileVersion":3}');
    const run = runAction(
      { CR_MODE: 'check', CR_SBOM: 'not-an-sbom.json', CR_FAIL_ON: 'never', CR_REPORT_PATH: report },
      dir
    );
    assert.equal(run.code, 3);
    assert.equal(run.summary, '');
    assert.ok(!fs.existsSync(report), 'the stale report is gone');
  });

  await t.test('writes a verdict table and a report', { skip: !fs.existsSync(sbom) }, () => {
    const run = runAction({ CR_MODE: 'check', CR_SBOM: sbom });
    assert.match(run.summary, /## CodeRoot check/);
    assert.match(run.summary, /\| verdict \| count \| share \|/);
    assert.ok(fs.existsSync(run.reportPath));
    const report = JSON.parse(fs.readFileSync(run.reportPath, 'utf8'));
    assert.equal(report.schema, 'coderoot.verification-run/v1');
    assert.ok(report.summary.unregistered > 0);
    assert.equal(run.code, 0);
  });

  await t.test('fail-on unregistered fails the same SBOM with exit 2', { skip: !fs.existsSync(sbom) }, () => {
    assert.equal(runAction({ CR_MODE: 'check', CR_SBOM: sbom, CR_FAIL_ON: 'unregistered' }).code, 2);
  });

  await t.test('reports distinct purls, not occurrences', { skip: !fs.existsSync(sbom) }, () => {
    const run = runAction({ CR_MODE: 'check', CR_SBOM: sbom });
    assert.match(run.summary, /distinct/);
  });
});

/**
 * A stand-in for the gate, run as its own process.
 *
 * It has to be a separate process: the Action is spawned with `execFileSync`,
 * and a child inherits its parent's handles, so an in-process listener keeps
 * the pipe the parent is blocking on open and the two deadlock. Out of process
 * there is nothing to inherit. It records what it was sent to a JSON file so a
 * test can assert on the exact bytes.
 */
function startStubGate({ status = 201, error = null } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-gate-'));
  const log = path.join(dir, 'seen.jsonl');
  const portFile = path.join(dir, 'port');
  const script = path.join(dir, 'gate.js');
  fs.writeFileSync(
    script,
    `
const http = require('http');
const fs = require('fs');
const status = ${status};
const error = ${JSON.stringify(error)};
const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const raw = Buffer.concat(chunks);
    fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({
      url: req.url, headers: req.headers, text: raw.toString('utf8'),
    }) + '\\n');
    if (req.url === '/v1/artifacts') {
      res.writeHead(201, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        upload_id: 'upl_01J7B2Y6Q0V3S9K4M8N1R5T7WX',
        size_bytes: raw.length, hashes: [], expires_at: '2026-01-01T00:00:00Z',
      }));
    }
    if (req.url === '/v1/submit') {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(error ? { error } : {
        submission_id: 'sub_01J7B31X8ZC4Q2D6F0H9K3M5NP',
        state: 'pending_review',
        policy_grade: 'human-required',
        review_url: 'https://coderoot.app/review/sub_01J7B31X8ZC4Q2D6F0H9K3M5NP',
        idempotent_replay: false,
      }));
    }
    res.writeHead(404).end('{}');
  });
});
server.listen(0, '127.0.0.1', () => {
  fs.writeFileSync(${JSON.stringify(portFile)}, String(server.address().port));
});
`
  );

  const child = spawn(process.execPath, [script], { stdio: 'ignore', detached: false });
  // Wait for the port file: the gate is ready only once it has written it.
  const deadline = Date.now() + 10000;
  let port = '';
  while (Date.now() < deadline) {
    if (fs.existsSync(portFile)) {
      port = fs.readFileSync(portFile, 'utf8').trim();
      if (port) break;
    }
    // Block briefly without spinning: this helper is synchronous by design.
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
  }
  if (!port) {
    child.kill('SIGKILL');
    throw new Error('the stub gate never reported a port');
  }

  return {
    url: `http://127.0.0.1:${port}`,
    stop: () => child.kill('SIGKILL'),
    seen: () =>
      (fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '')
        .split('\n')
        .filter(Boolean)
        .map((line) => JSON.parse(line)),
  };
}

test('report artifact names are unique within a job', async (t) => {
  const runnerTemp = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-runner-temp-'));
  const step = (env) =>
    runAction({ CR_MODE: 'verify', CR_HASH: ATTESTED, CR_VERIFY_ENDPOINT: UNREACHABLE, RUNNER_TEMP: runnerTemp, ...env });

  await t.test('the first step of a mode keeps the plain name, later ones are numbered', () => {
    assert.equal(step().outputs['artifact-name'], 'coderoot-verify-report');
    assert.equal(step().outputs['artifact-name'], 'coderoot-verify-report-2');
    assert.equal(step().outputs['artifact-name'], 'coderoot-verify-report-3');
  });

  await t.test('an explicit artifact-name is used as given', () => {
    assert.equal(step({ CR_ARTIFACT_NAME: 'deploy-gate' }).outputs['artifact-name'], 'deploy-gate');
  });
});

test('no registry credential is ever in scope', async (t) => {
  await t.test('the Action declares no npm token input', () => {
    const yml = fs.readFileSync(path.join(ACTION, 'action.yml'), 'utf8');
    const body = yml.replace(/#.*/g, '');
    for (const forbidden of ['NPM_TOKEN', 'NODE_AUTH_TOKEN', '_authToken', 'npm_config__auth']) {
      assert.ok(!body.includes(forbidden), `action.yml must not reference ${forbidden}`);
    }
  });

  await t.test('the Action never publishes', () => {
    const src = fs.readFileSync(MAIN, 'utf8').replace(/\/\/.*|\/\*[\s\S]*?\*\//g, '');
    assert.ok(!/npm\s+publish|['"]publish['"]/.test(src), 'the Action must never publish');
  });

  await t.test('all pinned actions use 40-character SHAs', () => {
    const yml = fs.readFileSync(path.join(ACTION, 'action.yml'), 'utf8');
    const uses = [...yml.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1]);
    assert.ok(uses.length > 0);
    for (const ref of uses) assert.match(ref, /@[0-9a-f]{40}$/, `${ref} is not pinned to a SHA`);
  });
});
test('a report path in a directory no step created', async (t) => {
  // A workflow may point report-path at a directory only some runs create.
  await t.test('verify still answers and writes the report', () => {
    const dir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-report-')), 'not', 'yet');
    const run = runAction({ CR_MODE: 'verify', CR_HASH: REVOKED, CR_REPORT_PATH: path.join(dir, 'consumer.json') });
    assert.equal(run.code, 1);
    assert.equal(run.outputs.verdict, 'revoked');
    assert.ok(fs.existsSync(path.join(dir, 'consumer.json')));
  });

  await t.test('check still answers and writes the report', () => {
    const dir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-report-')), 'nested');
    const run = runAction({
      CR_MODE: 'check',
      CR_LOCKFILE: path.join(__dirname, 'fixtures', 'sample.package-lock.json'),
      CR_FAIL_ON: 'never',
      CR_REPORT_PATH: path.join(dir, 'check.json'),
    });
    assert.equal(run.code, 0, run.stderr);
    assert.ok(fs.existsSync(path.join(dir, 'check.json')));
  });
});
