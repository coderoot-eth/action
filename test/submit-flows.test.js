'use strict';

// submit for a release the publisher put on npm themselves: flow `published`
// (checked against npm's dist.integrity) and flow `staged` (the npm stage id
// and the provenance bundle, uploaded and bound by hash). Flows sign in with
// the job's GitHub identity token only; the gate-publish path keeps `token`.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { runAction, startServer } = require('./helpers/run-action');
const { hexToIntegrity, idempotencyKeyFor, multipartFile } = require('../src/main.js');

const NAME = '@vitrotech/gate-spike-b';
const STAGE_ID = '65e9ba3c-7a59-4ac1-823e-e51c0b4fadcc';
const REQUEST_TOKEN = 'request-token-for-tests';
// The real @vitrotech/gate-spike-b@0.0.3 and the provenance bundle npm attached when it was staged.
const TARBALL = path.join(__dirname, 'fixtures', 'vitrotech-gate-spike-b-0.0.3.tgz');
const BUNDLE = path.join(__dirname, 'fixtures', 'gate-spike-b-0.0.3.provenance.sigstore.json');

function startRecordingMock() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-mock-'));
  const portFile = path.join(dir, 'port');
  const log = path.join(dir, 'seen.jsonl');
  const server = startServer(path.join(__dirname, 'helpers', 'recording-mock.mjs'), [portFile, log], portFile);
  const seen = (url) =>
    (fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '')
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line))
      .filter((entry) => entry.url === url);
  return { ...server, uploads: () => seen('/v1/artifacts'), submits: () => seen('/v1/submit') };
}

function startFakes(config) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-fakes-'));
  const portFile = path.join(dir, 'port');
  const configFile = path.join(dir, 'config.json');
  const log = path.join(dir, 'seen.jsonl');
  fs.writeFileSync(configFile, JSON.stringify({ requestToken: REQUEST_TOKEN, versions: {}, ...config }));
  const server = startServer(path.join(__dirname, 'helpers', 'fake-npm-oidc.mjs'), [portFile, configFile, log], portFile);
  const seen = () =>
    (fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  return { ...server, seen };
}

/** A tarball stand-in in its own directory, and its npm integrity string. */
function artifact(version, from) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-flow-'));
  const file = path.join(dir, `vitrotech-gate-spike-b-${version}.tgz`);
  if (from) fs.copyFileSync(from, file);
  else fs.writeFileSync(file, crypto.randomBytes(512));
  const sha512 = `sha512:${crypto.createHash('sha512').update(fs.readFileSync(file)).digest('hex')}`;
  return { dir, file, integrity: hexToIntegrity(sha512) };
}

const github = {
  GITHUB_SERVER_URL: 'https://github.com',
  GITHUB_REPOSITORY: 'VitroTech/coderoot-gate-spike',
  GITHUB_SHA: 'aeea3b8ea956744a260b41dd7b4e2fd41f8e8efe',
  GITHUB_RUN_ID: '38337064742',
};

function env(mock, fakes, extra) {
  return {
    CR_MODE: 'submit',
    CR_SUBMIT_ENDPOINT: mock.url,
    CR_REGISTRY: `${fakes.url}/registry`,
    CR_REGISTRY_POLL_MS: '100',
    ACTIONS_ID_TOKEN_REQUEST_URL: `${fakes.url}/oidc?api-version=2.0`,
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: REQUEST_TOKEN,
    ...github,
    ...extra,
  };
}

function stagedEnv(art, extra = {}) {
  return { CR_FLOW: 'staged', CR_STAGE_ID: STAGE_ID, CR_ARTIFACT: art.file, CR_PROVENANCE_BUNDLE: BUNDLE, CR_NAME: NAME, CR_VERSION: '0.0.3', ...extra };
}

const lastBody = (mock) => JSON.parse(Buffer.from(mock.submits().at(-1).body, 'base64').toString('utf8'));

function withServers(t, config = {}) {
  const mock = startRecordingMock();
  const fakes = startFakes(config);
  t.after(() => {
    mock.stop();
    fakes.stop();
  });
  return { mock, fakes };
}

test('flow published: waits for npm, matches dist.integrity, signs in with the identity token', async (t) => {
  const art = artifact('1.0.0');
  const { mock, fakes } = withServers(t, { versions: { [`${NAME}@1.0.0`]: { integrity: art.integrity, visibleAfterMs: 300 } } });

  const run = runAction(env(mock, fakes, { CR_FLOW: 'published', CR_ARTIFACT: art.file, CR_NAME: NAME, CR_VERSION: '1.0.0' }), art.dir);
  assert.equal(run.code, 0, run.stderr);

  const registryReads = fakes.seen().filter((r) => r.path.startsWith('/registry/'));
  assert.ok(registryReads.length >= 2, 'a 404 from a new version is retried, not fatal');
  assert.equal(fakes.seen().find((r) => r.path === '/oidc').query.includes('audience=secure.coderoot.app'), true);

  const submit = mock.submits().at(-1);
  assert.equal(submit.status, 201, submit.response);
  assert.match(submit.headers.authorization, /^Bearer eyJ/);
  const body = lastBody(mock);
  assert.equal(body.flow, 'published');
  assert.equal('stage_id' in body, false);
  assert.equal('provenance' in body, false);
  assert.deepEqual(Object.keys(body).slice(2, 4), ['coordinates', 'flow']);

  assert.match(run.outputs['review-url'], /^https:\/\/coderoot\.app\/review\/detail\?id=sub_/);
  assert.equal(run.outputs['flow'], 'published');
  assert.match(run.summary, /GitHub identity token/);
  assert.match(run.summary, /\*\*Queue:\*\* https:\/\/coderoot\.app\/review/);
});

test('flow published: an artifact that is not what npm serves is refused locally, exit 2, nothing submitted', async (t) => {
  const art = artifact('1.0.1');
  const other = artifact('1.0.1');
  const { mock, fakes } = withServers(t, { versions: { [`${NAME}@1.0.1`]: { integrity: other.integrity } } });

  const run = runAction(env(mock, fakes, { CR_FLOW: 'published', CR_ARTIFACT: art.file, CR_NAME: NAME, CR_VERSION: '1.0.1' }), art.dir);
  assert.equal(run.code, 2, run.stderr);
  assert.equal(mock.uploads().length, 0);
  assert.equal(mock.submits().length, 0);
  assert.match(run.summary, /not what npm serves/);
});

test('flow published: a version npm never shows fails after registry-wait, exit 3', async (t) => {
  const art = artifact('1.0.2');
  const { mock, fakes } = withServers(t);
  const run = runAction(
    env(mock, fakes, { CR_FLOW: 'published', CR_ARTIFACT: art.file, CR_NAME: NAME, CR_VERSION: '1.0.2', CR_REGISTRY_WAIT: '1' }),
    art.dir
  );
  assert.equal(run.code, 3);
  assert.match(run.stderr, /not visible on npm after 1s/);
  assert.equal(mock.submits().length, 0);
});

test('flow staged: uploads the tarball and its provenance bundle, and names the bundle by hash', async (t) => {
  const art = artifact('0.0.3', TARBALL);
  const { mock, fakes } = withServers(t);
  const npmOutput = path.join(art.dir, 'stage.log');
  fs.writeFileSync(npmOutput, `npm notice stage package ${NAME}@0.0.3 has been staged with tag latest\n+ ${NAME}@0.0.3 (staged with id ${STAGE_ID})\n`);

  const run = runAction(env(mock, fakes, stagedEnv(art, { CR_STAGE_ID: '', CR_NPM_OUTPUT: npmOutput })), art.dir);
  assert.equal(run.code, 0, run.stderr);

  assert.equal(mock.uploads().length, 2, 'the tarball and the bundle');
  assert.equal(mock.submits().at(-1).status, 201, mock.submits().at(-1).response);
  const body = lastBody(mock);
  const bundleSha = `sha256:${crypto.createHash('sha256').update(fs.readFileSync(BUNDLE)).digest('hex')}`;
  assert.equal(body.flow, 'staged');
  assert.equal(body.stage_id, STAGE_ID);
  assert.equal(body.provenance.sha256, bundleSha);
  assert.match(body.provenance.upload_id, /^upl_/);
  assert.deepEqual(Object.keys(body).slice(2, 6), ['coordinates', 'flow', 'stage_id', 'provenance']);
  assert.equal(fakes.seen().filter((r) => r.path.startsWith('/registry/')).length, 0, 'npm hides staged versions; no registry read');
  assert.match(run.summary, new RegExp(`npm stage approve ${STAGE_ID}`));
});

test('flow staged: no bundle is a usage error, and a bundle for other bytes is refused locally; nothing is uploaded', async (t) => {
  const { mock, fakes } = withServers(t);
  const real = artifact('0.0.3', TARBALL);
  const missing = runAction(env(mock, fakes, stagedEnv(real, { CR_PROVENANCE_BUNDLE: '' })), real.dir);
  assert.equal(missing.code, 3);
  assert.match(missing.stderr, /needs `provenance-bundle`/);

  const other = artifact('0.0.3');
  const wrong = runAction(env(mock, fakes, stagedEnv(other)), other.dir);
  assert.equal(wrong.code, 2, wrong.stderr);
  assert.match(wrong.summary, /not for this artifact/);

  const otherVersion = runAction(env(mock, fakes, stagedEnv(real, { CR_VERSION: '0.0.4' })), real.dir);
  assert.equal(otherVersion.code, 2, otherVersion.stderr);

  assert.equal(mock.uploads().length, 0);
});

test('flow usage errors exit 3 before anything is sent', async (t) => {
  const art = artifact('1.2.0');
  const { mock, fakes } = withServers(t);
  const cases = [
    [{ CR_FLOW: 'staged', CR_ARTIFACT: art.file }, /needs `stage-id`/],
    [{ CR_FLOW: 'staged', CR_ARTIFACT: art.file, CR_STAGE_ID: 'not-a-uuid' }, /must be a UUID/],
    [{ CR_FLOW: 'published', CR_ARTIFACT: art.file, CR_STAGE_ID: STAGE_ID }, /flow `staged` only/],
    [{ CR_FLOW: 'gate', CR_ARTIFACT: art.file }, /flow must be one of/],
    [{ CR_FLOW: 'published' }, /Pack once/],
  ];
  for (const [extra, message] of cases) {
    const run = runAction(env(mock, fakes, { CR_NAME: NAME, CR_VERSION: '1.2.0', ...extra }), art.dir);
    assert.equal(run.code, 3, JSON.stringify(extra));
    assert.match(run.stderr, message);
  }
  assert.equal(mock.uploads().length, 0);
});

test('submit signs in only with the identity token: without one the job fails before any upload', async (t) => {
  const art = artifact('0.0.3', TARBALL);
  const { mock, fakes } = withServers(t, { oidcStatus: 403 });

  const refused = runAction(env(mock, fakes, stagedEnv(art)), art.dir);
  assert.equal(refused.code, 3);
  assert.match(refused.stderr, /Could not get a GitHub identity token/);

  const cannotMint = runAction(
    { CR_MODE: 'submit', CR_SUBMIT_ENDPOINT: mock.url, ...stagedEnv(art), ...github },
    art.dir
  );
  assert.equal(cannotMint.code, 3);
  assert.match(cannotMint.stderr, /cannot mint one/);

  assert.equal(mock.uploads().length, 0);
});

test('a gate refusal shows its named reason in the job summary', async (t) => {
  const art = artifact('0.0.3', TARBALL);
  const { mock, fakes } = withServers(t);
  assert.equal(runAction(env(mock, fakes, stagedEnv(art)), art.dir).code, 0);
  const again = runAction(env(mock, fakes, stagedEnv(art, { CR_NOTE: 'second' })), art.dir);
  assert.equal(again.code, 3);
  assert.match(again.summary, /Submission refused/);
  assert.match(again.summary, /package_identity_pending/);
});

test('a repository, workflow or package outside the workspace link is refused by name', async (t) => {
  const other = '@vitrotech/not-linked';
  const art = artifact('1.0.2');
  const { mock, fakes } = withServers(t, { versions: { [`${other}@1.0.2`]: { integrity: art.integrity } } });
  const run = runAction(env(mock, fakes, { CR_FLOW: 'published', CR_ARTIFACT: art.file, CR_NAME: other, CR_VERSION: '1.0.2' }), art.dir);
  assert.equal(run.code, 3);
  assert.match(run.summary, /repository_not_authorized/);
});

test('submit needs a flow: there is no other path', async (t) => {
  const art = artifact('1.0.3');
  const { mock, fakes } = withServers(t);
  const run = runAction(env(mock, fakes, { CR_ARTIFACT: art.file, CR_NAME: NAME, CR_VERSION: '1.0.3' }), art.dir);
  assert.equal(run.code, 3);
  assert.match(run.stderr, /submit needs `flow`/);
  assert.equal(mock.uploads().length, 0);
});

test('the submitted body: key set and order, both digests, source from the GitHub context', async (t) => {
  const art = artifact('1.0.4');
  const { mock, fakes } = withServers(t, { versions: { [`${NAME}@1.0.4`]: { integrity: art.integrity } } });
  const run = runAction(env(mock, fakes, { CR_FLOW: 'published', CR_ARTIFACT: art.file, CR_NAME: NAME, CR_VERSION: '1.0.4' }), art.dir);
  assert.equal(run.code, 0);

  const sent = mock.submits().at(-1);
  const raw = Buffer.from(sent.body, 'base64').toString('utf8');
  const body = JSON.parse(raw);
  assert.deepEqual(Object.keys(body), ['artifact', 'hashes', 'coordinates', 'flow', 'source', 'signatures', 'evidence', 'agent', 'submitter_note']);
  assert.equal(raw, JSON.stringify(body, null, 2), 'two-space indent, no trailing newline');
  assert.equal(body.artifact.upload_id, mock.uploads().at(-1) && JSON.parse(mock.uploads().at(-1).response).upload_id, 'the upload comes first');
  assert.match(body.hashes[0], /^sha256:[0-9a-f]{64}$/);
  assert.match(body.hashes[1], /^sha512:[0-9a-f]{128}$/);
  assert.deepEqual(body.coordinates, { registry: 'npm', name: NAME, version: '1.0.4' });
  assert.deepEqual(body.source, {
    repo: 'https://github.com/VitroTech/coderoot-gate-spike',
    commit: github.GITHUB_SHA,
    build_system: 'github-actions',
    build_uri: `https://github.com/VitroTech/coderoot-gate-spike/actions/runs/${github.GITHUB_RUN_ID}`,
  });
  assert.deepEqual([body.signatures, body.evidence, body.agent], [[], [], null]);

  assert.match(sent.headers['idempotency-key'], /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(sent.headers['idempotency-key'], idempotencyKeyFor(raw));
  assert.match(sent.headers.authorization, /^Bearer [^.]+\.[^.]+\.[^.]+$/, 'the identity token, never a stored secret');

  assert.match(run.outputs['submission-id'], /^sub_/);
  assert.match(run.outputs['review-url'], /coderoot\.app\/review\//);
});

test('submit refuses to guess the source when the GitHub context is absent', async (t) => {
  const art = artifact('1.0.5');
  const { mock, fakes } = withServers(t, { versions: { [`${NAME}@1.0.5`]: { integrity: art.integrity } } });
  const run = runAction(
    env(mock, fakes, { CR_FLOW: 'published', CR_ARTIFACT: art.file, CR_NAME: NAME, CR_VERSION: '1.0.5', GITHUB_SERVER_URL: '', GITHUB_REPOSITORY: '', GITHUB_SHA: '', GITHUB_RUN_ID: '' }),
    art.dir
  );
  assert.equal(run.code, 3);
  assert.equal(mock.submits().length, 0);
});

test('submit has no fail-open: an unreachable gate fails the job', async (t) => {
  const art = artifact('1.0.6');
  const { mock, fakes } = withServers(t, { versions: { [`${NAME}@1.0.6`]: { integrity: art.integrity } } });
  const run = runAction(env(mock, fakes, { CR_FLOW: 'published', CR_ARTIFACT: art.file, CR_NAME: NAME, CR_VERSION: '1.0.6', CR_SUBMIT_ENDPOINT: 'http://127.0.0.1:1' }), art.dir);
  assert.equal(run.code, 3);
});

test('idempotencyKeyFor', () => {
  const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  assert.equal(idempotencyKeyFor('{"a":1}'), idempotencyKeyFor('{"a":1}'));
  assert.notEqual(idempotencyKeyFor('{"a":1}'), idempotencyKeyFor('{"a":2}'));
  for (const payload of ['', 'x', '{"a":1}', 'z'.repeat(1000)]) assert.match(idempotencyKeyFor(payload), UUID_V4);
});

test('multipartFile', () => {
  const bytes = Buffer.from('tarball bytes');
  const { contentType, body } = multipartFile(bytes, 'odd"nameé.tgz');
  const boundary = contentType.split('boundary=')[1];
  assert.ok(!bytes.includes(boundary));
  assert.match(body.toString('latin1'), /filename="odd_name_\.tgz"\r\n/);
  assert.ok(body.includes(bytes));
  assert.match(multipartFile(bytes, '').body.toString('latin1'), /filename="artifact\.tgz"/);
});
