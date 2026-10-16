#!/usr/bin/env node
/**
 * The Action's entry point: read inputs from the environment, dispatch to a
 * mode, write a job summary and a report, and set the exit code.
 *
 * Plain Node with no dependencies, so the Action has nothing to install and
 * nothing to audit beyond src/. The verification logic itself lives in
 * @coderoot-eth/verify, vendored under vendor/verify; this is the integration.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { request: sendRequest, requestWithRetry } = require('./http');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const EXIT = { CLEAN: 0, REVOKED: 1, MISMATCH: 2, ERROR: 3, CREDENTIAL: 4 };

/** Verdicts ordered worst-first, for picking what a whole run amounts to. */
const SEVERITY = ['revoked', 'unregistered', 'attested-bytes-unproven', 'verified'];

/** Each `fail-on` value also fails on every result to its left. */
const FAIL_ON = ['never', 'revoked', 'mismatch', 'unregistered'];

const FAIL_ON_DEFAULT = { check: 'mismatch', verify: 'unregistered' };

/**
 * Whether a degraded answer passes when `fail-open` is not set. Degraded means
 * the answer could not be fully checked: verify was unreachable, or it answered
 * but could not read the gate's revocations, so a revoke made minutes ago may
 * be missing. `verify` is the deploy-time check, a release job, so it fails;
 * `check` reports on a build, so it warns.
 */
const FAIL_OPEN_DEFAULT = { check: true, verify: false };

function input(name, fallback = '') {
  const value = process.env[`CR_${name}`];
  return value === undefined || value === '' ? fallback : value;
}

function bool(name, fallback) {
  const value = input(name, String(fallback)).toLowerCase();
  return value === 'true' || value === '1' || value === 'yes';
}

/** GitHub reads outputs from a file, not stdout. */
function setOutput(name, value) {
  const file = process.env['GITHUB_OUTPUT'];
  const line = `${name}=${String(value ?? '').replace(/\n/g, ' ')}\n`;
  if (file) fs.appendFileSync(file, line);
  else process.stdout.write(`::set-output-fallback ${line}`);
}

function summary(markdown) {
  const file = process.env['GITHUB_STEP_SUMMARY'];
  if (file) fs.appendFileSync(file, markdown + '\n');
  else process.stdout.write(markdown + '\n');
}

function fail(message) {
  console.error(`::error::${message}`);
  setOutput('exit-code', EXIT.ERROR);
  process.exit(EXIT.ERROR);
}

/**
 * Locate the verification client. Vendored inside the Action in a release; a
 * sibling checkout during development.
 */
function clientEntry() {
  const actionPath = input('ACTION_PATH', process.cwd());
  const candidates = [
    path.join(actionPath, 'vendor', 'verify', 'build', 'bin', 'coderoot.js'),
    path.join(actionPath, '..', 'verify', 'build', 'bin', 'coderoot.js'),
    process.env['CODEROOT_CLIENT'] || '',
  ].filter(Boolean);
  return candidates.find((candidate) => fs.existsSync(candidate)) || null;
}

function childEnv() {
  const env = { ...process.env };
  delete env['ACTIONS_ID_TOKEN_REQUEST_TOKEN'];
  delete env['ACTIONS_ID_TOKEN_REQUEST_URL'];
  return env;
}

/** Run the client and capture its JSON, whatever exit code it used. */
function runClient(args) {
  const entry = clientEntry();
  if (!entry) {
    fail(
      'Could not find the CodeRoot client. Expected it vendored at ' +
        'vendor/verify/build, or CODEROOT_CLIENT set to its entry point.'
    );
  }
  try {
    const stdout = execFileSync(process.execPath, [entry, ...args], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'inherit'],
      env: childEnv(),
    });
    return { code: 0, stdout };
  } catch (error) {
    // A non-zero exit is an answer here, not a crash: 1 means revoked.
    return { code: typeof error.status === 'number' ? error.status : EXIT.ERROR, stdout: error.stdout || '' };
  }
}

function parseJson(text, what) {
  try {
    return JSON.parse(text);
  } catch {
    fail(`Could not parse ${what} as JSON. Output was: ${String(text).slice(0, 300)}`);
  }
}

function failOnInput(mode) {
  const value = input('FAIL_ON', FAIL_ON_DEFAULT[mode]).toLowerCase();
  if (!FAIL_ON.includes(value)) {
    fail(`fail-on must be one of ${FAIL_ON.join(', ')} (got "${value}").`);
  }
  return value;
}

function failsOn(failOn, result) {
  return FAIL_ON.indexOf(failOn) >= FAIL_ON.indexOf(result);
}

/**
 * A cached revocation comes back `revoked`, not degraded, so fail-open never passes it.
 *
 * `authorCpoaRevoked` rides on top of the verdict rather than replacing it (the
 * four verdicts stay closed) and fails the build regardless of `fail-on` or
 * `fail-open`, but it never outranks the bytes themselves being revoked.
 * `null` (chain unreadable) fails too - unknown is not clear.
 */
function verifyExit({ code, verdict, degraded, authorCpoaRevoked }, { failOn, failOpen }) {
  if (code === EXIT.ERROR) return EXIT.ERROR;
  if (verdict === 'revoked') return failsOn(failOn, 'revoked') ? EXIT.REVOKED : EXIT.CLEAN;
  const authorCpoaFlagged = authorCpoaRevoked !== false && authorCpoaRevoked !== undefined;
  if (authorCpoaFlagged) return EXIT.MISMATCH;
  if (degraded) return failOpen ? EXIT.CLEAN : EXIT.ERROR;
  if (verdict === 'verified') return EXIT.CLEAN;
  return failsOn(failOn, 'unregistered') ? EXIT.MISMATCH : EXIT.CLEAN;
}

/** Reads the summary counts because `mismatch` is a per-record flag, not a verdict. */
function checkExit(summary, { failOn, failOpen }) {
  const s = summary || {};
  if ((s.revoked ?? 0) > 0) return failsOn(failOn, 'revoked') ? EXIT.REVOKED : EXIT.CLEAN;
  if ((s.degraded ?? 0) > 0 && !failOpen) return EXIT.ERROR;
  if ((s.mismatch ?? 0) > 0 && failsOn(failOn, 'mismatch')) return EXIT.MISMATCH;
  if ((s.unregistered ?? 0) > 0 && failsOn(failOn, 'unregistered')) return EXIT.MISMATCH;
  return EXIT.CLEAN;
}

/** What made an answer degraded, in words. An older client does not say, so assume the outage. */
function degradedCause(result) {
  return result && result.unreachable === false
    ? "verify could not read the gate's revocations"
    : 'the verify endpoint was unreachable';
}

function failOpenError(cause = 'the verify endpoint was unreachable') {
  console.error(
    `::error::This could not be fully checked (${cause}) and \`fail-open\` is false, so it is ` +
      'treated as a failure rather than waved through.'
  );
}

function failOpenWarning(cause) {
  console.error(
    `::warning::This could not be fully checked (${cause}); proceeding because \`fail-open\` is true.`
  );
}

// ------------------------------------------------------ registry credentials

const NPM_AUTH_KEY = /(^|:)_(authtoken|auth|password)$/i;

function npmrcFiles() {
  const env = process.env;
  const home = env['HOME'] || os.homedir();
  const prefix =
    env['NPM_CONFIG_PREFIX'] || env['npm_config_prefix'] || path.dirname(path.dirname(process.execPath));
  const files = [
    path.resolve('.npmrc'),
    env['GITHUB_WORKSPACE'] ? path.join(env['GITHUB_WORKSPACE'], '.npmrc') : '',
    env['NPM_CONFIG_USERCONFIG'] || env['npm_config_userconfig'] || path.join(home, '.npmrc'),
    env['NPM_CONFIG_GLOBALCONFIG'] || env['npm_config_globalconfig'] || path.join(prefix, 'etc', 'npmrc'),
  ];
  return [...new Set(files.filter(Boolean))];
}

function hasAuthLine(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch {
    return false;
  }
  return text.split(/\r?\n/).some((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) return false;
    return NPM_AUTH_KEY.test(trimmed.split('=')[0].trim());
  });
}

/**
 * Find any registry credential reachable from this job.
 *
 * `submit` is the mode that reads an artifact and talks to the gate, so a
 * registry token in scope there is the case worth stopping: it is the shape of
 * a job that could publish. `check` and `verify` only read digests and query
 * the verify endpoint, so a token in scope is untidy rather than dangerous, and
 * stopping the job would break pipelines that legitimately publish in a later
 * step.
 */
function findRegistryCredentials() {
  const found = [];
  for (const [name, value] of Object.entries(process.env)) {
    if (!value) continue;
    if (name === 'NPM_TOKEN' || name === 'NODE_AUTH_TOKEN') found.push(name);
    else if (/^npm_config_/i.test(name) && NPM_AUTH_KEY.test(name.slice('npm_config_'.length))) {
      found.push(name);
    }
  }
  for (const file of npmrcFiles()) {
    if (hasAuthLine(file)) found.push(`an auth line in ${file}`);
  }
  return found;
}

/** Stop `submit`; warn the read-only modes. */
function checkRegistryCredentials(mode) {
  const found = findRegistryCredentials();
  if (found.length === 0) return;

  const what = `A registry credential is in scope: ${found.join(', ')}.`;
  if (mode === 'submit') {
    console.error(
      `::error::${what} This Action never publishes, and submit does not run where a registry ` +
        'token is reachable. Remove it from this job.'
    );
    setOutput('exit-code', EXIT.CREDENTIAL);
    process.exit(EXIT.CREDENTIAL);
  }
  console.error(`::warning::${what} This Action never publishes and does not read it.`);
}

// ------------------------------------------------------------ revoked cache

/*
 * CODEROOT_REVOKED_CACHE lives outside CR_REVOKED_CACHE_DIR because a later
 * step in the same job restores into that dir again, which would drop entries
 * this job learned if their save did not land.
 */
const CACHE_FILE = 'revoked-cache.json';

function readCacheEntries(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!Array.isArray(parsed.entries)) return [];
    return parsed.entries.filter((entry) => typeof entry?.digest === 'string' && entry.digest.includes(':'));
  } catch {
    return [];
  }
}

/** Sorted so equal sets produce the same content-addressed cache key. */
function mergeEntries(...lists) {
  const byDigest = new Map();
  for (const list of lists) {
    for (const entry of list) {
      const digest = entry.digest.toLowerCase();
      if (!byDigest.has(digest)) byDigest.set(digest, { ...entry, digest });
    }
  }
  return [...byDigest.values()].sort((a, b) => (a.digest < b.digest ? -1 : a.digest > b.digest ? 1 : 0));
}

/** The report path, with its directory created: a step may name a directory no earlier step made. */
function reportPathInput() {
  const file = input('REPORT_PATH', 'coderoot-report.json');
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  return file;
}

function writeCache(file, entries) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ schema: 'coderoot.revoked-cache/v1', entries }, null, 2));
}

function loadRevokedCache() {
  const dir = input('REVOKED_CACHE_DIR');
  const working = process.env['CODEROOT_REVOKED_CACHE'];
  if (!dir || !working) return null;
  const restored = readCacheEntries(path.join(dir, CACHE_FILE));
  writeCache(working, mergeEntries(restored, readCacheEntries(working)));
  return new Set(restored.map((entry) => entry.digest.toLowerCase()));
}

function storeRevokedCache(restored) {
  if (!restored) return;
  const entries = mergeEntries(readCacheEntries(process.env['CODEROOT_REVOKED_CACHE']));
  const grew = entries.some((entry) => !restored.has(entry.digest));
  setOutput('revoked-cache-changed', grew ? 'true' : 'false');
  if (!grew) return;
  writeCache(path.join(input('REVOKED_CACHE_DIR'), CACHE_FILE), entries);
  const digestList = entries.map((entry) => entry.digest).join('\n');
  const key = crypto.createHash('sha256').update(digestList).digest('hex').slice(0, 32);
  setOutput('revoked-cache-key', `coderoot-revoked-${key}`);
}

// --------------------------------------------------------------- verify mode

function modeVerify() {
  const hash = input('HASH');
  const artifact = input('ARTIFACT');
  if (!hash && !artifact) fail('verify needs either `hash` or `artifact`.');
  if (hash && artifact) fail('verify takes `hash` or `artifact`, not both.');
  const failOn = failOnInput('verify');
  const failOpen = bool('FAIL_OPEN', FAIL_OPEN_DEFAULT.verify);

  const args = ['verify', '--json', hash ? '--hash' : '--file', hash || artifact];
  const endpoint = input('VERIFY_ENDPOINT');
  if (endpoint) args.push('--base-url', endpoint);

  const restored = loadRevokedCache();
  const { code, stdout } = runClient(args);
  storeRevokedCache(restored);
  if (code === EXIT.ERROR) fail('The client rejected the input; see the error above.');
  const result = parseJson(stdout, 'the verify result');
  const reportPath = reportPathInput();
  fs.writeFileSync(reportPath, JSON.stringify(result, null, 2));

  const mark = { verified: '✅', revoked: '⛔', unregistered: '⚠️' }[result.verdict] || '⚠️';
  summary(
    `## CodeRoot verify\n\n` +
      `${mark} **${result.verdict}**\n\n` +
      `| | |\n|---|---|\n` +
      `| digest | \`${result.queried || '—'}\` |\n` +
      `| source | ${result.hashSource} |\n` +
      `| reason | ${result.reason} |\n` +
      (result.attestations?.length
        ? `| attestation UIDs | ${result.attestations.map((a) => `\`${a.uid}\``).join('<br>')} |\n`
        : '') +
      (result.degraded
        ? failOpen
          ? `\n> Not fully checked: ${degradedCause(result)}. \`fail-open\` is true, so this job proceeds with a warning.\n`
          : `\n> Not fully checked: ${degradedCause(result)}, so this release job fails. ` +
            `Set \`fail-open: true\` on a job that only needs a warning.\n`
        : '') +
      (result.authorCpoaRevoked !== false && result.authorCpoaRevoked !== undefined
        ? `\n> ⛔ The authoring agent's CPoA is ${result.authorCpoaRevoked === null ? 'unreadable' : 'revoked'}` +
          `, refusing this build regardless of \`fail-on\`.` +
          (result.authorCpoaRevokedUids?.length
            ? ` UID: ${result.authorCpoaRevokedUids.map((u) => `\`${u}\``).join(', ')}`
            : '') +
          `\n`
        : '') +
      `\nfail-on \`${failOn}\`\n`
  );

  setOutput('verdict', result.verdict);
  setOutput('report', reportPath);
  setOutput('exit-code', code);
  setOutput('degraded', result.degraded ? 'true' : 'false');
  setOutput('author-cpoa-revoked', result.authorCpoaRevoked === undefined ? 'false' : String(result.authorCpoaRevoked));
  // A revoked or agent-refused answer fails on its own; say "not fully checked"
  // only when that is what decides the outcome.
  const exit = verifyExit(
    { code, verdict: result.verdict, degraded: result.degraded, authorCpoaRevoked: result.authorCpoaRevoked },
    { failOn, failOpen }
  );
  if (result.degraded && exit === EXIT.ERROR) failOpenError(degradedCause(result));
  else if (result.degraded && failOpen && exit === EXIT.CLEAN) failOpenWarning(degradedCause(result));
  return exit;
}

// ---------------------------------------------------------------- check mode

function modeCheck() {
  const sbom = input('SBOM');
  const lockfile = input('LOCKFILE');
  if (sbom && lockfile) {
    fail('check takes `sbom` or `lockfile`, not both.');
  }
  if (!sbom && !lockfile) {
    // The Action does not generate SBOMs; say so rather than guessing.
    fail(
      'check needs `sbom` (a CycloneDX or SPDX document) or `lockfile` (an npm package-lock.json). ' +
        'This Action does not generate SBOMs - produce one with syft, cdxgen or npm sbom first.'
    );
  }
  const failOn = failOnInput('check');
  const failOpen = bool('FAIL_OPEN', FAIL_OPEN_DEFAULT.check);

  const reportPath = reportPathInput();
  const args = ['verify', lockfile ? '--lockfile' : '--sbom', lockfile || sbom, '--json', reportPath];
  const endpoint = input('VERIFY_ENDPOINT');
  if (endpoint) args.push('--base-url', endpoint);

  // An earlier step may have left a report at this path.
  fs.rmSync(reportPath, { force: true });
  const restored = loadRevokedCache();
  const { code } = runClient(args);
  storeRevokedCache(restored);
  if (code === EXIT.ERROR) fail('The client could not read the SBOM; see the error above.');
  if (!fs.existsSync(reportPath)) fail('The client produced no report.');
  const report = parseJson(fs.readFileSync(reportPath, 'utf8'), 'the run report');
  const s = report.summary || {};

  const worst =
    SEVERITY.find((verdict) => {
      const key = { 'attested-bytes-unproven': 'attestedBytesUnproven' }[verdict] || verdict;
      return (s[key] || 0) > 0;
    }) || 'verified';

  const degraded = (s.degraded ?? 0) > 0;
  const exit = checkExit(s, { failOn, failOpen });
  // What the degraded components did to this job: failed it, only warned, or
  // nothing, because a revoked or mismatched component already fails it.
  const degradedOutcome =
    exit === EXIT.ERROR
      ? '`fail-open` is false, so this job fails.'
      : exit === EXIT.CLEAN
        ? 'Warning only: `fail-open` is true.'
        : 'The job fails anyway, on the result above.';

  const pct = (n) => (s.total ? ((100 * n) / s.total).toFixed(1) + '%' : '0.0%');
  summary(
    `## CodeRoot check\n\n` +
      `\`${report.source?.file || lockfile || sbom}\` — ${report.source?.components ?? 0} components, ` +
      `**${report.source?.distinct ?? 0} distinct**\n\n` +
      `| verdict | count | share |\n|---|--:|--:|\n` +
      `| ✅ verified | ${s.verified ?? 0} | ${pct(s.verified ?? 0)} |\n` +
      `| ⚠️ attested-bytes-unproven | ${s.attestedBytesUnproven ?? 0} | ${pct(s.attestedBytesUnproven ?? 0)} |\n` +
      `| ⚪ unregistered | ${s.unregistered ?? 0} | ${pct(s.unregistered ?? 0)} |\n` +
      `| ⛔ revoked | ${s.revoked ?? 0} | ${pct(s.revoked ?? 0)} |\n\n` +
      `mismatch flags ${s.mismatch ?? 0} · not queried ${s.notQueried ?? 0} · degraded ${s.degraded ?? 0}\n\n` +
      (degraded
        ? `> ${s.degraded} component(s) could not be fully checked (verify unreachable, or the gate's ` +
          `revocations unread). ${degradedOutcome}\n\n`
        : '') +
      (s.authorCpoaRevoked
        ? `> ⚠️ ${s.authorCpoaRevoked} component(s) were authored by an agent whose CPoA is ` +
          `revoked or unreadable. This warns only - check never fails on it; see \`verify\`.\n\n`
        : '') +
      `> Components whose only digest came from the SBOM are never queried, so they cannot\n` +
      `> produce a false mismatch. They are counted under *not queried*.\n\n` +
      `fail-on \`${failOn}\`\n`
  );

  setOutput('verdict', worst);
  setOutput('report', reportPath);
  setOutput('exit-code', code);
  setOutput('degraded', degraded ? 'true' : 'false');
  setOutput('author-cpoa-revoked-count', String(s.authorCpoaRevoked ?? 0));
  // As in verify: "proceeding" only when the job does proceed. A revoked or
  // mismatched component fails on its own, and says so.
  const cause = "verify unreachable, or the gate's revocations unread";
  if (exit === EXIT.ERROR) failOpenError(cause);
  else if (degraded && exit === EXIT.CLEAN) failOpenWarning(cause);
  return exit;
}

// ----------------------------------------------------------------- transport

/** Uploads have no replay contract: keep them single-shot. */
function request(url, options) {
  return sendRequest(url, { ...options, timeoutMs: Number(input('HTTP_TIMEOUT_MS', '30000')) });
}

/**
 * Turn a gate error envelope into a one-line message. The `id` is the stable
 * part a team can grep for and the part the contract pins, so it leads.
 */
function gateError(response) {
  const error = response.body && response.body.error;
  if (!error) return `HTTP ${response.status}: ${String(response.text || '').slice(0, 300)}`;
  const detail = error.detail ? ` (${JSON.stringify(error.detail)})` : '';
  return `${error.id}: ${error.message}${detail}`;
}

// One `file` part and nothing else: the gate's streaming parser rejects a
// preamble, a second part, and a missing or non-ASCII filename.
function multipartFile(bytes, filename) {
  let boundary;
  do boundary = `coderoot-${crypto.randomBytes(16).toString('hex')}`;
  while (bytes.includes(boundary));
  const name = filename.replace(/[^\x20-\x7e]|["\\]/g, '_') || 'artifact.tgz';
  return {
    contentType: `multipart/form-data; boundary=${boundary}`,
    body: Buffer.concat([
      Buffer.from(
        `--${boundary}\r\n` +
          `Content-Disposition: form-data; name="file"; filename="${name}"\r\n` +
          'Content-Type: application/octet-stream\r\n\r\n'
      ),
      bytes,
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ]),
  };
}

// Derived from the body so that resending the same body replays it. The gate
// accepts only UUIDv4-shaped keys.
function idempotencyKeyFor(payload) {
  const b = crypto.createHash('sha256').update(payload).digest().subarray(0, 16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = b.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// --------------------------------------------------------------- submit mode

const FLOWS = ['published', 'staged'];
const STAGE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * The gate credential: the job's GitHub identity token, and nothing else. It
 * names the repository, workflow and run that submit, which a stored token
 * cannot, and the job holds no secret.
 */
async function gateCredential(flow) {
  const url = process.env['ACTIONS_ID_TOKEN_REQUEST_URL'];
  const requestToken = process.env['ACTIONS_ID_TOKEN_REQUEST_TOKEN'];
  const audience = input('OIDC_AUDIENCE', 'secure.coderoot.app');
  if (!url || !requestToken) {
    fail(
      `flow \`${flow}\` signs in with the job's GitHub identity token, and this job cannot mint one. ` +
        'Give the job `permissions: id-token: write`.'
    );
  }
  let res;
  try {
    res = await request(`${url}&audience=${encodeURIComponent(audience)}`, {
      headers: { Authorization: `bearer ${requestToken}`, Accept: 'application/json' },
    });
  } catch (error) {
    fail(`Could not get a GitHub identity token for ${audience}: ${error.message}`);
  }
  if (res.status !== 200 || typeof res.body?.value !== 'string') {
    fail(`Could not get a GitHub identity token for ${audience} (HTTP ${res.status}).`);
  }
  return res.body.value;
}

/** Which flow the release reached npm by, and its stage id when staged. */
function readFlow() {
  const flow = input('FLOW').toLowerCase();
  if (!flow) fail(`submit needs \`flow\`: ${FLOWS.join(' or ')}, how the release reached npm.`);
  if (!FLOWS.includes(flow)) fail(`flow must be one of ${FLOWS.join(', ')} (got "${flow}").`);
  if (flow === 'published') {
    if (input('STAGE_ID')) fail('stage-id applies to flow `staged` only.');
    return { flow, stageId: null };
  }
  let stageId = input('STAGE_ID').toLowerCase();
  const npmOutput = input('NPM_OUTPUT');
  if (!stageId && npmOutput) {
    if (!fs.existsSync(npmOutput)) fail(`npm-output not found: ${npmOutput}`);
    const match = /staged with id ([0-9a-f-]{36})/i.exec(fs.readFileSync(npmOutput, 'utf8'));
    stageId = match ? match[1].toLowerCase() : '';
    if (!stageId) fail(`No stage id in ${npmOutput}. Pass the output of \`npm stage publish\`, or set \`stage-id\`.`);
  }
  if (!stageId) fail('flow `staged` needs `stage-id`, or `npm-output` holding the output of `npm stage publish`.');
  if (!STAGE_ID_RE.test(stageId)) fail(`stage-id must be a UUID (got "${stageId}").`);
  return { flow, stageId };
}

/**
 * npm's `dist.integrity` for a published version. A new version can take a
 * minute or more to become visible, so a 404 is retried until `registry-wait`
 * runs out rather than failing on the first read.
 */
async function registryIntegrity(name, version) {
  const registry = input('REGISTRY', 'https://registry.npmjs.org').replace(/\/+$/, '');
  const url = `${registry}/${name.replace('/', '%2f')}/${encodeURIComponent(version)}`;
  const waitMs = Number(input('REGISTRY_WAIT', '300')) * 1000;
  const pollMs = Number(input('REGISTRY_POLL_MS', '10000'));
  const deadline = Date.now() + waitMs;
  let last = '';
  for (;;) {
    try {
      const res = await request(url, { headers: { Accept: 'application/json' } });
      if (res.status === 200) {
        const integrity = String(res.body?.dist?.integrity || '');
        const sha512 = integrity.split(/\s+/).find((entry) => entry.startsWith('sha512-'));
        if (!sha512) fail(`npm returned ${name}@${version} without a sha512 integrity.`);
        return { url, integrity: sha512 };
      }
      last = `HTTP ${res.status}`;
      if (res.status !== 404) fail(`Could not read ${name}@${version} from npm (${last}).`);
    } catch (error) {
      last = error.message;
    }
    if (Date.now() + pollMs > deadline) break;
    await sleep(pollMs);
  }
  fail(
    `${name}@${version} is not visible on npm after ${waitMs / 1000}s (last read: ${last}). ` +
      'Raise `registry-wait` if the registry is slow, or check that the publish succeeded.'
  );
}

function hexToIntegrity(hash) {
  return `sha512-${Buffer.from(hash.slice('sha512:'.length), 'hex').toString('base64')}`;
}

/** npm's purl for a package, as its provenance subject names it: the scope's "@" is percent-encoded. */
function npmPurl(name, version) {
  return `pkg:npm/${name.replace(/^@/, '%40')}@${version}`;
}

/**
 * The staged release's provenance bundle, checked locally against the tarball
 * before anything is sent: one subject, this package's purl, this SHA-512. The
 * gate verifies the signature and the signing identity.
 */
function readProvenanceBundle(file, name, version, sha512) {
  if (!file) {
    fail(
      'flow `staged` needs `provenance-bundle`: the Sigstore bundle npm attached to the staged version ' +
        '(create it in an earlier step and stage with `npm stage publish --provenance-file <bundle>`).'
    );
  }
  if (!fs.existsSync(file)) fail(`provenance-bundle not found: ${file}`);
  const bytes = fs.readFileSync(file);
  let subjects;
  try {
    const bundle = JSON.parse(bytes.toString('utf8'));
    if (!String(bundle.mediaType || '').startsWith('application/vnd.dev.sigstore.bundle')) throw new Error('mediaType');
    subjects = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString('utf8')).subject;
  } catch {
    fail(`${file} is not a Sigstore bundle with a DSSE statement.`);
  }
  const purl = npmPurl(name, version);
  if (!Array.isArray(subjects) || subjects.length !== 1 || subjects[0].name !== purl || subjects[0].digest?.sha512 !== sha512.slice('sha512:'.length)) {
    refuse(
      'The provenance bundle is not for this artifact',
      `\`${file}\` must name exactly one subject, \`${purl}\` with the artifact's SHA-512. Nothing was submitted.`,
      EXIT.MISMATCH
    );
  }
  return bytes;
}

/** Upload bytes to the gate and return the receipt; a refusal stops the job. */
async function uploadArtifact(endpoint, bearer, bytes, filename, what) {
  const form = multipartFile(bytes, filename);
  let res;
  try {
    res = await request(`${endpoint}/v1/artifacts`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${bearer}`, 'Content-Type': form.contentType, 'Content-Length': form.body.length },
      body: form.body,
    });
  } catch (error) {
    fail(`Could not reach the gate to upload the ${what}: ${error.message}`);
  }
  if (res.status !== 201) refuse(`Upload of the ${what} refused`, gateError(res));
  return res.body;
}

/** Report a refusal in the job summary as well as the log, then stop. */
function refuse(heading, message, code = EXIT.ERROR) {
  summary(`## CodeRoot submit\n\n⛔ **${heading}**\n\n${message}\n`);
  console.error(`::error::${heading}. ${message}`);
  setOutput('exit-code', code);
  process.exit(code);
}

function readPackageJson() {
  const file = path.resolve('package.json');
  if (!fs.existsSync(file)) return {};
  return parseJson(fs.readFileSync(file, 'utf8'), 'package.json');
}

/**
 * The `source` block, built from the GitHub context.
 *
 * `repo` and `commit` are required and `build_*` are optional, so an
 * absent optional field is OMITTED rather than sent as an empty string: the
 * gate's schema is closed and rejects `""` as `not a URL`. Missing required
 * context is a usage error with a message that names what to set, not a body
 * the gate will refuse.
 */
function buildSource() {
  const server = process.env['GITHUB_SERVER_URL'] || '';
  const repository = process.env['GITHUB_REPOSITORY'] || '';
  const runId = process.env['GITHUB_RUN_ID'] || '';

  const repo = input('REPO', server && repository ? `${server}/${repository}` : '');
  const commit = input('COMMIT', process.env['GITHUB_SHA'] || '');
  if (!repo) {
    fail(
      'submit needs the source repository. It is read from GITHUB_SERVER_URL and ' +
        'GITHUB_REPOSITORY inside Actions; set `repo` when running elsewhere.'
    );
  }
  if (!/^[0-9a-f]{40}$/.test(commit)) {
    fail(
      `submit needs the 40-hex commit sha (got ${commit ? `"${commit}"` : 'nothing'}). ` +
        'It is read from GITHUB_SHA inside Actions; set `commit` when running elsewhere.'
    );
  }

  const source = { repo, commit, build_system: 'github-actions' };
  if (server && repository && runId) {
    source.build_uri = `${server}/${repository}/actions/runs/${runId}`;
  }
  return source;
}

async function modeSubmit() {
  const { flow, stageId } = readFlow();
  const token = await gateCredential(flow);
  const artifact = input('ARTIFACT');
  if (!artifact) {
    // A fresh pack after a publish is not guaranteed to reproduce the published bytes.
    fail(`flow \`${flow}\` needs \`artifact\`: the tarball that was published or staged. Pack once and pass that file.`);
  }
  if (!fs.existsSync(artifact)) fail(`Artifact not found: ${artifact}`);

  const { code: hashCode, stdout } = runClient(['hash', artifact, '--json', '--algorithm', 'both']);
  if (hashCode !== EXIT.CLEAN) fail('Could not hash the artifact.');
  const hashed = parseJson(stdout, 'the hash result');
  const hashes = [hashed.digests?.sha256, hashed.digests?.sha512];
  if (!/^sha256:[0-9a-f]{64}$/.test(hashes[0] || '') || !/^sha512:[0-9a-f]{128}$/.test(hashes[1] || '')) {
    fail(`The client returned no sha256/sha512 pair for the artifact: ${stdout.slice(0, 300)}`);
  }

  const pkg = readPackageJson();
  const name = input('NAME', pkg.name || '');
  const version = input('VERSION', pkg.version || '');
  if (!name || !version) fail('submit needs `name` and `version`, or a package.json that has them.');

  // A published release must be the bytes npm serves; refuse locally before the gate sees it.
  let registryCheck = null;
  if (flow === 'published') {
    registryCheck = await registryIntegrity(name, version);
    const local = hexToIntegrity(hashes[1]);
    if (registryCheck.integrity !== local) {
      refuse(
        'The artifact is not what npm serves',
        `npm's \`dist.integrity\` for \`${name}@${version}\` is \`${registryCheck.integrity}\`, ` +
          `but the artifact hashes to \`${local}\`. Nothing was submitted.`,
        EXIT.MISMATCH
      );
    }
  }

  const endpoint = input('SUBMIT_ENDPOINT', 'https://secure.coderoot.app').replace(/\/+$/, '');
  const bytes = fs.readFileSync(artifact);

  // --- step 1: upload the bytes. The receipt carries the gate's own digests,
  // and the submission must declare hashes equal to them.
  const bundleBytes = flow === 'staged' ? readProvenanceBundle(input('PROVENANCE_BUNDLE'), name, version, hashes[1]) : null;
  const upload = { body: await uploadArtifact(endpoint, token, bytes, path.basename(artifact), 'artifact') };
  let provenance = null;
  if (bundleBytes) {
    const receipt = await uploadArtifact(endpoint, token, bundleBytes, path.basename(input('PROVENANCE_BUNDLE')), 'provenance bundle');
    provenance = { upload_id: receipt.upload_id, sha256: receipt.hashes[0] };
  }

  // Always present, never omitted: absent means [] and null, not missing.
  const evidencePath = input('EVIDENCE');
  const signaturesPath = input('SIGNATURES');
  const body = {
    artifact: {
      upload_id: upload.body.upload_id,
      kind: 'npm-tarball',
      filename: path.basename(artifact),
    },
    hashes,
    coordinates: { registry: 'npm', name, version },
    flow,
    ...(flow === 'staged' ? { stage_id: stageId, provenance } : {}),
    // Build provenance from the GitHub context: what repo, which commit, which
    // run produced these bytes. The gate records it; it is not proof on its own.
    source: buildSource(),
    signatures: signaturesPath ? parseJson(fs.readFileSync(signaturesPath, 'utf8'), 'signatures') : [],
    evidence: evidencePath ? parseJson(fs.readFileSync(evidencePath, 'utf8'), 'evidence') : [],
    // Agent submissions arrive through the AgentRoot gateway with a
    // gateway-minted assertion, never through this Action.
    agent: null,
    submitter_note: input('NOTE', `${name}@${version} via GitHub Actions`),
  };

  const reportPath = reportPathInput();
  fs.writeFileSync(reportPath, JSON.stringify(body, null, 2));
  setOutput('report', reportPath);

  // --- step 2: submit. The key is derived from the body actually being sent,
  // `upload_id` included, because each upload mints a fresh one: deriving it
  // from the bytes alone would send a second attempt under the same key with a
  // different body, which the gate refuses as `idempotency_key_reused`. Sending
  // one key per distinct body makes a retry safe, and duplicate submissions of
  // the same release are caught by the gate's identity rule instead
  // (`409 package_identity_pending`), which is the check that actually protects
  // a pending human review.
  // The exact bytes: this key order, two-space indent, no trailing newline.
  const payload = JSON.stringify(body, null, 2);
  const idempotencyKey = input('IDEMPOTENCY_KEY', idempotencyKeyFor(payload));

  let submitted;
  try {
    submitted = await requestWithRetry(`${endpoint}/v1/submit`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Idempotency-Key': idempotencyKey,
        'Content-Length': Buffer.byteLength(payload),
      },
      body: payload,
    }, { timeoutMs: Number(input('HTTP_TIMEOUT_MS', '30000')) });
  } catch (error) {
    fail(`Could not reach the gate to submit: ${error.message}`);
  }

  // 201 is a new submission, 200 an idempotent replay of one already made.
  if (submitted.status !== 201 && submitted.status !== 200) {
    refuse('Submission refused', gateError(submitted));
  }

  const result = submitted.body || {};
  fs.writeFileSync(reportPath, JSON.stringify({ request: body, response: result }, null, 2));

  summary(
    `## CodeRoot submit\n\n` +
      `\`${name}@${version}\` — ${path.basename(artifact)}\n\n` +
      `| | |\n|---|---|\n` +
      `| submission | \`${result.submission_id || '—'}\` |\n` +
      `| state | ${result.state || '—'} |\n` +
      `| policy grade | ${result.policy_grade || '—'} |\n` +
      (flow ? `| flow | ${flow}${stageId ? ` (stage \`${stageId}\`)` : ''} |\n` : '') +
      '| signed in with | GitHub identity token |\n' +
      (provenance ? `| provenance | \`${provenance.sha256}\` |\n` : '') +
      (result.review_url ? `| review | ${result.review_url} |\n` : '') +
      (result.idempotent_replay ? `| replay | this build was already submitted |\n` : '') +
      `\n` +
      body.hashes.map((h) => `- \`${h}\``).join('\n') +
      `\n\n` +
      (result.review_url ? `**Queue:** ${result.review_url}\n\n` : '') +
      (flow === 'published'
        ? `> Already live on npm; the artifact matches npm's \`dist.integrity\`. Attest it in CodeRoot.\n`
        : flow === 'staged'
          ? `> Staged on npm, not installable yet. Attest it in CodeRoot first, then approve it on npm: ` +
            `\`npm stage approve ${stageId}\`.\n`
          : `> Submitted for human approval. This job does not wait for a decision and never publishes.\n`)
  );

  setOutput('submission-id', result.submission_id || '');
  setOutput('review-url', result.review_url || '');
  setOutput('flow', flow || '');
  setOutput('exit-code', EXIT.CLEAN);
  return EXIT.CLEAN;
}

// ----------------------------------------------------------- report upload

/** upload-artifact rejects a duplicate name within a job; RUNNER_TEMP is per job. */
function artifactName(mode) {
  const requested = input('ARTIFACT_NAME');
  if (requested) return requested;
  const base = `coderoot-${mode}-report`;
  const temp = process.env['RUNNER_TEMP'];
  if (!temp) return base;
  const ledger = path.join(temp, 'coderoot-artifact-names');
  const used = fs.existsSync(ledger) ? fs.readFileSync(ledger, 'utf8').split('\n') : [];
  let name = base;
  for (let n = 2; used.includes(name); n += 1) name = `${base}-${n}`;
  fs.appendFileSync(ledger, name + '\n');
  return name;
}

// --------------------------------------------------------------------- entry

async function main() {
  const mode = input('MODE').toLowerCase();
  const modes = { check: modeCheck, submit: modeSubmit, verify: modeVerify };
  if (!modes[mode]) {
    fail(`mode must be one of check, submit, verify (got ${mode ? `"${mode}"` : 'nothing'}).`);
  }
  checkRegistryCredentials(mode);
  setOutput('artifact-name', artifactName(mode));
  process.exit(await modes[mode]());
}

if (require.main === module) {
  main().catch((error) => fail(error && error.message ? error.message : String(error)));
}

module.exports = {
  EXIT,
  hexToIntegrity,
  npmPurl,
  FAIL_ON,
  FAIL_ON_DEFAULT,
  FAIL_OPEN_DEFAULT,
  verifyExit,
  checkExit,
  mergeEntries,
  multipartFile,
  idempotencyKeyFor,
};
