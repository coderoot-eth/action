'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawn } = require('child_process');

const ACTION = path.join(__dirname, '..', '..');
const MAIN = path.join(ACTION, 'src', 'main.js');
const CLIENT =
  process.env['CODEROOT_CLIENT'] ||
  path.join(ACTION, 'vendor', 'verify', 'build', 'bin', 'coderoot.js');

const ATTESTED = 'sha256:634e3ed585d7c8857f00cb7556f79422614e8defd008f8bb34b6018c1faefa0f';
const REVOKED = 'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
const UNREACHABLE = 'http://127.0.0.1:1';

function isolatedEnv() {
  const env = { ...process.env };
  for (const name of Object.keys(env)) {
    if (
      name === 'NPM_TOKEN' ||
      name === 'NODE_AUTH_TOKEN' ||
      name === 'CODEROOT_REVOKED_CACHE' ||
      name === 'RUNNER_TEMP' ||
      name === 'ACTIONS_ID_TOKEN_REQUEST_URL' ||
      name === 'ACTIONS_ID_TOKEN_REQUEST_TOKEN' ||
      /^CR_/.test(name) ||
      /^npm_config_/i.test(name)
    ) {
      delete env[name];
    }
  }
  return env;
}

function runAction(env, cwd = process.cwd()) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-action-'));
  const outputs = path.join(dir, 'out.txt');
  const summary = path.join(dir, 'summary.md');
  const stderrFile = path.join(dir, 'stderr.txt');
  fs.writeFileSync(outputs, '');
  fs.writeFileSync(summary, '');
  fs.writeFileSync(stderrFile, '');
  fs.mkdirSync(path.join(dir, 'home'));

  let code = 0;
  let stderr = '';
  try {
    execFileSync(process.execPath, [MAIN], {
      cwd,
      encoding: 'utf8',
      // stderr goes to a file rather than a pipe: execFileSync only hands it
      // back on a throw, and a run that exits 0 still writes warnings there.
      stdio: ['ignore', 'pipe', fs.openSync(stderrFile, 'a')],
      env: {
        ...isolatedEnv(),
        HOME: path.join(dir, 'home'), // a developer's ~/.npmrc would trip the credential guard
        CODEROOT_CLIENT: CLIENT,
        CODEROOT_REVOKED_CACHE: path.join(dir, 'revoked-cache.json'),
        CR_ACTION_PATH: ACTION,
        GITHUB_OUTPUT: outputs,
        GITHUB_STEP_SUMMARY: summary,
        CR_REPORT_PATH: path.join(dir, 'report.json'),
        ...env,
      },
    });
  } catch (error) {
    code = typeof error.status === 'number' ? error.status : 1;
  }
  stderr = fs.readFileSync(stderrFile, 'utf8');

  const parsed = {};
  for (const line of fs.readFileSync(outputs, 'utf8').split('\n')) {
    const eq = line.indexOf('=');
    if (eq > 0) parsed[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return {
    code,
    stderr,
    outputs: parsed,
    summary: fs.readFileSync(summary, 'utf8'),
    reportPath: path.join(dir, 'report.json'),
  };
}

/** A separate process: an in-process server cannot answer while execFileSync blocks the event loop. */
function startServer(script, args, portFile) {
  const child = spawn(process.execPath, [script, ...args], { stdio: 'ignore' });
  const deadline = Date.now() + 10000;
  let port = '';
  while (Date.now() < deadline) {
    if (fs.existsSync(portFile)) {
      port = fs.readFileSync(portFile, 'utf8').trim();
      if (port) break;
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
  }
  if (!port) {
    child.kill('SIGKILL');
    throw new Error(`${path.basename(script)} never reported a port`);
  }
  return { url: `http://127.0.0.1:${port}`, stop: () => child.kill('SIGKILL') };
}

module.exports = { ACTION, MAIN, CLIENT, ATTESTED, REVOKED, UNREACHABLE, runAction, startServer };
