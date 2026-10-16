'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { request, requestWithRetry } = require('../src/http');
const crypto = require('node:crypto');
const { runAction, startServer } = require('./helpers/run-action');

function clock() {
  let time = Date.parse('2026-10-15T00:00:00Z');
  const waits = [];
  return { now: () => time, random: () => 0, waits,
    sleep: async ms => { waits.push(ms); time += ms; } };
}

test('recovery replays the exact body, authorization and idempotency key', async () => {
  const timing = clock(), seen = [];
  const options = { method: 'POST', body: '{\n  "upload_id": "upl_original"\n}',
    headers: { Authorization: 'Bearer synthetic', 'Idempotency-Key': 'original' } };
  const responses = [{ status: 503 }, { status: 429, headers: { 'retry-after': '2' } }, { status: 200 }];
  const result = await requestWithRetry('https://gate.invalid/v1/submit', options, { ...timing,
    send: async (_url, opts) => { seen.push(opts); return responses.shift(); } });
  assert.equal(result.status, 200);
  assert.deepEqual(timing.waits, [500, 2000]);
  assert.equal(seen.length, 3);
  for (const sent of seen) {
    assert.equal(sent.body, options.body);
    assert.deepEqual(sent.headers, options.headers);
  }
  assert.deepEqual(seen.map(sent => sent.timeoutMs), [30000, 29500, 27500]);
});

test('network recovery and exhaustion have a fixed three-attempt cap', async () => {
  const timing = clock();
  let calls = 0;
  const send = async () => { calls++; throw Object.assign(new Error('reset'), { code: 'ECONNRESET' }); };
  await assert.rejects(requestWithRetry('https://gate.invalid', {}, { ...timing, send }), /reset/);
  assert.equal(calls, 3);
  calls = 0;
  const result = await requestWithRetry('https://gate.invalid', {}, { ...clock(), send: async () => {
    if (++calls === 1) throw Object.assign(new Error('dns'), { code: 'EAI_AGAIN' });
    return { status: 201 };
  } });
  assert.equal(result.status, 201);
  assert.equal(calls, 2);
});

test('permanent refusals and TLS/configuration failures are never retried', async () => {
  for (const status of [400, 401, 403, 404, 409, 422, 501, 505]) {
    let calls = 0;
    const result = await requestWithRetry('https://gate.invalid', {}, { ...clock(), send: async () => {
      calls++; return { status };
    } });
    assert.equal(result.status, status);
    assert.equal(calls, 1);
  }
  let calls = 0;
  await assert.rejects(requestWithRetry('https://gate.invalid', {}, { ...clock(), send: async () => {
    calls++; throw Object.assign(new Error('certificate'), { code: 'CERT_HAS_EXPIRED' });
  } }), /certificate/);
  assert.equal(calls, 1);
});

test('Retry-After dates and the total deadline limit retry scheduling', async () => {
  const timing = clock();
  let calls = 0;
  await requestWithRetry('https://gate.invalid', {}, { ...timing, send: async () => {
    return ++calls === 1 ? { status: 503, headers: { 'retry-after': new Date(timing.now() + 3000).toUTCString() } } : { status: 200 };
  } });
  assert.deepEqual(timing.waits, [3000]);
  const limited = clock();
  calls = 0;
  const result = await requestWithRetry('https://gate.invalid', {}, { ...limited, timeoutMs: 1000,
    send: async () => { calls++; return { status: 429, headers: { 'retry-after': '60' } }; } });
  assert.equal(result.status, 429);
  assert.equal(calls, 1);
  assert.deepEqual(limited.waits, []);
  const late = clock();
  await assert.rejects(requestWithRetry('https://gate.invalid', {}, { ...late, timeoutMs: 100,
    send: async () => { await late.sleep(101); return { status: 200 }; } }), /deadline/);
});

test('the transport aborts a stalled response and rejects a truncated body', async t => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '100' });
    res.write('{');
    if (req.url === '/truncated') setImmediate(() => res.destroy());
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const url = `http://127.0.0.1:${server.address().port}`;
  await assert.rejects(request(`${url}/stalled`, { timeoutMs: 25 }), error => error.code === 'ETIMEDOUT');
  await assert.rejects(request(`${url}/truncated`), error => error.code === 'ECONNRESET');
});

function gate(t, mode) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-retry-'));
  const log = path.join(dir, 'seen.jsonl'), portFile = path.join(dir, 'port');
  const script = path.join(dir, 'gate.js');
  fs.writeFileSync(script, `
    const http = require('http'), fs = require('fs');
    let submits = 0;
    const server = http.createServer((req,res) => {
      const chunks=[];
      req.on('data', c=>chunks.push(c));
      req.on('end',()=>{
        fs.appendFileSync(${JSON.stringify(log)},JSON.stringify({url:req.url,headers:req.headers,body:Buffer.concat(chunks).toString('base64')})+'\\n');
        if(req.url==='/v1/artifacts') {
          if(${JSON.stringify(mode)}==='upload-reset') return req.socket.destroy();
          res.writeHead(${mode === 'upload-503' ? 503 : 201},{'Content-Type':'application/json'});
          return res.end(JSON.stringify({upload_id:'upl_original'}));
        }
        submits++;
        if(submits===1 && ${JSON.stringify(mode)}==='submit-reset') return req.socket.destroy();
        const status=${JSON.stringify(mode)}==='permanent'?409:submits===1?503:200;
        res.writeHead(status,{'Content-Type':'application/json','Retry-After':'0'});
        res.end(JSON.stringify(status===200?{submission_id:'sub_original',state:'pending_review',idempotent_replay:true}:{error:{id:'synthetic_refusal',message:'synthetic'}}));
      });
    });
    server.listen(0,'127.0.0.1',()=>fs.writeFileSync(${JSON.stringify(portFile)},String(server.address().port)));
  `);
  const server = startServer(script, [], portFile);
  t.after(() => { server.stop(); fs.rmSync(dir, { recursive: true, force: true }); });
  const artifact = path.join(dir, 'artifact.tgz');
  fs.writeFileSync(artifact, 'original artifact');
  // The identity token and npm's version document come from the shared fake.
  const integrity = `sha512-${crypto.createHash('sha512').update('original artifact').digest('base64')}`;
  const fakeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-retry-fakes-'));
  const fakeConfig = path.join(fakeDir, 'config.json'), fakePort = path.join(fakeDir, 'port');
  fs.writeFileSync(fakeConfig, JSON.stringify({ requestToken: 'rt', versions: { 'retry-fixture@1.0.0': { integrity } } }));
  const fakes = startServer(path.join(__dirname, 'helpers', 'fake-npm-oidc.mjs'), [fakePort, fakeConfig, path.join(fakeDir, 'log')], fakePort);
  t.after(() => { fakes.stop(); fs.rmSync(fakeDir, { recursive: true, force: true }); });
  return { run: () => runAction({ CR_MODE: 'submit', CR_FLOW: 'published', CR_ARTIFACT: artifact,
    CR_NAME: 'retry-fixture', CR_VERSION: '1.0.0',
    CR_REGISTRY: `${fakes.url}/registry`, CR_REGISTRY_POLL_MS: '100',
    ACTIONS_ID_TOKEN_REQUEST_URL: `${fakes.url}/oidc?api-version=2.0`, ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'rt',
    CR_REPO: 'https://github.com/test/retry', CR_COMMIT: '1'.repeat(40), CR_SUBMIT_ENDPOINT: server.url }),
    seen: () => fs.readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse) };
}

for (const mode of ['submit-503', 'submit-reset']) {
  test(`submit integration: ${mode} retains one upload and byte-identical replay`, t => {
    const stub = gate(t, mode), run = stub.run();
    assert.equal(run.code, 0, run.stderr);
    const seen = stub.seen();
    assert.equal(seen.filter(r => r.url === '/v1/artifacts').length, 1);
    const submits = seen.filter(r => r.url === '/v1/submit');
    assert.equal(submits.length, 2);
    assert.equal(submits[0].body, submits[1].body);
    assert.equal(submits[0].headers['idempotency-key'], submits[1].headers['idempotency-key']);
    assert.equal(run.outputs['submission-id'], 'sub_original');
  });
}

for (const mode of ['upload-reset', 'upload-503', 'permanent']) {
  test(`submit integration: ${mode} stops without replaying an unsafe upload or permanent refusal`, t => {
    const stub = gate(t, mode), run = stub.run();
    assert.equal(run.code, 3);
    const seen = stub.seen();
    assert.equal(seen.filter(r => r.url === '/v1/artifacts').length, 1);
    assert.equal(seen.filter(r => r.url === '/v1/submit').length, mode === 'permanent' ? 1 : 0);
  });
}
