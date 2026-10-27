// Usage: node fake-npm-oidc.mjs <port-file> <config-file> <log-file>
//
// Stands in for two services the submit flows talk to:
//   GET /oidc?...&audience=<aud>   GitHub's identity-token endpoint
//   GET /registry/<name>/<version> npm's version document
//   GET /registry/-/npm/v1/attestations/<name>@<version>  npm's attestations
// The config file is read per request, so a test can change it between runs:
//   { requestToken, oidcStatus?,
//     versions: { "<name>@<version>": { integrity, visibleAfterMs?, provenance? = true, provenanceAfterMs? } } }

import fs from 'node:fs';
import http from 'node:http';

const [portFile, configFile, logFile] = process.argv.slice(2);
const firstSeen = new Map();

const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

const server = http.createServer((req, res) => {
  const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
  const url = new URL(req.url, 'http://localhost');
  fs.appendFileSync(logFile, JSON.stringify({ path: url.pathname, query: url.search, authorization: req.headers.authorization || '' }) + '\n');
  const send = (status, body) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };

  if (url.pathname === '/oidc') {
    if (config.oidcStatus) return send(config.oidcStatus, { message: 'refused' });
    if (req.headers.authorization !== `bearer ${config.requestToken}`) return send(401, { message: 'bad request token' });
    const claims = {
      iss: 'https://token.actions.githubusercontent.com',
      aud: url.searchParams.get('audience'),
      exp: Math.floor(Date.now() / 1000) + 300,
      repository: 'VitroTech/coderoot-gate-spike',
      repository_id: '1375901957',
      repository_owner_id: '42622955',
      workflow_ref: 'VitroTech/coderoot-gate-spike/.github/workflows/env-publish.yml@refs/heads/main',
    };
    return send(200, { value: `${enc({ alg: 'RS256', typ: 'JWT' })}.${enc(claims)}.c2ln` });
  }

  const a = /^\/registry\/-\/npm\/v1\/attestations\/(.+)$/.exec(url.pathname);
  if (a) {
    const key = decodeURIComponent(a[1]);
    const entry = config.versions?.[key];
    if (!entry || entry.provenance === false || !firstSeen.has(key)) return send(404, { error: 'not found' });
    if (Date.now() - firstSeen.get(key) < (entry.provenanceAfterMs || 0)) return send(404, { error: 'not found' });
    return send(200, {
      attestations: [
        { predicateType: 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1' },
        { predicateType: 'https://slsa.dev/provenance/v1' },
      ],
    });
  }

  const m = /^\/registry\/(.+)\/([^/]+)$/.exec(url.pathname);
  if (m) {
    const key = `${decodeURIComponent(m[1])}@${decodeURIComponent(m[2])}`;
    const entry = config.versions?.[key];
    if (!entry) return send(404, { error: 'version not found' });
    if (!firstSeen.has(key)) firstSeen.set(key, Date.now());
    if (Date.now() - firstSeen.get(key) < (entry.visibleAfterMs || 0)) return send(404, { error: 'version not found' });
    return send(200, { name: key.slice(0, key.lastIndexOf('@')), version: m[2], dist: { integrity: entry.integrity } });
  }
  send(404, { error: 'not found' });
});

server.listen(0, '127.0.0.1', () => fs.writeFileSync(portFile, String(server.address().port)));
