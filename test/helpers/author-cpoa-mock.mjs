// Minimal stand-in for verify.coderoot.app's /verify/<hash> route, serving
// fixed authorCpoaRevoked responses for three fixed test digests. There is no
// live fixture with authorCpoaRevoked: true today (both live fixtures are
// human-authored, refUid zero), so this mock is how the Action's refusal path
// gets end-to-end coverage.
//
// Usage: node author-cpoa-mock.mjs <port-file>

import fs from 'node:fs';
import http from 'node:http';

const [portFile] = process.argv.slice(2);

const KILLED = 'c'.repeat(64);
const UNREADABLE = 'd'.repeat(64);
const CLEAN = 'a'.repeat(64);

const server = http.createServer((req, res) => {
  const url = decodeURIComponent(req.url ?? '');
  const send = (body) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };

  if (url.includes(KILLED)) {
    return send({
      verdict: 'verified',
      totalAttestations: 1,
      authorCpoaRevoked: true,
      authorCpoaRevokedUids: [`0x${'e1'.repeat(32)}`],
    });
  }
  if (url.includes(UNREADABLE)) {
    return send({
      verdict: 'verified',
      totalAttestations: 1,
      authorCpoaRevoked: null,
      authorCpoaRevokedUids: [],
    });
  }
  if (url.includes(CLEAN)) {
    return send({ verdict: 'verified', totalAttestations: 1, authorCpoaRevoked: false });
  }
  send({ verdict: 'unregistered' });
});

server.listen(0, '127.0.0.1', () => fs.writeFileSync(portFile, String(server.address().port)));
