// Minimal stand-in for verify.coderoot.app answering while the gate's
// revocations could not be read: HTTP 200 with `degraded: true`.
// The live endpoint only answers this way during a gate outage, so this mock
// is how the Action's "release jobs fail, other jobs warn" rule gets
// end-to-end coverage.
//
// Usage: node degraded-mock.mjs <port-file>

import fs from 'node:fs';
import http from 'node:http';

const [portFile] = process.argv.slice(2);

const GATE_UNREAD_VERIFIED = '9'.repeat(64);
const GATE_UNREAD_UNREGISTERED = '8'.repeat(64);
const GATE_UNREAD_REVOKED = '7'.repeat(64);
const gateUnread = {
  degraded: true,
  gateRevocation: { checked: false, revoked: null, releaseIds: [], note: 'HTTP 500' },
};

const server = http.createServer((req, res) => {
  const url = decodeURIComponent(req.url ?? '');
  const send = (body) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };

  // A lockfile's sha512 integrity of 64 bytes of 0x99 is '9' x 128 in hex.
  if (url.includes(GATE_UNREAD_VERIFIED)) return send({ verdict: 'verified', totalAttestations: 1, ...gateUnread });
  if (url.includes(GATE_UNREAD_UNREGISTERED)) return send({ verdict: 'unregistered', totalAttestations: 0, ...gateUnread });
  if (url.includes(GATE_UNREAD_REVOKED)) {
    return send({ verdict: 'revoked', totalAttestations: 1, revokedAttestations: 1, ...gateUnread });
  }
  send({ verdict: 'verified', totalAttestations: 1, degraded: false });
});

server.listen(0, '127.0.0.1', () => fs.writeFileSync(portFile, String(server.address().port)));
