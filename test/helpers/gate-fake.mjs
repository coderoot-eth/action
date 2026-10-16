// A stand-in for the gate's two client routes, POST /v1/artifacts and
// POST /v1/submit, as spec/submit.md in @coderoot-eth/verify describes them.
// It reads identity-token claims without checking the signature.

import crypto from 'node:crypto';
import http from 'node:http';

const ISSUER = 'https://token.actions.githubusercontent.com';
const AUDIENCE = 'secure.coderoot.app';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const LINK = {
  repository_id: '1375901957',
  repository_owner_id: '42622955',
  workflow: '.github/workflows/env-publish.yml',
  packages: ['@vitrotech/gate-spike-a', '@vitrotech/gate-spike-b'],
};

class Refusal extends Error {
  constructor(status, id, detail = {}) {
    super(id);
    Object.assign(this, { status, id, detail });
  }
}

const digest = (alg, bytes) => `${alg}:${crypto.createHash(alg).update(bytes).digest('hex')}`;
const npmPurl = (name, version) => `pkg:npm/${name.replace(/^@/, '%40')}@${version}`;
const ulid = (prefix) => `${prefix}_${crypto.randomBytes(13).toString('hex').toUpperCase().slice(0, 26)}`;

function claimsOf(authorization) {
  const token = /^Bearer (.+)$/.exec(authorization || '')?.[1] || '';
  const parts = token.split('.');
  if (parts.length !== 3) throw new Refusal(403, 'github_oidc_required');
  let claims;
  try {
    claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    throw new Refusal(401, 'credential_invalid', { reason: 'malformed' });
  }
  if (claims.iss !== ISSUER) throw new Refusal(401, 'credential_invalid', { reason: 'issuer' });
  if (claims.aud !== AUDIENCE) throw new Refusal(401, 'credential_invalid', { reason: 'audience' });
  if (!(claims.exp > Date.now() / 1000)) throw new Refusal(401, 'credential_invalid', { reason: 'expired' });
  return claims;
}

function fileFrom(req, body) {
  const type = req.headers['content-type'] || '';
  const boundary = /boundary=(.+)$/.exec(type)?.[1];
  if (!boundary) return body;
  const text = body.toString('latin1');
  const start = text.indexOf('\r\n\r\n', text.indexOf('name="file"')) + 4;
  const end = text.indexOf(`\r\n--${boundary}`, start);
  if (start < 4 || end < 0) throw new Refusal(400, 'body_invalid', { path: 'file' });
  return body.subarray(start, end);
}

export function createGate({ link = LINK } = {}) {
  const uploads = new Map();
  const submissions = new Map();
  const byKey = new Map();

  function upload(req, body) {
    claimsOf(req.headers.authorization);
    const bytes = fileFrom(req, body);
    if (bytes.length === 0) throw new Refusal(400, 'body_invalid', { path: 'file' });
    const receipt = {
      upload_id: ulid('upl'),
      size_bytes: bytes.length,
      hashes: [digest('sha256', bytes), digest('sha512', bytes)],
      expires_at: new Date(Date.now() + 3600e3).toISOString(),
    };
    uploads.set(receipt.upload_id, { bytes, receipt });
    return [201, receipt];
  }

  function submit(req, raw) {
    const claims = claimsOf(req.headers.authorization);
    const key = req.headers['idempotency-key'];
    if (!key) throw new Refusal(400, 'idempotency_key_missing');
    const previous = byKey.get(key);
    if (previous) {
      if (!previous.raw.equals(raw)) throw new Refusal(409, 'idempotency_key_reused');
      return [200, { ...previous.response, idempotent_replay: true }];
    }
    let body;
    try {
      body = JSON.parse(raw.toString('utf8'));
    } catch {
      throw new Refusal(400, 'body_invalid', { path: '$' });
    }
    if (!['published', 'staged'].includes(body.flow)) throw new Refusal(400, 'body_invalid', { path: 'flow' });
    const { name, version } = body.coordinates || {};
    const workflow = String(claims.workflow_ref || '').split('@')[0].replace(`${claims.repository}/`, '');
    if (
      String(claims.repository_id) !== link.repository_id ||
      String(claims.repository_owner_id) !== link.repository_owner_id ||
      workflow !== link.workflow ||
      !link.packages.includes(name)
    ) {
      throw new Refusal(403, 'repository_not_authorized', { repository: claims.repository, workflow, package: name });
    }
    const artifact = uploads.get(body.artifact?.upload_id);
    if (!artifact) throw new Refusal(400, 'artifact_upload_not_found');
    const [sha256, sha512] = artifact.receipt.hashes;
    if (!Array.isArray(body.hashes) || body.hashes.length !== 2) throw new Refusal(400, 'hash_set_incomplete');
    if (body.hashes[0] !== sha256 || body.hashes[1] !== sha512) {
      throw new Refusal(400, 'hash_mismatch', { declared: body.hashes, computed: artifact.receipt.hashes });
    }
    if (body.flow === 'staged') {
      if (!UUID.test(body.stage_id || '')) throw new Refusal(400, 'body_invalid', { path: 'stage_id' });
      if (!body.provenance) throw new Refusal(422, 'staged_proof_unavailable');
      const bundle = uploads.get(body.provenance.upload_id);
      if (!bundle) throw new Refusal(400, 'artifact_upload_not_found');
      if (bundle.receipt.hashes[0] !== body.provenance.sha256) {
        throw new Refusal(422, 'provenance_invalid', { reason: 'the bundle does not hash to provenance.sha256' });
      }
      let subject;
      try {
        const parsed = JSON.parse(bundle.bytes.toString('utf8'));
        subject = JSON.parse(Buffer.from(parsed.dsseEnvelope.payload, 'base64').toString('utf8')).subject;
      } catch {
        throw new Refusal(422, 'provenance_invalid', { reason: 'not a Sigstore bundle with a DSSE statement' });
      }
      if (!Array.isArray(subject) || subject.length !== 1 || subject[0].name !== npmPurl(name, version) || `sha512:${subject[0].digest?.sha512}` !== sha512) {
        throw new Refusal(422, 'provenance_invalid', { reason: 'the subject is not this release' });
      }
    }
    const identity = `npm:${name}@${version}`;
    if (submissions.has(identity)) throw new Refusal(409, 'package_identity_pending', { package_identity: identity });
    const id = ulid('sub');
    const response = {
      submission_id: id,
      state: 'pending_review',
      policy_grade: 'human-required',
      package_identity: identity,
      hashes: body.hashes,
      flow: body.flow,
      attestation: { state: 'none', eas_uid: null, tx_hash: null },
      publish: { state: 'none', registry_url: null },
      review_url: `https://coderoot.app/review/detail?id=${id}`,
      idempotent_replay: false,
    };
    submissions.set(identity, response);
    byKey.set(key, { raw, response });
    return [201, response];
  }

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      let status;
      let payload;
      try {
        if (req.method === 'POST' && req.url === '/v1/artifacts') [status, payload] = upload(req, body);
        else if (req.method === 'POST' && req.url === '/v1/submit') [status, payload] = submit(req, body);
        else throw new Refusal(404, 'not_found');
      } catch (error) {
        if (!(error instanceof Refusal)) throw error;
        status = error.status;
        payload = { error: { id: error.id, message: error.id, detail: error.detail, request_id: ulid('req') } };
      }
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(payload));
    });
  });

  return {
    listen: (port, host) =>
      new Promise((resolve) => server.listen(port, host, () => resolve(`http://${host}:${server.address().port}`))),
    close: () => server.close(),
  };
}
