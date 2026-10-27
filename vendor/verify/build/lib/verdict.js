"use strict";
/**
 * The four-verdict client for the public verify endpoint.
 *
 * Vocabulary:
 *
 *   verified                 an acquired hash matched an attested record
 *   attested-bytes-unproven  a record exists for these coordinates but no
 *                            strong hash was matched - NOT a pass
 *   unregistered             no record exists
 *   revoked                  a record exists and has been revoked
 *
 * Two rules this module enforces rather than assumes:
 *
 * 1. The name@version route can never answer `verified`. /verify/npm/axios/1.7.9
 *    returns "attested-bytes-unproven" while /verify/<that release's sha256>
 *    returns "verified". A coordinate lookup is an index probe, never proof.
 *
 * 2. SHA-256 is tried first when both digests are held. A v1 record is
 *    indexed by SHA-256 only, so a SHA-512 query against one legitimately
 *    comes back unregistered rather than finding it. A v2 record answers a
 *    direct SHA-512 query correctly. SHA-512 is sent directly when it is the
 *    only digest held (a lockfile's own `integrity`, almost always SHA-512).
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.compareContentHash = compareContentHash;
exports.verifyDigest = verifyDigest;
exports.probeCoordinates = probeCoordinates;
exports.assertQueryable = assertQueryable;
const digest_1 = require("./digest");
const DEFAULT_BASE_URL = 'https://verify.coderoot.app';
/** Normalize a digest for comparison: strip any 0x prefix, lowercase. */
function bareHex(value) {
    if (!value)
        return null;
    const raw = value.trim().toLowerCase();
    const body = raw.startsWith('0x') ? raw.slice(2) : raw;
    return /^[0-9a-f]+$/.test(body) ? body : null;
}
/**
 * Compare an acquired digest against the digest the endpoint holds.
 *
 * This is the only place a mismatch is detectable. The hash route answers
 * `unregistered` for a digest it does not hold - it never says "that disagrees
 * with what we have". The coordinate route, though, returns `contentHash` for
 * the release, so an acquired digest can be checked against it.
 *
 * A mismatch means both digests are real and they disagree: the bytes in hand
 * are not the bytes that were attested. That is worth an exit code, but it is
 * NOT a fifth verdict - the four are canonical and closed. It rides as a flag
 * on `attested-bytes-unproven`, which is what such a component is.
 */
function compareContentHash(acquiredSha256, endpointContentHash) {
    const ours = bareHex(acquiredSha256);
    const theirs = bareHex(endpointContentHash);
    if (!ours || !theirs)
        return false; // nothing to compare is not a mismatch
    return ours !== theirs;
}
/**
 * The endpoint's own degraded flag, with its reason. Only an explicit `true`
 * counts: an endpoint that predates the gate read omits the field, and that is
 * not an outage.
 */
function endpointDegraded(body) {
    if (body.degraded !== true)
        return null;
    const why = body.gateRevocation?.note;
    return {
        degraded: true,
        note: `The endpoint could not read the gate's revocations${why ? ` (${why})` : ''}, ` +
            'so a revoke made in the last minutes may be missing.',
    };
}
function normalizeVerdict(raw, fallback) {
    switch ((raw ?? '').toLowerCase()) {
        case 'verified':
            return 'verified';
        case 'attested-bytes-unproven':
            return 'attested-bytes-unproven';
        case 'revoked':
            return 'revoked';
        case 'unregistered':
            return 'unregistered';
        default:
            return fallback;
    }
}
async function getJson(url, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(url, {
            signal: controller.signal,
            headers: { accept: 'application/json' },
        });
        const body = (await response.json().catch(() => ({})));
        return { ok: response.ok, status: response.status, body };
    }
    finally {
        clearTimeout(timer);
    }
}
/**
 * Verify one acquired digest.
 *
 * `hashSource` is required because it changes the meaning of the answer: a
 * digest that exists only inside an SBOM (`sbom-hint`) is not evidence and must
 * never yield `verified`, however the endpoint replies. Measured: cdxgen writes a correspondence-free SHA-256 for
 * 100% of its Go components, so trusting the document would report a false
 * mismatch for every one of them.
 */
async function verifyDigest(digests, hashSource, options = {}) {
    const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
    const timeoutMs = options.timeoutMs ?? 15000;
    // Every early return below sets authorCpoaRevoked: false explicitly, since
    // none of these paths reached a live response to read the field from.
    if (!digests || hashSource === 'none') {
        return {
            verdict: 'attested-bytes-unproven',
            queried: null,
            hashSource: 'none',
            reason: 'No digest could be obtained for this component; nothing was queried.',
            authorCpoaRevoked: false,
        };
    }
    if (hashSource === 'sbom-hint') {
        return {
            verdict: 'attested-bytes-unproven',
            queried: null,
            hashSource,
            reason: 'The only digest available came from the SBOM itself and was confirmable nowhere else. ' +
                'A declared hash is never compared to an attestation.',
            authorCpoaRevoked: false,
        };
    }
    if (!digests.sha256 && !digests.sha512) {
        return {
            verdict: 'attested-bytes-unproven',
            queried: null,
            hashSource,
            reason: 'A digest was acquired but neither sha256 nor sha512 could be queried.',
            authorCpoaRevoked: false,
        };
    }
    // Prefer sha256: it reaches v1 records that predate sha512 as a lookup
    // key. sha512 is sent directly when that's the only digest held.
    const queried = digests.sha256 ? `sha256:${digests.sha256}` : `sha512:${digests.sha512}`;
    // Verify is always asked first. The local revoked cache answers only when
    // verify cannot be read, so an outage cannot pass a digest seen revoked.
    const fromCache = (why) => options.revokedCache?.has(queried)
        ? {
            verdict: 'revoked',
            queried,
            hashSource,
            reason: `Verify could not be read (${why}); this digest was previously observed as revoked by this client (local cache).`,
            authorCpoaRevoked: false,
        }
        : null;
    let response;
    try {
        response = await getJson(`${baseUrl}/verify/${encodeURIComponent(queried)}`, timeoutMs);
    }
    catch (error) {
        const cached = fromCache(error.message);
        if (cached)
            return cached;
        // Anything else is degraded: whether that fails or warns is the caller's
        // call (release jobs fail, other jobs warn).
        return {
            verdict: 'attested-bytes-unproven',
            queried,
            hashSource,
            degraded: true,
            unreachable: true,
            reason: `Verify endpoint unreachable (${error.message}).`,
            authorCpoaRevoked: false,
        };
    }
    if (!response.ok) {
        const cached = fromCache(`HTTP ${response.status}`);
        if (cached)
            return cached;
        return {
            verdict: 'attested-bytes-unproven',
            queried,
            hashSource,
            degraded: true,
            unreachable: true,
            reason: `Verify endpoint answered ${response.status}: ${response.body.error ?? 'no detail'}`,
            authorCpoaRevoked: false,
        };
    }
    const body = response.body;
    const verdict = normalizeVerdict(body.verdict, 'unregistered');
    const partial = endpointDegraded(body);
    if (verdict === 'revoked') {
        options.revokedCache?.add(queried);
    }
    return {
        verdict,
        queried,
        hashSource,
        ...(partial ? { degraded: true } : {}),
        reason: partial ? `${reasonFor(verdict, hashSource)} ${partial.note}` : reasonFor(verdict, hashSource),
        contentHash: body.contentHash,
        totalAttestations: body.totalAttestations,
        revokedAttestations: body.revokedAttestations,
        attestations: extractAttestations(body),
        // `?? false` would coerce an explicit `null` (chain unreadable) to false,
        // silently dropping it. Default only when the endpoint omits the field.
        authorCpoaRevoked: body.authorCpoaRevoked === undefined ? false : body.authorCpoaRevoked,
        authorCpoaRevokedUids: body.authorCpoaRevokedUids,
    };
}
/**
 * Pull EAS attestation UIDs out of a response, for independent re-checking.
 *
 * `attestationUids` is the supported field: a flat list of every UID across
 * both eras, so consumers do not have to know that `attestations[]` is the
 * legacy v0 array and `v1Attestations[]` the current one. The revoked
 * fixture 9f86d081…0a08 returns two UIDs, one from each era.
 *
 * The per-era arrays are still read, but only to enrich a UID with its
 * attester and on-chain revocation state, and only when they happen to carry
 * the same UID. A UID that appears in neither array is still reported.
 */
function extractAttestations(body) {
    const seconds = (value) => {
        const n = Number(value);
        return Number.isFinite(n) && n > 0 ? n : undefined;
    };
    const detail = new Map();
    for (const a of [...(body.attestations ?? []), ...(body.v1Attestations ?? []), ...(body.v2Attestations ?? [])]) {
        if (typeof a?.id === 'string' && a.id.length > 0 && !detail.has(a.id)) {
            const entry = { attester: a.attester, revokedOnChain: a.revokedOnChain };
            const attestedAt = seconds(a.blockTimestamp);
            const revokedAt = seconds(a.revokedAt);
            if (attestedAt !== undefined)
                entry.attestedAt = attestedAt;
            if (revokedAt !== undefined)
                entry.revokedAt = revokedAt;
            detail.set(a.id, entry);
        }
    }
    const uids = (body.attestationUids ?? []).filter((u) => typeof u === 'string' && u.length > 0);
    // Fall back to the per-era arrays for an endpoint that predates the flat list.
    const ordered = uids.length > 0 ? uids : [...detail.keys()];
    const out = ordered.map((uid) => ({ uid, ...(detail.get(uid) ?? {}) }));
    return out.length > 0 ? out : undefined;
}
function reasonFor(verdict, hashSource) {
    switch (verdict) {
        case 'verified':
            return `An acquired ${hashSource} digest matched an attested record.`;
        case 'revoked':
            return 'A record exists for these bytes and has been revoked.';
        case 'unregistered':
            return 'No attested record exists for these bytes.';
        default:
            return 'A record exists for these coordinates but no strong hash was matched.';
    }
}
/**
 * Look up by coordinates. Capped at `attested-bytes-unproven` by construction:
 * this route is an index probe, and a name/version match is not proof of bytes.
 */
async function probeCoordinates(registry, name, version, options = {}) {
    const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
    const timeoutMs = options.timeoutMs ?? 15000;
    const path = `${baseUrl}/verify/${encodeURIComponent(registry)}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
    let response;
    try {
        response = await getJson(path, timeoutMs);
    }
    catch (error) {
        return {
            verdict: 'attested-bytes-unproven',
            queried: null,
            hashSource: 'none',
            degraded: true,
            unreachable: true,
            reason: `Verify endpoint unreachable (${error.message}).`,
            authorCpoaRevoked: false,
        };
    }
    if (!response.ok) {
        return {
            verdict: 'unregistered',
            queried: null,
            hashSource: 'none',
            reason: `No record for ${registry}:${name}@${version}.`,
            authorCpoaRevoked: false,
        };
    }
    const raw = normalizeVerdict(response.body.verdict, 'attested-bytes-unproven');
    // Ruling 2: never let this route report `verified`, whatever it says.
    const verdict = raw === 'verified' ? 'attested-bytes-unproven' : raw;
    const partial = endpointDegraded(response.body);
    const reason = verdict === 'revoked'
        ? 'A record for these coordinates has been revoked.'
        : 'Coordinates matched a record; bytes were not proven (coordinates are an index, not proof).';
    return {
        verdict,
        queried: null,
        hashSource: 'none',
        ...(partial ? { degraded: true } : {}),
        reason: partial ? `${reason} ${partial.note}` : reason,
        contentHash: response.body.contentHash,
        totalAttestations: response.body.totalAttestations,
        revokedAttestations: response.body.revokedAttestations,
        attestations: extractAttestations(response.body),
        authorCpoaRevoked: response.body.authorCpoaRevoked === undefined ? false : response.body.authorCpoaRevoked,
        authorCpoaRevokedUids: response.body.authorCpoaRevokedUids,
    };
}
/**
 * Parse a user-supplied digest and tag it for querying.
 *
 * Both algorithms pass through; sha512 is no longer rejected. A sha512 query
 * against a record only ever indexed by sha256 (a v1 attestation) legitimately
 * comes back unregistered - the index's answer, not a client-side block.
 */
function assertQueryable(input) {
    const { algorithm, hex } = (0, digest_1.parseDigest)(input);
    return `${algorithm}:${hex}`;
}
//# sourceMappingURL=verdict.js.map