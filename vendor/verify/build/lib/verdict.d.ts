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
import { DigestSet } from './digest';
export type Verdict = 'verified' | 'attested-bytes-unproven' | 'unregistered' | 'revoked';
/** Where the digest we asked about came from. */
export type HashSource = 'lockfile' | 'bytes' | 'registry' | 'sbom-hint' | 'none';
/**
 * One attestation as the endpoint reports it.
 *
 * `uid` is the EAS attestation UID. It is recorded so a third party can re-check
 * the attestation directly on EAS without going through CodeRoot - which is the
 * point of an evidence record that outlives the run.
 */
export interface AttestationRef {
    uid: string;
    attester?: string | undefined;
    revokedOnChain?: boolean | undefined;
}
export interface VerdictResult {
    verdict: Verdict;
    /** The tagged digest actually queried, or null when no digest was obtainable. */
    queried: string | null;
    hashSource: HashSource;
    /** Why this verdict, in words - carried into the evidence record. */
    reason: string;
    /**
     * True when the answer could not be fully checked: the endpoint was
     * unreachable, or it answered but could not read the gate's revocations, so
     * a revoke made in the last minutes may be missing. A
     * release job fails on this; other jobs warn.
     */
    degraded?: boolean | undefined;
    /** True when no answer came back at all (unreachable, or a non-2xx). Implies `degraded`. */
    unreachable?: boolean | undefined;
    /**
     * True when an acquired digest disagreed with the digest the endpoint holds
     * for these coordinates. Not a verdict (the four are closed) - a flag on top
     * of one. See `compareContentHash`.
     */
    mismatch?: boolean | undefined;
    contentHash?: string | undefined;
    totalAttestations?: number | undefined;
    revokedAttestations?: number | undefined;
    /** EAS attestation UIDs backing this answer, for independent re-checking. */
    attestations?: AttestationRef[] | undefined;
    /**
     * True when any unrevoked attestation behind this verdict was produced by an
     * agent whose CPoA is now revoked. `null` means the chain could not be read -
     * the link exists but its state is unknown. The verdict itself never changes
     * on this; a caller treats the flag as a refusal.
     */
    authorCpoaRevoked?: boolean | null | undefined;
    /** The revoked CPoA UIDs behind `authorCpoaRevoked`. */
    authorCpoaRevokedUids?: string[] | undefined;
}
export interface VerifyOptions {
    baseUrl?: string;
    timeoutMs?: number;
    /** Digests previously seen as revoked, tagged. Survives an unreachable endpoint. */
    revokedCache?: Set<string>;
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
export declare function compareContentHash(acquiredSha256: string, endpointContentHash: string | undefined): boolean;
/**
 * Verify one acquired digest.
 *
 * `hashSource` is required because it changes the meaning of the answer: a
 * digest that exists only inside an SBOM (`sbom-hint`) is not evidence and must
 * never yield `verified`, however the endpoint replies. Measured: cdxgen writes a correspondence-free SHA-256 for
 * 100% of its Go components, so trusting the document would report a false
 * mismatch for every one of them.
 */
export declare function verifyDigest(digests: DigestSet | null, hashSource: HashSource, options?: VerifyOptions): Promise<VerdictResult>;
/**
 * Look up by coordinates. Capped at `attested-bytes-unproven` by construction:
 * this route is an index probe, and a name/version match is not proof of bytes.
 */
export declare function probeCoordinates(registry: string, name: string, version: string, options?: VerifyOptions): Promise<VerdictResult>;
/**
 * Parse a user-supplied digest and tag it for querying.
 *
 * Both algorithms pass through; sha512 is no longer rejected. A sha512 query
 * against a record only ever indexed by sha256 (a v1 attestation) legitimately
 * comes back unregistered - the index's answer, not a client-side block.
 */
export declare function assertQueryable(input: string): string;
