/**
 * The local last-known-revoked cache.
 *
 * Fail-open says: when the verify endpoint is unreachable,
 * warn and exit 0 rather than blocking a deploy on an outage. That rule has one
 * carve-out - a digest this client has previously seen `revoked` still fails,
 * even with the endpoint down.
 *
 * Without somewhere to keep that knowledge, the carve-out is empty: a fresh
 * process has seen nothing, so every unreachable-endpoint run fails open on
 * everything, and an attacker who can break the connection can ship a revoked
 * build. This file is what makes the exception real across runs.
 *
 * What it is:
 *
 *   - append-only, keyed on the TAGGED digest (`sha256:<hex>`), so a digest can
 *     never be confused with the same hex under another algorithm
 *   - one JSON file, default `~/.coderoot/revoked-cache.json`
 *   - entries are never evicted by age. A revocation does not expire, and a
 *     cache that forgets one is worse than no cache - it would fail open on
 *     exactly the digest it was built to catch
 *   - it only ever ADDS a failure. A digest absent from the cache is not
 *     treated as good, and the cache is never consulted when the endpoint is
 *     reachable, so a revocation that is later lifted upstream is still
 *     observed correctly on any successful query
 *
 * What it is not: a verdict store. It answers one question - "have I ever seen
 * this exact digest revoked?" - and nothing else.
 */
export interface RevokedEntry {
    /** Tagged digest, e.g. "sha256:<64 hex>". */
    digest: string;
    /** When this client first saw it revoked, ISO 8601 UTC. */
    seenAt: string;
    /** Coordinates, when known - for the human reading the file. */
    purl?: string;
}
export declare function defaultCachePath(): string;
export declare class RevokedCache {
    private readonly file;
    private readonly digests;
    private entries;
    private dirty;
    constructor(file?: string);
    /**
     * A malformed or unreadable cache must never take the run down: it is an
     * optimization on top of the endpoint's answer, not a source of truth.
     */
    private load;
    /** Has this exact tagged digest ever been seen revoked? */
    has(taggedDigest: string): boolean;
    /** Record a revocation. Idempotent. */
    add(taggedDigest: string, purl?: string): void;
    /** Persist if anything was added. Failure to write is reported, not thrown. */
    flush(): {
        written: boolean;
        error?: string;
    };
    get size(): number;
    get path(): string;
    /** The Set the verify functions take, backed by this cache. */
    asSet(): Set<string>;
}
