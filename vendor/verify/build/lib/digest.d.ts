/**
 * Algorithm-tagged digests for artifact verification. Artifact verification
 * needs SHA-512, and needs the algorithm to travel with the digest.
 *
 * Why both algorithms, always, from the same read:
 *
 *   - npm publishes `dist.integrity` as SHA-512. Measured over a corpus of real SBOMs,
 *     every npm package carrying any digest carries SHA-512 (3,851 of 5,541);
 *     not one is SHA-256-only.
 *   - SHA-256 still reaches more of the ecosystem: a v1 attestation (most of
 *     it) is indexed by SHA-256 only, so a SHA-512 query against one comes
 *     back honestly `unregistered` rather than finding it. A direct SHA-512
 *     query against a v2 record works correctly. verifyDigest in
 *     lib/verdict.ts sends SHA-256 when it is held, for exactly this reach
 *     reason, and SHA-512 directly otherwise.
 *
 * A SHA-256 cannot be derived from a SHA-512, or the reverse - they are
 * independent one-way functions. The only bridge between the registry's
 * SHA-512 and the API's SHA-256 is the artifact bytes themselves, so whenever
 * we hold the bytes we compute both at once and keep them together.
 */
export type DigestAlgorithm = 'sha256' | 'sha512';
/** Both digests of one byte string, plus the length they were taken over. */
export interface DigestSet {
    sha256: string;
    sha512: string;
    bytes: number;
}
/** Compute both digests over a buffer in one pass over the same bytes. */
export declare function digestBuffer(data: Uint8Array): DigestSet;
/** Compute both digests of a file. Throws if the file is missing. */
export declare function digestFile(filePath: string): DigestSet;
/** Render as `sha256:<hex>` / `sha512:<hex>` - the form the submit contract uses. */
export declare function tagged(algorithm: DigestAlgorithm, hex: string): string;
/** Both digests of a DigestSet in tagged form, SHA-256 first (the submit contract's `hashes[]` order). */
export declare function taggedPair(set: DigestSet): string[];
/**
 * Parse `sha256:<hex>`, `sha512:<hex>`, `0x<hex>` or bare hex.
 *
 * The algorithm is inferred from length ONLY when untagged, and never used to
 * identify a digest whose algorithm was declared: PyPI's `blake2b_256` is also
 * 64 hex characters, so length alone cannot prove an algorithm. A tagged input
 * whose body length contradicts its tag is rejected rather than reinterpreted.
 */
export declare function parseDigest(input: string): {
    algorithm: DigestAlgorithm;
    hex: string;
};
/**
 * Decode an npm Subresource Integrity string (`sha512-<base64>`) to tagged hex.
 *
 * This is what `package-lock.json` `.integrity` and the packument's
 * `dist.integrity` both carry. SRI may hold several space-separated entries;
 * the strongest supported one wins.
 */
export declare function parseIntegrity(integrity: string): {
    algorithm: DigestAlgorithm;
    hex: string;
};
