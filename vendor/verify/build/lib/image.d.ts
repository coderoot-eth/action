/**
 * Image digest acquisition for `coderoot hash --image`.
 *
 * `coderoot hash` otherwise takes a local file or npm tarball and has no
 * notion of a registry reference. Given `<ref>` (a tag or a digest pin),
 * this resolves the digest that should be attested, and says which one it
 * is and why. The decision this module exists to get right:
 *
 *   - Multi-arch image (the registry returns an index/manifest-list): attest
 *     the INDEX digest, not any one platform's manifest digest. One tag maps
 *     to several legitimate per-platform digests; the index digest is the
 *     one stable value that identifies "this tag, as multi-arch consumers
 *     pull it".
 *   - Single-arch image (the registry returns a single manifest): attest that
 *     manifest digest directly. There is no index to defer to.
 *
 * Measured against `docker.io/library/node:20-alpine`: the index for a BuildKit-built multi-arch image contains not only one
 * manifest per real platform, but also sibling "attestation manifest"
 * entries — `vnd.docker.reference.type: attestation-manifest`,
 * `platform: {architecture: "unknown", os: "unknown"}` — carrying the
 * image's own SBOM/provenance. These are not platforms and must never be
 * counted as one, or a report of "N platforms in this image" double-counts
 * them, the same error as counting occurrences instead of distinct packages.
 * This module filters them out explicitly rather than trusting manifest count.
 *
 * Every function here shells out to `crane`. A result is cross-checked
 * against `crane digest`, and using the same
 * tool for resolution and for the check would hide a shared bug, so
 * `resolveImageDigest` does its own manifest fetch/parse and a caller
 * verifies it against a separately-invoked `crane digest`.
 */
export interface ManifestPlatform {
    digest?: string | undefined;
    os?: string | undefined;
    architecture?: string | undefined;
    variant?: string | undefined;
}
export interface ResolvedImageDigest {
    kind: 'index' | 'single';
    digest: string;
    sha512: string;
    platformCount?: number;
    attestationManifestCount?: number;
    platforms?: ManifestPlatform[];
    raw: unknown;
}
interface RawManifestEntry {
    digest?: string;
    platform?: {
        architecture?: string;
        os?: string;
        variant?: string;
    };
    annotations?: Record<string, string>;
}
/**
 * Real platform manifests only - decoy attestation-manifest entries dropped.
 * See module docstring for why this filter exists.
 */
export declare function realPlatforms(manifests: RawManifestEntry[]): RawManifestEntry[];
/** Resolve `ref` (tag or digest pin) to the digest that should be attested. */
export declare function resolveImageDigest(ref: string): ResolvedImageDigest;
/**
 * Cross-check `resolveImageDigest`'s answer against `crane digest <ref>`
 * called independently. Throws if they disagree - that
 * disagreement is itself the finding a naive implementation would hide.
 */
export declare function crossCheckAgainstCrane(ref: string, resolved: ResolvedImageDigest): string;
export {};
