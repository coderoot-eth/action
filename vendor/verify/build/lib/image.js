"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.realPlatforms = realPlatforms;
exports.resolveImageDigest = resolveImageDigest;
exports.crossCheckAgainstCrane = crossCheckAgainstCrane;
const child_process_1 = require("child_process");
const digest_1 = require("./digest");
const OCI_INDEX = 'application/vnd.oci.image.index.v1+json';
const DOCKER_MANIFEST_LIST = 'application/vnd.docker.distribution.manifest.list.v2+json';
const INDEX_MEDIA_TYPES = new Set([OCI_INDEX, DOCKER_MANIFEST_LIST]);
/**
 * Raw manifest bytes for a reference, exactly as the registry served them.
 * Kept as bytes (not crane's re-serialized JSON) because SHA-512 of the
 * manifest is only meaningful over the bytes that were actually served -
 * re-serializing JSON can reorder keys or change whitespace and silently
 * change the hash of "the same" document.
 */
function craneManifestBytes(ref) {
    try {
        return (0, child_process_1.execFileSync)('crane', ['manifest', ref], { maxBuffer: 64 * 1024 * 1024 });
    }
    catch (error) {
        throw new Error(`crane manifest ${ref} failed: ${error.message}`);
    }
}
function craneDigest(ref) {
    try {
        return (0, child_process_1.execFileSync)('crane', ['digest', ref], { encoding: 'utf8' }).trim();
    }
    catch (error) {
        throw new Error(`crane digest ${ref} failed: ${error.message}`);
    }
}
/**
 * Real platform manifests only - decoy attestation-manifest entries dropped.
 * See module docstring for why this filter exists.
 */
function realPlatforms(manifests) {
    return manifests.filter((m) => {
        const platform = m.platform || {};
        const isAttestation = m.annotations?.['vnd.docker.reference.type'] === 'attestation-manifest';
        const isUnknownPlatform = platform.architecture === 'unknown' || platform.os === 'unknown';
        return !isAttestation && !isUnknownPlatform;
    });
}
/** Resolve `ref` (tag or digest pin) to the digest that should be attested. */
function resolveImageDigest(ref) {
    const bytes = craneManifestBytes(ref);
    let parsed;
    try {
        parsed = JSON.parse(bytes.toString('utf8'));
    }
    catch (error) {
        throw new Error(`could not parse manifest for ${ref} as JSON: ${error.message}`);
    }
    const digests = (0, digest_1.digestBuffer)(bytes);
    const sha256Tagged = (0, digest_1.tagged)('sha256', digests.sha256);
    const sha512Tagged = (0, digest_1.tagged)('sha512', digests.sha512);
    if (parsed.mediaType && INDEX_MEDIA_TYPES.has(parsed.mediaType)) {
        const all = Array.isArray(parsed.manifests) ? parsed.manifests : [];
        const platforms = realPlatforms(all);
        return {
            kind: 'index',
            digest: sha256Tagged,
            sha512: sha512Tagged,
            platformCount: platforms.length,
            attestationManifestCount: all.length - platforms.length,
            platforms: platforms.map((p) => ({
                digest: p.digest,
                os: p.platform?.os,
                architecture: p.platform?.architecture,
                variant: p.platform?.variant,
            })),
            raw: parsed,
        };
    }
    return {
        kind: 'single',
        digest: sha256Tagged,
        sha512: sha512Tagged,
        raw: parsed,
    };
}
/**
 * Cross-check `resolveImageDigest`'s answer against `crane digest <ref>`
 * called independently. Throws if they disagree - that
 * disagreement is itself the finding a naive implementation would hide.
 */
function crossCheckAgainstCrane(ref, resolved) {
    const craneAnswer = craneDigest(ref);
    if (craneAnswer.trim() !== resolved.digest) {
        throw new Error(`digest mismatch for ${ref}: resolveImageDigest got ${resolved.digest}, ` +
            `crane digest got ${craneAnswer}. Do not attest either until this is understood.`);
    }
    return craneAnswer;
}
//# sourceMappingURL=image.js.map