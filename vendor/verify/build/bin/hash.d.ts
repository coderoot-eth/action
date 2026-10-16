#!/usr/bin/env node
/**
 * coderoot hash <file>
 * coderoot hash --image <ref>
 *
 * SHA-256 and SHA-512 of a file, an npm tarball, or a container image
 * manifest, algorithm-tagged.
 *
 * No network for the file form. This is the local half of the verification
 * story: it tells you what you are holding, so you can compare it against
 * what a registry or an attestation claims. The comparison itself is
 * `coderoot verify`.
 *
 *   --json          machine-readable output
 *   --algorithm     sha256 | sha512 | both (default: both) - file form only
 *   --image <ref>   resolve a registry reference instead of a local file.
 *                   Requires `crane` on PATH.
 *
 * Both digests come from one read of the bytes, because neither converts to
 * the other: npm publishes SHA-512 in `dist.integrity`, while the live verify
 * schema records SHA-256 only. Holding the artifact is the only bridge.
 *
 * `--image` resolves the digest that should be attested for a registry
 * reference: the index digest for a multi-arch image, the single
 * manifest digest otherwise. See lib/image.ts for the index-vs-single-arch
 * and attestation-manifest-filtering rules this depends on.
 */
/** Run the hash command. Returns an exit code; never exits. */
export declare function runHash(argv: string[]): number;
