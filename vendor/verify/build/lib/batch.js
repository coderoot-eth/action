"use strict";
/**
 * Verify a list of components: obtain a digest for each, ask the endpoint, and
 * check the bytes against what is attested for the same name and version.
 *
 * The tier order is lockfile -> bytes -> registry -> sbom-hint -> none. For npm,
 * the client downloads the tarball and hashes it itself whenever it can: it
 * then holds the artifact, not someone else's record of what it should be.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyComponent = verifyComponent;
exports.verifyComponentDetailed = verifyComponentDetailed;
exports.verifyComponents = verifyComponents;
const sbom_1 = require("./sbom");
const verdict_1 = require("./verdict");
const digest_1 = require("./digest");
const report_1 = require("./report");
/** Run `fn` over items with a fixed number of workers, preserving order. */
async function pool(items, workers, fn) {
    const out = new Array(items.length);
    let cursor = 0;
    await Promise.all(Array.from({ length: Math.max(1, workers) }, async () => {
        while (cursor < items.length) {
            const index = cursor++;
            out[index] = await fn(items[index]);
        }
    }));
    return out;
}
/** A declared digest, shaped for the result. */
function fromDeclared(declared, hashSource) {
    if (!declared)
        return { hashSource: 'none', digests: [], declared: null };
    const digests = [`${declared.algorithm}:${declared.hex}`];
    if (declared.algorithm === 'sha256')
        return { hashSource, sha256: declared.hex, digests, declared };
    if (declared.algorithm === 'sha512')
        return { hashSource, sha512: declared.hex, digests, declared };
    return { hashSource, digests, declared };
}
async function acquire(component, offline, declaredSource, registryUrl = 'https://registry.npmjs.org') {
    const declared = (0, sbom_1.strongestDeclared)(component);
    if (offline || component.ecosystem !== 'npm' || !component.version)
        return fromDeclared(declared, declaredSource);
    try {
        const packument = (await (await fetch(`${registryUrl.replace(/\/+$/, '')}/${component.name}`)).json());
        const tarball = packument.versions?.[component.version]?.dist?.tarball;
        if (!tarball)
            return fromDeclared(declared, declaredSource);
        const bytes = new Uint8Array(await (await fetch(tarball)).arrayBuffer());
        const set = (0, digest_1.digestBuffer)(bytes);
        return {
            hashSource: 'bytes',
            sha256: set.sha256,
            sha512: set.sha512,
            digests: [`sha256:${set.sha256}`, `sha512:${set.sha512}`],
            declared,
        };
    }
    catch {
        return fromDeclared(declared, declaredSource);
    }
}
/** Verify one component and return its evidence record. */
async function verifyComponent(component, options) {
    return (await verifyComponentDetailed(component, options)).record;
}
/** As verifyComponent, plus the endpoint's full answer (attesters and on-chain times). */
async function verifyComponentDetailed(component, options) {
    const verifyOptions = options.verify ?? {};
    const acquired = await acquire(component, options.offline ?? false, options.declaredSource, options.registryUrl);
    const outcome = options.offline
        ? {
            verdict: 'attested-bytes-unproven',
            queried: null,
            hashSource: acquired.hashSource,
            reason: 'Offline: resolved and classified, but not queried.',
        }
        : await (0, verdict_1.verifyDigest)(acquired.sha256 || acquired.sha512
            ? { sha256: acquired.sha256 ?? '', sha512: acquired.sha512 ?? '', bytes: 0 }
            : null, acquired.hashSource, verifyOptions);
    // Both mismatch checks need bytes the client hashed itself.
    let mismatch = false;
    if (!options.offline && acquired.sha256 && acquired.hashSource === 'bytes' && component.ecosystem === 'npm' && component.version) {
        const coordinates = await (0, verdict_1.probeCoordinates)(component.ecosystem, component.name ?? '', component.version, verifyOptions);
        mismatch = (0, verdict_1.compareContentHash)(acquired.sha256, coordinates.contentHash);
        if (!mismatch && options.declaredSource === 'lockfile' && acquired.declared) {
            const ours = acquired.declared.algorithm === 'sha512' ? acquired.sha512 : acquired.sha256;
            if (ours)
                mismatch = (0, verdict_1.compareContentHash)(ours, acquired.declared.hex);
        }
    }
    const record = (0, report_1.toEvidenceRecord)(component, {
        verdict: outcome.verdict,
        hashSource: outcome.hashSource,
        queried: outcome.queried,
        reason: outcome.reason,
        degraded: outcome.degraded,
        mismatch,
        attestations: outcome.totalAttestations,
        attestationUids: outcome.attestations?.map((a) => a.uid),
        authorCpoaRevoked: outcome.authorCpoaRevoked,
        authorCpoaRevokedUids: outcome.authorCpoaRevokedUids,
    }, acquired.digests);
    return { record, result: { ...outcome, mismatch } };
}
/** Verify components in parallel, preserving their order. */
async function verifyComponents(components, options) {
    let done = 0;
    return pool(components, options.concurrency ?? 8, async (component) => {
        const record = await verifyComponent(component, options);
        options.onProgress?.(++done, components.length);
        return record;
    });
}
//# sourceMappingURL=batch.js.map