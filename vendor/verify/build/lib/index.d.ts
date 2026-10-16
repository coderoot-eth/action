/**
 * The library behind the `coderoot` CLI. The purl is only an index; the hash
 * is the trust: nothing here reports `verified` from a name and version alone.
 */
export { digestBuffer, digestFile, parseDigest, parseIntegrity, tagged, taggedPair } from './digest';
export type { DigestAlgorithm, DigestSet } from './digest';
export { verifyDigest, probeCoordinates, compareContentHash, assertQueryable } from './verdict';
export type { Verdict, HashSource, VerdictResult, VerifyOptions, AttestationRef } from './verdict';
export { parseSbom, parseSbomFile, parseLockfile, parseLockfileFile, distinctByPurl, strongestDeclared } from './sbom';
export type { SbomFormat, SbomComponent, ParsedSbom, DeclaredHash } from './sbom';
export { EXIT, buildReport, summarize, exitCodeFor, renderSummary, toEvidenceRecord } from './report';
export type { EvidenceRecord, RunReport } from './report';
export { RevokedCache, defaultCachePath } from './revoked-cache';
export type { RevokedEntry } from './revoked-cache';
export { resolveImageDigest, crossCheckAgainstCrane, realPlatforms } from './image';
export type { ResolvedImageDigest, ManifestPlatform } from './image';
