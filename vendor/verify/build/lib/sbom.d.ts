/**
 * CycloneDX + SPDX parsing for the batch verification client, with these
 * measured rules:
 *
 *  - Read all three hash field paths. `cyclonedx-npm` writes a correct
 *    SHA-512 to `components[].externalReferences[].hashes[]`, two levels down;
 *    a parser reading only `components[].hashes[]` reports zero coverage for it
 *    silently. Measured: 629 hashes on axios, 710 on undici, all there.
 *  - Dedupe on the full purl, never the name. Counting by name
 *    conflates versions and inflates coverage.
 *  - The algorithm always travels with the digest. PyPI's `blake2b_256` is also
 *    64 hex characters, so digest length can never imply an algorithm.
 *  - Exclude SPDX `packageVerificationCode`: it is a hash over a file set, not
 *    of the published artifact.
 *
 * Everything a document merely *declares* is recorded as `sbom-hint` and never
 * as evidence. The acquirer decides what is obtainable; this layer
 * only reports what the document says.
 */
export type SbomFormat = 'cyclonedx' | 'spdx' | 'npm-lockfile';
/** A digest as the document stated it, with where it was found. */
export interface DeclaredHash {
    /** Lowercased algorithm as declared, e.g. "sha256", "sha512", "sha1". */
    algorithm: string;
    hex: string;
    /** Which field path carried it. */
    path: 'components[].hashes[]' | 'externalReferences[].hashes[]' | 'packages[].checksums[]' | 'package-lock.packages[].integrity';
    /** For externalReferences: "distribution", "vcs", … - says what the digest is OF. */
    refType?: string | undefined;
    refUrl?: string | undefined;
}
export interface SbomComponent {
    /** Full purl, URL-decoded. The dedupe key. Null when the document gives none. */
    purl: string | null;
    /** Ecosystem from the purl ("npm", "pypi", "apk", "deb", "golang", "maven"). */
    ecosystem: string | null;
    name: string;
    version: string | null;
    declared: DeclaredHash[];
}
export interface ParsedSbom {
    format: SbomFormat;
    /** Components carrying a purl - the only ones that can be identity-joined. */
    components: SbomComponent[];
    /**
     * Components with no purl. Syft emits `type: file` entries whose digests are
     * of files on disk, not of a published artifact; with no purl there is no
     * identity to join on, so they are counted and then set aside.
     */
    purllessCount: number;
    purllessHashCount: number;
}
/** Detect the format and parse. Throws on a document that is neither. */
export declare function parseSbom(raw: string): ParsedSbom;
export declare function parseSbomFile(filePath: string): ParsedSbom;
export declare function parseLockfile(raw: string): ParsedSbom;
export declare function parseLockfileFile(filePath: string): ParsedSbom;
/**
 * Distinct components by full purl.
 *
 * A package used by two projects appears twice in a document; counting
 * occurrences would report it as two packages. Coverage
 * percentages must be taken over this, not over the raw list.
 */
export declare function distinctByPurl(components: SbomComponent[]): SbomComponent[];
/** Pick the strongest declared digest, or null. sha1/md5 are never strong. */
export declare function strongestDeclared(component: SbomComponent): DeclaredHash | null;
