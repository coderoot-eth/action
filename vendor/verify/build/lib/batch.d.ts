/**
 * Verify a list of components: obtain a digest for each, ask the endpoint, and
 * check the bytes against what is attested for the same name and version.
 *
 * The tier order is lockfile -> bytes -> registry -> sbom-hint -> none. For npm,
 * the client downloads the tarball and hashes it itself whenever it can: it
 * then holds the artifact, not someone else's record of what it should be.
 */
import { SbomComponent } from './sbom';
import { VerifyOptions, VerdictResult } from './verdict';
import { EvidenceRecord } from './report';
export interface BatchOptions {
    /**
     * What a digest the input merely declares counts as. An SBOM's declared hash
     * is a hint and never queried; a package-lock.json's `integrity` is npm's own
     * install-time record, so it is `lockfile` and queried normally.
     */
    declaredSource: 'sbom-hint' | 'lockfile';
    /** Resolve and classify only; never call the network. */
    offline?: boolean;
    /** Parallel lookups (default 8). */
    concurrency?: number;
    verify?: VerifyOptions;
    /** npm registry to fetch packuments and tarballs from (default https://registry.npmjs.org). */
    registryUrl?: string;
    /** Called after each component, with how many are done. */
    onProgress?: (done: number, total: number) => void;
}
/** Verify one component and return its evidence record. */
export declare function verifyComponent(component: SbomComponent, options: BatchOptions): Promise<EvidenceRecord>;
/** As verifyComponent, plus the endpoint's full answer (attesters and on-chain times). */
export declare function verifyComponentDetailed(component: SbomComponent, options: BatchOptions): Promise<{
    record: EvidenceRecord;
    result: VerdictResult;
}>;
/** Verify components in parallel, preserving their order. */
export declare function verifyComponents(components: SbomComponent[], options: BatchOptions): Promise<EvidenceRecord[]>;
