/**
 * Batch verification report + exit codes.
 *
 * Turns a run over an SBOM into one JSON document and one exit status, so a CI
 * job can act on it without parsing prose.
 *
 * Exit codes carry the policy, and the distinction that matters is between
 * "failed" and "cannot be proven":
 *
 *   0  clean - everything verified, or unverifiable by nature
 *   1  revoked - at least one component is revoked (must be impossible to miss)
 *   2  mismatch - an acquired strong digest disagreed with an attested record
 *   3  usage/parse error
 *
 * Alpine can never be verified: APKINDEX publishes SHA-1 and nothing else
 * Exiting non-zero on that would be wrong, and would teach teams to
 * add `continue-on-error: true`, which disables the check they installed.
 */
import { SbomComponent } from './sbom';
import { HashSource, Verdict } from './verdict';
export declare const EXIT: {
    readonly CLEAN: 0;
    readonly REVOKED: 1;
    readonly MISMATCH: 2;
    readonly ERROR: 3;
};
/** One component's outcome. This object is the evidence record (spec/evidence-record.md). */
export interface EvidenceRecord {
    purl: string;
    ecosystem: string | null;
    name: string;
    version: string | null;
    verdict: Verdict;
    hashSource: HashSource;
    /** The tagged digest actually sent, or null when nothing was queried. */
    queried: string | null;
    /** Algorithm of the acquired digest, kept beside it - never inferred later. */
    algorithm: string | null;
    /** Every digest held for this artifact, tagged; may hold more than `queried`. */
    digests: string[];
    reason: string;
    degraded?: boolean;
    /**
     * True when the acquired digest disagreed with the digest the endpoint holds
     * for these coordinates. Rides on top of a verdict; it is not a fifth one.
     */
    mismatch?: boolean;
    attestations?: number | undefined;
    /**
     * EAS attestation UIDs backing this answer. Recorded so a third party can
     * re-check the attestation on EAS directly, without CodeRoot in the loop.
     */
    attestationUids?: string[];
    /**
     * True/null carries the same meaning as the live field: the authoring agent's
     * CPoA is revoked, or its chain could not be read. A batch only warns on this;
     * a single-artifact check refuses.
     */
    authorCpoaRevoked?: boolean | null;
    authorCpoaRevokedUids?: string[];
}
export interface RunReport {
    schema: 'coderoot.verification-run/v1';
    tool: {
        name: string;
        version: string;
    };
    source: {
        file: string;
        format: string;
        components: number;
        distinct: number;
    };
    startedAt: string;
    finishedAt: string;
    summary: {
        total: number;
        verified: number;
        attestedBytesUnproven: number;
        unregistered: number;
        revoked: number;
        mismatch: number;
        notQueried: number;
        degraded: number;
        authorCpoaRevoked: number;
    };
    hashSources: Record<string, number>;
    exitCode: number;
    records: EvidenceRecord[];
}
export declare function summarize(records: EvidenceRecord[]): RunReport['summary'];
/**
 * Decide the run's exit status.
 *
 * Revoked outranks mismatch: a revoked build is a live instruction to stop,
 * while a mismatch is a discrepancy to investigate.
 */
export declare function exitCodeFor(summary: RunReport['summary']): number;
export declare function buildReport(args: {
    file: string;
    format: string;
    components: number;
    distinct: number;
    startedAt: string;
    records: EvidenceRecord[];
    toolVersion: string;
}): RunReport;
/** Human summary for stderr, so stdout stays pure JSON and pipeable. */
export declare function renderSummary(report: RunReport): string;
/** Build one evidence record from a component and its verdict. */
export declare function toEvidenceRecord(component: SbomComponent, outcome: {
    verdict: Verdict;
    hashSource: HashSource;
    queried: string | null;
    reason: string;
    degraded?: boolean | undefined;
    mismatch?: boolean | undefined;
    attestations?: number | undefined;
    attestationUids?: string[] | undefined;
    authorCpoaRevoked?: boolean | null | undefined;
    authorCpoaRevokedUids?: string[] | undefined;
}, digests: string[]): EvidenceRecord;
