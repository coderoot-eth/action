#!/usr/bin/env node
/**
 * coderoot verify --hash <algorithm:digest>
 *
 * The deploy-time check: one artifact, one answer, one exit code. A deploy
 * script runs this before starting a service and refuses to start on non-zero.
 *
 *   --hash <algo:digest>  sha256:<64 hex>, 0x<hex>, or bare hex
 *   --file <path>         hash a local file instead of passing a digest
 *   --source <source>     lockfile|registry|bytes - how a --hash digest was
 *                         obtained; ignored with --file (always 'bytes').
 *                         Default 'lockfile'.
 *   --json                machine-readable output on stdout
 *   --base-url <url>      verify endpoint
 *   --no-cache            skip the last-known-revoked cache
 *   --warn-on-degraded    pass with a warning when the answer could not be
 *                         fully checked, instead of refusing (exit 4)
 *
 * Exit: 0 attested and not revoked · 1 revoked · 2 unregistered, unproven, or
 *       the authoring agent's CPoA is revoked/unreadable · 3 usage error ·
 *       4 could not be fully checked (degraded).
 *
 * Degraded means verify was unreachable, or it answered but could not read the
 * gate's revocations, so a revoke made minutes ago may be missing. This check
 * is a release job, so it refuses: release jobs fail on a degraded answer, other
 * jobs warn. A job that only needs a warning passes --warn-on-degraded.
 *
 * A revoked CPoA rides on top of the verdict, same as a batch mismatch: the
 * bytes are still attested, so it never promotes to exit 1.
 *
 * Note this differs from the batch client's mapping, and deliberately. A batch
 * run over an SBOM reports a population and exits 0 when nothing FAILED; a
 * single deploy-time check is asking "may I start this build?", where "no
 * record exists" is not a pass.
 */
import { VerdictResult } from '../lib/verdict';
/**
 * The exit code for one answer. Revoked always refuses. A degraded answer that
 * would otherwise refuse keeps its own code (it says more); one that would
 * pass refuses with 4, unless the caller asked for a warning instead.
 *
 * authorCpoaRevoked rides on top of the verdict and never outranks a revoked
 * digest (exit 1 already means refuse).
 */
export declare function exitFor(result: VerdictResult, warnOnDegraded: boolean): number;
/** Run the single-artifact check. Returns the exit code; never exits. */
export declare function runVerifyHash(argv: string[]): Promise<number>;
