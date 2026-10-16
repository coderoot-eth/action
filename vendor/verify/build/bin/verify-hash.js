#!/usr/bin/env node
"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.exitFor = exitFor;
exports.runVerifyHash = runVerifyHash;
const digest_1 = require("../lib/digest");
const verdict_1 = require("../lib/verdict");
const revoked_cache_1 = require("../lib/revoked-cache");
const EXIT = { OK: 0, REVOKED: 1, UNPROVEN: 2, USAGE: 3, DEGRADED: 4 };
const HASH_SOURCES = ['lockfile', 'registry', 'bytes'];
function parseArgs(argv) {
    const args = { json: false, cache: true, source: 'lockfile', warnOnDegraded: false };
    for (let i = 0; i < argv.length; i += 1) {
        const flag = argv[i];
        const next = () => argv[++i];
        if (flag === '--hash')
            args.hash = next();
        else if (flag === '--file')
            args.file = next();
        else if (flag === '--base-url')
            args.baseUrl = next();
        else if (flag === '--json')
            args.json = true;
        else if (flag === '--no-cache')
            args.cache = false;
        else if (flag === '--warn-on-degraded')
            args.warnOnDegraded = true;
        else if (flag === '--source') {
            const value = next();
            if (!HASH_SOURCES.includes(value)) {
                usage(EXIT.USAGE, `--source must be one of ${HASH_SOURCES.join(', ')} (got "${value}")`);
            }
            args.source = value;
        }
        else if (flag === '--help' || flag === '-h')
            usage(EXIT.OK);
        else if (flag === '--agent-id') {
            // Rejected locally, by design. Only the AgentRoot gateway can mint the
            // per-request signed assertion an agent submission needs, so a CLI that
            // accepted this flag could only ever produce a request the gate refuses.
            usage(EXIT.USAGE, '--agent-id is not accepted by this client. Agent submissions must go through the ' +
                'AgentRoot gateway (coderoot_submit), which signs the per-request assertion.');
        }
        else if (flag.startsWith('-'))
            usage(EXIT.USAGE, `unknown flag ${flag}`);
    }
    return args;
}
/** Thrown to unwind to the caller with an exit code, instead of exiting here. */
class ExitSignal extends Error {
    constructor(code) {
        super(`exit ${code}`);
        this.code = code;
    }
}
function usage(code, message) {
    if (message)
        console.error(`error: ${message}`);
    console.error('usage: coderoot verify --hash <algorithm:digest> [--source lockfile|registry|bytes] [--json] [--no-cache]\n' +
        '                       [--warn-on-degraded]\n' +
        '       coderoot verify --file <path> [--json] [--warn-on-degraded]\n\n' +
        'exit: 0 attested · 1 revoked · 2 unregistered/unproven · 3 usage · 4 not fully checked');
    throw new ExitSignal(code);
}
/**
 * The exit code for one answer. Revoked always refuses. A degraded answer that
 * would otherwise refuse keeps its own code (it says more); one that would
 * pass refuses with 4, unless the caller asked for a warning instead.
 *
 * authorCpoaRevoked rides on top of the verdict and never outranks a revoked
 * digest (exit 1 already means refuse).
 */
function exitFor(result, warnOnDegraded) {
    if (result.verdict === 'revoked')
        return EXIT.REVOKED;
    const authorCpoaFlagged = result.authorCpoaRevoked === true || result.authorCpoaRevoked === null;
    // What the answer alone would mean; an unreachable endpoint gave no answer.
    const answered = result.unreachable
        ? null
        : result.verdict === 'verified' && !authorCpoaFlagged
            ? EXIT.OK
            : EXIT.UNPROVEN;
    if (!result.degraded)
        return answered ?? EXIT.UNPROVEN;
    if (answered !== null && answered !== EXIT.OK)
        return answered;
    return warnOnDegraded ? EXIT.OK : EXIT.DEGRADED;
}
/** Run the single-artifact check. Returns the exit code; never exits. */
async function runVerifyHash(argv) {
    let args;
    try {
        args = parseArgs(argv);
    }
    catch (error) {
        if (error instanceof ExitSignal)
            return error.code;
        throw error;
    }
    if (!args.hash && !args.file) {
        console.error('error: one of --hash or --file is required');
        return EXIT.USAGE;
    }
    if (args.hash && args.file) {
        console.error('error: --hash and --file are mutually exclusive');
        return EXIT.USAGE;
    }
    let tagged;
    let sha256 = '';
    let sha512 = '';
    let bytes = 0;
    try {
        if (args.file) {
            // We hold the artifact, so both digests come from the same read.
            const set = (0, digest_1.digestFile)(args.file);
            sha256 = set.sha256;
            sha512 = set.sha512;
            bytes = set.bytes;
            tagged = `sha256:${set.sha256}`;
        }
        else {
            // Routed into the field matching its own algorithm, not assumed sha256.
            tagged = (0, verdict_1.assertQueryable)(args.hash);
            const parsed = (0, digest_1.parseDigest)(tagged);
            if (parsed.algorithm === 'sha512')
                sha512 = parsed.hex;
            else
                sha256 = parsed.hex;
        }
    }
    catch (error) {
        console.error(`error: ${error.message}`);
        return EXIT.USAGE;
    }
    const cache = args.cache ? new revoked_cache_1.RevokedCache() : null;
    const options = {
        ...(args.baseUrl ? { baseUrl: args.baseUrl } : {}),
        ...(cache ? { revokedCache: cache.asSet() } : {}),
    };
    // A digest handed to us on the command line has no provenance we can vouch
    // for, but it is not an SBOM hint either: the caller is asserting these are
    // the bytes. `bytes` when we hashed the file ourselves; otherwise whatever
    // the caller told us via --source (lockfile by default, registry for a
    // container image digest).
    const result = await (0, verdict_1.verifyDigest)({ sha256, sha512, bytes }, args.file ? 'bytes' : args.source, options);
    cache?.flush();
    const exitCode = exitFor(result, args.warnOnDegraded);
    if (result.degraded) {
        const what = result.unreachable
            ? 'the verify endpoint was unreachable'
            : "verify could not read the gate's revocations";
        console.error(exitCode === EXIT.DEGRADED
            ? `error: ${what}, so this digest could not be fully checked. Refusing (exit 4); ` +
                'a job that only needs a warning can pass --warn-on-degraded.'
            : `warning: ${what}; passing anyway because --warn-on-degraded was given.`);
    }
    if (args.json) {
        process.stdout.write(JSON.stringify({
            schema: 'coderoot.verify-hash/v1',
            queried: result.queried,
            digests: [sha256 && `sha256:${sha256}`, sha512 && `sha512:${sha512}`].filter(Boolean),
            verdict: result.verdict,
            hashSource: result.hashSource,
            reason: result.reason,
            attestations: result.attestations ?? [],
            degraded: result.degraded ?? false,
            unreachable: result.unreachable ?? false,
            authorCpoaRevoked: result.authorCpoaRevoked === undefined ? false : result.authorCpoaRevoked,
            authorCpoaRevokedUids: result.authorCpoaRevokedUids ?? [],
            exitCode,
        }, null, 2) + '\n');
    }
    else {
        const mark = result.verdict === 'verified' ? '✓' : result.verdict === 'revoked' ? '✗' : '!';
        console.log(`${mark} ${result.verdict}`);
        console.log(`  digest  ${result.queried}`);
        if (bytes > 0)
            console.log(`  bytes   ${bytes}`);
        console.log(`  reason  ${result.reason}`);
        for (const attestation of result.attestations ?? []) {
            console.log(`  uid     ${attestation.uid}`);
        }
        if (result.degraded) {
            const what = result.unreachable ? 'endpoint unreachable' : 'gate revocations could not be read';
            console.log(`  note    ${what}; ${exitCode === EXIT.DEGRADED ? 'refused (exit 4)' : 'passed with a warning'}`);
        }
        if (result.authorCpoaRevoked === true || result.authorCpoaRevoked === null) {
            const state = result.authorCpoaRevoked === null ? 'unknown (chain unreadable)' : 'true';
            console.log(`  authorCpoaRevoked  ${state}`);
            for (const uid of result.authorCpoaRevokedUids ?? [])
                console.log(`  cpoa uid  ${uid}`);
        }
    }
    return exitCode;
}
// Direct invocation: `ts-node bin/verify-hash.ts …` still works.
if (require.main === module) {
    runVerifyHash(process.argv.slice(2)).then((code) => process.exit(code), (error) => {
        console.error(`error: ${error.message}`);
        process.exit(EXIT.USAGE);
    });
}
//# sourceMappingURL=verify-hash.js.map