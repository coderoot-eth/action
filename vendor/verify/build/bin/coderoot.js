#!/usr/bin/env node
"use strict";
/**
 * coderoot - the consumer-side verification client.
 *
 *   coderoot verify --hash <algorithm:digest>   one artifact, by digest
 *   coderoot verify --file <path>               one artifact, hashed here
 *   coderoot verify --sbom <path>               every component in an SBOM
 *   coderoot verify --lockfile <path>           every component in a package-lock.json
 *
 * One `verify` command over three inputs, because they answer the same question
 * at different scales: are these the bytes the maintainer published, and are
 * they still trusted?
 *
 * The single-artifact form is the deploy-time check - a deploy script runs it
 * before starting a service and refuses to start on a non-zero exit.
 */
Object.defineProperty(exports, "__esModule", { value: true });
const hash_1 = require("./hash");
const verify_hash_1 = require("./verify-hash");
const verify_sbom_1 = require("./verify-sbom");
const USAGE = `coderoot - consumer-side verification client

usage:
  coderoot hash <file>                      [--json] [--algorithm sha256|sha512|both]
  coderoot hash --image <ref>               [--json]              (requires crane on PATH)
  coderoot verify --hash <algorithm:digest> [--json] [--no-cache] [--warn-on-degraded]
  coderoot verify --file <path>             [--json] [--no-cache] [--warn-on-degraded]
  coderoot verify --sbom <path>             [--json <out>] [--limit n]
                                            [--offline] [--concurrency n]
  coderoot verify --lockfile <path>         [--json <out>] [--limit n]
                                            [--offline] [--concurrency n]

single artifact (--hash / --file), the deploy-time check:
  exit 0  attested and not revoked
  exit 1  revoked
  exit 2  unregistered, or a record exists but the bytes were not proven
  exit 3  usage error
  exit 4  could not be fully checked (verify unreachable, or the gate's
          revocations unread); --warn-on-degraded passes with a warning

batch (--sbom / --lockfile), reporting over a population:
  exit 0  clean - nothing failed
  exit 1  at least one component revoked
  exit 2  at least one mismatch
  exit 3  usage or parse error

The two mappings differ on purpose: a batch run reports a population, while a
single check asks "may I start this build?", where "no record exists" is not a
pass. For the same reason a degraded answer fails a single check and only warns
in a batch.

common options:
  --json            machine-readable output on stdout
  --base-url <url>  verify endpoint (default https://verify.coderoot.app)
  --no-cache        skip the local last-known-revoked cache
`;
async function main() {
    const argv = process.argv.slice(2);
    const command = argv[0];
    if (!command || command === '--help' || command === '-h' || command === 'help') {
        process.stdout.write(USAGE);
        process.exit(command ? 0 : 3);
    }
    if (command === 'hash') {
        // Local only: prints what you are holding. No network, no endpoint.
        process.exit((0, hash_1.runHash)(argv.slice(1)));
    }
    if (command !== 'verify') {
        console.error(`error: unknown command "${command}"\n`);
        process.stderr.write(USAGE);
        process.exit(3);
    }
    const rest = argv.slice(1);
    // --sbom/--lockfile select the batch client; --hash/--file the
    // single-artifact one. Routing on the input flag keeps one verb over three
    // scales.
    const isBatch = rest.includes('--sbom') || rest.includes('--lockfile');
    const exitCode = isBatch ? await (0, verify_sbom_1.runVerifySbom)(rest) : await (0, verify_hash_1.runVerifyHash)(rest);
    process.exit(exitCode);
}
main().catch((error) => {
    console.error(`error: ${error.message}`);
    process.exit(3);
});
//# sourceMappingURL=coderoot.js.map