#!/usr/bin/env ts-node
/**
 * coderoot verify --sbom <file>
 * coderoot verify --lockfile <file>
 *
 * The batch verification client: parse an SBOM or a package-lock.json,
 * resolve every component by identity, query the verify endpoint for each
 * obtainable digest, and emit one JSON report plus an exit code.
 *
 *   --sbom <path>      CycloneDX or SPDX document
 *   --lockfile <path>  npm package-lock.json, lockfileVersion 2 or 3
 *   --json <path>      write the report here (default: stdout)
 *   --limit <n>        max components to process (default: all)
 *   --concurrency <n>  parallel lookups (default: 8)
 *   --offline          resolve and classify, but never call the network
 *   --base-url <url>   verify endpoint (default: https://verify.coderoot.app)
 *   --no-cache         skip the last-known-revoked cache
 *
 * Exactly one of --sbom / --lockfile is required. Both feed the same
 * pipeline; only what an unacquired declared digest falls back to differs -
 * see acquire()'s `declaredSource` argument.
 *
 * Exit: 0 clean · 1 revoked · 2 mismatch · 3 usage/parse error.
 *
 * stdout carries only the JSON report, so it pipes into jq. Progress and the
 * human summary go to stderr.
 */
/** Run the batch verification. Returns the exit code; never exits. */
export declare function runVerifySbom(argv: string[]): Promise<number>;
