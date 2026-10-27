#!/usr/bin/env ts-node
"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.runVerifySbom = runVerifySbom;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const sbom_1 = require("../lib/sbom");
const report_1 = require("../lib/report");
const revoked_cache_1 = require("../lib/revoked-cache");
const batch_1 = require("../lib/batch");
const version_1 = require("../lib/version");
function parseArgs(argv) {
    const args = { concurrency: 8, offline: false, cache: true };
    for (let i = 0; i < argv.length; i += 1) {
        const flag = argv[i];
        const next = () => argv[++i];
        if (flag === '--sbom')
            args.sbom = next();
        else if (flag === '--lockfile')
            args.lockfile = next();
        else if (flag === '--json')
            args.json = next();
        else if (flag === '--limit')
            args.limit = Number(next());
        else if (flag === '--concurrency')
            args.concurrency = Number(next());
        else if (flag === '--base-url')
            args.baseUrl = next();
        else if (flag === '--offline')
            args.offline = true;
        else if (flag === '--no-cache')
            args.cache = false;
        else if (flag === '--help' || flag === '-h') {
            console.error('usage: coderoot verify --sbom <file> [--json <out>] [--limit n] [--offline] [--no-cache]\n' +
                '       coderoot verify --lockfile <file> [--json <out>] [--limit n] [--offline] [--no-cache]');
            args.help = true;
        }
    }
    return args;
}
/** Run the batch verification. Returns the exit code; never exits. */
async function runVerifySbom(argv) {
    const args = parseArgs(argv);
    if (args.help)
        return report_1.EXIT.ERROR;
    if (!args.sbom && !args.lockfile) {
        console.error('error: --sbom <file> or --lockfile <file> is required');
        return report_1.EXIT.ERROR;
    }
    if (args.sbom && args.lockfile) {
        console.error('error: --sbom and --lockfile are mutually exclusive');
        return report_1.EXIT.ERROR;
    }
    const inputPath = (args.sbom ?? args.lockfile);
    const declaredSource = args.lockfile ? 'lockfile' : 'sbom-hint';
    const startedAt = new Date().toISOString();
    let parsed;
    try {
        parsed = args.lockfile ? (0, sbom_1.parseLockfileFile)(args.lockfile) : (0, sbom_1.parseSbomFile)(args.sbom);
    }
    catch (error) {
        console.error(`error: ${error.message}`);
        return report_1.EXIT.ERROR;
    }
    // Coverage is counted over distinct purls, never occurrences.
    let components = (0, sbom_1.distinctByPurl)(parsed.components);
    const distinct = components.length;
    if (args.limit && args.limit < components.length)
        components = components.slice(0, args.limit);
    process.stderr.write(`parsed ${parsed.components.length} components (${distinct} distinct) from ${path.basename(inputPath)}\n` +
        `verifying ${components.length}${args.offline ? ' (offline)' : ''}...\n`);
    const cache = args.cache ? new revoked_cache_1.RevokedCache() : null;
    const verifyOptions = {
        ...(args.baseUrl ? { baseUrl: args.baseUrl } : {}),
        ...(cache ? { revokedCache: cache.asSet() } : {}),
    };
    const records = await (0, batch_1.verifyComponents)(components, {
        declaredSource,
        offline: args.offline,
        concurrency: args.concurrency,
        verify: verifyOptions,
        onProgress: (done, total) => {
            if (done % 25 === 0)
                process.stderr.write(`  ${done}/${total}\n`);
        },
    });
    cache?.flush();
    const report = (0, report_1.buildReport)({
        file: path.basename(inputPath),
        format: parsed.format,
        components: parsed.components.length,
        distinct,
        startedAt,
        records,
        toolVersion: (0, version_1.packageVersion)(),
    });
    const json = JSON.stringify(report, null, 2);
    if (args.json) {
        fs.writeFileSync(args.json, json);
        process.stderr.write(`\nreport -> ${args.json}\n`);
    }
    else {
        process.stdout.write(json + '\n');
    }
    process.stderr.write('\n' + (0, report_1.renderSummary)(report) + '\n');
    return report.exitCode;
}
// Direct invocation: `ts-node bin/verify-sbom.ts …` still works.
if (require.main === module) {
    runVerifySbom(process.argv.slice(2)).then((code) => process.exit(code), (error) => {
        console.error(`error: ${error.message}`);
        process.exit(report_1.EXIT.ERROR);
    });
}
//# sourceMappingURL=verify-sbom.js.map