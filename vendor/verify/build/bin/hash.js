#!/usr/bin/env node
"use strict";
/**
 * coderoot hash <file>
 * coderoot hash --image <ref>
 *
 * SHA-256 and SHA-512 of a file, an npm tarball, or a container image
 * manifest, algorithm-tagged.
 *
 * No network for the file form. This is the local half of the verification
 * story: it tells you what you are holding, so you can compare it against
 * what a registry or an attestation claims. The comparison itself is
 * `coderoot verify`.
 *
 *   --json          machine-readable output
 *   --algorithm     sha256 | sha512 | both (default: both) - file form only
 *   --image <ref>   resolve a registry reference instead of a local file.
 *                   Requires `crane` on PATH.
 *
 * Both digests come from one read of the bytes, because neither converts to
 * the other: npm publishes SHA-512 in `dist.integrity`, while the live verify
 * schema records SHA-256 only. Holding the artifact is the only bridge.
 *
 * `--image` resolves the digest that should be attested for a registry
 * reference: the index digest for a multi-arch image, the single
 * manifest digest otherwise. See lib/image.ts for the index-vs-single-arch
 * and attestation-manifest-filtering rules this depends on.
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
exports.runHash = runHash;
const path = __importStar(require("path"));
const digest_1 = require("../lib/digest");
const image_1 = require("../lib/image");
const EXIT = { OK: 0, USAGE: 3 };
function usage(code, message) {
    if (message)
        console.error(`error: ${message}`);
    console.error('usage: coderoot hash <file> [--json] [--algorithm sha256|sha512|both]\n' +
        '       coderoot hash --image <ref> [--json]\n\n' +
        'Prints algorithm-tagged digests of a file, an npm tarball, or a container\n' +
        'image reference (--image, requires crane on PATH). No network for the file form.');
    process.exit(code);
}
function parseArgs(argv) {
    const args = { json: false, algorithm: 'both' };
    for (let i = 0; i < argv.length; i += 1) {
        const flag = argv[i];
        if (flag === '--json')
            args.json = true;
        else if (flag === '--image')
            args.image = argv[++i];
        else if (flag === '--algorithm' || flag === '-a') {
            const value = argv[++i];
            if (value !== 'sha256' && value !== 'sha512' && value !== 'both') {
                usage(EXIT.USAGE, `--algorithm must be sha256, sha512 or both (got "${value ?? ''}")`);
            }
            args.algorithm = value;
        }
        else if (flag === '--help' || flag === '-h')
            usage(EXIT.OK);
        else if (flag.startsWith('-'))
            usage(EXIT.USAGE, `unknown flag ${flag}`);
        else if (args.file)
            usage(EXIT.USAGE, 'hash takes one file');
        else
            args.file = flag;
    }
    return args;
}
/** Run the --image form. Returns an exit code; never exits. */
function runHashImage(ref, json) {
    let resolved;
    try {
        resolved = (0, image_1.resolveImageDigest)(ref);
    }
    catch (error) {
        console.error(`error: ${error.message}`);
        return EXIT.USAGE;
    }
    let craneConfirmed;
    try {
        craneConfirmed = (0, image_1.crossCheckAgainstCrane)(ref, resolved);
    }
    catch (error) {
        console.error(`error: ${error.message}`);
        return EXIT.USAGE;
    }
    if (json) {
        process.stdout.write(JSON.stringify({
            schema: 'coderoot.hash-image/v1',
            ref,
            kind: resolved.kind,
            digest: resolved.digest,
            sha512: resolved.sha512,
            craneDigestConfirmed: craneConfirmed,
            ...(resolved.kind === 'index'
                ? {
                    platformCount: resolved.platformCount,
                    attestationManifestCount: resolved.attestationManifestCount,
                    platforms: resolved.platforms,
                }
                : {}),
        }, null, 2) + '\n');
    }
    else {
        console.log(`${resolved.kind === 'index' ? 'index' : 'manifest'} digest: ${resolved.digest}`);
        console.log(`sha512 (manifest bytes): ${resolved.sha512}`);
        console.log(`crane digest confirms:   ${craneConfirmed}`);
        if (resolved.kind === 'index') {
            console.log(`platforms folded in:     ${resolved.platformCount}`);
            if ((resolved.attestationManifestCount ?? 0) > 0) {
                console.log(`attestation-manifest entries filtered out: ${resolved.attestationManifestCount} (not platforms)`);
            }
            for (const p of resolved.platforms ?? []) {
                console.log(`  ${p.os}/${p.architecture}${p.variant ? '/' + p.variant : ''}  ${p.digest}`);
            }
        }
    }
    return EXIT.OK;
}
/** Run the hash command. Returns an exit code; never exits. */
function runHash(argv) {
    let args;
    try {
        args = parseArgs(argv);
    }
    catch (error) {
        // parseArgs calls usage(), which exits; this guards a future refactor.
        throw error;
    }
    if (args.file && args.image) {
        console.error('error: a file and --image are mutually exclusive');
        return EXIT.USAGE;
    }
    if (args.image)
        return runHashImage(args.image, args.json);
    if (!args.file) {
        console.error('error: hash needs a file or --image');
        return EXIT.USAGE;
    }
    let set;
    try {
        set = (0, digest_1.digestFile)(args.file);
    }
    catch (error) {
        console.error(`error: ${error.message}`);
        return EXIT.USAGE;
    }
    const wanted = args.algorithm === 'both' ? ['sha256', 'sha512'] : [args.algorithm];
    if (args.json) {
        const digests = {};
        for (const algorithm of wanted)
            digests[algorithm] = `${algorithm}:${set[algorithm]}`;
        process.stdout.write(JSON.stringify({
            schema: 'coderoot.hash/v1',
            file: path.basename(args.file),
            bytes: set.bytes,
            digests,
        }, null, 2) + '\n');
    }
    else {
        for (const algorithm of wanted)
            console.log(`${algorithm}:${set[algorithm]}`);
        console.error(`  ${set.bytes} bytes  ${path.basename(args.file)}`);
    }
    return EXIT.OK;
}
if (require.main === module) {
    process.exit(runHash(process.argv.slice(2)));
}
//# sourceMappingURL=hash.js.map