"use strict";
/**
 * Algorithm-tagged digests for artifact verification. Artifact verification
 * needs SHA-512, and needs the algorithm to travel with the digest.
 *
 * Why both algorithms, always, from the same read:
 *
 *   - npm publishes `dist.integrity` as SHA-512. Measured over a corpus of real SBOMs,
 *     every npm package carrying any digest carries SHA-512 (3,851 of 5,541);
 *     not one is SHA-256-only.
 *   - SHA-256 still reaches more of the ecosystem: a v1 attestation (most of
 *     it) is indexed by SHA-256 only, so a SHA-512 query against one comes
 *     back honestly `unregistered` rather than finding it. A direct SHA-512
 *     query against a v2 record works correctly. verifyDigest in
 *     lib/verdict.ts sends SHA-256 when it is held, for exactly this reach
 *     reason, and SHA-512 directly otherwise.
 *
 * A SHA-256 cannot be derived from a SHA-512, or the reverse - they are
 * independent one-way functions. The only bridge between the registry's
 * SHA-512 and the API's SHA-256 is the artifact bytes themselves, so whenever
 * we hold the bytes we compute both at once and keep them together.
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
exports.digestBuffer = digestBuffer;
exports.digestFile = digestFile;
exports.tagged = tagged;
exports.taggedPair = taggedPair;
exports.parseDigest = parseDigest;
exports.parseIntegrity = parseIntegrity;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const sha256_1 = require("@noble/hashes/sha256");
const sha512_1 = require("@noble/hashes/sha512");
const HEX_LENGTH = { sha256: 64, sha512: 128 };
function toHex(bytes) {
    return Buffer.from(bytes).toString('hex');
}
/** Compute both digests over a buffer in one pass over the same bytes. */
function digestBuffer(data) {
    return { sha256: toHex((0, sha256_1.sha256)(data)), sha512: toHex((0, sha512_1.sha512)(data)), bytes: data.length };
}
/** Compute both digests of a file. Throws if the file is missing. */
function digestFile(filePath) {
    const absolute = path.resolve(filePath);
    if (!fs.existsSync(absolute)) {
        throw new Error(`File not found: ${filePath}`);
    }
    return digestBuffer(fs.readFileSync(absolute));
}
/** Render as `sha256:<hex>` / `sha512:<hex>` - the form the submit contract uses. */
function tagged(algorithm, hex) {
    return `${algorithm}:${hex}`;
}
/** Both digests of a DigestSet in tagged form, SHA-256 first (the submit contract's `hashes[]` order). */
function taggedPair(set) {
    return [tagged('sha256', set.sha256), tagged('sha512', set.sha512)];
}
/**
 * Parse `sha256:<hex>`, `sha512:<hex>`, `0x<hex>` or bare hex.
 *
 * The algorithm is inferred from length ONLY when untagged, and never used to
 * identify a digest whose algorithm was declared: PyPI's `blake2b_256` is also
 * 64 hex characters, so length alone cannot prove an algorithm. A tagged input
 * whose body length contradicts its tag is rejected rather than reinterpreted.
 */
function parseDigest(input) {
    const raw = input.trim();
    if (!raw)
        throw new Error('Empty digest');
    const colon = raw.indexOf(':');
    if (colon > 0) {
        const tag = raw.slice(0, colon).toLowerCase();
        const body = raw.slice(colon + 1).toLowerCase();
        if (tag !== 'sha256' && tag !== 'sha512') {
            throw new Error(`Unsupported algorithm "${tag}". Supported: sha256, sha512.`);
        }
        assertHex(body, HEX_LENGTH[tag], tag);
        return { algorithm: tag, hex: body };
    }
    const body = (raw.startsWith('0x') || raw.startsWith('0X') ? raw.slice(2) : raw).toLowerCase();
    if (body.length === 64) {
        assertHex(body, 64, 'sha256');
        return { algorithm: 'sha256', hex: body };
    }
    if (body.length === 128) {
        assertHex(body, 128, 'sha512');
        return { algorithm: 'sha512', hex: body };
    }
    throw new Error(`Invalid digest - expected sha256:<64 hex>, sha512:<128 hex>, or bare hex of either length (got ${body.length} characters).`);
}
function assertHex(body, expected, algorithm) {
    if (body.length !== expected) {
        throw new Error(`Invalid ${algorithm} digest - expected ${expected} hex characters, got ${body.length}.`);
    }
    if (!/^[0-9a-f]+$/.test(body)) {
        throw new Error(`Invalid ${algorithm} digest - contains non-hex characters.`);
    }
}
/**
 * Decode an npm Subresource Integrity string (`sha512-<base64>`) to tagged hex.
 *
 * This is what `package-lock.json` `.integrity` and the packument's
 * `dist.integrity` both carry. SRI may hold several space-separated entries;
 * the strongest supported one wins.
 */
function parseIntegrity(integrity) {
    const candidates = [];
    for (const token of integrity.trim().split(/\s+/)) {
        const dash = token.indexOf('-');
        if (dash <= 0)
            continue;
        const alg = token.slice(0, dash).toLowerCase();
        if (alg !== 'sha256' && alg !== 'sha512')
            continue; // sha1 is never proof
        const hex = Buffer.from(token.slice(dash + 1), 'base64').toString('hex');
        if (hex.length === HEX_LENGTH[alg])
            candidates.push({ algorithm: alg, hex });
    }
    if (candidates.length === 0) {
        throw new Error(`No sha256/sha512 entry in integrity string: ${integrity}`);
    }
    return candidates.find((c) => c.algorithm === 'sha512') ?? candidates[0];
}
//# sourceMappingURL=digest.js.map