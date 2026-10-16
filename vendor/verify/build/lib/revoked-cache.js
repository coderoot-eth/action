"use strict";
/**
 * The local last-known-revoked cache.
 *
 * Fail-open says: when the verify endpoint is unreachable,
 * warn and exit 0 rather than blocking a deploy on an outage. That rule has one
 * carve-out - a digest this client has previously seen `revoked` still fails,
 * even with the endpoint down.
 *
 * Without somewhere to keep that knowledge, the carve-out is empty: a fresh
 * process has seen nothing, so every unreachable-endpoint run fails open on
 * everything, and an attacker who can break the connection can ship a revoked
 * build. This file is what makes the exception real across runs.
 *
 * What it is:
 *
 *   - append-only, keyed on the TAGGED digest (`sha256:<hex>`), so a digest can
 *     never be confused with the same hex under another algorithm
 *   - one JSON file, default `~/.coderoot/revoked-cache.json`
 *   - entries are never evicted by age. A revocation does not expire, and a
 *     cache that forgets one is worse than no cache - it would fail open on
 *     exactly the digest it was built to catch
 *   - it only ever ADDS a failure. A digest absent from the cache is not
 *     treated as good, and the cache is never consulted when the endpoint is
 *     reachable, so a revocation that is later lifted upstream is still
 *     observed correctly on any successful query
 *
 * What it is not: a verdict store. It answers one question - "have I ever seen
 * this exact digest revoked?" - and nothing else.
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
exports.RevokedCache = void 0;
exports.defaultCachePath = defaultCachePath;
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const EMPTY = { schema: 'coderoot.revoked-cache/v1', entries: [] };
function defaultCachePath() {
    return (process.env['CODEROOT_REVOKED_CACHE'] ??
        path.join(os.homedir(), '.coderoot', 'revoked-cache.json'));
}
class RevokedCache {
    constructor(file = defaultCachePath()) {
        this.digests = new Set();
        this.entries = [];
        this.dirty = false;
        this.file = file;
        this.load();
    }
    /**
     * A malformed or unreadable cache must never take the run down: it is an
     * optimization on top of the endpoint's answer, not a source of truth.
     */
    load() {
        try {
            if (!fs.existsSync(this.file))
                return;
            const parsed = JSON.parse(fs.readFileSync(this.file, 'utf8'));
            if (!Array.isArray(parsed.entries))
                return;
            for (const entry of parsed.entries) {
                if (typeof entry?.digest === 'string' && entry.digest.includes(':')) {
                    this.entries.push(entry);
                    this.digests.add(entry.digest.toLowerCase());
                }
            }
        }
        catch {
            // Start empty rather than fail; the endpoint still governs live answers.
        }
    }
    /** Has this exact tagged digest ever been seen revoked? */
    has(taggedDigest) {
        return this.digests.has(taggedDigest.toLowerCase());
    }
    /** Record a revocation. Idempotent. */
    add(taggedDigest, purl) {
        const key = taggedDigest.toLowerCase();
        if (this.digests.has(key))
            return;
        this.digests.add(key);
        const entry = { digest: key, seenAt: new Date().toISOString() };
        if (purl)
            entry.purl = purl;
        this.entries.push(entry);
        this.dirty = true;
    }
    /** Persist if anything was added. Failure to write is reported, not thrown. */
    flush() {
        if (!this.dirty)
            return { written: false };
        try {
            fs.mkdirSync(path.dirname(this.file), { recursive: true });
            const payload = { schema: EMPTY.schema, entries: this.entries };
            fs.writeFileSync(this.file, JSON.stringify(payload, null, 2));
            this.dirty = false;
            return { written: true };
        }
        catch (error) {
            return { written: false, error: error.message };
        }
    }
    get size() {
        return this.digests.size;
    }
    get path() {
        return this.file;
    }
    /** The Set the verify functions take, backed by this cache. */
    asSet() {
        // Proxy writes back into the cache so a revocation observed mid-run persists.
        const cache = this;
        const set = new Set(this.digests);
        const originalAdd = set.add.bind(set);
        set.add = (value) => {
            cache.add(value);
            return originalAdd(value);
        };
        return set;
    }
}
exports.RevokedCache = RevokedCache;
//# sourceMappingURL=revoked-cache.js.map