"use strict";
/**
 * CycloneDX + SPDX parsing for the batch verification client, with these
 * measured rules:
 *
 *  - Read all three hash field paths. `cyclonedx-npm` writes a correct
 *    SHA-512 to `components[].externalReferences[].hashes[]`, two levels down;
 *    a parser reading only `components[].hashes[]` reports zero coverage for it
 *    silently. Measured: 629 hashes on axios, 710 on undici, all there.
 *  - Dedupe on the full purl, never the name. Counting by name
 *    conflates versions and inflates coverage.
 *  - The algorithm always travels with the digest. PyPI's `blake2b_256` is also
 *    64 hex characters, so digest length can never imply an algorithm.
 *  - Exclude SPDX `packageVerificationCode`: it is a hash over a file set, not
 *    of the published artifact.
 *
 * Everything a document merely *declares* is recorded as `sbom-hint` and never
 * as evidence. The acquirer decides what is obtainable; this layer
 * only reports what the document says.
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
exports.parseSbom = parseSbom;
exports.parseSbomFile = parseSbomFile;
exports.parseLockfile = parseLockfile;
exports.parseLockfileFile = parseLockfileFile;
exports.distinctByPurl = distinctByPurl;
exports.strongestDeclared = strongestDeclared;
const fs = __importStar(require("fs"));
const digest_1 = require("./digest");
/** Decode a CycloneDX hash body, which may be hex or base64. */
function decodeHashContent(content) {
    const raw = (content ?? '').trim();
    if (!raw)
        return null;
    if (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0)
        return raw.toLowerCase();
    try {
        const hex = Buffer.from(raw, 'base64').toString('hex');
        return hex.length > 0 ? hex : null;
    }
    catch {
        return null;
    }
}
/** "SHA-512" -> "sha512"; the algorithm is kept exactly as declared, never inferred. */
function canonicalAlgorithm(alg) {
    if (!alg)
        return null;
    const normalized = alg.toLowerCase().replace(/[-_\s]/g, '');
    if (normalized.startsWith('blake2b'))
        return 'blake2b-256';
    if (['sha1', 'sha256', 'sha384', 'sha512', 'md5'].includes(normalized))
        return normalized;
    return normalized || null;
}
function parsePurl(purl) {
    if (!purl)
        return { purl: null, ecosystem: null, name: null, version: null };
    // purls URL-encode "@" as %40 and "+" as %2B; decode before using as a key.
    const decoded = safeDecode(purl.trim());
    const match = /^pkg:([^/]+)\/(.+)$/.exec(decoded);
    if (!match)
        return { purl: decoded, ecosystem: null, name: null, version: null };
    const ecosystem = match[1].toLowerCase();
    let rest = match[2];
    const qualifier = rest.search(/[?#]/);
    if (qualifier >= 0)
        rest = rest.slice(0, qualifier);
    const at = rest.lastIndexOf('@');
    const name = at > 0 ? rest.slice(0, at) : rest;
    const version = at > 0 ? rest.slice(at + 1) : null;
    return { purl: decoded, ecosystem, name, version };
}
function safeDecode(value) {
    try {
        return decodeURIComponent(value);
    }
    catch {
        return value;
    }
}
/** Walk CycloneDX's nested `components[]` tree; sub-components are real components. */
function flattenCycloneDx(root) {
    const out = [];
    const queue = [...root];
    while (queue.length > 0) {
        const component = queue.shift();
        out.push(component);
        const nested = component['components'];
        if (Array.isArray(nested))
            queue.push(...nested);
    }
    return out;
}
function parseCycloneDx(doc) {
    const raw = Array.isArray(doc['components'])
        ? flattenCycloneDx(doc['components'])
        : [];
    const components = [];
    let purllessCount = 0;
    let purllessHashCount = 0;
    for (const component of raw) {
        const declared = [];
        for (const h of component['hashes'] ?? []) {
            const algorithm = canonicalAlgorithm(h['alg']);
            const hex = decodeHashContent(h['content']);
            if (algorithm && hex)
                declared.push({ algorithm, hex, path: 'components[].hashes[]' });
        }
        // The path a reader of components[].hashes[] alone would miss entirely.
        for (const ref of component['externalReferences'] ?? []) {
            for (const h of ref['hashes'] ?? []) {
                const algorithm = canonicalAlgorithm(h['alg']);
                const hex = decodeHashContent(h['content']);
                if (algorithm && hex) {
                    declared.push({
                        algorithm,
                        hex,
                        path: 'externalReferences[].hashes[]',
                        refType: ref['type'],
                        refUrl: ref['url'],
                    });
                }
            }
        }
        const identity = parsePurl(component['purl']);
        if (!identity.purl) {
            purllessCount += 1;
            purllessHashCount += declared.length;
            continue;
        }
        components.push({
            purl: identity.purl,
            ecosystem: identity.ecosystem,
            name: identity.name ?? String(component['name'] ?? ''),
            version: identity.version ?? (component['version'] || null),
            declared,
        });
    }
    return { format: 'cyclonedx', components, purllessCount, purllessHashCount };
}
function parseSpdx(doc) {
    const packages = doc['packages'] ?? [];
    const components = [];
    let purllessCount = 0;
    let purllessHashCount = 0;
    for (const pkg of packages) {
        const declared = [];
        // checksums[] only. packageVerificationCode is a hash over a file set, not
        // of the published artifact, and is deliberately not read here.
        for (const c of pkg['checksums'] ?? []) {
            const algorithm = canonicalAlgorithm(c['algorithm']);
            const hex = decodeHashContent(c['checksumValue']);
            if (algorithm && hex)
                declared.push({ algorithm, hex, path: 'packages[].checksums[]' });
        }
        const refs = pkg['externalRefs'] ?? [];
        const purlRef = refs.find((r) => r['referenceType'] === 'purl');
        const identity = parsePurl(purlRef?.['referenceLocator']);
        if (!identity.purl) {
            purllessCount += 1;
            purllessHashCount += declared.length;
            continue;
        }
        components.push({
            purl: identity.purl,
            ecosystem: identity.ecosystem,
            name: identity.name ?? String(pkg['name'] ?? ''),
            version: identity.version ?? (pkg['versionInfo'] || null),
            declared,
        });
    }
    return { format: 'spdx', components, purllessCount, purllessHashCount };
}
/** Detect the format and parse. Throws on a document that is neither. */
function parseSbom(raw) {
    // An empty file is a generator that produced nothing, not malformed JSON.
    // Measured: npmsbom on the npm CLI lockfile (both formats) and
    // cyclonedx-py on poetry.lock each wrote a 0-byte document. Say so plainly
    // rather than surfacing "Unexpected end of JSON input".
    if (raw.trim().length === 0) {
        throw new Error('Empty SBOM - the generator produced no output.');
    }
    let doc;
    try {
        doc = JSON.parse(raw);
    }
    catch (error) {
        throw new Error(`Malformed SBOM JSON: ${error.message}`);
    }
    // GitHub's dependency-graph API wraps the document one level down.
    if (doc['sbom'] && typeof doc['sbom'] === 'object') {
        doc = doc['sbom'];
    }
    if (doc['bomFormat'] === 'CycloneDX' || Array.isArray(doc['components'])) {
        return parseCycloneDx(doc);
    }
    if (doc['spdxVersion'] || Array.isArray(doc['packages'])) {
        return parseSpdx(doc);
    }
    throw new Error('Unrecognized SBOM: expected CycloneDX (bomFormat/components) or SPDX (spdxVersion/packages).');
}
function parseSbomFile(filePath) {
    if (!fs.existsSync(filePath))
        throw new Error(`SBOM not found: ${filePath}`);
    return parseSbom(fs.readFileSync(filePath, 'utf8'));
}
/**
 * A `package-lock.json` entry (lockfileVersion 2/3's flat `packages` map).
 * The path's last `node_modules/`-prefixed segment is the install location,
 * not necessarily the package name: a nested entry like
 * `node_modules/a/node_modules/b` is package `b`, installed inside `a`'s own
 * tree, often at a different version than any top-level `b`. An npm alias
 * (`"foo": "npm:bar@1.0.0"`) installs at `node_modules/foo` while the
 * entry's own `name` field says `bar`, the real registry name. `pkg.name`
 * is used when present; the path segment is the fallback for the unaliased
 * case, where the field is absent and the path segment IS the name.
 *
 * Each occurrence keeps its own identity (purl includes its version), same
 * as the SBOM dedupe-by-purl rule; a later distinctByPurl pass collapses
 * only genuinely repeated purls.
 */
function parseNpmLockfile(doc) {
    const packages = doc['packages'] ?? {};
    const components = [];
    let purllessCount = 0;
    let purllessHashCount = 0;
    for (const [key, pkg] of Object.entries(packages)) {
        // The root key ('') describes the project itself, not a dependency.
        if (!key)
            continue;
        const segments = key.split('node_modules/');
        const pathSegment = segments[segments.length - 1];
        const name = pkg['name'] || pathSegment;
        if (!name)
            continue;
        const version = pkg['version'] || null;
        const integrity = pkg['integrity'];
        const declared = [];
        if (integrity) {
            try {
                const { algorithm, hex } = (0, digest_1.parseIntegrity)(integrity);
                declared.push({ algorithm, hex, path: 'package-lock.packages[].integrity' });
            }
            catch {
                // sha1-only or otherwise unusable - recorded as no declared hash,
                // same as any other package.json manifest without one. Never thrown:
                // one malformed entry must not fail parsing the whole lockfile.
            }
        }
        if (!version) {
            purllessCount += 1;
            purllessHashCount += declared.length;
            continue;
        }
        // purl convention (matching the fixtures already in this repo): the `@`
        // introducing a scope is %-encoded, the `/` separating scope and name is
        // not, and the final `@version` is literal.
        const purlName = name.startsWith('@') ? `%40${name.slice(1)}` : name;
        const purl = `pkg:npm/${purlName}@${version}`;
        components.push({ purl, ecosystem: 'npm', name, version, declared });
    }
    return { format: 'npm-lockfile', components, purllessCount, purllessHashCount };
}
function parseLockfile(raw) {
    if (raw.trim().length === 0) {
        throw new Error('Empty lockfile - nothing to parse.');
    }
    let doc;
    try {
        doc = JSON.parse(raw);
    }
    catch (error) {
        throw new Error(`Malformed lockfile JSON: ${error.message}`);
    }
    if (typeof doc['packages'] !== 'object' || doc['packages'] === null) {
        throw new Error('Unrecognized lockfile: expected a `packages` map (npm lockfileVersion 2 or 3). ' +
            'lockfileVersion 1 is not supported.');
    }
    return parseNpmLockfile(doc);
}
function parseLockfileFile(filePath) {
    if (!fs.existsSync(filePath))
        throw new Error(`Lockfile not found: ${filePath}`);
    return parseLockfile(fs.readFileSync(filePath, 'utf8'));
}
/**
 * Distinct components by full purl.
 *
 * A package used by two projects appears twice in a document; counting
 * occurrences would report it as two packages. Coverage
 * percentages must be taken over this, not over the raw list.
 */
function distinctByPurl(components) {
    const seen = new Map();
    for (const component of components) {
        if (!component.purl)
            continue;
        const existing = seen.get(component.purl);
        if (!existing) {
            seen.set(component.purl, component);
        }
        else if (component.declared.length > existing.declared.length) {
            // Keep the richer occurrence, so a hash present in one copy is not lost.
            seen.set(component.purl, component);
        }
    }
    return [...seen.values()];
}
/** Pick the strongest declared digest, or null. sha1/md5 are never strong. */
function strongestDeclared(component) {
    const order = ['sha512', 'sha256'];
    for (const algorithm of order) {
        const hit = component.declared.find((d) => d.algorithm === algorithm);
        if (hit)
            return hit;
    }
    return null;
}
//# sourceMappingURL=sbom.js.map