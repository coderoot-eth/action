"use strict";
/**
 * The library behind the `coderoot` CLI. The purl is only an index; the hash
 * is the trust: nothing here reports `verified` from a name and version alone.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.packageVersion = exports.verifyComponents = exports.verifyComponentDetailed = exports.verifyComponent = exports.realPlatforms = exports.crossCheckAgainstCrane = exports.resolveImageDigest = exports.defaultCachePath = exports.RevokedCache = exports.toEvidenceRecord = exports.renderSummary = exports.exitCodeFor = exports.summarize = exports.buildReport = exports.EXIT = exports.strongestDeclared = exports.distinctByPurl = exports.parseLockfileFile = exports.parseLockfile = exports.parseSbomFile = exports.parseSbom = exports.assertQueryable = exports.compareContentHash = exports.probeCoordinates = exports.verifyDigest = exports.taggedPair = exports.tagged = exports.parseIntegrity = exports.parseDigest = exports.digestFile = exports.digestBuffer = void 0;
var digest_1 = require("./digest");
Object.defineProperty(exports, "digestBuffer", { enumerable: true, get: function () { return digest_1.digestBuffer; } });
Object.defineProperty(exports, "digestFile", { enumerable: true, get: function () { return digest_1.digestFile; } });
Object.defineProperty(exports, "parseDigest", { enumerable: true, get: function () { return digest_1.parseDigest; } });
Object.defineProperty(exports, "parseIntegrity", { enumerable: true, get: function () { return digest_1.parseIntegrity; } });
Object.defineProperty(exports, "tagged", { enumerable: true, get: function () { return digest_1.tagged; } });
Object.defineProperty(exports, "taggedPair", { enumerable: true, get: function () { return digest_1.taggedPair; } });
var verdict_1 = require("./verdict");
Object.defineProperty(exports, "verifyDigest", { enumerable: true, get: function () { return verdict_1.verifyDigest; } });
Object.defineProperty(exports, "probeCoordinates", { enumerable: true, get: function () { return verdict_1.probeCoordinates; } });
Object.defineProperty(exports, "compareContentHash", { enumerable: true, get: function () { return verdict_1.compareContentHash; } });
Object.defineProperty(exports, "assertQueryable", { enumerable: true, get: function () { return verdict_1.assertQueryable; } });
var sbom_1 = require("./sbom");
Object.defineProperty(exports, "parseSbom", { enumerable: true, get: function () { return sbom_1.parseSbom; } });
Object.defineProperty(exports, "parseSbomFile", { enumerable: true, get: function () { return sbom_1.parseSbomFile; } });
Object.defineProperty(exports, "parseLockfile", { enumerable: true, get: function () { return sbom_1.parseLockfile; } });
Object.defineProperty(exports, "parseLockfileFile", { enumerable: true, get: function () { return sbom_1.parseLockfileFile; } });
Object.defineProperty(exports, "distinctByPurl", { enumerable: true, get: function () { return sbom_1.distinctByPurl; } });
Object.defineProperty(exports, "strongestDeclared", { enumerable: true, get: function () { return sbom_1.strongestDeclared; } });
var report_1 = require("./report");
Object.defineProperty(exports, "EXIT", { enumerable: true, get: function () { return report_1.EXIT; } });
Object.defineProperty(exports, "buildReport", { enumerable: true, get: function () { return report_1.buildReport; } });
Object.defineProperty(exports, "summarize", { enumerable: true, get: function () { return report_1.summarize; } });
Object.defineProperty(exports, "exitCodeFor", { enumerable: true, get: function () { return report_1.exitCodeFor; } });
Object.defineProperty(exports, "renderSummary", { enumerable: true, get: function () { return report_1.renderSummary; } });
Object.defineProperty(exports, "toEvidenceRecord", { enumerable: true, get: function () { return report_1.toEvidenceRecord; } });
var revoked_cache_1 = require("./revoked-cache");
Object.defineProperty(exports, "RevokedCache", { enumerable: true, get: function () { return revoked_cache_1.RevokedCache; } });
Object.defineProperty(exports, "defaultCachePath", { enumerable: true, get: function () { return revoked_cache_1.defaultCachePath; } });
var image_1 = require("./image");
Object.defineProperty(exports, "resolveImageDigest", { enumerable: true, get: function () { return image_1.resolveImageDigest; } });
Object.defineProperty(exports, "crossCheckAgainstCrane", { enumerable: true, get: function () { return image_1.crossCheckAgainstCrane; } });
Object.defineProperty(exports, "realPlatforms", { enumerable: true, get: function () { return image_1.realPlatforms; } });
var batch_1 = require("./batch");
Object.defineProperty(exports, "verifyComponent", { enumerable: true, get: function () { return batch_1.verifyComponent; } });
Object.defineProperty(exports, "verifyComponentDetailed", { enumerable: true, get: function () { return batch_1.verifyComponentDetailed; } });
Object.defineProperty(exports, "verifyComponents", { enumerable: true, get: function () { return batch_1.verifyComponents; } });
var version_1 = require("./version");
Object.defineProperty(exports, "packageVersion", { enumerable: true, get: function () { return version_1.packageVersion; } });
//# sourceMappingURL=index.js.map