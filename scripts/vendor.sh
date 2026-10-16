#!/usr/bin/env bash
# Rebuild vendor/verify from a published @coderoot-eth/verify release.
# Usage: scripts/vendor.sh <version>   (or a local .tgz from `npm pack`)
set -euo pipefail
src="${1:?usage: scripts/vendor.sh <version|path-to.tgz>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ -f "$src" ]; then cp "$src" "$work/verify.tgz"
else (cd "$work" && npm pack "@coderoot-eth/verify@$src" --silent >/dev/null && mv ./*.tgz verify.tgz); fi
tar -xzf "$work/verify.tgz" -C "$work"
(cd "$work/package" && npm install --omit=dev --ignore-scripts --no-audit --no-fund --silent)

out="$root/vendor/verify"
rm -rf "$out" && mkdir -p "$out"
cp -R "$work/package/build" "$work/package/package.json" "$work/package/LICENSE" "$work/package/NOTICE" "$out/"
find "$out/build" -name '*.map' -delete
# The one runtime dependency, reduced to what runs.
mkdir -p "$out/node_modules/@noble"
cp -R "$work/package/node_modules/@noble/hashes" "$out/node_modules/@noble/"
find "$out/node_modules" -type f ! -name '*.js' ! -name 'LICENSE' ! -name 'README.md' ! -name 'package.json' -delete
find "$out/node_modules" -type d -empty -delete

version="$(node -p "require('$out/package.json').version")"
integrity="sha512-$(openssl dgst -sha512 -binary "$work/verify.tgz" | base64 | tr -d '\n')"
printf '@coderoot-eth/verify %s\nintegrity %s\n\nbuild/ is the package'"'"'s own build without source maps; node_modules/ holds its one\nruntime dependency, @noble/hashes, reduced to .js, LICENSE, README and package.json.\nRegenerate with scripts/vendor.sh %s and diff.\n' "$version" "$integrity" "$version" > "$out/SOURCE"
echo "vendored @coderoot-eth/verify $version"
