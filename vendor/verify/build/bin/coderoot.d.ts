#!/usr/bin/env node
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
export {};
