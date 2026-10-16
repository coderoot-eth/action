# CodeRoot Action

Check what you pull, submit what you ship.

```yaml
- uses: coderoot-eth/action@v1
  with:
    mode: verify
    hash: sha256:634e3ed585d7c8857f00cb7556f79422614e8defd008f8bb34b6018c1faefa0f
```

**This Action never publishes and never holds a registry token.** `check` and `verify` need
`permissions: contents: read`; `submit` also needs `id-token: write`, and nothing else. If
`NPM_TOKEN`, `NODE_AUTH_TOKEN`, an `npm_config_*` auth variable or an `.npmrc` auth line is in
scope when a `submit` step starts, the Action stops with exit 4 before doing anything, and CI tests
that it does. `check` and `verify` only read digests and query the verify endpoint, so they warn
instead: stopping them would break a pipeline that publishes in a later step of the same job.

## Modes

One mode per step; use several steps for several modes.

| mode | question | when |
|---|---|---|
| `check` | are my dependencies attested? | pull request |
| `submit` | submit this release for a person's approval | after `npm publish` or `npm stage publish` |
| `verify` | may I start this build? | deploy |

### `verify` — the deploy-time gate

```yaml
- uses: coderoot-eth/action@v1
  with:
    mode: verify
    hash: ${{ inputs.artifact_hash }}   # or: artifact: ./dist/app.tgz
```

Exits 0 only on `verified`. `unregistered` is not a pass: no record existing is not the same as
the bytes being right, so it exits 2 unless you soften it with `fail-on`.

### `check` — dependency verdicts

```yaml
- uses: coderoot-eth/action@v1
  with:
    mode: check
    sbom: sbom.cyclonedx.json
    # or: lockfile: package-lock.json
```

Resolves every component by identity, never by the digest the document declared, following
`lockfile → bytes → registry`. A digest that exists only inside an SBOM is recorded as a hint
and never sent, so it cannot produce a false mismatch; a digest from a real `package-lock.json`'s
own `integrity` is stronger than that (npm's own install-time record, not a third party's guess)
and is sent whenever it is queryable.

**This Action does not generate SBOMs.** Produce one with `syft`, `cdxgen` or `npm sbom` first,
or pass `lockfile` directly for npm's own `package-lock.json` (lockfileVersion 2 or 3). `sbom`
and `lockfile` are mutually exclusive.

### `submit` — a release for approval

```yaml
- uses: coderoot-eth/action@v1
  with:
    mode: submit
    flow: published
    artifact: dist/package.tgz
```

Uploads the artifact to the gate as `multipart/form-data` (one part, `file`), then submits it for
human review: `POST /v1/artifacts` returns an `upload_id` the submission references, so the gate
verifies the declared digests against the bytes it received. The digests come from `coderoot hash`,
offline. The request body is in the exact form
[spec/submit.md](https://github.com/coderoot-eth/verify/blob/main/spec/submit.md) gives (key order,
two-space indent, no trailing newline). The `Idempotency-Key` is a UUIDv4 derived
from that body, so a retry of the same body is an idempotent replay. The job is done at that
point: it does not wait for a decision and it does not publish. The job summary carries the
submission id and its review link.

Submission requests retry recognized connection failures and HTTP 429, 500, 502, 503 and 504,
up to three attempts within a shared 30-second deadline. Delays use exponential backoff with
jitter and honor `Retry-After` (seconds or HTTP date). Every attempt sends the original body
and idempotency key. Permanent refusals, including 409, stop immediately. Artifact uploads
remain single-shot: their contract creates a fresh `upload_id` and has no idempotent replay.
An ambiguous upload failure requires inspection before rerunning the job.

`submit` has no fail-open. An unreachable gate fails the job, because a release that was never
submitted must never look as though it shipped.

Agent submissions go through the AgentRoot gateway, which signs the per-request assertion, so there
is no `agent-id` input here.

#### Signing in

`submit` signs in with the job's GitHub identity token (audience `secure.coderoot.app`), so no
secret is stored anywhere; the job needs `permissions: id-token: write`. The token names the
repository, workflow and run that submit, and the gate accepts it only when they and the package
are linked to your CodeRoot workspace.

#### After publishing to npm yourself

Release with npm trusted publishing, then submit the same tarball. Pack once, publish or stage that
file, and pass the same file as `artifact`: a fresh pack is not guaranteed to reproduce the bytes,
so `submit` never packs.

```yaml
publish:
  environment: npm
  permissions: { contents: read, id-token: write }
  steps:
    # ...pack once to dist/package.tgz, then:
    - run: npm publish dist/package.tgz --provenance --access public
    # Pass dist/package.tgz to the next job, e.g. with actions/upload-artifact.

submit:
  needs: publish
  permissions: { contents: read, id-token: write } # no environment: this job cannot publish
  steps:
    - uses: coderoot-eth/action@v1
      with:
        mode: submit
        flow: published
        artifact: dist/package.tgz
```

- `flow: published`: the version is live. `submit` reads npm's `dist.integrity` for it, waiting up
  to `registry-wait` seconds for a new version to appear, and stops with exit 2 before contacting
  the gate if the artifact is not those bytes.
- `flow: staged`: the version was staged with `npm stage publish` and is not installable yet. npm
  serves nothing about it before approval, so the proof is the provenance bundle npm attached:
  create it in an earlier step, stage with `npm stage publish --provenance-file <bundle>`, and pass
  the same file as `provenance-bundle`. `submit` checks locally that the bundle names this package
  and this tarball's SHA-512 (exit 2 if not), uploads it next to the tarball, and sends its hash with
  the stage id (from `stage-id`, or read from the file in `npm-output`). The summary says to attest
  in CodeRoot first, then approve on npm.

Keep the `submit` step in its own job without the npm environment: any step in a job that can
publish can mint the npm trust token. It stays in the same workflow file, so the workflow its
identity token names is the one npm's provenance names.

## Inputs

| input | modes | default | meaning |
|---|---|---|---|
| `mode` | all | — | `check`, `submit` or `verify` |
| `sbom` | check | — | CycloneDX or SPDX document |
| `lockfile` | check | — | npm `package-lock.json`, lockfileVersion 2 or 3. Not both with `sbom` |
| `hash` | verify | — | tagged digest, `sha256:<64 hex>` |
| `artifact` | verify, submit | — | verify: a file to hash. submit: the tarball that was published or staged (required) |
| `flow` | submit | — | `published` or `staged` (required) |
| `stage-id` | submit | from `npm-output` | flow `staged`: the npm stage id |
| `npm-output` | submit | — | flow `staged`: a file holding the output of `npm stage publish` |
| `provenance-bundle` | submit | — | flow `staged`: the Sigstore bundle npm attached, staged with `--provenance-file` |
| `registry` | submit | `https://registry.npmjs.org` | flow `published`: where `dist.integrity` is read |
| `registry-wait` | submit | `300` | flow `published`: seconds to wait for a new version to appear |
| `oidc-audience` | submit | `secure.coderoot.app` | audience of the identity token used to sign in |
| `evidence` | submit | — | JSON array, passed through verbatim |
| `signatures` | submit | — | JSON array of signature references |
| `name`, `version` | submit | from `package.json` | package coordinates |
| `repo`, `commit` | submit | from the GitHub context | required by the gate; set them outside Actions |
| `note` | submit | generated | the submitter note recorded with the submission |
| `idempotency-key` | submit | UUIDv4 derived from the body | override only to force a distinct attempt; the gate accepts UUIDv4 keys only |
| `submit-endpoint` | submit | `https://secure.coderoot.app` | the gate |
| `verify-endpoint` | all | `https://verify.coderoot.app` | |
| `fail-open` | check, verify | `false` (verify), `true` (check) | whether an answer that could not be fully checked passes with a warning (`true`) or fails (`false`). Not submit |
| `fail-on` | check, verify | `unregistered` (verify), `mismatch` (check) | the mildest result that still fails; see below |
| `report-path` | all | `coderoot-report.json` | |
| `artifact-name` | all | `coderoot-<mode>-report` | name of the uploaded report. A second step of the same mode in one job gets `-2`, `-3` |

## Outputs

| output | modes | meaning |
|---|---|---|
| `verdict` | check, verify | verify: the verdict. check: the worst verdict seen |
| `report` | all | path to the JSON report, also uploaded as a workflow artifact (see `artifact-name`) |
| `submission-id` | submit | the id the gate returned |
| `review-url` | submit | where a person reviews and attests the submission |
| `exit-code` | all | the client's exit code, before `fail-on` and `fail-open`. verify: `4` means the answer could not be fully checked (degraded); the step exits `3` by default |
| `degraded` | check, verify | `true` when the answer could not be fully checked: verify unreachable, or the gate's revocations unread |
| `author-cpoa-revoked` | verify | `true`, `false` or `null` (chain unreadable); see below |
| `author-cpoa-revoked-count` | check | how many components carried the flag |

Every mode writes a job summary and uploads its JSON report as a workflow artifact.

## Exit codes

| code | meaning |
|--:|---|
| 0 | clean |
| 1 | revoked |
| 2 | check: a mismatch, or `unregistered` under `fail-on: unregistered`. verify: not `verified`. submit: the artifact is not what npm serves (`published`), or the provenance bundle is not for it (`staged`) |
| 3 | usage or parse error, or a degraded answer with `fail-open: false` (the verify default) |
| 4 | a registry credential is in scope for `submit` |

### `fail-on`

`fail-on` names the mildest result that still fails the step. Each value fails on itself and
everything worse:

| `fail-on` | fails on |
|---|---|
| `unregistered` | revoked, mismatch and `unregistered`. In verify: anything other than `verified` |
| `mismatch` | revoked and mismatch |
| `revoked` | revoked |
| `never` | nothing; the verdict is still reported |

verify defaults to `unregistered`, so it passes only `verified`. check defaults to `mismatch`:
most of the ecosystem is not attested yet, so failing every build on `unregistered` would teach
teams to turn the check off.

`fail-on` exists so a team never needs `continue-on-error`, which disables the whole check
silently. With `fail-on` the verdict is still reported; it just does not fail the job. A usage
error always fails, whatever `fail-on` says, and so does an unknown `fail-on` value.

**Unverifiable is not failure.** Alpine packages publish SHA-1 and nothing else, so they can never
be verified; check reports them as `attested-bytes-unproven` and exits 0 rather than teaching
teams to disable it.

### Fail-open

Verify reads revocations from EAS and from the gate, and revoked from either wins. An answer is
**degraded** when it could not be fully checked: verify was unreachable, or it answered but could
not read the gate's revocations, so a revoke made minutes ago may be missing. The `degraded`
output and the job summary say which.

Release jobs fail on a degraded answer and other jobs warn. So `verify`, the
deploy-time check, defaults to `fail-open: false` and fails with exit 3; `check`, which reports
on a build, defaults to `fail-open: true` and passes with a warning. Set `fail-open` on either to
override, for example `fail-open: true` on a `verify` step that only needs a warning.

An answer that already fails keeps its own result: `revoked` is still exit 1, and `fail-on` still
applies to the verdict. A digest this client has previously seen `revoked` fails from a local
cache keyed on the tagged digest, even when the network is down, so no setting can soften it.

`submit` has no fail-open at all, whatever this input says.

### `authorCpoaRevoked`

Separate from the four verdicts, and not softened by `fail-on` or `fail-open`. The endpoint
follows each unrevoked attestation back to the producing agent's CPoA and reads it live: `true`
means the bytes are still attested but the agent that shipped them has lost its authority. `null`
means the chain could not be read - unknown, not clear.

`verify` fails on either `true` or `null`, regardless of `fail-on`, exiting 2 (the same code as
a batch mismatch) and naming the UID(s) in the job summary and the `author-cpoa-revoked` output.
`check` only warns and reports a count in `author-cpoa-revoked-count`; it never fails the job on
this flag.

### The revoked cache between jobs

A hosted runner starts every job with an empty disk, so the Action carries the cache between jobs
with `actions/cache`. It restores the newest cache the job can see before running, and saves a new
one when the run learned a revocation, keyed by the cache's content. The file only ever grows.

GitHub's cache rules limit this. A cache unused for 7 days is evicted, and a run only sees caches
from its own branch and the default branch. Treat it as a strong default, not a guarantee. Both
`verify` and `check` read and save it.

## Why a composite action

The verification logic lives in [`@coderoot-eth/verify`](https://github.com/coderoot-eth/verify),
which has its own tests. A composite keeps this Action a thin integration over that CLI rather than
a second implementation of the same rules, and lets it call `actions/cache` and
`actions/upload-artifact` directly. The package is vendored under `vendor/verify`, so the Action
installs nothing at run time; `vendor/verify/SOURCE` names the release and its integrity, and
`scripts/vendor.sh <version>` regenerates it.

## Releasing

Releasing happens by merging to `main`. The test suite runs against that commit, then
semantic-release reads conventional-commit prefixes since the last tag to pick the version:
`feat` bumps minor, `fix` bumps patch, a `!` or `BREAKING CHANGE` footer bumps major. It tags
`vX.Y.Z` and force-moves `v1` to match. A merge with no recognized prefix is a clean no-op.

## Tests

```bash
node --test test/*.test.js
```

- `action.test.js`: mode dispatch, and verify and check end to end against the live endpoint
- `fail-on.test.js`: the `fail-on` and `fail-open` matrix for both modes
- `revoked-cache.test.js`: a digest seen revoked fails during an outage, from this job's cache or
  one restored from an earlier job
- `submit-flows.test.js`: flows `published` and `staged` against a fake gate
  (`test/helpers/gate-fake.mjs`), a fake npm registry and a fake GitHub identity-token endpoint, with
  a real published tarball and its provenance bundle: the wait for a new version, the integrity
  refusal, the bundle check and upload, the stage id read from npm's output, the body's exact form,
  the identity-token-only sign-in, and refusals in the summary
- `retry.test.js`: transient recovery and exhaustion, deadlines and `Retry-After`, permanent
  refusals, byte-identical submission replay after a lost response, and single-shot uploads
- `credentials.test.js`: the negative test, one case per way a registry credential can be in scope,
  plus the read-only modes warning rather than stopping
- `author-cpoa.test.js`: `verifyExit`/`checkExit` coverage for `true`/`null`/`false`, plus `verify`
  end to end against a mock endpoint (no live fixture has `authorCpoaRevoked: true` today)

CI also runs the Action by reference: a revocation learned in one job must fail a later job during
an outage, and a job with `NPM_TOKEN` set must fail.
