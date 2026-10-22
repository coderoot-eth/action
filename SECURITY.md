# Security policy

Report a vulnerability privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Do not open a public issue for it.

Include what you found, how to reproduce it, and the Action version or commit you used.

## In scope

- A step that passes when it should refuse: a revoked digest, an unregistered digest under
  `fail-on: unregistered`, or a degraded answer with `fail-open: false`.
- `submit` running with a registry credential in scope, or sending anything other than the job's
  GitHub identity token.
- A workflow input reaching a shell command other than through the environment.
- The revoked cache being written from a pull request, or a revoked entry being dropped.

The verification logic itself lives in [`@coderoot-eth/verify`](https://github.com/coderoot-eth/verify);
report client issues there.
