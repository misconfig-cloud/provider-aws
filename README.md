# Misconfig AWS provider adapter

This is the named AWS implementation of Misconfig's provider-neutral
credential-adapter protocol. AWS-specific role trust, STS session policies,
`credential_process`, and CloudTrail source identity stay in this repository.
The session control plane does not contain an AWS branch.

The first release is deliberately read-only. It translates an explicit set of
signed Misconfig operations into an AWS inline session policy, then intersects
that policy with the customer's role permissions through STS `AssumeRole`.
Unknown operations, narrower resource prefixes that AWS cannot enforce, target
substitution, policy widening, and malformed credential material fail closed.
Because AWS exposes `sts:GetCallerIdentity` even when IAM denies it, every
accepted authorization must declare that identity operation explicitly.

This repository does not make shell interception the security boundary. Even
if an agent invokes an SDK from a nested process, the short-lived credentials
retain the same AWS action ceiling.

## Commands

- `serve` runs the authenticated prepare, verify, and issue broker.
- `configure` renders a session-local AWS config using `credential_process`.
- `render` validates and returns AWS process-credential JSON.
- `keygen` creates an Ed25519 publisher key pair.
- `sign-manifest` emits the immutable signed release manifest.
- `version` prints the exact renderer release version embedded at build time.

## Install a renderer release

Download the archive for the agent host from the immutable GitHub release,
verify `checksums.txt` and its Sigstore bundle, extract it, then run:

```sh
MISCONFIG_INSTALL_PREFIX="$HOME/.local" ./install.sh
```

The installer never edits AWS configuration. A governed session asks the
runtime to create a private session directory and points AWS SDKs at the
generated `credential_process` profile only for that child process. Remove the
renderer with `MISCONFIG_INSTALL_PREFIX="$HOME/.local" ./uninstall.sh --yes`.

The public release contains reproducible Darwin/Linux amd64/arm64 archives, an
SPDX SBOM, checksums, GitHub provenance, a keyless Sigstore signature, and a
digest-addressable multi-architecture broker image.

Licensed under Apache-2.0.
