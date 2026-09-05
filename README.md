# Misconfig AWS provider adapter

This is the named AWS implementation of Misconfig's provider-neutral
credential-adapter protocol. AWS-specific role trust, STS session policies,
`credential_process`, and CloudTrail source identity stay in this repository.
The session control plane does not contain an AWS branch.

Read sessions remain deliberately read-only. The adapter translates an
explicit set of signed Misconfig operations into an AWS inline session policy,
then intersects that policy with the customer's role permissions through STS
`AssumeRole`.
Unknown operations, narrower resource prefixes that AWS cannot enforce, target
substitution, policy widening, and malformed credential material fail closed.
Because AWS exposes `sts:GetCallerIdentity` even when IAM denies it, every
accepted authorization must declare that identity operation explicitly.

This repository does not make shell interception the security boundary. Even
if an agent invokes an SDK from a nested process, the short-lived credentials
retain the same AWS action ceiling.

The first separately approved typed action changes reserved concurrency for
one exact Lambda function. It is not part of the session credential. The
control plane issues one short-lived, single-use action authority; this adapter
recomputes its canonical digest, assumes an exact-resource mutation policy,
records the AWS request ID, then assumes a separate read-only verification
session and reads the resulting state back. Setting the former value (or
removing the limit when it was previously absent) is the explicit rollback.

Customers who want this action attach the following outer ceiling to the
connected role. Omitting it leaves read sessions fully functional and makes
the typed action fail closed:

```json
{
  "Effect": "Allow",
  "Action": [
    "lambda:GetFunctionConcurrency",
    "lambda:PutFunctionConcurrency",
    "lambda:DeleteFunctionConcurrency"
  ],
  "Resource": "arn:aws:lambda:*:ACCOUNT_ID:function:*"
}
```

The outer role ceiling does not itself authorize an agent action. The adapter
intersects it with a second inline policy for one function ARN only after the
exact capability, parameters, session, policy release, and human approval have
been bound.

## Commands

- `serve` runs the authenticated credential broker plus typed action executor
  and independent verifier.
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
