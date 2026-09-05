# Security policy

## Supported releases

Only the latest signed release is supported. The release manifest, checksum
file, Sigstore bundle, GitHub artifact attestations, and container digest are
the authority for an installed adapter. Tags, mutable image names, and copied
binaries are not release identity.

## Trust boundary

This process is an external provider adapter. It receives only authenticated
protocol requests from the Misconfig session control plane and returns
short-lived provider material. It must not be exposed directly to agent
processes or the public internet.

The first AWS release is read-only. It intersects the immutable Misconfig
authorization with the customer role by using an AWS STS inline session
policy. Unknown allowed operations, account substitution, unsupported resource
scopes, overlong credentials, and release changes fail closed.

The broker's AWS principal may call `sts:AssumeRole` only for customer roles
that explicitly trust it with the connection-specific external ID and
`sts:SourceIdentity`. The customer role remains the outer permission ceiling.

## Reporting

Report vulnerabilities privately to security@misconfig.cloud. Do not include
live credentials, customer identifiers, or provider payloads in a report.
