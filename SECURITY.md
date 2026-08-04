# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, report it privately:

Use a private GitHub security advisory or contact the repository owner privately.

Do not open a public issue for security vulnerabilities.

We will respond within 48 hours and work on a fix as quickly as possible.

## Major-update trust boundary

Ordinary v1 updates are same-major only. The explicit major-update path binds
the selected asset SHA-256 to one Sigstore bundle whose certificate identity is
the exact `Cd1s/ssm/.github/workflows/release.yml@refs/tags/vX.Y.Z` workflow
ref, issued by `https://token.actions.githubusercontent.com` on a GitHub-hosted
runner for repository `Cd1s/ssm`. Branch refs, wildcard identities, additional
subjects, and checksum-only evidence are rejected.
