# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, report it privately:

Use a private GitHub security advisory or contact the repository owner privately.

Do not open a public issue for security vulnerabilities.

We will respond within 48 hours and work on a fix as quickly as possible.

## Release Verification

Official release replacements require the selected SHA-256 digest and
keyless provenance pinned to the `Cd1s/ssm` release workflow and GitHub
Actions OIDC issuer. A provenance failure preserves the installed executable.
Do not work around a failed update by copying the downloaded binary or looking
for a verification-skip option; report unexpected official-release failures
privately through the channels above.
