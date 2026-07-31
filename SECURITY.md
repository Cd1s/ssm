# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, report it privately:

Use a private GitHub security advisory or contact the repository owner privately.

Do not open a public issue for security vulnerabilities.

We will respond within 48 hours and work on a fix as quickly as possible.

## Release Verification

Official release replacements require the selected SHA-256 digest and
keyless provenance pinned to the exact selected release tag in the `Cd1s/ssm`
release workflow and GitHub Actions OIDC issuer. Release selection also
requires the exact supported 14-asset manifest. A selection or provenance
failure preserves the installed executable. Do not work around a failed update
by copying the downloaded binary or looking for a verification-skip option;
report unexpected official-release failures privately through the channels
above.

The tag text is identity data, not a display version. Distinct Git tags such as
`1.2.3` and `v1.2.3` do not authorize one another's provenance.

Release downloads are streamed with hard ceilings of 1,048,576 bytes for
release metadata, 16,384 bytes for checksums, 1,048,576 bytes for each
provenance bundle, and 67,108,864 bytes for a binary. The updater and installer
reject on the next byte even when a redirect has no `Content-Length`; declared
length and curl checks are early optimizations only. The installer therefore
requires `curl`, `head -c`, `wc`, `jq`, a SHA-256 tool, and a current GitHub CLI
with `gh attestation verify`.
