# Trusted Roots Directory

This directory contains the trusted root CA certificates that the CT log will accept.

## Adding Root Certificates

Place PEM-encoded root CA certificates in this directory with the `.pem` extension.

Example:
- `root-ca-1.pem`
- `root-ca-2.pem`

The CT log will only accept certificate chains that can be validated against one of these trusted roots.

## Certificate Validation

When validation is enabled in `Config.toml`, the log will:
1. Check that submitted certificate chains terminate in one of these trusted roots
2. Verify that certificates fall within the configured temporal window
3. Ensure signature algorithms are from the allowed list
