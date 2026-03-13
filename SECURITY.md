# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Reporting a Vulnerability

OWS handles private keys and signing operations. We take security seriously.

**Do not open a public issue for security vulnerabilities.**

Instead, please email **security@dawnlabs.ai** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within **48 hours** and aim to provide a fix or mitigation within **7 days** for critical issues.

## Scope

The following are in scope for security reports:

- Key material exposure or leakage
- Bypass of the policy engine
- Signing enclave isolation failures
- Vault encryption weaknesses
- Path traversal or unauthorized file access
- Dependency vulnerabilities with a viable exploit path

## Disclosure Policy

- We follow coordinated disclosure. Please give us reasonable time to address the issue before any public disclosure.
- Credit will be given to reporters in the release notes (unless anonymity is preferred).

## Security Design

For details on how OWS protects key material, see:

- [Key Isolation](docs/05-key-isolation.md)
- [Storage Format](docs/01-storage-format.md)
- [Policy Engine](docs/04-policy-engine.md)
