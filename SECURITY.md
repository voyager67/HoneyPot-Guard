# Security policy

## Scope

Honeypot Guard is a local-first, pattern-based pre-commit scanner. It is not a security boundary and cannot guarantee that a repository is free of secrets or vulnerabilities.

## Reporting a vulnerability

Do not publish live credentials, sensitive repository content, or an exploitable payload in a public issue. Use GitHub's private vulnerability reporting for this repository when available. Otherwise, contact the maintainer through the GitHub profile before sharing sensitive details.

## Credential exposure

If a real credential is detected, treat it as exposed: revoke or rotate it with the provider, review access logs, and remove it from repository history where appropriate. A later deletion does not make an exposed credential safe again.

## Safe testing

Use synthetic values, reserved example domains, and temporary repositories. The project must not verify credentials or send test payloads to third-party endpoints. Scanner output should remain redacted in text, JSON, and SARIF.
