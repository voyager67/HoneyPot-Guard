# Detection rule reference

All rules run locally against added lines in the Git index, except filename rules, which inspect staged paths. Rules are heuristic and can produce false positives and false negatives.

| Rule | Severity | Purpose |
|---|---|---|
| AWS-001 | Critical | AWS access-key-shaped identifier |
| GH-001 | Critical | GitHub-token-shaped value |
| ANT-001 | Critical | Anthropic API-key-shaped value |
| OAI-001 | Critical | OpenAI API-key-shaped value |
| STR-001 | Critical | Stripe live secret/restricted key shape |
| SLK-001 | High | Slack-token-shaped value |
| GCP-001 | High | Google API-key-shaped value |
| KEY-001 | Critical | Private-key block header |
| GEN-001 | High | Literal credential-like assignment |
| ENV-001 | High | Non-placeholder sensitive assignment in staged `.env*` file |
| FIL-001 | Critical | Sensitive filename staged for commit |
| NET-001 | High | Outbound call to a known request-catcher/tunnel-style host |
| NET-002 | Medium | Outbound call to a literal IP address |
| NET-003 | Medium | Outbound host not present in configured allowlist |
| TLS-001 | Medium | TLS certificate verification appears disabled |
| TLS-002 | Medium | Outbound request uses plain HTTP |
| PROC-001 | Medium | Subprocess invocation enables shell interpretation |
| FLOW-001 | High | Same-file bounded identifier heuristic links sensitive env-derived value to outbound sink |

## Suppression

Add `honeypot-guard:ignore` to an added line to suppress line-based findings on that line. Filename findings are not suppressed by line comments. Prefer `ignoredPaths` or a policy change for generated fixtures, and document the reason in the same pull request.
