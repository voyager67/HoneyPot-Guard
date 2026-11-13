# Contributing

Thanks for helping improve Honeypot Guard.

## Development

Requirements: Node.js 18.12+ and Git. There are no runtime dependencies.

```bash
npm test
npm run demo
npm run check
```

## Detection rules

- Add synthetic regression tests for every new rule.
- Include a negative control to check false positives.
- Keep credential values out of all reports, screenshots, fixtures, and issue text.
- Do not add live credential verification or outbound test requests.
- Give each rule a stable ID, severity, explanation, and actionable remediation.
- State limitations. Do not describe heuristic matching as proof of exfiltration or compromise.

## Pull request checklist

- [ ] Tests pass locally.
- [ ] New behavior has positive and negative tests.
- [ ] Text, JSON, and SARIF output remain redacted.
- [ ] README and research protocol are updated when behavior changes.
- [ ] No real secrets, personal data, or live callback destinations are included.
