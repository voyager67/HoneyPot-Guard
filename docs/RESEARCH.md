# Research protocol

## Research question

Can lightweight context-aware analysis over staged changes identify potentially risky credential-to-network patterns beyond line-level secret matching, while keeping false positives and pre-commit latency acceptable?

This document describes an evaluation protocol. It does not report experimental results or claim that Honeypot Guard outperforms existing scanners.

## Hypotheses

- **H1 — Incremental signal:** a same-file credential-to-network heuristic identifies some planted risky patterns that line-level secret matching alone does not identify.
- **H2 — Transformation sensitivity:** basic pattern detection changes under encoding, string splitting, renaming, and formatting transformations.
- **H3 — Operational cost:** staged-diff scanning has lower input scope and bounded runtime compared with whole-repository scans, but this must be measured rather than assumed.
- **H4 — Precision trade-off:** adding endpoint and flow heuristics increases recall for selected synthetic scenarios but may also increase false positives.

## Benchmark construction

Build a versioned corpus of small, self-contained repositories. Each fixture must be synthetic and safe to publish. Do not include live credentials, reachable request-catcher URLs, or any payload that sends data to an external service.

### Positive controls

1. Provider-shaped credential literals in added source lines.
2. Generic password, token, API-key, and secret assignments.
3. Sensitive values in staged `.env` files and sensitive filenames.
4. Outbound calls to reserved example hosts and known test-only destination strings.
5. Sensitive environment-derived identifiers explicitly referenced by nearby outbound request payloads.
6. Disabled TLS verification and shell-enabled subprocess calls.

### Negative controls

1. Placeholder values and environment-variable references.
2. Safe `.env.example`, `.env.sample`, and template files.
3. URLs in documentation that are not used by an outbound request.
4. Allowlisted service hosts.
5. Suppressed lines and ignored fixture paths.
6. Similar identifiers that do not contain sensitive environment names or reach a request sink.

## Transformations

Apply one transformation at a time and retain the original fixture as the paired control:

- whitespace and formatting changes;
- identifier renaming;
- string concatenation or splitting;
- URL encoding;
- moving a request sink within a file;
- changing the staged diff so the environment read is unchanged but the request line is newly added;
- adding an intervening helper function.

Record exactly which transformations are in scope. The current flow rule is a bounded same-file identifier heuristic and should be expected to miss cases that require interprocedural or whole-program data flow.

## Baselines

Compare the same fixture revisions against:

- Honeypot Guard provider/generic secret rules only;
- Honeypot Guard with endpoint and flow heuristics enabled;
- Gitleaks with a pinned version and documented configuration;
- TruffleHog with a pinned version and documented configuration.

Run each baseline on identical staged Git states. Record the exact tool versions, configuration, runtime, operating system, and commit hash. Do not describe differing tool scopes as a head-to-head accuracy contest without qualification.

## Metrics

For every tool and fixture set, report:

- true positives, false positives, true negatives, and false negatives;
- precision, recall, F1, and false-positive rate;
- median and p95 wall-clock scan time over repeated runs;
- findings by rule ID and severity;
- install/setup failures separately from detection failures.

A result without a denominator, version, fixture revision, and reproducible command is not a benchmark result.

## Reproducibility checklist

- [ ] Publish synthetic fixture source and labels.
- [ ] Pin scanner and baseline versions.
- [ ] Publish operating system, CPU, memory, and Node.js version.
- [ ] State the exact Git staged-diff command for every run.
- [ ] Preserve raw machine-readable reports with secrets redacted.
- [ ] Run repeated timing trials and publish dispersion, not only the best time.
- [ ] Publish false-positive examples and known misses.
- [ ] Separate results from interpretation and limitations.

## Reporting template

| Tool / configuration | TP | FP | TN | FN | Precision | Recall | F1 | Median ms | p95 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| To be measured | — | — | — | — | — | — | — | — | — |

No values should be filled until the evaluation has been executed.
