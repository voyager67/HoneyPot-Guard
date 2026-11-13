'use strict';

const SEVERITY_LEVEL = Object.freeze({ low: 'note', medium: 'warning', high: 'error', critical: 'error' });
const SECURITY_SCORE = Object.freeze({ low: '3.0', medium: '5.0', high: '7.0', critical: '9.0' });

function colorEnabled(options = {}) {
  return Boolean(process.stdout.isTTY && !process.env.NO_COLOR && !options.noColor);
}

function paint(enabled, code, value) {
  return enabled ? `\u001b[${code}m${value}\u001b[0m` : value;
}

function formatText(result, elapsedMs, mode, options = {}) {
  const color = colorEnabled(options);
  const bold = (value) => paint(color, '1', value);
  const dim = (value) => paint(color, '2', value);
  const green = (value) => paint(color, '32', value);
  const yellow = (value) => paint(color, '33', value);
  const red = (value) => paint(color, '31', value);
  const severityLabel = (severity) => {
    if (severity === 'critical') return red('CRITICAL');
    if (severity === 'high') return yellow('HIGH    ');
    if (severity === 'medium') return dim('MEDIUM  ');
    return dim('LOW     ');
  };

  const rule = '─'.repeat(68);
  const out = [
    bold('HONEYPOT-GUARD™  PRE-COMMIT RED-FLAG AUDIT'),
    dim(`mode: ${mode} · local-only · ${elapsedMs}ms`),
    dim(rule),
  ];

  if (!result.findings.length) {
    out.push(green('✔ No red flags detected in the staged additions.'));
  } else {
    out.push(`Findings requiring review: ${bold(String(result.findings.length))}`);
    out.push('');
    for (const finding of result.findings) {
      const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
      out.push(` ${severityLabel(finding.severity)}  ${finding.id}  ${finding.name}`);
      out.push(`          ${dim(location)}  ${finding.evidence}`);
      out.push(`          ${dim(`Action: ${finding.recommendation}`)}`);
    }
  }

  const tierIndex = result.score === 0 ? 0 : result.score <= 2 ? 1 : result.score <= 5 ? 2 : result.score <= 9 ? 3 : result.score <= 14 ? 4 : 5;
  const filled = (tierIndex + 1) * 2;
  const bar = '█'.repeat(filled) + '░'.repeat(12 - filled);
  const ratingColor = tierIndex >= 4 ? red : tierIndex >= 2 ? yellow : green;

  out.push(dim(rule));
  out.push(`SEVERITY   ${result.counts.critical} critical · ${result.counts.high} high · ${result.counts.medium} medium · ${result.counts.low} low`);
  out.push(`EXPOSURE   ${ratingColor(bar)}  ${dim(`score ${result.score}`)}`);
  out.push(`VERDICT    ${ratingColor(bold(result.rating.toUpperCase()))}`);
  out.push(`NOTE       ${result.ratingNote}`);
  out.push(dim(rule));
  out.push(dim("Even $3 trillion in AI compute couldn't detect a red flag. This script checked the staged diff."));
  return out.join('\n');
}

function toJson(result, mode, elapsedMs) {
  return {
    schemaVersion: '1.0',
    tool: { name: 'honeypot-guard', version: '1.0.0' },
    mode,
    localOnly: true,
    elapsedMs,
    summary: {
      findings: result.findings.length,
      score: result.score,
      rating: result.rating,
      counts: result.counts,
    },
    findings: result.findings,
  };
}

function toSarif(result) {
  const rules = new Map();
  const results = result.findings.map((finding) => {
    if (!rules.has(finding.id)) {
      rules.set(finding.id, {
        id: finding.id,
        name: finding.name,
        shortDescription: { text: finding.name },
        fullDescription: { text: finding.message },
        help: { text: finding.recommendation },
        defaultConfiguration: { level: SEVERITY_LEVEL[finding.severity] },
        properties: { tags: ['security', 'secrets', 'pre-commit'], precision: 'medium' },
      });
    }
    const location = {
      physicalLocation: {
        artifactLocation: { uri: finding.file.replace(/\\/g, '/') },
      },
    };
    if (finding.line > 0) location.physicalLocation.region = { startLine: finding.line };
    return {
      ruleId: finding.id,
      level: SEVERITY_LEVEL[finding.severity],
      message: { text: `${finding.message} ${finding.evidence}` },
      locations: [location],
      properties: {
        severity: finding.severity,
        securitySeverity: SECURITY_SCORE[finding.severity],
        recommendation: finding.recommendation,
      },
    };
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'honeypot-guard',
          version: '1.0.0',
          informationUri: 'https://github.com/voyager67/HoneyPot-Guard',
          rules: [...rules.values()],
        },
      },
      results,
    }],
  };
}

module.exports = { formatText, toJson, toSarif };
