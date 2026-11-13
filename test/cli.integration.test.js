'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const projectRoot = path.resolve(__dirname, '..');
const cli = path.join(projectRoot, 'bin', 'honeypot-guard.js');

function run(args, cwd) {
  return spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8' });
}

function git(args, cwd) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr || `git ${args.join(' ')} failed`);
  return result.stdout;
}

function tempRepo() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'honeypot-guard-'));
  git(['init', '-q', '-b', 'main'], directory);
  git(['config', 'user.email', 'tests@example.invalid'], directory);
  git(['config', 'user.name', 'Honeypot Guard Tests'], directory);
  return directory;
}

test('scans staged additions, redacts secrets, and blocks at the default threshold', () => {
  const directory = tempRepo();
  try {
    const secret = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
    fs.mkdirSync(path.join(directory, 'src'));
    fs.writeFileSync(path.join(directory, 'src', 'app.js'), `const value = "${secret}";\n`);
    git(['add', 'src/app.js'], directory);

    const blocked = run(['scan', '--staged', '--format', 'json'], directory);
    assert.equal(blocked.status, 1, blocked.stderr);
    const report = JSON.parse(blocked.stdout);
    assert.ok(report.findings.some((finding) => finding.id === 'AWS-001'));
    assert.equal(blocked.stdout.includes(secret), false);

    const dryRun = run(['scan', '--staged', '--dry-run', '--format', 'json'], directory);
    assert.equal(dryRun.status, 0, dryRun.stderr);
    assert.ok(JSON.parse(dryRun.stdout).findings.length > 0);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('demo exits successfully and supports JSON output', () => {
  const result = run(['demo', '--format', 'json'], projectRoot);
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.mode, 'synthetic demo');
  assert.equal(typeof report.elapsedMs, 'number');
  assert.ok(report.summary.findings >= 7);
});

test('managed hook installer is idempotent and refuses to overwrite a user hook', () => {
  const directory = tempRepo();
  try {
    const installed = run(['install'], directory);
    assert.equal(installed.status, 0, installed.stderr);
    const hook = path.join(directory, '.git', 'hooks', 'pre-commit');
    assert.ok(fs.readFileSync(hook, 'utf8').includes('honeypot-guard: managed hook'));

    const second = run(['install'], directory);
    assert.equal(second.status, 0, second.stderr);
    const removed = run(['uninstall'], directory);
    assert.equal(removed.status, 0, removed.stderr);
    assert.equal(fs.existsSync(hook), false);

    fs.writeFileSync(hook, '#!/bin/sh\necho user-hook\n', { mode: 0o755 });
    const conflict = run(['install'], directory);
    assert.equal(conflict.status, 2);
    assert.match(conflict.stderr, /Refusing to overwrite/);
    assert.match(fs.readFileSync(hook, 'utf8'), /user-hook/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('empty index is a clean scan rather than an error', () => {
  const directory = tempRepo();
  try {
    const result = run(['scan', '--staged', '--format', 'json'], directory);
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.summary.findings, 0);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('unknown options fail with a usage error instead of being silently ignored', () => {
  const result = run(['scan', '--surprise'], projectRoot);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /Unknown option/);
});


test('rejects inherited object property names as fail-on levels', () => {
  for (const value of ['constructor', 'toString', '__proto__']) {
    const result = run(['scan', '--fail-on', value], projectRoot);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /Invalid --fail-on value/);
  }
});
