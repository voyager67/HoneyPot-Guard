'use strict';

const { execFileSync } = require('node:child_process');
const path = require('node:path');

function runGit(args, options = {}) {
  try {
    return execFileSync('git', args, {
      cwd: options.cwd,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
  } catch (error) {
    const stderr = error.stderr ? String(error.stderr).trim() : '';
    const detail = stderr || error.message || 'Git command failed.';
    const wrapped = new Error(detail);
    wrapped.code = error.status || 2;
    throw wrapped;
  }
}

function findRepositoryRoot(cwd = process.cwd()) {
  return runGit(['rev-parse', '--show-toplevel'], { cwd }).trim();
}

function parseAddedLines(patch, file) {
  const items = [];
  let lineNumber = 0;
  for (const row of patch.split(/\r?\n/)) {
    const hunk = row.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) {
      lineNumber = Number.parseInt(hunk[1], 10);
      continue;
    }
    if (row.startsWith('+++') || row.startsWith('---') || row.startsWith('\\')) continue;
    if (row.startsWith('+')) {
      items.push({ file, line: lineNumber, text: row.slice(1) });
      lineNumber += 1;
    } else if (row.startsWith(' ')) {
      lineNumber += 1;
    }
  }
  return items;
}

function readStagedChanges(cwd = process.cwd()) {
  const root = findRepositoryRoot(cwd);
  const nameOutput = runGit(
    ['diff', '--cached', '--name-only', '-z', '--diff-filter=ACMRT'],
    { cwd: root },
  );
  const names = nameOutput.split('\0').filter(Boolean);
  const items = [];

  for (const file of names) {
    const patch = runGit(
      ['diff', '--cached', '--no-ext-diff', '--no-color', '--unified=0', '--diff-filter=ACMRT', '--', file],
      { cwd: root },
    );
    items.push(...parseAddedLines(patch, file));
  }

  return { root: path.resolve(root), items, names };
}

function installHook(cwd = process.cwd()) {
  const root = findRepositoryRoot(cwd);
  const hookDirectory = path.resolve(root, runGit(['rev-parse', '--git-path', 'hooks'], { cwd: root }).trim());
  const hookPath = path.join(hookDirectory, 'pre-commit');
  const marker = '# honeypot-guard: managed hook';

  const fs = require('node:fs');
  fs.mkdirSync(hookDirectory, { recursive: true });

  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, 'utf8');
    if (existing.includes(marker)) return { hookPath, alreadyInstalled: true };
    throw new Error(`A pre-commit hook already exists at ${hookPath}. Refusing to overwrite it.`);
  }

  const hook = `#!/bin/sh\n${marker}\nROOT="$(git rev-parse --show-toplevel)" || exit 2\nBIN="$ROOT/node_modules/.bin/honeypot-guard"\nif [ -x "$BIN" ]; then\n  exec "$BIN" scan --staged\nfi\necho "honeypot-guard: CLI not found in node_modules/.bin; install the project dependency first." >&2\nexit 2\n`;
  fs.writeFileSync(hookPath, hook, { mode: 0o755, flag: 'wx' });
  return { hookPath, alreadyInstalled: false };
}

function uninstallHook(cwd = process.cwd()) {
  const root = findRepositoryRoot(cwd);
  const hookDirectory = path.resolve(root, runGit(['rev-parse', '--git-path', 'hooks'], { cwd: root }).trim());
  const hookPath = path.join(hookDirectory, 'pre-commit');
  const marker = '# honeypot-guard: managed hook';
  const fs = require('node:fs');

  if (!fs.existsSync(hookPath)) return { hookPath, removed: false };
  const existing = fs.readFileSync(hookPath, 'utf8');
  if (!existing.includes(marker)) {
    throw new Error(`The pre-commit hook at ${hookPath} is not managed by honeypot-guard. It was left unchanged.`);
  }
  fs.unlinkSync(hookPath);
  return { hookPath, removed: true };
}

module.exports = {
  findRepositoryRoot,
  installHook,
  parseAddedLines,
  readStagedChanges,
  runGit,
  uninstallHook,
};
