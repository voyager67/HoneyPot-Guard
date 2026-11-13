'use strict';

const { loadConfig } = require('./config');
const { findRepositoryRoot, installHook, readStagedChanges, uninstallHook } = require('./git');
const { formatText, toJson, toSarif } = require('./report');
const { demoChanges, scanChanges } = require('./scanner');

const VERSION = '1.0.0';
const FAIL_LEVEL = Object.freeze({ never: 99, low: 1, medium: 2, high: 3, critical: 4 });

function parseArgs(args) {
  const parsed = { positionals: [], flags: new Set(), values: new Map() };
  const valueOptions = new Set(['--format', '--fail-on', '--config']);
  const flagOptions = new Set(['--help', '-h', '--version', '-v', '--dry-run', '--no-color', '--staged', '--install', '--uninstall']);
  for (let i = 0; i < args.length; i += 1) {
    const item = args[i];
    if (!item.startsWith('-')) {
      parsed.positionals.push(item);
      continue;
    }
    if (valueOptions.has(item)) {
      if (!args[i + 1] || args[i + 1].startsWith('-')) throw new Error(`Option ${item} requires a value.`);
      parsed.values.set(item, args[i + 1]);
      i += 1;
    } else if (flagOptions.has(item)) {
      parsed.flags.add(item);
    } else {
      throw new Error(`Unknown option: ${item}`);
    }
  }
  if (parsed.positionals.length > 1) throw new Error(`Unexpected argument: ${parsed.positionals[1]}`);
  return parsed;
}

function printHelp() {
  console.log(`🍯 honeypot-guard v${VERSION}

Even $3 trillion in AI compute couldn't detect a red flag. Your pre-commit hook can.

USAGE
  honeypot-guard demo [--no-color]
  honeypot-guard --dry-run [--no-color]             Run the synthetic demo
  honeypot-guard scan --staged [options]            Scan added lines in the Git index
  honeypot-guard install                            Install a safe pre-commit hook
  honeypot-guard uninstall                          Remove only this tool's managed hook

SCAN OPTIONS
  --dry-run                 Report findings without blocking the commit
  --fail-on <level>         never | low | medium | high | critical (default: high)
  --format <format>         text | json | sarif (default: text)
  --config <path>           Use an alternate JSON policy file
  --no-color                Disable ANSI colors

POLICY
  .honeypot-guard.json supports allowedHosts, ignoredPaths, and disabledRules.
  Add  // honeypot-guard:ignore  to an added line to suppress that line.

EXIT CODES
  0  No finding meets the blocking threshold, or demo/dry-run mode
  1  A finding meets the blocking threshold
  2  Git, configuration, argument, or hook installation error`);
}

function validateFormat(format) {
  if (!['text', 'json', 'sarif'].includes(format)) throw new Error(`Unknown output format: ${format}`);
  return format;
}

function outputResult(result, format, mode, elapsedMs, noColor) {
  if (format === 'json') {
    console.log(JSON.stringify(toJson(result, mode, elapsedMs), null, 2));
  } else if (format === 'sarif') {
    console.log(JSON.stringify(toSarif(result), null, 2));
  } else {
    console.log(formatText(result, elapsedMs, mode, { noColor }));
  }
}

function scanCommand(parsed) {
  const format = validateFormat(parsed.values.get('--format') || 'text');
  const failOn = parsed.values.get('--fail-on') || 'high';
  if (!Object.hasOwn(FAIL_LEVEL, failOn)) throw new Error(`Invalid --fail-on value: ${failOn}`);
  const started = process.hrtime.bigint();
  const noColor = parsed.flags.has('--no-color');
  const root = findRepositoryRoot();
  const config = loadConfig(root, parsed.values.get('--config'));
  const changes = readStagedChanges(root);
  const result = scanChanges(changes, config);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  const dryRun = parsed.flags.has('--dry-run');
  outputResult(result, format, dryRun ? 'staged scan · dry-run' : 'staged scan', Number(elapsedMs.toFixed(1)), noColor);

  if (dryRun) return 0;

  const blocking = result.findings.some((finding) => FAIL_LEVEL[finding.severity] >= FAIL_LEVEL[failOn]);
  return blocking ? 1 : 0;
}

function demoCommand(parsed) {
  const started = process.hrtime.bigint();
  const result = scanChanges(demoChanges(), {});
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  const format = validateFormat(parsed.values.get('--format') || 'text');
  outputResult(result, format, 'synthetic demo', Number(elapsedMs.toFixed(1)), parsed.flags.has('--no-color'));
  return 0;
}

function main(argv = process.argv.slice(2)) {
  try {
    const parsed = parseArgs(argv);
    if (parsed.flags.has('--help') || parsed.flags.has('-h') || parsed.positionals[0] === 'help') {
      printHelp();
      return 0;
    }
    if (parsed.flags.has('--version') || parsed.flags.has('-v')) {
      console.log(VERSION);
      return 0;
    }

    const command = parsed.positionals[0];
    if (command === 'demo' || (!command && parsed.flags.has('--dry-run'))) return demoCommand(parsed);

    if (command === 'install' || parsed.flags.has('--install')) {
      const result = installHook();
      console.log(result.alreadyInstalled ? `Pre-commit hook already managed at ${result.hookPath}` : `Installed pre-commit hook at ${result.hookPath}`);
      return 0;
    }

    if (command === 'uninstall' || parsed.flags.has('--uninstall')) {
      const result = uninstallHook();
      console.log(result.removed ? `Removed managed pre-commit hook at ${result.hookPath}` : 'No managed pre-commit hook was installed.');
      return 0;
    }

    if (!command || command === 'scan') return scanCommand(parsed);
    throw new Error(`Unknown command: ${command}`);
  } catch (error) {
    console.error(`honeypot-guard: ${error.message}`);
    return 2;
  }
}

module.exports = { FAIL_LEVEL, main, parseArgs, scanCommand };
