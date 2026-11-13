'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_CONFIG = Object.freeze({
  allowedHosts: [],
  ignoredPaths: [],
  disabledRules: [],
});

function assertStringArray(value, field) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || !item.trim())) {
    throw new Error(`Configuration field "${field}" must be an array of non-empty strings.`);
  }
}

function loadConfig(projectRoot, configPath) {
  const target = configPath
    ? path.resolve(projectRoot, configPath)
    : path.join(projectRoot, '.honeypot-guard.json');

  if (!fs.existsSync(target)) return { ...DEFAULT_CONFIG };

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(target, 'utf8'));
  } catch (error) {
    throw new Error(`Cannot parse ${target}: ${error.message}`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Configuration must be a JSON object.');
  }

  const allowedKeys = new Set(Object.keys(DEFAULT_CONFIG));
  for (const key of Object.keys(parsed)) {
    if (!allowedKeys.has(key)) throw new Error(`Unknown configuration field: ${key}`);
  }

  for (const key of Object.keys(DEFAULT_CONFIG)) {
    if (parsed[key] !== undefined) assertStringArray(parsed[key], key);
  }

  return {
    allowedHosts: (parsed.allowedHosts || []).map((host) => host.trim().toLowerCase()),
    ignoredPaths: parsed.ignoredPaths || [],
    disabledRules: parsed.disabledRules || [],
  };
}

function globToRegExp(glob) {
  let out = '^';
  for (let i = 0; i < glob.length; i += 1) {
    const ch = glob[i];
    const next = glob[i + 1];
    if (ch === '*' && next === '*') {
      if (glob[i + 2] === '/') {
        out += '(?:.*/)?';
        i += 2;
      } else {
        out += '.*';
        i += 1;
      }
    } else if (ch === '*') {
      out += '[^/]*';
    } else if (ch === '?') {
      out += '[^/]';
    } else {
      out += ch.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
    }
  }
  return new RegExp(`${out}$`);
}

function isIgnoredPath(file, patterns) {
  const normalized = file.replace(/\\/g, '/').replace(/^\.\//, '');
  return patterns.some((pattern) => globToRegExp(pattern).test(normalized));
}

function isAllowedHost(hostname, allowedHosts) {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  return allowedHosts.some((entry) => {
    const rule = entry.toLowerCase().replace(/\.$/, '');
    if (rule.startsWith('*.')) {
      const suffix = rule.slice(1);
      return host.endsWith(suffix) && host.length > suffix.length;
    }
    return host === rule;
  });
}

module.exports = {
  DEFAULT_CONFIG,
  globToRegExp,
  isAllowedHost,
  isIgnoredPath,
  loadConfig,
};
