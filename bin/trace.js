#!/usr/bin/env node

/**
 * TRACE — Threat Reconnaissance & Attack-path Correlation Engine
 * Node.js & NPX launcher for the TRACE Python engine.
 *
 * Fast paths (--version, install-skill) run in Node.js with zero
 * dependencies. Everything else resolves a Python interpreter
 * (TRACE_PYTHON > ~/.trace/venv > ./.venv > system) and spawns
 * `python -m trace_engine.cli`.
 */

import { spawn } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import { resolve, join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { MIN_PYTHON } from './lib/config.js';
import { resolvePython, hasTraceDeps, installHint } from './lib/python.js';
import { dedicatedPaths, ensureVenv } from './lib/venv.js';
import { installSkills } from './lib/skills.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, '..');
const args = process.argv.slice(2);
const isWin = process.platform === 'win32';
const [minMajor, minMinor] = MIN_PYTHON;

// --version: instant, no Python needed.
if (['--version', '-v', '-V', 'version'].includes(args[0])) {
  try {
    const pkg = JSON.parse(readFileSync(join(projectRoot, 'package.json'), 'utf-8'));
    console.log(`TRACE v${pkg.version}`);
  } catch {
    console.log('TRACE');
  }
  process.exit(0);
}

// install-skill: instant, zero-dependency agent setup.
if (['install-skill', 'setup-agent', 'install-agent'].includes(args[0])) {
  installSkills(process.cwd(), projectRoot);
  process.exit(0);
}

// Resolve Python.
const userHome = process.env.USERPROFILE || process.env.HOME || '';
const { python: dedicatedPython } = dedicatedPaths(userHome, isWin);
const reqFile = join(projectRoot, 'requirements.txt');

let { bin: pythonBin } = resolvePython({ isWin, dedicatedPython, projectRoot });

if (!pythonBin) {
  console.error(`\n\x1b[31m\x1b[1m[TRACE ERROR]\x1b[0m Python ${minMajor}.${minMinor}+ is required to execute TRACE.`);
  console.error(`  \x1b[36m${installHint(isWin)}\x1b[0m\n`);
  process.exit(1);
}

// Provision deps when the resolved interpreter lacks them.
if (!hasTraceDeps(pythonBin)) {
  if (existsSync(dedicatedPython) && hasTraceDeps(dedicatedPython)) {
    pythonBin = dedicatedPython;
  } else {
    const provisioned = ensureVenv(userHome, isWin, reqFile);
    if (provisioned) pythonBin = provisioned;
  }
}

const cliArgs = ['-m', 'trace_engine.cli', ...args];
const sep = isWin ? ';' : ':';

const proc = spawn(pythonBin, cliArgs, {
  cwd: process.cwd(),
  stdio: 'inherit',
  env: {
    ...process.env,
    PYTHONPATH: join(projectRoot, 'src') + (process.env.PYTHONPATH ? sep + process.env.PYTHONPATH : ''),
    PYTHONIOENCODING: 'utf-8',
  },
});

proc.on('exit', (code) => {
  process.exit(code || 0);
});

proc.on('error', (err) => {
  console.error(`[TRACE] Failed to spawn Python process (${pythonBin}):`, err.message);
  console.error(`Please ensure Python ${minMajor}.${minMinor}+ is installed and on your PATH, or run: pip install -e .`);
  process.exit(1);
});
