#!/usr/bin/env node

/**
 * TRACE — Threat Reconnaissance & Attack-path Correlation Engine
 * Node.js & NPX launcher for TRACE Python engine.
 */

import { spawn } from 'child_process';
import { existsSync } from 'fs';
import { resolve, join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, '..');

// Find virtual environment python or system python
const isWin = process.platform === 'win32';
const venvPython = isWin
  ? join(projectRoot, '.venv', 'Scripts', 'python.exe')
  : join(projectRoot, '.venv', 'bin', 'python');

const pythonBin = existsSync(venvPython) ? venvPython : (isWin ? 'python' : 'python3');

const args = process.argv.slice(2);
const cliArgs = ['-m', 'trace_engine.cli', ...args];

const proc = spawn(pythonBin, cliArgs, {
  cwd: process.cwd(),
  stdio: 'inherit',
  env: {
    ...process.env,
    PYTHONPATH: join(projectRoot, 'src') + (process.env.PYTHONPATH ? (isWin ? ';' : ':') + process.env.PYTHONPATH : ''),
    PYTHONIOENCODING: 'utf-8',
  },
});

proc.on('exit', (code) => {
  process.exit(code || 0);
});

proc.on('error', (err) => {
  console.error(`[TRACE] Failed to spawn Python process (${pythonBin}):`, err.message);
  process.exit(1);
});
