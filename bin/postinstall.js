#!/usr/bin/env node

/**
 * TRACE post-install: provisions Python + dependencies so that `trace`
 * works immediately after `npm install -g trace-sec`.
 *
 * Must never fail the install: on any problem it exits 0 and the launcher
 * (bin/trace.js) finishes setup on first run.
 */

import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';
import { dedicatedPaths, ensureVenv } from './lib/venv.js';
import { hasTraceDeps } from './lib/python.js';

try {
  if (process.env.TRACE_SKIP_POSTINSTALL === '1' || process.env.CI === 'true') process.exit(0);

  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const isWin = process.platform === 'win32';
  const home = process.env.USERPROFILE || process.env.HOME || '';
  const { python } = dedicatedPaths(home, isWin);

  if (!hasTraceDeps(python)) {
    const ready = ensureVenv(home, isWin, join(root, 'requirements.txt'));
    if (!ready) {
      console.log('[TRACE] Python 3.11+ was not found; it will be set up on first run of `trace`.');
    }
  }
  console.log('\x1b[32m\x1b[1m✓ TRACE installed.\x1b[0m Run \x1b[36mtrace\x1b[0m from any terminal.\n');
} catch {
  // Never break `npm install`.
}
process.exit(0);
