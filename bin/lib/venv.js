/**
 * Dedicated virtual environment provisioning (~/.trace/venv).
 */

import { execSync } from 'child_process';
import { existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { FALLBACK_GIT_URL } from './config.js';
import { ensurePython, hasTraceDeps } from './python.js';

// Quiet, non-interactive pip: no version-check nags, no progress noise.
const PIP_FLAGS = '-q --disable-pip-version-check --no-input --no-warn-script-location';
const PIP_ENV = { ...process.env, PIP_DISABLE_PIP_VERSION_CHECK: '1', PYTHONWARNINGS: 'ignore' };

export function dedicatedPaths(userHome, isWin) {
  const venv = join(userHome, '.trace', 'venv');
  const binDir = join(venv, isWin ? 'Scripts' : 'bin');
  return {
    venv,
    python: join(binDir, isWin ? 'python.exe' : 'python'),
  };
}

/**
 * Ensure the dedicated venv exists and satisfies TRACE deps.
 * Returns the venv python path, or null when provisioning is impossible.
 * Never throws: callers fall back to whatever interpreter resolved.
 *
 * Lite deps by default for a fast install; TRACE_FULL_DEPS=1 adds the full
 * AI stack (torch, transformers) from requirements.txt.
 */
export function ensureVenv(userHome, isWin, reqFile, { quiet = false } = {}) {
  const { venv, python } = dedicatedPaths(userHome, isWin);
  const say = (m) => { if (!quiet) console.log(m); };
  try {
    say('\n\x1b[32m\x1b[1m[TRACE]\x1b[0m Setting up TRACE runtime (one-time)...');
    mkdirSync(join(userHome, '.trace'), { recursive: true });
    if (!existsSync(python)) {
      const sysPy = ensurePython(isWin);
      if (!sysPy) return null;
      say('  \x1b[38;2;255;158;59m›\x1b[0m Creating isolated Python environment...');
      execSync(`${sysPy} -m venv "${venv}"`, { stdio: 'ignore' });
    }
    say('  \x1b[38;2;255;158;59m›\x1b[0m Installing dependencies...');
    const run = (cmd) => execSync(cmd, { stdio: ['ignore', 'ignore', 'inherit'], env: PIP_ENV });
    if (process.env.TRACE_FULL_DEPS === '1' && reqFile && existsSync(reqFile)) {
      run(`"${python}" -m pip install ${PIP_FLAGS} -r "${reqFile}"`);
    } else {
      run(
        `"${python}" -m pip install ${PIP_FLAGS} typer rich pydantic pydantic-settings networkx httpx orjson tomli-w tree-sitter tree-sitter-language-pack`,
      );
    }
    say('\x1b[32m✓ TRACE runtime ready.\x1b[0m\n');
    return hasTraceDeps(python) ? python : null;
  } catch (e) {
    console.warn(`[TRACE] Automatic environment setup incomplete: ${e.message}`);
    console.warn(`Fallback: pip install ${FALLBACK_GIT_URL}\n`);
    return null;
  }
}
