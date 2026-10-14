/**
 * Dedicated virtual environment provisioning (~/.trace/venv).
 */

import { execSync } from 'child_process';
import { existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { FALLBACK_GIT_URL } from './config.js';
import { findSystemPython, hasTraceDeps } from './python.js';

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
 */
export function ensureVenv(userHome, isWin, reqFile) {
  const { venv, python } = dedicatedPaths(userHome, isWin);
  try {
    console.log('\n\x1b[32m\x1b[1m[TRACE]\x1b[0m Initializing TRACE runtime dependencies in dedicated environment (~/.trace/venv)...');
    mkdirSync(join(userHome, '.trace'), { recursive: true });
    if (!existsSync(python)) {
      console.log('  \x1b[38;2;255;158;59m›\x1b[0m Creating Python virtual environment in ~/.trace/venv...');
      const sysPy = findSystemPython(isWin);
      if (!sysPy) return null;
      execSync(`${sysPy} -m venv "${venv}"`, { stdio: 'inherit' });
    }
    console.log('  \x1b[38;2;255;158;59m›\x1b[0m Installing core dependencies via pip...');
    // Lite by default for fast first runs; set TRACE_FULL_DEPS=1 for the
    // full AI stack (torch, transformers) from requirements.txt.
    if (process.env.TRACE_FULL_DEPS === '1' && reqFile && existsSync(reqFile)) {
      execSync(`"${python}" -m pip install -r "${reqFile}"`, { stdio: 'inherit' });
    } else {
      execSync(
        `"${python}" -m pip install typer rich pydantic pydantic-settings networkx httpx orjson tomli-w tree-sitter tree-sitter-language-pack`,
        { stdio: 'inherit' },
      );
    }
    console.log('\x1b[32m✓ Runtime dependencies provisioned successfully.\x1b[0m\n');
    return hasTraceDeps(python) ? python : null;
  } catch (e) {
    console.warn(`[TRACE] Automatic environment setup warning: ${e.message}`);
    console.warn(`If command fails, install directly via: pip install ${FALLBACK_GIT_URL}\n`);
    return null;
  }
}
