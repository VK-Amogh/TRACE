/**
 * Python interpreter discovery and dependency probing.
 */

import { execSync } from 'child_process';
import { existsSync } from 'fs';
import { join } from 'path';
import { MIN_PYTHON, LITE_DEPS, meetsMinimum } from './config.js';

function queryVersion(pythonCmd) {
  const out = execSync(`${pythonCmd} -c "import sys; print(sys.version_info[0], sys.version_info[1])"`, {
    stdio: ['ignore', 'pipe', 'ignore'],
    encoding: 'utf-8',
  }).trim();
  const parts = out.split(/\s+/).map(Number);
  if (parts.length < 2 || parts.some(Number.isNaN)) return null;
  return parts;
}

function systemCandidates(isWin) {
  if (isWin) {
    const localApp = process.env.LOCALAPPDATA || '';
    const progFiles = process.env.PROGRAMFILES || '';
    return [
      'python',
      'py -3',
      'py',
      'python3',
      join(localApp, 'Programs', 'Python', 'Python313', 'python.exe'),
      join(localApp, 'Programs', 'Python', 'Python312', 'python.exe'),
      join(localApp, 'Programs', 'Python', 'Python311', 'python.exe'),
      join(progFiles, 'Python313', 'python.exe'),
      join(progFiles, 'Python312', 'python.exe'),
      join(progFiles, 'Python311', 'python.exe'),
    ];
  }
  return ['python3', 'python', '/usr/bin/python3', '/usr/local/bin/python3', '/opt/homebrew/bin/python3'];
}

export function findSystemPython(isWin) {
  for (const cmd of systemCandidates(isWin)) {
    if (!cmd || !cmd.trim()) continue;
    try {
      const execCmd = cmd.includes(' ') && !cmd.startsWith('py ') ? `"${cmd}"` : cmd;
      const ver = queryVersion(execCmd);
      if (ver && meetsMinimum(ver)) return execCmd;
    } catch {
      // try next candidate
    }
  }
  return null;
}

function hasCommand(cmd) {
  try {
    execSync(`${process.platform === 'win32' ? 'where' : 'command -v'} ${cmd}`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Find a suitable Python, installing one via the OS package manager when
 * none exists (winget on Windows, Homebrew on macOS). Returns null when it
 * cannot be provisioned without elevated privileges (e.g. Linux apt).
 * Opt out with TRACE_SKIP_PYTHON_INSTALL=1.
 */
export function ensurePython(isWin) {
  const found = findSystemPython(isWin);
  if (found || process.env.TRACE_SKIP_PYTHON_INSTALL === '1') return found;
  const [major, minor] = MIN_PYTHON;
  try {
    if (isWin && hasCommand('winget')) {
      console.log(`  \x1b[38;2;255;158;59m›\x1b[0m Installing Python ${major}.12 (one-time, via winget)...`);
      execSync(
        `winget install -e --id Python.Python.${major}.12 --silent --scope user --accept-package-agreements --accept-source-agreements`,
        { stdio: 'ignore' },
      );
    } else if (process.platform === 'darwin' && hasCommand('brew')) {
      console.log(`  \x1b[38;2;255;158;59m›\x1b[0m Installing Python ${major}.${minor}+ (one-time, via Homebrew)...`);
      execSync('brew install python', { stdio: 'ignore' });
    }
  } catch {
    // fall through to re-detection / hint
  }
  return findSystemPython(isWin);
}

/**
 * Resolve a usable Python in priority order:
 * TRACE_PYTHON > dedicated venv > ./​.venv > project .venv > system.
 * Returns { bin, fromVenv } or { bin: null }.
 */
export function resolvePython({ isWin, dedicatedPython, projectRoot }) {
  const candidates = [
    process.env.TRACE_PYTHON,
    dedicatedPython,
    join(process.cwd(), '.venv', isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python'),
    join(projectRoot, '.venv', isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python'),
  ];
  for (const cand of candidates) {
    if (cand && existsSync(cand)) {
      return { bin: cand, fromVenv: true };
    }
  }
  return { bin: findSystemPython(isWin), fromVenv: false };
}

export function hasTraceDeps(pythonBin) {
  try {
    const mods = LITE_DEPS.map((d) => d.replace(/-/g, '_')).join(', ');
    execSync(`"${pythonBin}" -c "import ${mods}"`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

export function installHint(isWin) {
  const [major, minor] = MIN_PYTHON;
  if (isWin) return `winget install Python.Python.3.${minor}  (or from https://www.python.org/)`;
  if (process.platform === 'darwin') return 'brew install python';
  return 'sudo apt install -y python3 python3-pip python3-venv';
}
