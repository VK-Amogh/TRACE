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
