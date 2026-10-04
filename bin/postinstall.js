#!/usr/bin/env node

/**
 * TRACE Post-Install Script
 * Automatically provisions Python runtime and core dependencies during `npm install`.
 */

import { execSync } from 'child_process';
import { existsSync, mkdirSync } from 'fs';
import { resolve, join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, '..');

const isWin = process.platform === 'win32';
const userHome = process.env.USERPROFILE || process.env.HOME || '';
const dedicatedDir = join(userHome, '.trace');
const dedicatedVenv = join(dedicatedDir, 'venv');
const venvPython = join(dedicatedVenv, isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python');
const venvPip = join(dedicatedVenv, isWin ? 'Scripts' : 'bin', isWin ? 'pip.exe' : 'pip');
const reqFile = join(projectRoot, 'requirements.txt');

function findSystemPython() {
  const candidates = isWin
    ? [
        'python',
        'py -3',
        'py',
        'python3',
        join(process.env.LOCALAPPDATA || '', 'Programs', 'Python', 'Python312', 'python.exe'),
        join(process.env.LOCALAPPDATA || '', 'Programs', 'Python', 'Python311', 'python.exe'),
        join(process.env.LOCALAPPDATA || '', 'Programs', 'Python', 'Python310', 'python.exe'),
        join(process.env.PROGRAMFILES || '', 'Python312', 'python.exe'),
        join(process.env.PROGRAMFILES || '', 'Python311', 'python.exe'),
        join(process.env.PROGRAMFILES || '', 'Python310', 'python.exe'),
      ]
    : [
        'python3',
        'python',
        '/usr/bin/python3',
        '/usr/local/bin/python3',
        '/opt/homebrew/bin/python3',
      ];

  for (const cmd of candidates) {
    if (!cmd || !cmd.trim()) continue;
    try {
      const execCmd = cmd.includes(' ') && !cmd.startsWith('py ') ? `"${cmd}"` : cmd;
      const ver = execSync(`${execCmd} -c "import sys; print(sys.version_info[0], sys.version_info[1])"`, {
        stdio: ['ignore', 'pipe', 'ignore'],
        encoding: 'utf-8',
      }).trim();
      const parts = ver.split(/\s+/).map(Number);
      if (parts[0] === 3 && parts[1] >= 9) {
        return execCmd;
      }
    } catch {
      // try next candidate
    }
  }
  return null;
}

try {
  console.log('\n\x1b[32m\x1b[1m[TRACE]\x1b[0m Configuring environment for autonomous security verification...');

  mkdirSync(dedicatedDir, { recursive: true });

  const sysPython = findSystemPython();
  if (!sysPython) {
    console.log('  \x1b[38;2;255;158;59m•\x1b[0m Python 3.10+ not detected on PATH yet.');
    console.log('  \x1b[38;2;255;158;59m•\x1b[0m Quick install:');
    if (isWin) {
      console.log('      \x1b[36mwinget install Python.Python.3.11\x1b[0m');
    } else if (process.platform === 'darwin') {
      console.log('      \x1b[36mbrew install python\x1b[0m');
    } else {
      console.log('      \x1b[36msudo apt install -y python3 python3-pip python3-venv\x1b[0m');
    }
    console.log('  Once installed, dependencies will configure automatically on first run.\n');
    process.exit(0);
  }

  // Create virtualenv if not already created
  if (!existsSync(venvPython)) {
    console.log(`  \x1b[38;2;255;158;59m›\x1b[0m Initializing isolated Python environment in ${dedicatedVenv}...`);
    execSync(`${sysPython} -m venv "${dedicatedVenv}"`, { stdio: 'inherit' });
  }

  // Check if dependencies are already satisfied
  let depsOk = false;
  try {
    execSync(`"${venvPython}" -c "import typer, rich, pydantic, tree_sitter"`, {
      stdio: 'ignore',
    });
    depsOk = true;
  } catch {
    depsOk = false;
  }

  if (!depsOk) {
    console.log('  \x1b[38;2;255;158;59m›\x1b[0m Installing core Python dependencies into dedicated environment...');
    if (existsSync(reqFile)) {
      execSync(`"${venvPython}" -m pip install -r "${reqFile}"`, { stdio: 'inherit' });
    } else {
      execSync(`"${venvPython}" -m pip install typer rich pydantic pydantic-settings networkx httpx orjson tomli-w tree-sitter tree-sitter-language-pack onnxruntime transformers safetensors numpy`, { stdio: 'inherit' });
    }
    console.log('  \x1b[32m✓\x1b[0m Dependencies successfully attached and verified.');
  } else {
    console.log('  \x1b[32m✓\x1b[0m Dedicated runtime dependencies already up to date.');
  }

  console.log('\x1b[32m\x1b[1m✓ TRACE ready to run!\x1b[0m Type \x1b[36mtrace\x1b[0m or \x1b[36mnpx trace-sec\x1b[0m to launch.\n');
} catch (err) {
  // Never fail npm install completely on postinstall warning
  console.log(`  \x1b[38;2;255;158;59m[TRACE]\x1b[0m Background setup notice: ${err.message}`);
  console.log('  Dependencies will be verified when you run \x1b[36mtrace\x1b[0m.\n');
}

