#!/usr/bin/env node

/**
 * TRACE — Threat Reconnaissance & Attack-path Correlation Engine
 * Node.js & NPX launcher for TRACE Python engine.
 */

import { spawn, execSync } from 'child_process';
import { existsSync, mkdirSync, cpSync, writeFileSync, readFileSync } from 'fs';
import { resolve, join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, '..');
const args = process.argv.slice(2);

// Handle --version / -v directly in Node.js for instant response
if (args[0] === '--version' || args[0] === '-v' || args[0] === '-V' || args[0] === 'version') {
  try {
    const pkg = JSON.parse(readFileSync(join(projectRoot, 'package.json'), 'utf-8'));
    console.log(`TRACE v${pkg.version}`);
  } catch {
    console.log('TRACE');
  }
  process.exit(0);
}

// Handle install-skill directly in Node.js for instant zero-dependency agent skill setup
if (args[0] === 'install-skill' || args[0] === 'setup-agent' || args[0] === 'install-agent') {
  const targetDir = process.cwd();
  const bundleDir = join(projectRoot, 'src', 'trace_engine', 'plugin', 'bundle');

  console.log('\n\x1b[32m\x1b[1mInstalling TRACE Autonomous Security Agent Skill & MCP Tools...\x1b[0m');

  if (existsSync(bundleDir)) {
    // 1. Antigravity plugin (.agents/plugins/trace-security)
    const agentPluginDir = join(targetDir, '.agents', 'plugins', 'trace-security');
    mkdirSync(agentPluginDir, { recursive: true });
    cpSync(bundleDir, agentPluginDir, { recursive: true });
    console.log(`  \x1b[32m✓\x1b[0m Antigravity Plugin : ${agentPluginDir}`);

    // 2. Direct agent skill (.agents/skills/trace-security-harness)
    const skillSrc = join(bundleDir, 'skills', 'trace-security-harness');
    if (existsSync(skillSrc)) {
      const agentSkillDir = join(targetDir, '.agents', 'skills', 'trace-security-harness');
      mkdirSync(agentSkillDir, { recursive: true });
      cpSync(skillSrc, agentSkillDir, { recursive: true });
      console.log(`  \x1b[32m✓\x1b[0m Agent Skill        : ${agentSkillDir}`);

      // 3. Claude Code skill (.claude/skills/trace-security)
      const claudeSkillDir = join(targetDir, '.claude', 'skills', 'trace-security');
      mkdirSync(claudeSkillDir, { recursive: true });
      cpSync(skillSrc, claudeSkillDir, { recursive: true });
      console.log(`  \x1b[32m✓\x1b[0m Claude Code Skill  : ${claudeSkillDir}`);
    }

    // 4. MCP Configuration (.mcp.json and .cursor/mcp.json)
    const isWin = process.platform === 'win32';
    const mcpConfig = {
      mcpServers: {
        trace: {
          command: isWin ? 'cmd.exe' : 'npx',
          args: isWin
            ? ['/c', 'npx', '-y', 'trace-sec', 'mcp']
            : ['-y', 'trace-sec', 'mcp'],
          env: {
            PYTHONUNBUFFERED: '1',
          },
        },
      },
    };
    const mcpJsonPath = join(targetDir, '.mcp.json');
    writeFileSync(mcpJsonPath, JSON.stringify(mcpConfig, null, 2), 'utf-8');
    console.log(`  \x1b[32m✓\x1b[0m Claude Code MCP    : ${mcpJsonPath}`);

    const cursorMcpDir = join(targetDir, '.cursor');
    mkdirSync(cursorMcpDir, { recursive: true });
    writeFileSync(join(cursorMcpDir, 'mcp.json'), JSON.stringify(mcpConfig, null, 2), 'utf-8');
    console.log(`  \x1b[32m✓\x1b[0m Cursor IDE MCP     : ${join(cursorMcpDir, 'mcp.json')}`);

    console.log('\n\x1b[1mCapabilities Enabled for AI Coding Agents:\x1b[0m');
    console.log('  • \x1b[32mClaude Code Integration:\x1b[0m Skills + MCP server ready');
    console.log('  • \x1b[32mAntigravity & Agentic IDEs:\x1b[0m .agents/plugins/trace-security active');
    console.log('  • \x1b[32mVerification Tools:\x1b[0m trace_scan, trace_findings, trace_verify, trace_harness_task');
    console.log('\n\x1b[90mTo register in Claude Code CLI directly:\x1b[0m');
    console.log('  \x1b[37mclaude mcp add trace -- npx trace-sec mcp\x1b[0m\n');
    process.exit(0);
  } else {
    console.error(`[TRACE] Bundle directory not found at ${bundleDir}`);
    process.exit(1);
  }
}

// Find virtual environment python or system python
const isWin = process.platform === 'win32';
const userHome = process.env.USERPROFILE || process.env.HOME || '';
const dedicatedVenv = join(userHome, '.trace', 'venv');
const dedicatedPython = join(dedicatedVenv, isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python');
const dedicatedPip = join(dedicatedVenv, isWin ? 'Scripts' : 'bin', isWin ? 'pip.exe' : 'pip');
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
      // try next
    }
  }
  return null;
}

const candidatePythons = [
  process.env.TRACE_PYTHON,
  dedicatedPython,
  join(process.cwd(), '.venv', isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python'),
  join(projectRoot, '.venv', isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python'),
];

let pythonBin = null;
for (const cand of candidatePythons) {
  if (cand && existsSync(cand)) {
    pythonBin = cand;
    break;
  }
}

if (!pythonBin) {
  pythonBin = findSystemPython();
}

if (!pythonBin) {
  console.error('\n\x1b[31m\x1b[1m[TRACE ERROR]\x1b[0m Python 3.10+ is required to execute TRACE.');
  console.error('Please install Python to proceed:');
  if (isWin) {
    console.error('  \x1b[36mwinget install Python.Python.3.11\x1b[0m  (or from https://www.python.org/)\n');
  } else if (process.platform === 'darwin') {
    console.error('  \x1b[36mbrew install python\x1b[0m\n');
  } else {
    console.error('  \x1b[36msudo apt install -y python3 python3-pip python3-venv\x1b[0m\n');
  }
  process.exit(1);
}

// Verify that the resolved Python environment has required TRACE dependencies
let depsOk = false;
try {
  execSync(`"${pythonBin}" -c "import typer, rich, pydantic, tree_sitter"`, { stdio: 'ignore' });
  depsOk = true;
} catch (e) {
  depsOk = false;
}

if (!depsOk) {
  if (existsSync(dedicatedPython)) {
    try {
      execSync(`"${dedicatedPython}" -c "import typer, rich, pydantic, tree_sitter"`, { stdio: 'ignore' });
      pythonBin = dedicatedPython;
      depsOk = true;
    } catch (e) {
      depsOk = false;
    }
  }

  if (!depsOk) {
    console.log('\n\x1b[32m\x1b[1m[TRACE]\x1b[0m Initializing TRACE runtime dependencies in dedicated environment (~/.trace/venv)...');
    try {
      mkdirSync(join(userHome, '.trace'), { recursive: true });
      if (!existsSync(dedicatedPython)) {
        console.log('  \x1b[38;2;255;158;59m›\x1b[0m Creating Python virtual environment in ~/.trace/venv...');
        const sysPy = findSystemPython();
        if (!sysPy) {
          throw new Error('System Python 3.10+ not found. Please install Python from https://www.python.org/');
        }
        execSync(`${sysPy} -m venv "${dedicatedVenv}"`, { stdio: 'inherit' });
      }
      console.log('  \x1b[38;2;255;158;59m›\x1b[0m Installing core dependencies via pip...');
      if (existsSync(reqFile)) {
        execSync(`"${dedicatedPython}" -m pip install -r "${reqFile}"`, { stdio: 'inherit' });
      } else {
        execSync(`"${dedicatedPython}" -m pip install typer rich pydantic pydantic-settings networkx httpx orjson tomli-w tree-sitter tree-sitter-language-pack onnxruntime transformers safetensors numpy`, { stdio: 'inherit' });
      }
      pythonBin = dedicatedPython;
      console.log('\x1b[32m✓ Runtime dependencies provisioned successfully.\x1b[0m\n');
    } catch (e) {
      console.warn(`[TRACE] Automatic environment setup warning: ${e.message}`);
      console.warn(`If command fails, install directly via: pip install git+https://github.com/VK-Amogh/TRACE.git\n`);
    }
  }
}

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
  console.error(`Please ensure Python 3.10+ is installed and on your PATH, or run: pip install -e .`);
  process.exit(1);
});
