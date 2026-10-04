#!/usr/bin/env node

/**
 * TRACE — Threat Reconnaissance & Attack-path Correlation Engine
 * Node.js & NPX launcher for TRACE Python engine.
 */

import { spawn, execSync } from 'child_process';
import { existsSync, mkdirSync, cpSync, writeFileSync } from 'fs';
import { resolve, join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, '..');
const args = process.argv.slice(2);

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
const candidatePythons = [
  process.env.TRACE_PYTHON,
  join(process.cwd(), '.venv', isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python'),
  join(projectRoot, '.venv', isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python'),
  isWin ? 'D:\\Startup\\TRACE\\.venv\\Scripts\\python.exe' : null,
  join(userHome, '.trace', 'venv', isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python'),
  join(userHome, '.trace', 'models', 'venv', isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python'),
  isWin ? 'python' : 'python3',
];

let pythonBin = isWin ? 'python' : 'python3';
for (const cand of candidatePythons) {
  if (cand && existsSync(cand)) {
    pythonBin = cand;
    break;
  }
}

// Verify that the resolved Python environment has required TRACE dependencies
let depsOk = false;
try {
  execSync(`"${pythonBin}" -c "import typer, rich, pydantic"`, { stdio: 'ignore' });
  depsOk = true;
} catch (e) {
  depsOk = false;
}

if (!depsOk) {
  const dedicatedVenv = join(userHome, '.trace', 'venv');
  const venvPython = join(dedicatedVenv, isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python');

  if (existsSync(venvPython)) {
    try {
      execSync(`"${venvPython}" -c "import typer, rich, pydantic"`, { stdio: 'ignore' });
      pythonBin = venvPython;
      depsOk = true;
    } catch (e) {
      depsOk = false;
    }
  }

  if (!depsOk) {
    console.log('\n\x1b[32m\x1b[1m[TRACE]\x1b[0m Initializing TRACE runtime dependencies in dedicated environment (~/.trace/venv)...');
    try {
      mkdirSync(join(userHome, '.trace'), { recursive: true });
      if (!existsSync(venvPython)) {
        console.log('  \x1b[38;2;255;158;59m›\x1b[0m Creating Python virtual environment in ~/.trace/venv...');
        execSync(`"${pythonBin}" -m venv "${dedicatedVenv}"`, { stdio: 'inherit' });
      }
      console.log('  \x1b[38;2;255;158;59m›\x1b[0m Installing core dependencies (typer, rich, pydantic, tree-sitter, torch, transformers)...');
      execSync(`"${venvPython}" -m pip install typer rich pydantic pydantic-settings networkx httpx orjson tomli-w tree-sitter tree-sitter-language-pack torch transformers safetensors onnxruntime numpy`, { stdio: 'inherit' });
      pythonBin = venvPython;
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
