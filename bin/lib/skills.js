/**
 * Zero-dependency agent skill installer (install-skill / setup-agent).
 */

import { existsSync, mkdirSync, cpSync, writeFileSync } from 'fs';
import { join } from 'path';

function logOk(label, target) {
  console.log(`  \x1b[32m✓\x1b[0m ${label} : ${target}`);
}

function mcpConfig(isWin) {
  return {
    mcpServers: {
      trace: {
        command: isWin ? 'cmd.exe' : 'npx',
        args: isWin ? ['/c', 'npx', '-y', 'trace-sec', 'mcp'] : ['-y', 'trace-sec', 'mcp'],
        env: { PYTHONUNBUFFERED: '1' },
      },
    },
  };
}

export function installSkills(targetDir, projectRoot) {
  const isWin = process.platform === 'win32';
  const bundleDir = join(projectRoot, 'src', 'trace_engine', 'plugin', 'bundle');

  console.log('\n\x1b[32m\x1b[1mInstalling TRACE Autonomous Security Agent Skill & MCP Tools...\x1b[0m');

  if (!existsSync(bundleDir)) {
    console.error(`[TRACE] Bundle directory not found at ${bundleDir}`);
    process.exit(1);
  }

  const agentPluginDir = join(targetDir, '.agents', 'plugins', 'trace-security');
  mkdirSync(agentPluginDir, { recursive: true });
  cpSync(bundleDir, agentPluginDir, { recursive: true });
  logOk('Antigravity Plugin', agentPluginDir);

  const skillSrc = join(bundleDir, 'skills', 'trace-security-harness');
  if (existsSync(skillSrc)) {
    const agentSkillDir = join(targetDir, '.agents', 'skills', 'trace-security-harness');
    mkdirSync(agentSkillDir, { recursive: true });
    cpSync(skillSrc, agentSkillDir, { recursive: true });
    logOk('Agent Skill       ', agentSkillDir);

    const claudeSkillDir = join(targetDir, '.claude', 'skills', 'trace-security');
    mkdirSync(claudeSkillDir, { recursive: true });
    cpSync(skillSrc, claudeSkillDir, { recursive: true });
    logOk('Claude Code Skill ', claudeSkillDir);
  }

  const config = mcpConfig(isWin);
  const mcpJsonPath = join(targetDir, '.mcp.json');
  writeFileSync(mcpJsonPath, JSON.stringify(config, null, 2), 'utf-8');
  logOk('Claude Code MCP   ', mcpJsonPath);

  const cursorMcpDir = join(targetDir, '.cursor');
  mkdirSync(cursorMcpDir, { recursive: true });
  writeFileSync(join(cursorMcpDir, 'mcp.json'), JSON.stringify(config, null, 2), 'utf-8');
  logOk('Cursor IDE MCP    ', join(cursorMcpDir, 'mcp.json'));

  console.log('\n\x1b[1mCapabilities Enabled for AI Coding Agents:\x1b[0m');
  console.log('  • \x1b[32mClaude Code Integration:\x1b[0m Skills + MCP server ready');
  console.log('  • \x1b[32mAntigravity & Agentic IDEs:\x1b[0m .agents/plugins/trace-security active');
  console.log('  • \x1b[32mVerification Tools:\x1b[0m trace_scan, trace_findings, trace_verify, trace_harness_task');
  console.log('\n\x1b[90mTo register in Claude Code CLI directly:\x1b[0m');
  console.log('  \x1b[37mclaude mcp add trace -- npx trace-sec mcp\x1b[0m\n');
}
