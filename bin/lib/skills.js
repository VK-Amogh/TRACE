/**
 * Zero-dependency, harness-agnostic agent skill installer
 * (install-skill / setup-agent / install-agent).
 *
 * Skills follow the open Agent Skills layout: <name>/SKILL.md plus optional
 * references/. They are written to the shared `.agents/skills/` directory,
 * which most agent harnesses read, and to per-harness directories for the
 * agents that do not (see AGENT_SKILL_DIRS). For any other harness use the
 * universal installer: `npx skills add <this package or repo> -a <agent>`.
 */

import {
  existsSync,
  mkdirSync,
  cpSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  renameSync,
} from 'fs';
import { homedir } from 'os';
import { join } from 'path';

/** Skill directory per harness, relative to the project (or home with --global). */
export const AGENT_SKILL_DIRS = {
  claude: '.claude/skills',
};

/** Always written: the cross-harness location. */
export const UNIVERSAL_SKILL_DIR = '.agents/skills';

function logOk(label, target) {
  console.log(`  \x1b[32m✓\x1b[0m ${label} : ${target}`);
}

function mcpServerEntry(isWin) {
  return {
    command: isWin ? 'cmd.exe' : 'npx',
    args: isWin ? ['/c', 'npx', '-y', 'trace-sec', 'mcp'] : ['-y', 'trace-sec', 'mcp'],
    env: { PYTHONUNBUFFERED: '1' },
  };
}

/**
 * Parse install-skill arguments (everything after the command name).
 * Throws on unknown flags so typos never silently install the wrong thing.
 */
export function parseInstallArgs(argv) {
  const opts = { global: false, agents: ['claude'], mcp: true, skillsOnly: false, list: false };
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (tok === '-g' || tok === '--global') {
      opts.global = true;
    } else if (tok === '--no-mcp') {
      opts.mcp = false;
    } else if (tok === '--skills-only') {
      opts.skillsOnly = true;
      opts.mcp = false;
    } else if (tok === '--list' || tok === '-l') {
      opts.list = true;
    } else if (tok === '--agents' || tok === '-a' || tok.startsWith('--agents=')) {
      const raw = tok.includes('=') ? tok.slice(tok.indexOf('=') + 1) : argv[++i];
      if (!raw || raw.startsWith('-')) throw new Error(`${tok} requires a comma-separated list or 'all'`);
      opts.agents = raw === 'all' || raw === '*'
        ? Object.keys(AGENT_SKILL_DIRS)
        : raw.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
    } else {
      throw new Error(`unknown option '${tok}' (try: --global, --agents, --no-mcp, --skills-only, --list)`);
    }
  }
  return opts;
}

/**
 * Collect installable skills: every `skills/<name>/SKILL.md` shipped in the
 * package. Directory name = skill name.
 */
export function collectSkills(projectRoot) {
  const found = new Map();
  const skillsRoot = join(projectRoot, 'skills');
  if (existsSync(skillsRoot)) {
    for (const entry of readdirSync(skillsRoot, { withFileTypes: true })) {
      if (entry.isDirectory() && existsSync(join(skillsRoot, entry.name, 'SKILL.md'))) {
        found.set(entry.name, join(skillsRoot, entry.name));
      }
    }
  }
  return found;
}

/** Add or update the `trace` server in an MCP config without touching other servers. */
export function mergeMcpConfig(file, isWin) {
  let config = {};
  if (existsSync(file)) {
    try {
      config = JSON.parse(readFileSync(file, 'utf-8'));
      if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('not an object');
    } catch {
      renameSync(file, `${file}.bak`);
      config = {};
    }
  }
  config.mcpServers = { ...(config.mcpServers || {}), trace: mcpServerEntry(isWin) };
  mkdirSync(join(file, '..'), { recursive: true });
  writeFileSync(file, JSON.stringify(config, null, 2), 'utf-8');
}

export function installSkills(targetDir, projectRoot, argv = []) {
  let opts;
  try {
    opts = parseInstallArgs(argv);
  } catch (e) {
    console.error(`[TRACE] ${e.message}`);
    process.exit(2);
  }

  const isWin = process.platform === 'win32';
  const skills = collectSkills(projectRoot);
  if (skills.size === 0) {
    console.error(`[TRACE] No skills found under ${projectRoot}`);
    process.exit(1);
  }

  if (opts.list) {
    for (const name of [...skills.keys()].sort()) console.log(name);
    return;
  }

  const unknown = opts.agents.filter((a) => !AGENT_SKILL_DIRS[a]);
  if (unknown.length) {
    console.error(
      `[TRACE] No built-in skills directory for: ${unknown.join(', ')}. ` +
        `Skills are still installed to ${UNIVERSAL_SKILL_DIR}/. ` +
        'For other harnesses run: npx skills add VK-Amogh/TRACE -a <agent>'
    );
  }

  const base = opts.global ? homedir() : targetDir;
  const scope = opts.global ? 'global' : 'project';
  console.log(`\n\x1b[32m\x1b[1mInstalling TRACE agent skills (${scope})...\x1b[0m`);

  const destRoots = [UNIVERSAL_SKILL_DIR, ...opts.agents.filter((a) => AGENT_SKILL_DIRS[a]).map((a) => AGENT_SKILL_DIRS[a])];
  for (const [name, src] of [...skills.entries()].sort()) {
    for (const rel of destRoots) {
      const dest = join(base, rel, name);
      mkdirSync(dest, { recursive: true });
      cpSync(src, dest, { recursive: true });
    }
    logOk('Skill', `${name} -> ${destRoots.join(', ')}`);
  }

  if (!opts.skillsOnly && !opts.global) {
    const bundleDir = join(projectRoot, 'src', 'trace_engine', 'plugin', 'bundle');
    if (existsSync(bundleDir)) {
      const pluginDir = join(base, '.agents', 'plugins', 'trace-security');
      mkdirSync(pluginDir, { recursive: true });
      cpSync(bundleDir, pluginDir, { recursive: true });
      logOk('Agent plugin', pluginDir);
    }
  }

  if (opts.mcp && !opts.global) {
    mergeMcpConfig(join(base, '.mcp.json'), isWin);
    logOk('MCP (.mcp.json)', join(base, '.mcp.json'));
    mergeMcpConfig(join(base, '.cursor', 'mcp.json'), isWin);
    logOk('MCP (.cursor/mcp.json)', join(base, '.cursor', 'mcp.json'));
  }

  console.log('\n\x1b[1mReady for any agent harness:\x1b[0m');
  console.log(`  • Skills in \x1b[32m${UNIVERSAL_SKILL_DIR}/\x1b[0m are read by harnesses that follow the shared layout.`);
  console.log('  • Other harnesses: \x1b[37mnpx skills add VK-Amogh/TRACE -a <agent>\x1b[0m (75+ agents)');
  console.log('  • Existing MCP servers in .mcp.json / .cursor/mcp.json were preserved.');
  console.log('\n\x1b[90mRegister the MCP server in Claude Code directly:\x1b[0m');
  console.log('  \x1b[37mclaude mcp add trace -- npx -y trace-sec mcp\x1b[0m\n');
}
