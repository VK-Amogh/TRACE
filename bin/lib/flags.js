/**
 * Global CLI flags handled by the NPX layer before delegating to Python:
 *   --verbose          echo resolved interpreter + command, enable debug logs
 *   --format <fmt>     inject --format for commands that support it
 */

export const FORMAT_COMMANDS = {
  scan: ['table', 'markdown', 'json', 'sarif'],
  audit: ['table', 'markdown', 'json'],
  'test-all': ['table', 'markdown', 'json'],
  report: ['markdown', 'html', 'json', 'sarif'],
};

/**
 * Split global flags out of argv. Returns { args, verbose, format }.
 * Throws on unknown/invalid flag usage (caller prints message + exits 2).
 */
export function parseGlobalFlags(argv) {
  const args = [];
  let verbose = false;
  let format = null;
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (tok === '--verbose') {
      verbose = true;
    } else if (tok === '--format') {
      const val = argv[i + 1];
      if (!val || val.startsWith('-')) {
        throw new Error('--format requires a value (table, json, markdown, html, sarif)');
      }
      format = val.toLowerCase();
      i++;
    } else if (tok.startsWith('--format=')) {
      format = tok.slice('--format='.length).toLowerCase() || null;
      if (!format) throw new Error('--format requires a value (table, json, markdown, html, sarif)');
    } else {
      args.push(tok);
    }
  }
  return { args, verbose, format };
}

/**
 * Apply --format to commands that support it. Returns final argv.
 * Throws when the command does not support --format or already has one.
 */
export function applyFormat(argv, format) {
  if (!format) return argv;
  const cmd = argv[0];
  const allowed = FORMAT_COMMANDS[cmd];
  if (!allowed) {
    throw new Error(`--format is not supported by '${cmd || '(no command)'}'`);
  }
  if (!allowed.includes(format)) {
    throw new Error(`--format '${format}' invalid for '${cmd}' (choose: ${allowed.join(', ')})`);
  }
  const hasFormat = argv.some((t, i) => t === '--format' || t === '-f' || t.startsWith('--format='));
  if (hasFormat) {
    throw new Error(`'${cmd}' already has an explicit --format; refusing to override`);
  }
  return [...argv, '--format', format];
}
