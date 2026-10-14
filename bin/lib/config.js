/**
 * Shared configuration for the TRACE NPX launcher.
 */

export const MIN_PYTHON = [3, 11];
export const PACKAGE_NAME = 'trace-sec';
export const FALLBACK_GIT_URL = 'git+https://github.com/VK-Amogh/TRACE.git';
export const LITE_DEPS = [
  'typer',
  'rich',
  'pydantic',
  'pydantic-settings',
  'networkx',
  'httpx',
  'orjson',
  'tomli-w',
  'tree-sitter',
  'tree-sitter-language-pack',
];

export function versionString([major, minor]) {
  return `${major}.${minor}`;
}

export function meetsMinimum([major, minor]) {
  return major === MIN_PYTHON[0] && minor >= MIN_PYTHON[1];
}
