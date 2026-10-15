# Accessibility

TRACE aims to be usable by everyone, including contributors and users who rely on
assistive technology or constrained devices.

## Commitments

- **CLI-first design.** Every workflow works in a plain terminal with no mouse,
  no color dependence, and no animation. Status is conveyed in words
  (`PASS`/`FAIL`, `FIXED`/`STILL_PRESENT`), never by color alone.
- **Piped output stays clean.** When stdout is not a terminal, TRACE disables
  ANSI styling automatically, so screen readers, log files, and CI logs receive
  plain text.
- **Docs as plain Markdown.** The site (`mkdocs.yml`) builds from the same
  Markdown in this repo — no information is locked inside images or video.
  Diagrams are accompanied by text descriptions of the pipeline stages.
- **Low-resource installs.** The lite package (`pip install -e .`) runs on
  4 GB machines without GPU or model downloads; heavy AI weights are optional
  (`pip install -r requirements.txt`).
- **Keyboard-only operation.** The interactive wizard (`trace`) accepts only
  typed input; every menu item shows its number and has a non-interactive CLI
  equivalent (see `docs/cli.md`).

## Reporting a barrier

If any part of TRACE — CLI output, docs site, installer, or contributor
workflow — is inaccessible to you, please open an issue with the `accessibility`
label (or contact the maintainers privately; see `SECURITY.md`). Describe the
assistive technology or constraint involved and what you expected. Accessibility
reports are treated with the same priority as functional bugs.
