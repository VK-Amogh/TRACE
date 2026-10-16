# Releases

## Versioning

One version, two manifests: `src/trace_engine/__init__.py:__version__` and
`package.json`. Never edit them by hand — use the helper, which also rolls the
`CHANGELOG.md` `[Unreleased]` section into the new version:

```bash
python scripts/release_tools.py bump 2.1.19
python scripts/release_tools.py check          # manifests agree
```

Versions follow [SemVer](https://semver.org/). A suffix such as `2.2.0-rc1`
publishes as a GitHub pre-release and under the npm `next` tag.

## Cutting a release

1. Bump the version (above), review `CHANGELOG.md`, commit, and merge to `main`.
2. Tag and push:

   ```bash
   git tag v2.1.19
   git push origin v2.1.19
   ```

3. Approve the run in the `release` environment when GitHub asks.

`release.yml` then, in order:

1. **Verify** — tag matches both manifests and is reachable from `main`.
2. **Test** — full suite on Linux, Windows and macOS.
3. **Build once** — sdist, wheel, npm tarball, `SHA256SUMS.txt`, and
   build-provenance attestations.
4. **Publish** the same artifacts to PyPI and npm.
5. **Create the GitHub Release** with CHANGELOG notes and all artifacts attached.

### Dry run

Actions → *Release: GitHub + PyPI + npm* → **Run workflow** (leave *dry_run*
checked). It verifies, tests and builds, but publishes nothing.

## Registries and secrets

| Target | Auth | Setup |
|---|---|---|
| PyPI (`trace-sec`) | `PYPI_API_TOKEN` secret; falls back to trusted publishing (OIDC) if unset | Prefer a project-scoped token, or add a trusted publisher at pypi.org (workflow `release.yml`, environment `release`) |
| npm (`trace-sec`) | `NPM_TOKEN` secret, published with provenance | Skipped with a warning when unset; registry errors still fail the run |
| GitHub Release | `GITHUB_TOKEN` (automatic) | None |

The `release` environment requires reviewer approval before any publish job runs.

## Branch flow

- `main` — always releasable, protected by the full CI matrix.
- `dev` — integration line; fork work lands here first, then PRs to `main`.
- Feature work goes on short branches PR'd into `dev`.
