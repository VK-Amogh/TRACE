# Releases

## Versioning

One version, two manifests: `src/trace_engine/__init__.py:__version__` and
`package.json`. Never edit them by hand — use the helper, which also rolls the
`CHANGELOG.md` `[Unreleased]` section into the new version:

```bash
python scripts/release_tools.py bump 2.2.2
python scripts/release_tools.py check          # manifests and skills agree
```

`bump` also sets `metadata.version` in every `skills/*/SKILL.md`, and `check`
fails when any skill drifts, so the skills published inside the npm package
and the wheel always match the tool version.

Versions follow [SemVer](https://semver.org/). A suffix such as `2.2.2-rc1`
publishes as a GitHub pre-release and under the npm `next` tag.

## Cutting a release

1. Bump the version (above), review `CHANGELOG.md`, commit, and merge to `main`.
2. Tag and push:

   ```bash
   git tag v2.2.2
   git push origin v2.2.2
   ```

3. Approve the run in the `release` environment when GitHub asks.

Before tagging, confirm the skills are in the artifacts:

```bash
npm pack --dry-run --json | grep '"path": "skills/'
```

The wheel carries them under `trace_engine/plugin/bundle/published-skills/`.
`npx skills add` reads the Git repository directly, so no extra publish step
is needed for it.

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

## Fork releases (auraflaa/TRACE)

The fork's `main` is also releasable with the same `release.yml`. All of the
above applies with the fork substituted for `origin`:

1. Secrets: add `PYPI_API_TOKEN` and `NPM_TOKEN` in *Settings → Secrets and
   variables → Actions* on the fork.
   - PyPI note: `trace-sec` had no PyPI project before the first release, so
     use a **user-scoped** API token for the first publish (project-scoped
     tokens require an existing project). Re-scope it afterwards if desired.
   - npm note: `trace-sec` is owned by the `vk.amogh` npm account; the token
     must be authorized to publish that package. Without `NPM_TOKEN` the
     workflow skips npm with a warning and still releases PyPI + GitHub.
   - Alternatively, register a **pending publisher** on pypi.org
     (`auraflaa/TRACE`, workflow `release.yml`, environment `release`) and
     leave `PYPI_API_TOKEN` unset — OIDC trusted publishing is used instead.
2. Tag the commit on the fork's `main` and push the tag there:

   ```bash
   git push origin v2.2.2
   ```

3. If the tag is pushed before secrets exist, delete and re-push it — publish
   jobs only act on the tag-push event.

## First-publish checklist

- [ ] `python scripts/release_tools.py check vX.Y.Z` passes locally.
- [ ] Secrets configured on the repo that runs the workflow.
- [ ] Optional: trigger Actions → *Release: GitHub + PyPI + npm* → **Run
      workflow** with *dry_run* checked first — it verifies, tests and builds
      without publishing and needs no secrets.
