# Releases

## Versioning

One version, two manifests: bump `src/trace_engine/__init__.py:__version__`
**and** `package.json` together. CI fails the release if either drifts from
the tag.

## Cutting a release

1. Bump both versions, commit to `dev`.
2. Open a PR `dev` → `main`, get it merged.
3. Tag `v<version>` (e.g. `v2.1.19`), push the tag.
4. Publish a GitHub release from the tag.

`release.yml` then verifies tag-vs-manifest consistency and publishes:

| Artifact | How | Setup |
|---|---|---|
| PyPI (`trace-sec`) | Trusted publishing (OIDC, no token) | One-time: add this repo as a trusted publisher at pypi.org |
| NPM (`trace-sec`) | `NPM_TOKEN` secret | Skips gracefully when unconfigured; real registry errors still fail |
| GitHub Packages | `GITHUB_TOKEN` (automatic) | Nothing to do |

## Branch flow

- `main` — always releasable, protected by the full CI matrix.
- `dev` — integration line; fork work lands here first, then PRs to `main`.
- Feature work goes on short branches PR'd into `dev`.
