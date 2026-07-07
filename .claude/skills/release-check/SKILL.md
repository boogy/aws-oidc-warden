---
name: release-check
description: Use before creating or pushing a release tag (vX.Y.Z or a prerelease like v1.2.3-rc.1), or when editing the release pipeline (.goreleaser.yaml, release.yml, ko image tags).
---

# Release Check

Pre-tag checklist: repo state, quality gate, changelog, tag semantics.

## Steps

### 1. Branch state

```bash
git status --porcelain          # must be empty
git branch --show-current       # must be main
git fetch origin && git rev-list --count origin/main..main   # 0 = synced
```

### 2. Quality gate

```bash
make check                      # fmt + lint + vuln + test
goreleaser check                # validates .goreleaser.yaml
```

### 3. Changelog

`CHANGELOG.md` has an entry for the new version. Deploy-only (`deploy/`)
changes belong in `deploy/README.md`, not the changelog.

### 4. Tag semantics

Verify the tag against the release pipeline rules (`.github/workflows/release.yml`):

- Final release `vX.Y.Z`: images get `<module>-<tag>`, `<module>-latest`,
  bare `<version>`, and `latest`.
- Prerelease `vX.Y.Z-rc.N` / `-beta.*`: **never** moves `*-latest`/`latest`.
- Tags must be annotated and signed: `git tag -s vX.Y.Z -m "vX.Y.Z"`.

If `release.yml` itself changed: ko image tags must be passed via
`--tags` on the CLI — a `tags:` key under `.ko.yaml` `builds[]` is not a
real ko option and is silently ignored.

### 5. Optional full dry-run

```bash
make release-snapshot           # goreleaser snapshot build, no publish
```

## Report

State pass/fail per step. Do not tag with any step failing.
