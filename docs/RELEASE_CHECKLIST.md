# Release checklist

## Code and behavior

- [ ] Version is identical in `app/version.py`, OpenAPI, health response, frontend package, changelog, and tag.
- [ ] Ruff, Bandit, backend tests, coverage gate, and frontend build pass.
- [ ] PostgreSQL and RLS tests pass in CI without skips.
- [ ] Database and configuration migrations are documented.

## Security and privacy

- [ ] Dependency audits, CodeQL, and dependency review pass.
- [ ] No secrets or production data are present in commits, fixtures, screenshots, or build artifacts.
- [ ] External endpoints are HTTPS and explicitly allowlisted.
- [ ] SBOM, SHA-256 checksums, and build provenance are attached to the release.
- [ ] Known limitations and unsupported deployment modes remain visible.

## Portfolio evidence

- [ ] README screenshot and Mermaid architecture match the released UI and behavior.
- [ ] Demo can be completed from a clean checkout in under five minutes.
- [ ] Promptfoo result records the exact tool version and Git SHA.
- [ ] Resume bullets contain only measurable facts from `PORTFOLIO_EVIDENCE.md`.
- [ ] The release tag is annotated and points at the CI-tested commit.

