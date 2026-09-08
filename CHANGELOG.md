# Changelog

All notable changes are documented here. Versions follow Semantic Versioning.

## [1.0.0] - 2026-09-02

### Added

- Five-stage runtime Guard for input, context, tool, tool result, and output boundaries.
- Privacy-minimized provenance graph and monotonic taint propagation.
- Parameter-bound one-time Capability Leases and durable approval workflows.
- Reproducible evaluation and red-team manifests with per-case run comparison.
- Budgeted deterministic multi-turn red-team strategy.
- OpenAI Agents SDK function-tool boundary adapter and Promptfoo external benchmark configuration.
- CodeQL, dependency review, coverage, CycloneDX SBOM, and release provenance workflows.

### Security

- External Agent allowlist is empty by default and remote control planes require HTTPS.
- Sensitive-source-to-egress flows block before execution.
- Untrusted-context-to-side-effect flows require an independent approval path.
- High-confidence privilege escalation, approval bypass, and credential exfiltration requests are denied by the default policy; the pinned Promptfoo smoke report passes 4/4 cases.

### Known limitations

- Built-in datasets are synthetic and do not establish real-world security accuracy.
- Untrusted arbitrary code and unknown stdio MCP servers are not executed.
- Production PostgreSQL, OIDC, Temporal, Phoenix, backup, and WORM adapters require environment-specific acceptance testing.
