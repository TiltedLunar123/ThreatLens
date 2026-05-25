# Changelog

All notable changes to ThreatLens will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Discovery detection now keeps sliding after a recon burst match so overlapping
  threshold-sized windows are not skipped.

## [2.2.1] - 2026-05-13

### Changed
- Renamed PyPI distribution to `threatlens-cli`. The `threatlens` slot
  on PyPI was already occupied by an unrelated project, so this release
  cuts a fresh distribution name. The Python import name (`import
  threatlens`) and the CLI command (`threatlens ...`) are unchanged.
- Bumped fallback version in `threatlens/__init__.py` to match.

### Fixed
- Codecov upload step in CI now passes `CODECOV_TOKEN`. Tokenless
  upload is no longer accepted for this repo.

## [2.2.0] - 2026-05-13

### Added
- Wazuh integration output (`--wazuh-url`) for shipping alerts to a Wazuh manager over the API.
- Splunk HTTP Event Collector output (`--splunk-url` / `--splunk-token`) for pushing alerts straight to a Splunk indexer.
- MITRE ATT&CK Navigator layer export (`--navigator-layer`) producing a Navigator v4.5 JSON layer ready to load at https://mitre-attack.github.io/attack-navigator/.
- STIX 2.1 indicator export (`--stix`) emitting a bundle of indicator + sighting objects for threat-intel sharing.
- Streamlit dashboard subcommand (`threatlens dashboard <report.json>`) with filters by severity, tactic, host, and rule.
- `--version` flag on the root parser and on each subcommand.
- Curated Sigma starter pack (`rules/sigma_starter/`) bundled with the project, mapped to the existing built-in detection coverage so `--sigma-rules` works without cloning SigmaHQ.
- Multi-format sample logs: `sample_data/sample_security_log.syslog` (RFC 5424), `sample_data/sample_security_log.cef`, and a generated EVTX equivalent through `scripts/generate_sample_data.py --evtx`.
- Benchmark script (`scripts/benchmark.py`) that generates synthetic corpora up to 1M events and reports parse + detect throughput.
- Comparison section in the README contrasting ThreatLens with Hayabusa, Chainsaw, and Zircolite.
- Real-world evaluation walkthrough in `docs/evaluation.md` documenting detections against the EVTX-ATTACK-SAMPLES corpus.
- SBOM generation script (`scripts/generate_sbom.py`) producing CycloneDX JSON without runtime dependencies on the cyclonedx-bom package.
- Windows runner added to the CI matrix alongside Ubuntu.
- mypy strict type checking step in CI.
- Dependabot configuration for pip and GitHub Actions.
- `SECURITY.md` with a coordinated disclosure path and explicit warnings about the supply-chain risk of `--plugin-dir`.
- `CONTRIBUTING.md` plus bug-report and feature-request issue templates.

### Changed
- README badges updated to include coverage and PyPI version. The "From PyPI" install instruction is now gated on the first tagged release.
- Output module structure: each shipping target now lives in its own file under `threatlens/outputs/` for parity (elasticsearch, wazuh, splunk, navigator, stix).
- Version fallback in `threatlens/__init__.py` now matches the value declared in `pyproject.toml` (2.2.0).

### Fixed
- Resolved version drift between `pyproject.toml` and `threatlens/__init__.py`.

## [2.1.0] - 2026-04 (untagged)

### Added
- MITRE ATT&CK heatmap data in the HTML report.
- Expanded detector test coverage across credential access, defense evasion, persistence, discovery, exfiltration, Kerberos attacks, and initial access modules.
- `--profile` flag for per-phase timing breakdowns.

### Fixed
- `scan` no longer exits with code 2 when `--fail-on` is not explicitly set.

### Notes
- This release was prepared in commit history but never tagged; its contents are rolled forward into 2.2.0.

## [2.0.0] - 2026-03 (untagged)

### Added
- Initial public source drop.
- 12 built-in detection modules: brute force, lateral movement, privilege escalation, suspicious process execution, defense evasion, persistence, discovery, exfiltration, Kerberos attacks, credential access, initial access, and attack-chain correlation.
- Parsers for JSON/NDJSON, EVTX (optional dependency), Syslog (RFC 3164 + 5424), and CEF.
- Custom YAML rule engine with 12 operators, thresholds, time windows, and group-by support.
- Sigma rule compatibility layer with selection blocks, field modifiers, condition expressions, logsource filtering, and MITRE tag extraction.
- Plugin loader for user-supplied Python detectors via `--plugin-dir`.
- Output formats: terminal, JSON, CSV, HTML report, interactive timeline, Elasticsearch bulk API.
- Real-time tailing mode (`follow` subcommand).
- Allowlist support for tuning out known-good alerts.
- Docker image and GitHub Actions CI workflow.

[Unreleased]: https://github.com/TiltedLunar123/ThreatLens/compare/v2.2.1...HEAD
[2.2.1]: https://github.com/TiltedLunar123/ThreatLens/releases/tag/v2.2.1
[2.2.0]: https://github.com/TiltedLunar123/ThreatLens/releases/tag/v2.2.0
[2.1.0]: https://github.com/TiltedLunar123/ThreatLens/releases/tag/v2.1.0
[2.0.0]: https://github.com/TiltedLunar123/ThreatLens/releases/tag/v2.0.0
