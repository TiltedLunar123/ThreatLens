# Contributing to ThreatLens

Thanks for your interest in contributing to ThreatLens! This guide will help you get started.

## Development Setup

```bash
git clone https://github.com/TiltedLunar123/ThreatLens.git
cd ThreatLens
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,evtx,enrichment]"
```

## Running Tests

```bash
pytest                          # run all tests
pytest --cov=threatlens         # with coverage report
pytest tests/test_detections.py # run a specific test file
```

## Linting

```bash
ruff check threatlens/ tests/
ruff format threatlens/ tests/
```

## Project Structure

```
threatlens/
├── cli.py                  # CLI entry point & argument parsing
├── models.py               # LogEvent, Alert, Severity data models
├── report.py               # Terminal & file report generation
├── utils.py                # Shared helpers (colors, tables, grouping)
├── detections/             # Detection rule modules
│   ├── base.py             # Abstract DetectionRule base class
│   ├── brute_force.py      # Brute-force / password spray
│   ├── lateral_movement.py # Multi-host authentication
│   ├── privilege_escalation.py
│   ├── suspicious_process.py
│   ├── network_anomaly.py  # DNS tunneling & beaconing
│   └── attack_chain.py     # Multi-stage kill chain correlation
├── parsers/                # Log format parsers
│   ├── json_parser.py      # JSON / NDJSON
│   ├── syslog_parser.py    # RFC 3164/5424 + CEF
│   └── evtx_parser.py      # Windows EVTX (optional dep)
├── rules/                  # Custom & Sigma rule engines
│   ├── yaml_rules.py       # User-defined YAML rules
│   └── sigma_loader.py     # Sigma rule compatibility
├── outputs/                # Output format modules
│   ├── html_report.py      # HTML report with charts
│   ├── timeline.py         # Interactive SVG timeline
│   ├── sarif.py            # SARIF for GitHub Security tab
│   └── elasticsearch.py    # Elasticsearch bulk API
└── enrichment/             # IP enrichment modules
    └── geoip.py            # GeoIP / threat intel enrichment
```

## Adding a New Detection Rule

1. Create a new file in `threatlens/detections/` (e.g., `my_detector.py`)
2. Subclass `DetectionRule` from `threatlens.detections.base`
3. Implement the `analyze(events) -> list[Alert]` method
4. Set the class attributes: `name`, `description`, `mitre_tactic`, `mitre_technique`
5. Register it in `threatlens/detections/__init__.py` by adding to `ALL_DETECTORS`
6. Add tests in `tests/test_detections.py`

```python
from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, LogEvent

class MyDetector(DetectionRule):
    name = "My Custom Detection"
    description = "Detects something interesting"
    mitre_tactic = "Discovery"
    mitre_technique = "T1087 - Account Discovery"

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        alerts = []
        # Your detection logic here
        return alerts
```

## Adding a New Output Format

1. Create a new file in `threatlens/outputs/` (e.g., `my_format.py`)
2. Implement an export function: `def export_myformat(alerts, output_path, ...)`
3. Wire it into `cli.py` in the `run_scan` function
4. Add a choice to the `--format` argument

## Adding a New Parser

1. Create a new file in `threatlens/parsers/` (e.g., `my_parser.py`)
2. Implement `load_*_events(path) -> list[LogEvent]` and `stream_*_events(path) -> Iterator[LogEvent]`
3. Register the format in `threatlens/parsers/__init__.py`
4. Add file extensions in `threatlens/cli.py` `_FORMAT_EXTENSIONS`

## Code Style

- Python 3.10+ with `from __future__ import annotations`
- Type hints on all function signatures
- Ruff for linting and formatting (config in `pyproject.toml`)
- Keep dependencies minimal — prefer stdlib solutions

## Commit Messages

- Use imperative mood: "Add feature" not "Added feature"
- Keep the first line under 72 characters
- Reference issue numbers where applicable

## Submitting a Pull Request

1. Fork the repo and create a feature branch
2. Write tests for any new functionality
3. Ensure `pytest` and `ruff check` pass
4. Open a PR against `main` with a clear description
