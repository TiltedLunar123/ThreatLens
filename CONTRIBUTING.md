# Contributing to ThreatLens

Thanks for taking the time to look at the project. ThreatLens is a small,
focused tool. Contributions that keep it focused are very welcome.

## Quick Setup

```bash
git clone https://github.com/TiltedLunar123/ThreatLens.git
cd ThreatLens

python -m venv .venv
source .venv/bin/activate     # Linux / macOS
.venv\Scripts\activate        # Windows

pip install -e ".[dev,evtx]"
pre-commit install            # optional, runs ruff before each commit
```

Run the test suite:

```bash
pytest tests/ -v
ruff check threatlens/ tests/
mypy threatlens/
```

The CI workflow runs the same three commands across Python 3.10 through 3.13
on both Ubuntu and Windows. If your change passes them locally, it will pass
in CI.

## What ThreatLens Wants

- New built-in detection modules that cover a fresh MITRE ATT&CK technique
  not already mapped in the coverage matrix.
- Sigma rule compatibility improvements (more field modifiers, more
  condition expressions).
- Parser robustness fixes (a real log file that breaks the JSON or syslog
  parser is a gift, please attach it to the issue).
- Output adapters for additional SIEM or threat-intel platforms, following
  the pattern in `threatlens/outputs/elasticsearch.py`.
- Performance improvements with benchmark numbers from `scripts/benchmark.py`.

## What ThreatLens Wants to Stay Away From

- Live network capture or active probing. The tool is offline by design.
- Heavy runtime dependencies. The core install is `pyyaml` only on purpose.
  EVTX support is optional behind an extra so the dependency is only paid
  for when needed. New mandatory dependencies need a strong justification.
- Vendoring large rule packs. The Sigma starter pack is small and curated;
  the SigmaHQ project is the right home for breadth.
- Features that require an external service to function. Adapters that
  *talk* to a service are fine; adapters that *require* one to run are not.

## Pull Request Checklist

Before opening a PR:

- [ ] Tests added or updated under `tests/`. Every detector has a unit test
      that exercises both a positive and negative case.
- [ ] `pytest tests/ -v` passes locally.
- [ ] `ruff check threatlens/ tests/` is clean.
- [ ] `mypy threatlens/` is clean for any file you touched (it is allowed
      to fail in CI for now, but the strict-mode rollout is in progress).
- [ ] If you added a CLI flag, the help text reads cleanly and the README
      Usage section is updated.
- [ ] If you added a new output target, it has its own module under
      `threatlens/outputs/` with at least one round-trip test.
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]`.

## Commit Message Style

Short, lower-case, present tense. Reference the area touched first.

```
detections: catch DCSync via 4662 with replication GUIDs
parsers/syslog: handle RFC 5424 structured data with escaped quotes
outputs/wazuh: clamp severity mapping at level 15
```

Avoid em dashes and avoid mentioning AI or LLM tooling in the commit log or
the code. Commit messages and code comments are written in the author's
voice.

## Reporting Bugs

Use the bug report issue template. Attach the smallest log sample that
reproduces the problem, the exact command you ran, and the `--profile`
output if it is a performance issue.

## Security Issues

Do not file public issues for security bugs. See [SECURITY.md](SECURITY.md)
for the disclosure process.

## License

By contributing, you agree that your contributions will be licensed under
the MIT License that covers the rest of the project.
