# Security Policy

## Supported Versions

ThreatLens is a small project maintained by a single author. Security fixes are
applied to the latest release on `main`. Older tags do not receive backports.

| Version | Supported          |
| ------- | ------------------ |
| 2.2.x   | Yes                |
| < 2.2   | No                 |

## Reporting a Vulnerability

If you believe you have found a security vulnerability in ThreatLens, please
report it privately so a fix can be developed before public disclosure.

- Open a private security advisory on GitHub:
  https://github.com/TiltedLunar123/ThreatLens/security/advisories/new
- Or email the author at hilgendorfjude@gmail.com with subject line
  `[security] ThreatLens` and a clear description of the issue, including:
  - Affected version (output of `threatlens --version`).
  - Steps to reproduce, ideally with a minimal log sample.
  - Impact assessment (data exposure, code execution, denial of service, etc.).

You can expect an initial acknowledgement within 5 business days and a
disclosure timeline within 30 days. Coordinated disclosure is preferred over
public issues for anything that could be weaponized.

## Threat Model

ThreatLens is a **defensive, offline** log triage tool. It is designed to run on
an analyst workstation or in a CI pipeline against logs that the operator
already has authorization to inspect. It is **not** designed to be a
network-exposed service, and the project does not accept reports about
scenarios where the tool is run with untrusted network input or as a
privileged daemon.

In scope:

- Parser bugs that crash, hang, or misparse a crafted log file.
- Detection rule bypasses that allow known-bad events to evade a built-in
  detector.
- Path traversal or injection in any output target (HTML report, timeline,
  Elasticsearch, Wazuh, Splunk, STIX, Navigator).
- Memory or CPU exhaustion triggered by an attacker-controlled log file.

Out of scope:

- Running `--plugin-dir` against an untrusted directory. See below.
- Sigma or YAML rule files supplied by the operator. The rule loader does not
  sandbox rule logic; rules are treated as trusted configuration.
- Running ThreatLens against logs the operator is not authorized to read.

## Plugin Loading is Code Execution

`--plugin-dir` loads every `.py` file in the supplied directory and executes
its module-level code as well as the `DetectionRule` subclasses it defines.
This is by design - it is how user plugins integrate - but it means the
plugin directory must be treated with the same trust as the ThreatLens
source tree itself.

Do not:

- Point `--plugin-dir` at a directory you do not control.
- Accept plugin files from email, chat, or third-party paste sites without
  reading them line by line first.
- Pull plugins from a network share that other users can write to.

A malicious plugin can execute arbitrary code with the same privileges as
the ThreatLens process. The same caution applies to YAML and Sigma rule
files at a lower level; rule expressions can construct regexes that consume
unbounded CPU.

## Hardening Recommendations

- Run ThreatLens inside the provided Docker image when scanning logs from an
  untrusted source. The container has no network access beyond what the
  operator explicitly grants and no persistent state.
- Use the `--allowlist` flag to suppress noisy detections rather than
  hand-editing rule files.
- When using `--elastic-url`, `--wazuh-url`, or `--splunk-url`, prefer
  authenticated TLS endpoints. The HTTP code paths are intended for local
  development only.
