<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/tests-18%20passing-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red?style=flat-square" alt="MITRE ATT&CK">
</p>

<h1 align="center">ThreatLens</h1>

<p align="center">
  <b>Log Analysis & Threat Hunting CLI for Security Analysts</b><br>
  Parse Windows Security & Sysmon logs. Detect attacks. Get actionable alerts mapped to MITRE ATT&CK.
</p>

---

## What is ThreatLens?

ThreatLens is a Python command-line tool that ingests Windows Security and Sysmon event logs, runs modular detection rules against them, and generates severity-ranked alerts with MITRE ATT&CK mapping. Built for SOC analysts, incident responders, and blue-team learners.

Security teams deal with thousands of log events daily. ThreatLens automates that first pass of triage — catching brute-force attacks, lateral movement, privilege escalation, and suspicious process execution — so analysts can focus on real investigation.

---

## Features

| Detection | What It Catches | MITRE Technique |
|---|---|---|
| **Brute-Force / Password Spray** | Bursts of failed logons from one source; distinguishes targeted brute-force from spray | T1110 |
| **Lateral Movement** | Single account authenticating to multiple hosts rapidly (network logons, RDP) | T1021 |
| **Privilege Escalation** | Sensitive privilege assignments (SeDebugPrivilege, SeTcbPrivilege) to non-system accounts | T1134 |
| **Suspicious Process Execution** | LOLBins, encoded PowerShell, certutil download cradles, SAM dumping, service creation | T1059 |

**Plus:**
- Severity ranking: CRITICAL / HIGH / MEDIUM / LOW
- JSON & CSV report export for SIEM ingestion
- Configurable detection thresholds via YAML
- Sample attack data included — demo it in 30 seconds
- 18 unit tests covering all detection modules

---

## Quick Start

```bash
# Clone
git clone https://github.com/TiltedLunar123/ThreatLens.git
cd ThreatLens

# Set up environment
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.venv\Scripts\activate       # Windows

# Install
pip install -r requirements.txt
pip install -e .

# Run against sample attack data
threatlens scan sample_data/sample_security_log.json
```

> **Requirements:** Python 3.10+

---

## Usage

```bash
# Basic scan
threatlens scan sample_data/sample_security_log.json

# Verbose mode — show evidence for each alert
threatlens scan sample_data/sample_security_log.json --verbose

# Only show HIGH and CRITICAL alerts
threatlens scan sample_data/sample_security_log.json --min-severity high

# Export JSON report
threatlens scan sample_data/sample_security_log.json -o report.json -f json

# Export CSV report
threatlens scan sample_data/sample_security_log.json -o report.csv -f csv

# Scan a directory of log files
threatlens scan /path/to/logs/

# List all detection rules
threatlens rules

# Run without installing
python -m threatlens.cli scan sample_data/sample_security_log.json
```

---

## Example Output

```
  _____ _                    _   _
 |_   _| |__  _ __ ___  __ _| |_| |    ___ _ __  ___
   | | | '_ \| '__/ _ \/ _` | __| |   / _ \ '_ \/ __|
   | | | | | | | |  __/ (_| | |_| |__|  __/ | | \__ \
   |_| |_| |_|_|  \___|\__,_|\__|_____\___|_| |_|___/

  Log Analysis & Threat Hunting CLI v1.0.0

  Scanning 1 file(s)...
  Parsed     26 events from sample_security_log.json

============================================================
  SCAN SUMMARY
============================================================
  Events analyzed:   26
  Alerts generated:  10
  Scan duration:     0.00s

  CRITICAL     1
  HIGH         4
  MEDIUM       3
  LOW          2
============================================================

  [CRITICAL] Suspicious Process: SAM registry hive access
    Time:       2025-01-15 09:15:00
    Detail:     Process 'reg.exe' executed with suspicious command line on DC-01 by jdoe
    MITRE:      Execution / T1059 - Command and Scripting Interpreter
    Action:     Review the full command line and parent process...

  [HIGH] Brute-Force Detected
    Time:       2025-01-15 08:30:01
    Detail:     7 failed logon attempts from 10.0.1.50 targeting 1 account(s) within 300s
    MITRE:      Credential Access / T1110 - Brute Force
    Action:     Investigate source 10.0.1.50. Consider blocking the IP...

  [HIGH] Lateral Movement Detected
    Time:       2025-01-15 09:00:00
    Detail:     User 'svc_deploy' authenticated to 4 distinct hosts within 600s
    MITRE:      Lateral Movement / T1021 - Remote Services

  [HIGH] Suspicious Privilege Assignment
    Time:       2025-01-15 09:05:00
    Detail:     User 'jdoe' was assigned sensitive privileges: SeDebugPrivilege, SeTcbPrivilege
    MITRE:      Privilege Escalation / T1134 - Access Token Manipulation

  [HIGH] Suspicious Process: Base64-encoded PowerShell command
    Time:       2025-01-15 09:10:00
    Detail:     Process 'powershell.exe' executed with suspicious command line
    MITRE:      Execution / T1059 - Command and Scripting Interpreter
```

---

## Project Structure

```
ThreatLens/
├── threatlens/
│   ├── __init__.py                  # Package metadata
│   ├── cli.py                       # CLI argument parsing & command routing
│   ├── parser.py                    # JSON/NDJSON log parsing & normalization
│   ├── models.py                    # LogEvent, Alert, Severity data models
│   ├── report.py                    # Terminal output, JSON/CSV export
│   ├── utils.py                     # Helpers (tables, colors, time grouping)
│   └── detections/
│       ├── __init__.py              # Detection registry
│       ├── base.py                  # Abstract DetectionRule base class
│       ├── brute_force.py           # Failed logon burst & spray detection
│       ├── lateral_movement.py      # Multi-host auth pattern detection
│       ├── privilege_escalation.py  # Sensitive privilege monitoring
│       └── suspicious_process.py    # LOLBin & command-line analysis
├── rules/
│   └── default_rules.yaml           # Tunable detection thresholds
├── sample_data/
│   └── sample_security_log.json     # 26 events simulating a real attack chain
├── tests/
│   └── test_detections.py           # 18 unit tests across all modules
├── setup.py
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

```
tests/test_detections.py::TestParser::test_parse_timestamp_iso         PASSED
tests/test_detections.py::TestParser::test_parse_event_basic           PASSED
tests/test_detections.py::TestBruteForce::test_triggers_on_burst       PASSED
tests/test_detections.py::TestBruteForce::test_password_spray_detected PASSED
tests/test_detections.py::TestLateralMovement::test_triggers_on_multi_host PASSED
tests/test_detections.py::TestPrivilegeEscalation::test_triggers_on_debug_priv PASSED
tests/test_detections.py::TestSuspiciousProcess::test_encoded_powershell PASSED
tests/test_detections.py::TestSuspiciousProcess::test_sam_dump         PASSED
...
18 passed in 0.02s
```

---

## Log Format

ThreatLens accepts JSON arrays or newline-delimited JSON (NDJSON). The schema mirrors standard Windows Event Log JSON exports:

```json
{
  "TimeCreated": "2025-01-15T08:30:01Z",
  "EventID": 4625,
  "Computer": "WS-PC01",
  "EventData": {
    "TargetUserName": "admin",
    "IpAddress": "10.0.1.50",
    "LogonType": 3
  }
}
```

**Export your own logs with PowerShell:**

```powershell
Get-WinEvent -LogName Security -MaxEvents 1000 |
  Select-Object TimeCreated, Id, MachineName, Message |
  ConvertTo-Json | Out-File security_events.json
```

---

## How It Works

1. **Parse** — Logs are loaded from JSON/NDJSON files and normalized into a common `LogEvent` data model regardless of source format
2. **Detect** — Four modular detection rules analyze the event stream for attack patterns using time-window grouping, field correlation, and regex matching
3. **Report** — Alerts are ranked by severity, mapped to MITRE ATT&CK, and displayed with actionable recommendations. Export to JSON or CSV for further analysis

---

## Security & Ethics

ThreatLens is a **defensive-only** tool. It analyzes logs that already exist on systems you own or are authorized to audit. It does **not**:

- Access remote systems or networks
- Capture or sniff network traffic
- Exploit any vulnerabilities
- Generate attack traffic or payloads

Use this tool only on systems and logs you have explicit authorization to analyze.

---

## Roadmap

- [ ] Native EVTX parsing (read `.evtx` files directly without export)
- [ ] YAML-based custom rule engine for user-defined detections
- [ ] Sigma rule compatibility layer
- [ ] HTML report generation with severity charts
- [ ] Real-time log tailing mode (`--follow`)
- [ ] Syslog / CEF input format support
- [ ] Elasticsearch output connector
- [ ] Attack timeline visualization

---

## Author

**Jude Hilgendorf** — [GitHub](https://github.com/TiltedLunar123)

---

## License

MIT License. See [LICENSE](LICENSE) for details.
