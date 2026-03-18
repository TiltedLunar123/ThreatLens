"""Detect suspicious process execution patterns."""

from __future__ import annotations

import re

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, EventCategory, LogEvent, Severity

# Processes commonly abused by attackers (LOLBins and common tools)
SUSPICIOUS_PROCESSES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "wmic.exe", "psexec.exe",
    "net.exe", "net1.exe", "schtasks.exe", "at.exe",
    "reg.exe", "sc.exe",
}

# Command-line patterns that are almost always malicious or worth investigating.
# Each tuple: (regex, severity, description, mitre_tactic, mitre_technique)
SUSPICIOUS_PATTERNS = [
    (r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", Severity.HIGH,
     "Base64-encoded PowerShell command",
     "Execution", "T1059.001 - PowerShell"),
    (r"Invoke-(WebRequest|RestMethod|Expression)", Severity.HIGH,
     "PowerShell download/exec cradle",
     "Execution", "T1059.001 - PowerShell"),
    (r"IEX\s*\(", Severity.HIGH,
     "PowerShell Invoke-Expression",
     "Execution", "T1059.001 - PowerShell"),
    (r"(New-Object\s+Net\.WebClient|DownloadString|DownloadFile)", Severity.HIGH,
     "Network download via PowerShell",
     "Command and Control", "T1105 - Ingress Tool Transfer"),
    (r"bypass\s+.*executionpolicy", Severity.MEDIUM,
     "Execution policy bypass",
     "Defense Evasion", "T1562.001 - Disable or Modify Tools"),
    (r"-nop(rofile)?\s+-w(indowstyle)?\s+hidden", Severity.HIGH,
     "Hidden PowerShell window",
     "Defense Evasion", "T1564.003 - Hidden Window"),
    (r"certutil.*-urlcache.*-split.*-f", Severity.HIGH,
     "Certutil used as download cradle",
     "Command and Control", "T1105 - Ingress Tool Transfer"),
    (r"reg\s+(add|save|export).*\\sam", Severity.CRITICAL,
     "SAM registry hive access",
     "Credential Access", "T1003.002 - Security Account Manager"),
    (r"sekurlsa|mimikatz|kerberos::list", Severity.CRITICAL,
     "Credential dumping tool keyword",
     "Credential Access", "T1003.001 - LSASS Memory"),
    (r"whoami\s+/priv", Severity.LOW,
     "Privilege enumeration",
     "Discovery", "T1033 - System Owner/User Discovery"),
    (r"net\s+user\s+\S+\s+\S+.*/(add|domain)", Severity.HIGH,
     "Account creation or password change",
     "Persistence", "T1136.001 - Local Account"),
    (r"net\s+(user|localgroup|group)\s+", Severity.LOW,
     "Account/group enumeration",
     "Discovery", "T1087 - Account Discovery"),
    (r"schtasks\s+/create\s+", Severity.HIGH,
     "Scheduled task creation (persistence)",
     "Persistence", "T1053.005 - Scheduled Task"),
    (r"sc\s+(create|config)\s+", Severity.HIGH,
     "Service creation/modification",
     "Persistence", "T1543.003 - Windows Service"),
]


class SuspiciousProcessDetector(DetectionRule):
    """Detects execution of suspicious processes and command-line patterns.

    Checks for known-abused binaries (LOLBins) and regex patterns commonly
    associated with attacker techniques like download cradles, encoded
    commands, and credential dumping tools.
    """

    name = "Suspicious Process Execution"
    description = "Potentially malicious process or command-line detected"
    mitre_tactic = "Execution"
    mitre_technique = "T1059 - Command and Scripting Interpreter"

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        process_events = [
            e for e in events
            if e.category == EventCategory.PROCESS and e.process_name
        ]
        if not process_events:
            return []

        alerts: list[Alert] = []

        for event in process_events:
            proc_name = event.process_name.lower().split("\\")[-1]
            cmd_line = event.command_line.lower()

            # Check for suspicious binaries with interesting command lines
            if proc_name in SUSPICIOUS_PROCESSES and cmd_line:
                for pattern, severity, desc, tactic, technique in SUSPICIOUS_PATTERNS:
                    if re.search(pattern, event.command_line, re.IGNORECASE):
                        evidence = [{
                            "timestamp": event.timestamp_str,
                            "process": event.process_name,
                            "command_line": event.command_line[:500],
                            "parent_process": event.parent_process,
                            "username": event.username,
                            "computer": event.computer,
                        }]

                        alerts.append(Alert(
                            rule_name=f"Suspicious Process: {desc}",
                            severity=severity,
                            description=(
                                f"Process '{proc_name}' executed with suspicious "
                                f"command line on {event.computer} by {event.username}"
                            ),
                            timestamp=event.timestamp,
                            evidence=evidence,
                            mitre_tactic=tactic,
                            mitre_technique=technique,
                            recommendation=(
                                "Review the full command line and parent process. "
                                "Determine if this was legitimate admin activity or "
                                "potential compromise."
                            ),
                        ))
                        break  # One alert per event is enough

        return alerts
