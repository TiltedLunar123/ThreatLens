"""Detect potential data exfiltration activity."""

from __future__ import annotations

import re
from typing import Any

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, LogEvent, Severity

_ARCHIVE_PATTERNS = [
    re.compile(r"\b(rar|7z|zip)\b.*\b(c:\\users|c:\\windows|\\\\|/home|/etc|/var)", re.IGNORECASE),
    re.compile(r"\b(compress-archive|tar\s+[cz])\b", re.IGNORECASE),
]

_SENSITIVE_PATHS = [
    "\\users\\", "\\documents\\", "\\desktop\\",
    "\\downloads\\", "\\appdata\\", "\\programdata\\",
    "/home/", "/etc/", "/var/log/",
]

_STAGING_PATTERNS = [
    re.compile(r"\b(compress|archive|zip|rar|7z)\b.*\b(c:\\|d:\\|/tmp|/var)", re.IGNORECASE),
    re.compile(r"\b(copy|xcopy|robocopy|cp|rsync)\b.*\b(\\\\|smb://)", re.IGNORECASE),
]


class ExfiltrationDetector(DetectionRule):
    """Detects data staging and exfiltration patterns such as suspicious
    archive creation targeting sensitive paths and large file staging.
    """

    name = "Data Exfiltration"
    description = "Suspicious archive creation or data staging activity"
    mitre_tactic = "Exfiltration"
    mitre_technique = "T1560 - Archive Collected Data"

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []

        for event in events:
            cmd = event.command_line or ""
            if not cmd:
                continue

            cmd_lower = cmd.lower()

            # Suspicious archive creation targeting sensitive paths
            for pattern in _ARCHIVE_PATTERNS:
                if pattern.search(cmd):
                    alerts.append(Alert(
                        rule_name="Suspicious Archive Creation",
                        severity=Severity.HIGH,
                        description=(
                            f"Archive tool used targeting sensitive paths on "
                            f"{event.computer} by {event.username or 'unknown'}: "
                            f"{cmd[:200]}"
                        ),
                        timestamp=event.timestamp,
                        evidence=[{
                            "timestamp": event.timestamp_str,
                            "event_id": event.event_id,
                            "computer": event.computer,
                            "username": event.username,
                            "command_line": cmd[:500],
                        }],
                        mitre_tactic=self.mitre_tactic,
                        mitre_technique="T1560.001 - Archive via Utility",
                        recommendation=(
                            "Review what data was archived and where it was "
                            "sent. This may indicate data exfiltration."
                        ),
                    ))
                    break

            # Large file staging patterns
            for pattern in _STAGING_PATTERNS:
                if pattern.search(cmd):
                    # Check if already caught by archive pattern
                    already_caught = any(p.search(cmd) for p in _ARCHIVE_PATTERNS)
                    if not already_caught:
                        alerts.append(Alert(
                            rule_name="Data Staging Detected",
                            severity=Severity.MEDIUM,
                            description=(
                                f"File staging activity on {event.computer} "
                                f"by {event.username or 'unknown'}: {cmd[:200]}"
                            ),
                            timestamp=event.timestamp,
                            evidence=[{
                                "timestamp": event.timestamp_str,
                                "event_id": event.event_id,
                                "computer": event.computer,
                                "username": event.username,
                                "command_line": cmd[:500],
                            }],
                            mitre_tactic=self.mitre_tactic,
                            mitre_technique="T1074 - Data Staged",
                            recommendation=(
                                "Verify the data transfer was authorized. "
                                "Large file copies to network shares may "
                                "indicate exfiltration staging."
                            ),
                        ))
                    break

        return alerts
