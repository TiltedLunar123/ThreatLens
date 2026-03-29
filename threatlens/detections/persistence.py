"""Detect persistence mechanisms."""

from __future__ import annotations

import re
from typing import Any

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, LogEvent, Severity

NEW_SERVICE_ID = 7045
SCHEDULED_TASK_ID = 4698
SYSMON_REGISTRY_ID = 13

_RUN_KEY_PATHS = [
    r"\\software\\microsoft\\windows\\currentversion\\run",
    r"\\software\\microsoft\\windows\\currentversion\\runonce",
    r"\\software\\wow6432node\\microsoft\\windows\\currentversion\\run",
    r"\\software\\wow6432node\\microsoft\\windows\\currentversion\\runonce",
]

_STARTUP_KEYWORDS = [
    "\\startup\\",
    "\\start menu\\programs\\startup\\",
]


class PersistenceDetector(DetectionRule):
    """Detects persistence mechanisms including new services, scheduled tasks,
    registry run key modifications, and startup folder changes.
    """

    name = "Persistence Mechanism"
    description = "Activity establishing persistence on the host"
    mitre_tactic = "Persistence"
    mitre_technique = "T1543 - Create or Modify System Process"

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []

        for event in events:
            # New service installed
            if event.event_id == NEW_SERVICE_ID:
                raw_str = str(event.raw).lower()
                severity = Severity.HIGH
                if "powershell" in raw_str or "cmd" in raw_str:
                    severity = Severity.CRITICAL

                alerts.append(Alert(
                    rule_name="New Service Created",
                    severity=severity,
                    description=(
                        f"New service installed on {event.computer} "
                        f"by {event.username or 'unknown'}"
                    ),
                    timestamp=event.timestamp,
                    evidence=[{
                        "timestamp": event.timestamp_str,
                        "event_id": event.event_id,
                        "computer": event.computer,
                        "username": event.username,
                        "command_line": event.command_line[:500] if event.command_line else "",
                    }],
                    mitre_tactic="Persistence",
                    mitre_technique="T1543.003 - Windows Service",
                    recommendation=(
                        "Review the service binary path and account. "
                        "Attackers create malicious services for persistence."
                    ),
                ))

            # Scheduled task creation
            if event.event_id == SCHEDULED_TASK_ID:
                alerts.append(Alert(
                    rule_name="Scheduled Task Created",
                    severity=Severity.HIGH,
                    description=(
                        f"Scheduled task created on {event.computer} "
                        f"by {event.username or 'unknown'}"
                    ),
                    timestamp=event.timestamp,
                    evidence=[{
                        "timestamp": event.timestamp_str,
                        "event_id": event.event_id,
                        "computer": event.computer,
                        "username": event.username,
                        "command_line": event.command_line[:500] if event.command_line else "",
                    }],
                    mitre_tactic="Persistence",
                    mitre_technique="T1053.005 - Scheduled Task",
                    recommendation=(
                        "Review the task definition and action. Scheduled "
                        "tasks are a common persistence mechanism."
                    ),
                ))

            # Registry run key modifications (Sysmon Event ID 13)
            if event.event_id == SYSMON_REGISTRY_ID:
                raw_str = str(event.raw).lower()
                if any(path in raw_str for path in _RUN_KEY_PATHS):
                    alerts.append(Alert(
                        rule_name="Registry Run Key Modified",
                        severity=Severity.HIGH,
                        description=(
                            f"Registry Run/RunOnce key modified on {event.computer} "
                            f"by {event.username or 'unknown'}"
                        ),
                        timestamp=event.timestamp,
                        evidence=[{
                            "timestamp": event.timestamp_str,
                            "event_id": event.event_id,
                            "computer": event.computer,
                            "username": event.username,
                            "process": event.process_name,
                        }],
                        mitre_tactic="Persistence",
                        mitre_technique="T1547.001 - Registry Run Keys / Startup Folder",
                        recommendation=(
                            "Review the registry value being set. Run keys "
                            "execute programs at user logon."
                        ),
                    ))

            # Startup folder modifications
            cmd_lower = (event.command_line or "").lower()
            proc_lower = (event.process_name or "").lower()
            raw_lower = str(event.raw).lower()
            if any(kw in raw_lower or kw in cmd_lower for kw in _STARTUP_KEYWORDS):
                # Avoid duplicate with registry run key alert
                if event.event_id != SYSMON_REGISTRY_ID:
                    alerts.append(Alert(
                        rule_name="Startup Folder Modified",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Startup folder modification detected on {event.computer} "
                            f"by {event.username or 'unknown'}"
                        ),
                        timestamp=event.timestamp,
                        evidence=[{
                            "timestamp": event.timestamp_str,
                            "event_id": event.event_id,
                            "computer": event.computer,
                            "username": event.username,
                            "command_line": event.command_line[:500] if event.command_line else "",
                        }],
                        mitre_tactic="Persistence",
                        mitre_technique="T1547.001 - Registry Run Keys / Startup Folder",
                        recommendation=(
                            "Check the file placed in the startup folder. "
                            "This is a simple but common persistence mechanism."
                        ),
                    ))

        return alerts
