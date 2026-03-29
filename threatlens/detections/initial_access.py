"""Detect initial access patterns."""

from __future__ import annotations

from typing import Any

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, LogEvent, Severity
from threatlens.utils import is_private_ip

LOGON_SUCCESS_ID = 4624
REMOTE_INTERACTIVE_LOGON = 10


class InitialAccessDetector(DetectionRule):
    """Detects suspicious initial access patterns including remote interactive
    logons from unusual IPs and after-hours logon activity.
    """

    name = "Initial Access"
    description = "Suspicious logon patterns indicating initial access"
    mitre_tactic = "Initial Access"
    mitre_technique = "T1078 - Valid Accounts"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.business_hours_start = int(self.config.get("business_hours_start", 6))
        self.business_hours_end = int(self.config.get("business_hours_end", 20))

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []

        for event in events:
            if event.event_id != LOGON_SUCCESS_ID:
                continue

            user = event.target_username or event.username or ""
            if not user or user.upper() in ("SYSTEM", "ANONYMOUS LOGON", "-", ""):
                continue

            # Suspicious remote interactive logon from external IPs
            if event.logon_type == REMOTE_INTERACTIVE_LOGON:
                if event.source_ip and not is_private_ip(event.source_ip):
                    alerts.append(Alert(
                        rule_name="External RDP Logon",
                        severity=Severity.HIGH,
                        description=(
                            f"Remote interactive logon from external IP "
                            f"{event.source_ip} to {event.computer} "
                            f"as '{user}'"
                        ),
                        timestamp=event.timestamp,
                        evidence=[{
                            "timestamp": event.timestamp_str,
                            "event_id": event.event_id,
                            "computer": event.computer,
                            "username": user,
                            "source_ip": event.source_ip,
                            "logon_type": event.logon_type,
                        }],
                        mitre_tactic="Initial Access",
                        mitre_technique="T1078 - Valid Accounts",
                        recommendation=(
                            f"Verify that '{user}' legitimately logged in "
                            f"from {event.source_ip}. External RDP access "
                            f"is a common initial access vector."
                        ),
                    ))

            # After-hours logon
            hour = event.timestamp.hour
            if hour < self.business_hours_start or hour >= self.business_hours_end:
                alerts.append(Alert(
                    rule_name="After-Hours Logon",
                    severity=Severity.LOW,
                    description=(
                        f"Logon outside business hours "
                        f"({self.business_hours_start}:00-{self.business_hours_end}:00) "
                        f"by '{user}' at {event.timestamp_str} on {event.computer}"
                    ),
                    timestamp=event.timestamp,
                    evidence=[{
                        "timestamp": event.timestamp_str,
                        "event_id": event.event_id,
                        "computer": event.computer,
                        "username": user,
                        "source_ip": event.source_ip,
                        "logon_type": event.logon_type,
                        "hour": hour,
                    }],
                    mitre_tactic="Initial Access",
                    mitre_technique="T1078 - Valid Accounts",
                    recommendation=(
                        f"Verify that '{user}' was expected to log in "
                        f"outside business hours."
                    ),
                ))

        return alerts
