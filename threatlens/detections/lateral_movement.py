"""Detect potential lateral movement patterns."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, LogEvent, Severity
from threatlens.utils import group_by_time_window

# Logon types indicating network/remote logons
NETWORK_LOGON_TYPES = {3, 10}  # 3 = Network, 10 = RemoteInteractive (RDP)
LOGON_EVENT_IDS = {4624, 4648}


class LateralMovementDetector(DetectionRule):
    """Detects signs of lateral movement across the network.

    Looks for a single account authenticating to multiple distinct hosts
    in a short time window, which may indicate an attacker pivoting.
    """

    name = "Lateral Movement"
    description = "Single account authenticating to multiple hosts rapidly"
    mitre_tactic = "Lateral Movement"
    mitre_technique = "T1021 - Remote Services"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.host_threshold = int(self.config.get("lateral_host_threshold", 3))
        self.window_seconds = int(self.config.get("lateral_window", 600))

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        network_logons = [
            e for e in events
            if e.event_id in LOGON_EVENT_IDS
            and e.logon_type in NETWORK_LOGON_TYPES
        ]
        if not network_logons:
            return []

        alerts: list[Alert] = []

        # Group by authenticating user
        by_user: dict[str, list[LogEvent]] = defaultdict(list)
        for event in network_logons:
            user = event.target_username or event.username
            if user and user not in ("SYSTEM", "ANONYMOUS LOGON", "-", ""):
                by_user[user].append(event)

        for user, user_events in by_user.items():
            windows = group_by_time_window(user_events, self.window_seconds)
            for window in windows:
                hosts = {e.computer for e in window}
                if len(hosts) >= self.host_threshold:
                    has_rdp = any(e.logon_type == 10 for e in window)
                    severity = Severity.HIGH if has_rdp else Severity.MEDIUM

                    evidence = [
                        {
                            "timestamp": e.timestamp_str,
                            "username": user,
                            "computer": e.computer,
                            "source_ip": e.source_ip,
                            "logon_type": e.logon_type,
                        }
                        for e in window
                    ]

                    alerts.append(Alert(
                        rule_name="Lateral Movement Detected",
                        severity=severity,
                        description=(
                            f"User '{user}' authenticated to {len(hosts)} distinct hosts "
                            f"within {self.window_seconds}s: {', '.join(sorted(hosts)[:5])}"
                        ),
                        timestamp=window[0].timestamp,
                        evidence=evidence,
                        mitre_tactic=self.mitre_tactic,
                        mitre_technique=self.mitre_technique,
                        recommendation=(
                            f"Verify that '{user}' has a legitimate reason for accessing "
                            f"multiple hosts. Check for compromised credentials."
                        ),
                    ))

        return alerts
