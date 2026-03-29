"""Detect reconnaissance and discovery activity."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, LogEvent, Severity

RECON_COMMANDS = {
    "whoami", "ipconfig", "systeminfo", "net", "nltest", "dsquery",
    "hostname", "nslookup", "tasklist", "netstat", "arp", "route",
    "wmic", "query", "cmdkey",
}


class DiscoveryDetector(DetectionRule):
    """Detects reconnaissance command bursts -- a rapid sequence of
    discovery commands run by the same user within a configurable time window.
    """

    name = "Discovery / Reconnaissance"
    description = "Rapid burst of reconnaissance commands by a single user"
    mitre_tactic = "Discovery"
    mitre_technique = "T1082 - System Information Discovery"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.threshold = int(self.config.get("recon_threshold", 3))
        self.window_seconds = int(self.config.get("recon_window", 120))

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        # Collect events whose process name matches a recon command
        recon_events: list[LogEvent] = []
        for event in events:
            proc = (event.process_name or "").lower().split("\\")[-1].replace(".exe", "")
            if proc in RECON_COMMANDS:
                recon_events.append(event)

        if not recon_events:
            return []

        # Group by user
        by_user: dict[str, list[LogEvent]] = defaultdict(list)
        for event in recon_events:
            user = event.username or event.target_username or "unknown"
            by_user[user].append(event)

        alerts: list[Alert] = []

        for user, user_events in by_user.items():
            user_events.sort(key=lambda e: e.timestamp)
            # Sliding window
            i = 0
            while i < len(user_events):
                window_end_ts = user_events[i].timestamp
                window = []
                for j in range(i, len(user_events)):
                    delta = (user_events[j].timestamp - user_events[i].timestamp).total_seconds()
                    if delta <= self.window_seconds:
                        window.append(user_events[j])
                    else:
                        break

                if len(window) >= self.threshold:
                    distinct_cmds = {
                        (e.process_name or "").lower().split("\\")[-1].replace(".exe", "")
                        for e in window
                    }
                    evidence = [
                        {
                            "timestamp": e.timestamp_str,
                            "username": user,
                            "computer": e.computer,
                            "process": e.process_name,
                            "command_line": e.command_line[:300] if e.command_line else "",
                        }
                        for e in window
                    ]

                    alerts.append(Alert(
                        rule_name="Reconnaissance Burst Detected",
                        severity=Severity.MEDIUM,
                        description=(
                            f"User '{user}' ran {len(window)} recon commands "
                            f"({', '.join(sorted(distinct_cmds))}) within "
                            f"{self.window_seconds}s on {window[0].computer}"
                        ),
                        timestamp=window[0].timestamp,
                        evidence=evidence,
                        mitre_tactic=self.mitre_tactic,
                        mitre_technique=self.mitre_technique,
                        recommendation=(
                            f"Investigate user '{user}'. A burst of discovery "
                            f"commands often indicates early-stage attacker activity."
                        ),
                    ))
                    # Skip past this window
                    i += len(window)
                else:
                    i += 1

        return alerts
