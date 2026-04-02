"""Detect brute-force login attempts from failed logon bursts."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, LogEvent, Severity
from threatlens.utils import find_dense_windows

# Windows Event IDs for failed logons
FAILED_LOGON_IDS = {4625, 4776}


class BruteForceDetector(DetectionRule):
    """Detects bursts of failed authentication attempts from the same source.

    Triggers when a single IP or username generates more failed logons than the
    configured threshold within a rolling time window.
    """

    name = "Brute-Force / Password Spray"
    description = "Multiple failed logon attempts in a short time window"
    mitre_tactic = "Credential Access"
    mitre_technique = "T1110 - Brute Force"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.threshold = int(self.config.get("brute_force_threshold", 5))
        self.window_seconds = int(self.config.get("brute_force_window", 300))

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        failed = [e for e in events if e.event_id in FAILED_LOGON_IDS]
        if not failed:
            return []

        alerts: list[Alert] = []

        # Group by source IP
        by_ip: dict[str, list[LogEvent]] = defaultdict(list)
        for event in failed:
            key = event.source_ip or "unknown"
            by_ip[key].append(event)

        for source, source_events in by_ip.items():
            windows = find_dense_windows(source_events, self.window_seconds, self.threshold)
            for window in windows:
                if len(window) >= self.threshold:
                    targets = {e.target_username or e.username for e in window}
                    severity = Severity.CRITICAL if len(window) >= self.threshold * 3 else (
                        Severity.HIGH if len(window) >= self.threshold * 2 else Severity.MEDIUM
                    )

                    # Check for password spray (many users from one source)
                    is_spray = len(targets) > 3
                    rule_label = "Password Spray" if is_spray else "Brute-Force"

                    evidence = [
                        {
                            "timestamp": e.timestamp_str,
                            "source_ip": e.source_ip,
                            "username": e.target_username or e.username,
                            "event_id": e.event_id,
                            "computer": e.computer,
                        }
                        for e in window
                    ]

                    alerts.append(Alert(
                        rule_name=f"{rule_label} Detected",
                        severity=severity,
                        description=(
                            f"{len(window)} failed logon attempts from {source} "
                            f"targeting {len(targets)} account(s) within "
                            f"{self.window_seconds}s"
                        ),
                        timestamp=window[0].timestamp,
                        evidence=evidence,
                        mitre_tactic=self.mitre_tactic,
                        mitre_technique=self.mitre_technique,
                        recommendation=(
                            f"Investigate source {source}. Consider blocking the IP "
                            f"and resetting passwords for targeted accounts: "
                            f"{', '.join(sorted(targets)[:5])}"
                        ),
                    ))

        return alerts
