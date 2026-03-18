"""Correlation-based attack chain detection for ThreatLens.

Identifies multi-stage attacks by correlating alerts from different
detection categories (credential access, privilege escalation, lateral
movement, execution) for the same entity within a time window.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, EventCategory, LogEvent, Severity

# Map event IDs / categories to attack stages
_STAGE_CREDENTIAL_ACCESS = "Credential Access"
_STAGE_PRIVILEGE_ESCALATION = "Privilege Escalation"
_STAGE_LATERAL_MOVEMENT = "Lateral Movement"
_STAGE_EXECUTION = "Execution"

# Event IDs that indicate each stage
CREDENTIAL_ACCESS_IDS = {4625, 4776}  # Failed logons
SUCCESSFUL_LOGON_IDS = {4624}
PRIV_ESCALATION_IDS = {4672, 4673, 4674}
NETWORK_LOGON_TYPES = {3, 10}

_STAGE_ORDER = [
    _STAGE_CREDENTIAL_ACCESS,
    _STAGE_PRIVILEGE_ESCALATION,
    _STAGE_LATERAL_MOVEMENT,
    _STAGE_EXECUTION,
]


def _classify_stage(event: LogEvent) -> str | None:
    """Classify an event into an attack stage, or None if not relevant."""
    if event.event_id in CREDENTIAL_ACCESS_IDS:
        return _STAGE_CREDENTIAL_ACCESS
    if event.event_id in PRIV_ESCALATION_IDS:
        return _STAGE_PRIVILEGE_ESCALATION
    if event.event_id in SUCCESSFUL_LOGON_IDS and event.logon_type in NETWORK_LOGON_TYPES:
        return _STAGE_LATERAL_MOVEMENT
    if event.category == EventCategory.PROCESS and event.process_name:
        return _STAGE_EXECUTION
    return None


class AttackChainDetector(DetectionRule):
    """Detects multi-stage attack chains by correlating events across categories.

    Looks for sequences where the same user or computer appears in multiple
    attack stages (credential access -> privilege escalation -> lateral movement
    -> execution) within a configurable time window.
    """

    name = "Attack Chain Correlation"
    description = "Multi-stage attack detected across kill chain phases"
    mitre_tactic = "Multiple"
    mitre_technique = "Multi-stage"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.window_seconds = int(self.config.get("chain_window", 3600))
        self.min_stages = int(self.config.get("chain_min_stages", 2))

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        # Group events by user, classifying each into a stage
        user_stages: dict[str, dict[str, list[LogEvent]]] = defaultdict(
            lambda: defaultdict(list)
        )

        for event in events:
            stage = _classify_stage(event)
            if stage is None:
                continue

            user = event.target_username or event.username
            if not user or user.upper() in ("SYSTEM", "ANONYMOUS LOGON", "-", ""):
                continue

            user_stages[user][stage].append(event)

        alerts: list[Alert] = []

        for user, stages in user_stages.items():
            if len(stages) < self.min_stages:
                continue

            # Check if the stages fall within the time window
            all_stage_events: list[LogEvent] = []
            for stage_events in stages.values():
                all_stage_events.extend(stage_events)
            all_stage_events.sort(key=lambda e: e.timestamp)

            if not all_stage_events:
                continue

            first_ts = all_stage_events[0].timestamp
            last_ts = all_stage_events[-1].timestamp
            span = (last_ts - first_ts).total_seconds()

            if span > self.window_seconds:
                # Try to find a sub-window that fits
                # Use sliding window approach
                found_chain = False
                for i, start_event in enumerate(all_stage_events):
                    window_end = start_event.timestamp + timedelta(seconds=self.window_seconds)
                    window_events = [
                        e for e in all_stage_events[i:]
                        if e.timestamp <= window_end
                    ]
                    window_stages = {_classify_stage(e) for e in window_events} - {None}
                    if len(window_stages) >= self.min_stages:
                        alert = self._build_alert(user, window_events, window_stages)
                        if alert:
                            alerts.append(alert)
                        found_chain = True
                        break
                if not found_chain:
                    continue
            else:
                observed_stages = set(stages.keys())
                alert = self._build_alert(user, all_stage_events, observed_stages)
                if alert:
                    alerts.append(alert)

        return alerts

    def _build_alert(
        self,
        user: str,
        events: list[LogEvent],
        observed_stages: set[str],
    ) -> Alert | None:
        if len(observed_stages) < self.min_stages:
            return None

        # Order stages by kill chain
        ordered = [s for s in _STAGE_ORDER if s in observed_stages]
        stage_count = len(ordered)

        severity = Severity.CRITICAL if stage_count >= 3 else Severity.HIGH

        chain_str = " -> ".join(ordered)

        evidence = [
            {
                "timestamp": e.timestamp_str,
                "stage": _classify_stage(e) or "unknown",
                "event_id": e.event_id,
                "computer": e.computer,
                "username": e.target_username or e.username,
                "process": e.process_name,
                "source_ip": e.source_ip,
            }
            for e in events[:15]
        ]

        span_seconds = (events[-1].timestamp - events[0].timestamp).total_seconds()

        return Alert(
            rule_name="Attack Chain Detected",
            severity=severity,
            description=(
                f"User '{user}' observed in {stage_count} attack stages "
                f"within {span_seconds:.0f}s: {chain_str}"
            ),
            timestamp=events[0].timestamp,
            evidence=evidence,
            mitre_tactic="Multiple",
            mitre_technique="Multi-stage Kill Chain",
            recommendation=(
                f"Investigate user '{user}' immediately. "
                f"This alert correlates activity across {stage_count} kill chain phases, "
                f"suggesting a coordinated attack. Review all evidence events and "
                f"check for compromised credentials."
            ),
        )
