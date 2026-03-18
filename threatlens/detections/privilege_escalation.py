"""Detect potential privilege escalation activity."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, LogEvent, Severity

# Sensitive privilege constants (Windows well-known privileges)
SENSITIVE_PRIVILEGES = {
    "SeDebugPrivilege",
    "SeTcbPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLoadDriverPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeImpersonatePrivilege",
}

# Accounts that normally receive elevated privileges (reduce noise)
SYSTEM_ACCOUNTS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "UMFD-0"}

PRIV_EVENT_IDS = {4672, 4673, 4674}


class PrivilegeEscalationDetector(DetectionRule):
    """Detects unusual privilege assignments or usage.

    Flags when non-system accounts receive sensitive privileges like
    SeDebugPrivilege, which attackers use for credential dumping.
    """

    name = "Privilege Escalation"
    description = "Sensitive privilege assigned to non-system account"
    mitre_tactic = "Privilege Escalation"
    mitre_technique = "T1134 - Access Token Manipulation"

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        priv_events = [e for e in events if e.event_id in PRIV_EVENT_IDS]
        if not priv_events:
            return []

        # Group by user to deduplicate — one alert per user with all evidence
        user_data: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"events": [], "privs": set()}
        )

        for event in priv_events:
            user = event.username or event.target_username
            if not user or user.upper() in SYSTEM_ACCOUNTS:
                continue

            raw_str = str(event.raw)
            found_privs = [p for p in SENSITIVE_PRIVILEGES if p in raw_str]

            if not found_privs:
                continue

            user_data[user]["events"].append(event)
            user_data[user]["privs"].update(found_privs)

        alerts: list[Alert] = []

        for user, data in user_data.items():
            all_privs = data["privs"]
            user_events = data["events"]
            is_debug = "SeDebugPrivilege" in all_privs
            severity = Severity.HIGH if is_debug else Severity.MEDIUM

            evidence = [{
                "timestamp": e.timestamp_str,
                "username": user,
                "computer": e.computer,
                "event_id": e.event_id,
                "privileges": [p for p in SENSITIVE_PRIVILEGES if p in str(e.raw)],
            } for e in user_events]

            alerts.append(Alert(
                rule_name="Suspicious Privilege Assignment",
                severity=severity,
                description=(
                    f"User '{user}' was assigned sensitive privileges "
                    f"({len(user_events)} event(s)): {', '.join(sorted(all_privs))}"
                ),
                timestamp=user_events[0].timestamp,
                evidence=evidence,
                mitre_tactic=self.mitre_tactic,
                mitre_technique=self.mitre_technique,
                recommendation=(
                    f"Verify that '{user}' requires these privileges. "
                    f"SeDebugPrivilege in particular is used by tools like "
                    f"Mimikatz for credential dumping."
                ),
            ))

        return alerts
