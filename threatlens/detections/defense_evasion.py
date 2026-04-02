"""Detect defense evasion techniques."""

from __future__ import annotations

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, LogEvent, Severity

# Event IDs related to defense evasion
LOG_CLEARED_IDS = {1102, 104}  # 1102 = Security log cleared, 104 = System log cleared
DEFENDER_DISABLED_ID = 5001
AUDIT_POLICY_CHANGE_ID = 4719

# Firewall-related keywords
_FIREWALL_KEYWORDS = [
    "netsh advfirewall",
    "set-netfirewallprofile",
    "disable-netfirewallrule",
    "new-netfirewallrule",
    "remove-netfirewallrule",
]


class DefenseEvasionDetector(DetectionRule):
    """Detects defense evasion techniques such as log clearing,
    disabling security tools, and modifying audit policies or firewall rules.
    """

    name = "Defense Evasion"
    description = "Activity that tampers with security controls or audit trails"
    mitre_tactic = "Defense Evasion"
    mitre_technique = "T1070 - Indicator Removal"

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []

        for event in events:
            # Log clearing
            if event.event_id in LOG_CLEARED_IDS:
                alerts.append(Alert(
                    rule_name="Log Clearing Detected",
                    severity=Severity.HIGH,
                    description=(
                        f"Event log cleared (Event ID {event.event_id}) "
                        f"on {event.computer} by {event.username or 'unknown'}"
                    ),
                    timestamp=event.timestamp,
                    evidence=[{
                        "timestamp": event.timestamp_str,
                        "event_id": event.event_id,
                        "computer": event.computer,
                        "username": event.username,
                    }],
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1070.001 - Clear Windows Event Logs",
                    recommendation=(
                        "Investigate why logs were cleared. This is a common "
                        "attacker technique to cover tracks."
                    ),
                ))

            # Windows Defender disabled
            if event.event_id == DEFENDER_DISABLED_ID:
                alerts.append(Alert(
                    rule_name="Windows Defender Disabled",
                    severity=Severity.HIGH,
                    description=(
                        f"Windows Defender was disabled on {event.computer} "
                        f"by {event.username or 'unknown'}"
                    ),
                    timestamp=event.timestamp,
                    evidence=[{
                        "timestamp": event.timestamp_str,
                        "event_id": event.event_id,
                        "computer": event.computer,
                        "username": event.username,
                    }],
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1562.001 - Disable or Modify Tools",
                    recommendation=(
                        "Verify this was an authorized change. Disabled "
                        "endpoint protection is a strong indicator of compromise."
                    ),
                ))

            # Audit policy changes
            if event.event_id == AUDIT_POLICY_CHANGE_ID:
                alerts.append(Alert(
                    rule_name="Audit Policy Modified",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Audit policy changed (Event ID {event.event_id}) "
                        f"on {event.computer} by {event.username or 'unknown'}"
                    ),
                    timestamp=event.timestamp,
                    evidence=[{
                        "timestamp": event.timestamp_str,
                        "event_id": event.event_id,
                        "computer": event.computer,
                        "username": event.username,
                    }],
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1562.002 - Disable Windows Event Logging",
                    recommendation=(
                        "Verify audit policy changes were authorized. "
                        "Attackers modify audit policies to reduce detection."
                    ),
                ))

            # Firewall rule modifications via command line
            cmd = event.command_line.lower() if event.command_line else ""
            if cmd and any(kw in cmd for kw in _FIREWALL_KEYWORDS):
                alerts.append(Alert(
                    rule_name="Firewall Rule Modification",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Firewall rule modified on {event.computer} "
                        f"by {event.username or 'unknown'}: "
                        f"{event.command_line[:200]}"
                    ),
                    timestamp=event.timestamp,
                    evidence=[{
                        "timestamp": event.timestamp_str,
                        "event_id": event.event_id,
                        "computer": event.computer,
                        "username": event.username,
                        "command_line": event.command_line[:500],
                    }],
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1562.004 - Disable or Modify System Firewall",
                    recommendation=(
                        "Verify firewall changes were authorized. Attackers "
                        "modify firewall rules to enable lateral movement."
                    ),
                ))

        return alerts
