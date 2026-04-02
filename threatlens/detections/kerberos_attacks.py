"""Detect Kerberos-based attacks (Kerberoasting and AS-REP Roasting)."""

from __future__ import annotations

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, LogEvent, Severity

TGS_REQUEST_ID = 4769  # Kerberos Service Ticket Request
TGT_REQUEST_ID = 4768  # Kerberos Authentication Ticket Request

# RC4 encryption type indicates potential Kerberoasting/AS-REP Roasting
RC4_ENCRYPTION = "0x17"


class KerberosAttackDetector(DetectionRule):
    """Detects Kerberos-based attacks including Kerberoasting (requesting
    service tickets with RC4 encryption) and AS-REP Roasting (requesting
    TGTs with RC4 for accounts without pre-authentication).
    """

    name = "Kerberos Attacks"
    description = "Kerberoasting or AS-REP Roasting activity detected"
    mitre_tactic = "Credential Access"
    mitre_technique = "T1558 - Steal or Forge Kerberos Tickets"

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []

        for event in events:
            raw_str = str(event.raw)

            # Kerberoasting: TGS request with RC4 for non-machine accounts
            if event.event_id == TGS_REQUEST_ID and (RC4_ENCRYPTION in raw_str or "0x17" in raw_str.lower()):
                    target = event.target_username or event.username or ""
                    # Machine accounts end with '$'
                    if target and not target.endswith("$"):
                        alerts.append(Alert(
                            rule_name="Potential Kerberoasting",
                            severity=Severity.HIGH,
                            description=(
                                f"TGS request with RC4 encryption for "
                                f"non-machine account '{target}' on "
                                f"{event.computer}"
                            ),
                            timestamp=event.timestamp,
                            evidence=[{
                                "timestamp": event.timestamp_str,
                                "event_id": event.event_id,
                                "computer": event.computer,
                                "username": event.username,
                                "target_username": target,
                                "encryption_type": RC4_ENCRYPTION,
                            }],
                            mitre_tactic="Credential Access",
                            mitre_technique="T1558.003 - Kerberoasting",
                            recommendation=(
                                "Review the requesting account and target service. "
                                "RC4 TGS requests for service accounts may indicate "
                                "Kerberoasting. Rotate the target service password."
                            ),
                        ))

            # AS-REP Roasting: TGT request with RC4
            if event.event_id == TGT_REQUEST_ID and (RC4_ENCRYPTION in raw_str or "0x17" in raw_str.lower()):
                    target = event.target_username or event.username or ""
                    alerts.append(Alert(
                        rule_name="Potential AS-REP Roasting",
                        severity=Severity.HIGH,
                        description=(
                            f"TGT request with RC4 encryption for "
                            f"account '{target}' on {event.computer}"
                        ),
                        timestamp=event.timestamp,
                        evidence=[{
                            "timestamp": event.timestamp_str,
                            "event_id": event.event_id,
                            "computer": event.computer,
                            "username": event.username,
                            "target_username": target,
                            "encryption_type": RC4_ENCRYPTION,
                        }],
                        mitre_tactic="Credential Access",
                        mitre_technique="T1558.004 - AS-REP Roasting",
                        recommendation=(
                            "Check if pre-authentication is disabled for this "
                            "account. Enable Kerberos pre-authentication and "
                            "rotate the account password."
                        ),
                    ))

        return alerts
