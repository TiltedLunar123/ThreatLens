"""Detect credential access techniques."""

from __future__ import annotations

from typing import Any

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, LogEvent, Severity

SYSMON_PROCESS_ACCESS_ID = 10
OBJECT_ACCESS_ID = 4663
DS_ACCESS_ID = 4662

# DCSync replication GUIDs
DCSYNC_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
}


class CredentialAccessDetector(DetectionRule):
    """Detects credential access techniques including LSASS memory access,
    SAM hive access, and DCSync attacks.
    """

    name = "Credential Access"
    description = "Credential theft or dumping activity detected"
    mitre_tactic = "Credential Access"
    mitre_technique = "T1003 - OS Credential Dumping"

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []

        for event in events:
            raw_str = str(event.raw).lower()

            # LSASS access (Sysmon Event ID 10)
            if event.event_id == SYSMON_PROCESS_ACCESS_ID:
                if "lsass.exe" in raw_str:
                    # Check TargetImage in raw data
                    target_image = ""
                    if isinstance(event.raw, dict):
                        ed = event.raw.get("EventData", event.raw)
                        if isinstance(ed, dict):
                            target_image = str(ed.get("TargetImage", ""))
                    if "lsass.exe" in target_image.lower() or "lsass.exe" in raw_str:
                        alerts.append(Alert(
                            rule_name="LSASS Memory Access",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Process accessed LSASS memory on {event.computer} "
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
                            mitre_tactic="Credential Access",
                            mitre_technique="T1003.001 - LSASS Memory",
                            recommendation=(
                                "Investigate the source process accessing LSASS. "
                                "This is commonly used by tools like Mimikatz."
                            ),
                        ))

            # SAM hive access (Event ID 4663)
            if event.event_id == OBJECT_ACCESS_ID:
                if "sam" in raw_str:
                    # Check if the object accessed is the SAM
                    obj_name = ""
                    if isinstance(event.raw, dict):
                        ed = event.raw.get("EventData", event.raw)
                        if isinstance(ed, dict):
                            obj_name = str(ed.get("ObjectName", ""))
                    if "sam" in obj_name.lower() or "sam" in raw_str:
                        alerts.append(Alert(
                            rule_name="SAM Hive Access",
                            severity=Severity.HIGH,
                            description=(
                                f"SAM registry hive accessed on {event.computer} "
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
                            mitre_tactic="Credential Access",
                            mitre_technique="T1003.002 - Security Account Manager",
                            recommendation=(
                                "Investigate SAM hive access. Attackers dump "
                                "the SAM to extract local account hashes."
                            ),
                        ))

            # DCSync (Event ID 4662 with replication GUIDs)
            if event.event_id == DS_ACCESS_ID:
                for guid in DCSYNC_GUIDS:
                    if guid in raw_str:
                        alerts.append(Alert(
                            rule_name="DCSync Attack Detected",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Directory replication request (DCSync) "
                                f"from {event.computer} by "
                                f"{event.username or 'unknown'}"
                            ),
                            timestamp=event.timestamp,
                            evidence=[{
                                "timestamp": event.timestamp_str,
                                "event_id": event.event_id,
                                "computer": event.computer,
                                "username": event.username,
                                "replication_guid": guid,
                            }],
                            mitre_tactic="Credential Access",
                            mitre_technique="T1003.006 - DCSync",
                            recommendation=(
                                "Verify this replication request was from a "
                                "legitimate domain controller. DCSync attacks "
                                "extract all domain credentials."
                            ),
                        ))
                        break  # One alert per event

        return alerts
