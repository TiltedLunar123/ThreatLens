"""STIX 2.1 indicator export for ThreatLens.

Emits a STIX 2.1 bundle containing one indicator + sighting per alert
plus a single identity SDO representing the ThreatLens scan. The output
is consumable by any STIX 2.1 compatible TAXII server or by manual
import into platforms like MISP, OpenCTI, or Anomali.

Reference: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html

This implementation deliberately avoids the optional ``stix2`` library
to keep the runtime dependency footprint at zero. The objects are
hand-built dicts that validate against the spec for the small slice of
SDOs we emit (identity, indicator, sighting, bundle).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from threatlens.models import Alert

# Namespace used to derive deterministic UUIDv5 ids per alert.
_NAMESPACE = uuid.UUID("a9a3a7e4-9f43-4d9c-9a51-7b7b3a8a0e9d")

# Map our severity to STIX confidence (0-100).
_CONFIDENCE = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 95,
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _id_from(prefix: str, *parts: str) -> str:
    """Build a deterministic STIX id from a namespaced UUIDv5."""
    seed = "|".join(parts) or _now()
    nsid = uuid.uuid5(_NAMESPACE, seed)
    return f"{prefix}--{nsid}"


def _pattern_for_alert(alert: Alert) -> str:
    """Render the alert's first evidence row as a STIX 2.1 pattern string."""
    if not alert.evidence:
        return f"[x-threatlens:rule = '{alert.rule_name}']"

    ev = alert.evidence[0]
    ip = ev.get("source_ip")
    user = ev.get("username") or ev.get("target_username")
    proc = ev.get("process_name") or ev.get("image")
    host = ev.get("computer")

    parts = []
    if ip:
        parts.append(f"ipv4-addr:value = '{ip}'")
    if user:
        parts.append(f"user-account:account_login = '{user}'")
    if proc:
        proc_name = proc.split("\\")[-1] if "\\" in proc else proc
        parts.append(f"process:name = '{proc_name}'")
    if host:
        parts.append(f"hostname:value = '{host}'")

    if not parts:
        return f"[x-threatlens:rule = '{alert.rule_name}']"
    return "[" + " AND ".join(parts) + "]"


def build_stix_bundle(
    alerts: list[Alert],
    creator_name: str = "ThreatLens",
) -> dict[str, Any]:
    """Build a STIX 2.1 bundle from a list of alerts."""
    now = _now()

    identity_id = _id_from("identity", creator_name)
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": creator_name,
        "identity_class": "system",
        "sectors": ["technology"],
        "description": "ThreatLens log analysis tool, emitting alerts as STIX 2.1 indicators.",
    }

    objects: list[dict[str, Any]] = [identity]

    for alert in alerts:
        seed = (
            f"{alert.rule_name}|{alert.timestamp.isoformat()}|"
            f"{alert.mitre_technique}|{hashlib.sha256(alert.description.encode()).hexdigest()[:16]}"
        )
        indicator_id = _id_from("indicator", seed)
        sighting_id = _id_from("sighting", seed + "|sighting")

        pattern = _pattern_for_alert(alert)
        confidence = _CONFIDENCE.get(str(alert.severity), 50)

        labels = [str(alert.severity), "threatlens"]
        if alert.mitre_tactic:
            labels.append(alert.mitre_tactic.lower().replace(" ", "-"))

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "name": alert.rule_name,
            "description": alert.description,
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": alert.timestamp.isoformat() + "Z"
            if not alert.timestamp.tzinfo else alert.timestamp.isoformat(),
            "confidence": confidence,
            "labels": labels,
        }
        if alert.mitre_technique:
            indicator["external_references"] = [{
                "source_name": "mitre-attack",
                "external_id": alert.mitre_technique.split(" ", 1)[0],
                "description": alert.mitre_technique,
            }]

        sighting = {
            "type": "sighting",
            "spec_version": "2.1",
            "id": sighting_id,
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "first_seen": alert.timestamp.isoformat() + "Z"
            if not alert.timestamp.tzinfo else alert.timestamp.isoformat(),
            "last_seen": alert.timestamp.isoformat() + "Z"
            if not alert.timestamp.tzinfo else alert.timestamp.isoformat(),
            "count": len(alert.evidence) or 1,
            "sighting_of_ref": indicator_id,
            "description": alert.recommendation or alert.description,
        }

        objects.append(indicator)
        objects.append(sighting)

    bundle = {
        "type": "bundle",
        "id": _id_from("bundle", now, str(len(alerts))),
        "objects": objects,
    }
    return bundle


def export_stix_bundle(
    alerts: list[Alert],
    output_path: Path,
    creator_name: str = "ThreatLens",
) -> None:
    """Write a STIX 2.1 bundle to disk."""
    bundle = build_stix_bundle(alerts, creator_name=creator_name)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
