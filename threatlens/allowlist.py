"""Allowlist loading and matching for ThreatLens."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("threatlens")


def load_allowlist(path: Path) -> list[dict[str, Any]]:
    """Load suppression rules from a YAML allowlist file.

    Each entry may specify ``rule_name``, ``username``, and/or
    ``computer`` -- an alert is suppressed when all specified fields match.
    """
    if not path.exists():
        logger.warning("Allowlist file not found: %s", path)
        return []
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if isinstance(data, dict):
        return data.get("allowlist", [])
    return []


def _alert_allowed(alert: Any, allowlist: list[dict[str, Any]]) -> str | None:
    """Return the reason string if the alert matches any allowlist entry.

    Returns None if not suppressed.
    """
    for entry in allowlist:
        match = True
        if "rule_name" in entry and entry["rule_name"].lower() not in alert.rule_name.lower():
            match = False
        if "username" in entry:
            usernames = {ev.get("username", "") for ev in alert.evidence}
            if entry["username"].lower() not in {u.lower() for u in usernames}:
                match = False
        if "computer" in entry:
            computers = {ev.get("computer", "") for ev in alert.evidence}
            if entry["computer"].lower() not in {c.lower() for c in computers}:
                match = False
        if "source_ip" in entry:
            ips = {ev.get("source_ip", "") for ev in alert.evidence}
            if entry["source_ip"] not in ips:
                match = False
        if "severity" in entry and entry["severity"].lower() != alert.severity.value.lower():
            match = False
        if "mitre_technique" in entry and entry["mitre_technique"].upper() not in alert.mitre_technique.upper():
            match = False
        if "event_id" in entry:
            event_ids = {str(ev.get("event_id", "")) for ev in alert.evidence}
            if str(entry["event_id"]) not in event_ids:
                match = False
        if match:
            return entry.get("reason", "allowlisted")
    return None
