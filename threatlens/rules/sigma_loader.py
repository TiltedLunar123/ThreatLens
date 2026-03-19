"""Sigma rule compatibility layer for ThreatLens.

Parses Sigma rule YAML files and converts them into ThreatLens detection rules.
Supports the core Sigma specification: logsource, detection (selection/filter/condition),
and standard metadata fields.

Reference: https://github.com/SigmaHQ/sigma-specification
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, EventCategory, LogEvent, Severity

# Map Sigma status to our severity (used as fallback)
_STATUS_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.LOW,
}

# Map Sigma level to severity
_LEVEL_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.LOW,
}

# Map Sigma field names to LogEvent attributes
_FIELD_MAP: dict[str, str] = {
    "EventID": "event_id",
    "eventid": "event_id",
    "event_id": "event_id",
    "Image": "process_name",
    "image": "process_name",
    "ProcessName": "process_name",
    "CommandLine": "command_line",
    "commandline": "command_line",
    "ParentImage": "parent_process",
    "ParentProcessName": "parent_process",
    "parentimage": "parent_process",
    "User": "username",
    "user": "username",
    "SubjectUserName": "username",
    "TargetUserName": "target_username",
    "SourceIp": "source_ip",
    "IpAddress": "source_ip",
    "src_ip": "source_ip",
    "Computer": "computer",
    "ComputerName": "computer",
    "LogonType": "logon_type",
}

# Map Sigma logsource categories to our EventCategory
_LOGSOURCE_CATEGORY_MAP = {
    "process_creation": EventCategory.PROCESS,
    "network_connection": EventCategory.NETWORK,
    "file_event": EventCategory.FILE,
    "registry_event": EventCategory.REGISTRY,
    "authentication": EventCategory.AUTHENTICATION,
    "privilege_escalation": EventCategory.PRIVILEGE,
}


def _map_field(sigma_field: str) -> str:
    """Map a Sigma field name to a LogEvent attribute."""
    return _FIELD_MAP.get(sigma_field, sigma_field)


def _get_event_value(event: LogEvent, field: str) -> Any:
    """Get a field value from an event."""
    mapped = _map_field(field)

    if hasattr(event, mapped):
        return getattr(event, mapped)

    # Check raw data
    val = event.raw.get(field)
    if val is not None:
        return val

    event_data = event.raw.get("EventData", {})
    if isinstance(event_data, dict):
        val = event_data.get(field)
        if val is not None:
            return val

    return None


def _value_matches(event_val: Any, expected: Any) -> bool:
    """Check if an event value matches a Sigma detection value.

    Sigma matching rules:
    - Strings are case-insensitive
    - Wildcards (*) are supported
    - Lists mean OR (any value matches)
    - Integer/numeric comparisons are exact
    """
    if event_val is None:
        return False

    if isinstance(expected, list):
        return any(_value_matches(event_val, item) for item in expected)

    if isinstance(expected, (int, float)):
        try:
            return float(event_val) == float(expected)
        except (ValueError, TypeError):
            return str(event_val) == str(expected)

    # String matching with wildcard support
    expected_str = str(expected)
    event_str = str(event_val)

    if "*" in expected_str:
        # Convert Sigma wildcards to regex
        pattern = re.escape(expected_str).replace(r"\*", ".*")
        return bool(re.match(f"^{pattern}$", event_str, re.IGNORECASE))

    return event_str.lower() == expected_str.lower()


def _selection_matches(event: LogEvent, selection: dict[str, Any]) -> bool:
    """Check if an event matches a Sigma selection block.

    A selection block is a dict of field: value pairs.
    All fields must match (AND logic within a selection).
    """
    for field, expected in selection.items():
        # Handle field|modifier syntax (e.g., CommandLine|contains)
        parts = field.split("|")
        field_name = parts[0]
        modifiers = parts[1:] if len(parts) > 1 else []

        event_val = _get_event_value(event, field_name)
        if event_val is None:
            event_val = ""

        if "contains" in modifiers:
            if isinstance(expected, list):
                if not any(str(e).lower() in str(event_val).lower() for e in expected):
                    return False
            elif str(expected).lower() not in str(event_val).lower():
                return False
        elif "startswith" in modifiers:
            if isinstance(expected, list):
                if not any(str(event_val).lower().startswith(str(e).lower()) for e in expected):
                    return False
            elif not str(event_val).lower().startswith(str(expected).lower()):
                return False
        elif "endswith" in modifiers:
            if isinstance(expected, list):
                if not any(str(event_val).lower().endswith(str(e).lower()) for e in expected):
                    return False
            elif not str(event_val).lower().endswith(str(expected).lower()):
                return False
        elif "re" in modifiers:
            if isinstance(expected, list):
                if not any(re.search(str(e), str(event_val), re.IGNORECASE) for e in expected):
                    return False
            elif not re.search(str(expected), str(event_val), re.IGNORECASE):
                return False
        elif "all" in modifiers:
            # All values in the list must match
            if isinstance(expected, list):
                for e in expected:
                    if not _value_matches(event_val, e):
                        return False
            elif not _value_matches(event_val, expected):
                return False
        else:
            if not _value_matches(event_val, expected):
                return False

    return True


def _parse_condition(condition_str: str, selections: dict[str, dict], event: LogEvent) -> bool:
    """Evaluate a Sigma condition expression against an event.

    Supports: selection references, AND, OR, NOT, parentheses, 1/all of selection*
    """
    condition_str = condition_str.strip()

    # Handle "1 of selection*" or "all of selection*" patterns
    of_match = re.match(r"(1|all)\s+of\s+(\w+)\*", condition_str)
    if of_match:
        quantifier, prefix = of_match.groups()
        matching_selections = {k: v for k, v in selections.items() if k.startswith(prefix)}
        if not matching_selections:
            return False
        if quantifier == "1":
            return any(_selection_matches(event, sel) for sel in matching_selections.values())
        else:  # all
            return all(_selection_matches(event, sel) for sel in matching_selections.values())

    # Handle "1 of them" / "all of them"
    of_them = re.match(r"(1|all)\s+of\s+them", condition_str)
    if of_them:
        quantifier = of_them.group(1)
        if quantifier == "1":
            return any(_selection_matches(event, sel) for sel in selections.values())
        else:
            return all(_selection_matches(event, sel) for sel in selections.values())

    # Handle compound conditions with AND/OR/NOT
    # Split on " and " first (lower precedence than OR in Sigma)
    if " and " in condition_str.lower():
        # Split carefully, respecting parentheses
        parts = re.split(r"\s+and\s+", condition_str, flags=re.IGNORECASE)
        return all(_parse_condition(p.strip(), selections, event) for p in parts)

    if " or " in condition_str.lower():
        parts = re.split(r"\s+or\s+", condition_str, flags=re.IGNORECASE)
        return any(_parse_condition(p.strip(), selections, event) for p in parts)

    # Handle NOT
    not_match = re.match(r"not\s+(.+)", condition_str, re.IGNORECASE)
    if not_match:
        return not _parse_condition(not_match.group(1).strip(), selections, event)

    # Handle parentheses
    if condition_str.startswith("(") and condition_str.endswith(")"):
        return _parse_condition(condition_str[1:-1].strip(), selections, event)

    # Direct selection reference
    if condition_str in selections:
        return _selection_matches(event, selections[condition_str])

    # "selection and not filter" pattern
    parts = re.split(r"\s+and\s+not\s+", condition_str, flags=re.IGNORECASE)
    if len(parts) == 2:
        sel_name, filter_name = parts
        sel_match = sel_name.strip() in selections and _selection_matches(event, selections[sel_name.strip()])
        fil_match = filter_name.strip() in selections and _selection_matches(event, selections[filter_name.strip()])
        return sel_match and not fil_match

    return False


class SigmaRule(DetectionRule):
    """A detection rule loaded from a Sigma YAML file."""

    def __init__(self, sigma_def: dict[str, Any], source_file: str = ""):
        self.name = sigma_def.get("title", "Sigma Rule")
        self.description = sigma_def.get("description", "")
        self.mitre_tactic = ""
        self.mitre_technique = ""
        self._source_file = source_file

        # Extract MITRE ATT&CK tags
        tags = sigma_def.get("tags", [])
        for tag in tags:
            if isinstance(tag, str):
                if tag.startswith("attack.t"):
                    self.mitre_technique = tag.replace("attack.", "").upper()
                elif tag.startswith("attack.") and not tag.startswith("attack.t"):
                    self.mitre_tactic = tag.replace("attack.", "").replace("_", " ").title()

        # Severity
        level = sigma_def.get("level", "medium")
        self._severity = _LEVEL_SEVERITY.get(level, Severity.MEDIUM)

        # Logsource for pre-filtering
        self._logsource = sigma_def.get("logsource", {})
        self._category = _LOGSOURCE_CATEGORY_MAP.get(self._logsource.get("category", ""))

        # Detection block
        detection = sigma_def.get("detection", {})
        self._condition = detection.pop("condition", "selection")
        # Remaining keys are selection/filter blocks
        self._selections: dict[str, dict] = {}
        for key, val in detection.items():
            if isinstance(val, dict):
                self._selections[key] = val
            elif isinstance(val, list):
                # List of dicts = OR of multiple selection blocks
                # Merge into a single selection with list values
                merged: dict[str, Any] = {}
                for item in val:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            if k in merged:
                                existing = merged[k]
                                if not isinstance(existing, list):
                                    existing = [existing]
                                if isinstance(v, list):
                                    existing.extend(v)
                                else:
                                    existing.append(v)
                                merged[k] = existing
                            else:
                                merged[k] = v
                self._selections[key] = merged

        self._recommendation = sigma_def.get("falsepositives", [""])[0] if sigma_def.get("falsepositives") else ""
        if self._recommendation:
            self._recommendation = f"Possible false positive: {self._recommendation}"

        super().__init__()

    def _logsource_matches(self, event: LogEvent) -> bool:
        """Pre-filter events by logsource criteria."""
        return not (self._category and event.category != self._category)

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []

        for event in events:
            if not self._logsource_matches(event):
                continue

            try:
                if _parse_condition(self._condition, self._selections, event):
                    evidence = [{
                        "timestamp": event.timestamp_str,
                        "event_id": event.event_id,
                        "computer": event.computer,
                        "username": event.username or event.target_username,
                        "process": event.process_name,
                        "command_line": event.command_line[:300] if event.command_line else "",
                        "sigma_rule": self._source_file,
                    }]

                    alerts.append(Alert(
                        rule_name=f"Sigma: {self.name}",
                        severity=self._severity,
                        description=self.description or self.name,
                        timestamp=event.timestamp,
                        evidence=evidence,
                        mitre_tactic=self.mitre_tactic,
                        mitre_technique=self.mitre_technique,
                        recommendation=self._recommendation,
                    ))
            except (ValueError, KeyError, TypeError, re.error):
                continue

        return alerts


def load_sigma_rules(sigma_path: Path) -> list[SigmaRule]:
    """Load Sigma rules from a file or directory.

    Supports both single-rule YAML files and multi-document YAML files.
    """
    rules: list[SigmaRule] = []

    if sigma_path.is_dir():
        yaml_files = sorted(sigma_path.rglob("*.yml")) + sorted(sigma_path.rglob("*.yaml"))
    elif sigma_path.is_file():
        yaml_files = [sigma_path]
    else:
        return []

    for yaml_file in yaml_files:
        try:
            with open(yaml_file, encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))

            for doc in docs:
                if not isinstance(doc, dict):
                    continue
                # Sigma rules must have a detection block
                if "detection" not in doc:
                    continue
                rules.append(SigmaRule(doc, source_file=str(yaml_file.name)))
        except Exception as e:
            print(f"  Warning: Failed to load Sigma rule {yaml_file}: {e}", file=sys.stderr)

    return rules
