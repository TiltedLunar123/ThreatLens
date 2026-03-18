"""YAML-based custom rule engine for user-defined detections."""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, LogEvent, Severity
from threatlens.utils import group_by_time_window

# Operator functions for field matching
_OPERATORS = {
    "equals": lambda val, expected: str(val).lower() == str(expected).lower(),
    "contains": lambda val, expected: str(expected).lower() in str(val).lower(),
    "startswith": lambda val, expected: str(val).lower().startswith(str(expected).lower()),
    "endswith": lambda val, expected: str(val).lower().endswith(str(expected).lower()),
    "regex": lambda val, expected: bool(re.search(expected, str(val), re.IGNORECASE)),
    "gt": lambda val, expected: _to_num(val) > _to_num(expected),
    "lt": lambda val, expected: _to_num(val) < _to_num(expected),
    "gte": lambda val, expected: _to_num(val) >= _to_num(expected),
    "lte": lambda val, expected: _to_num(val) <= _to_num(expected),
    "in": lambda val, expected: str(val).lower() in [str(e).lower() for e in expected],
    "not_equals": lambda val, expected: str(val).lower() != str(expected).lower(),
    "not_contains": lambda val, expected: str(expected).lower() not in str(val).lower(),
}


def _to_num(val: Any) -> float:
    try:
        return float(val)
    except (ValueError, TypeError):
        return 0.0


def _get_event_value(event: LogEvent, field: str) -> Any:
    """Get a field value from an event, supporting dot notation for raw data."""
    if hasattr(event, field):
        return getattr(event, field)

    # Support dot notation for nested raw fields: raw.EventData.SomeField
    if field.startswith("raw."):
        parts = field.split(".")[1:]
        obj: Any = event.raw
        for part in parts:
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return ""
            if obj is None:
                return ""
        return obj

    # Check raw dict directly
    val = event.raw.get(field)
    if val is not None:
        return val

    event_data = event.raw.get("EventData", {})
    if isinstance(event_data, dict):
        val = event_data.get(field)
        if val is not None:
            return val

    return ""


class YamlRule(DetectionRule):
    """A detection rule defined in YAML configuration."""

    def __init__(self, rule_def: dict[str, Any]):
        self.name = rule_def.get("name", "Custom Rule")
        self.description = rule_def.get("description", "")
        self.mitre_tactic = rule_def.get("mitre_tactic", "")
        self.mitre_technique = rule_def.get("mitre_technique", "")
        self._severity = Severity(rule_def.get("severity", "medium").lower())
        self._conditions: list[dict[str, Any]] = rule_def.get("conditions", [])
        self._group_by: str = rule_def.get("group_by", "")
        self._threshold: int = int(rule_def.get("threshold", 1))
        self._window_seconds: int = int(rule_def.get("window_seconds", 300))
        self._recommendation: str = rule_def.get("recommendation", "")
        super().__init__()

    def _event_matches(self, event: LogEvent) -> bool:
        """Check if an event matches all conditions."""
        for condition in self._conditions:
            field = condition.get("field", "")
            operator = condition.get("operator", "equals")
            value = condition.get("value", "")

            event_val = _get_event_value(event, field)

            op_func = _OPERATORS.get(operator)
            if not op_func:
                continue

            if not op_func(event_val, value):
                return False

        return True

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        matching = [e for e in events if self._event_matches(e)]
        if not matching:
            return []

        alerts: list[Alert] = []

        if self._group_by:
            # Group matching events by a field, apply threshold
            groups: dict[str, list[LogEvent]] = defaultdict(list)
            for event in matching:
                key = str(_get_event_value(event, self._group_by))
                groups[key].append(event)

            for group_key, group_events in groups.items():
                if self._window_seconds > 0:
                    windows = group_by_time_window(group_events, self._window_seconds)
                else:
                    windows = [group_events]

                for window in windows:
                    if len(window) >= self._threshold:
                        evidence = [
                            {
                                "timestamp": e.timestamp_str,
                                "group_key": group_key,
                                "event_id": e.event_id,
                                "computer": e.computer,
                                "username": e.username or e.target_username,
                            }
                            for e in window[:10]
                        ]

                        alerts.append(Alert(
                            rule_name=self.name,
                            severity=self._severity,
                            description=(
                                f"{self.description} — {len(window)} matching event(s) "
                                f"for {self._group_by}='{group_key}'"
                            ),
                            timestamp=window[0].timestamp,
                            evidence=evidence,
                            mitre_tactic=self.mitre_tactic,
                            mitre_technique=self.mitre_technique,
                            recommendation=self._recommendation,
                        ))
        else:
            # No grouping — threshold applies to total count
            if self._threshold <= 1:
                # One alert per matching event
                for event in matching:
                    evidence = [{
                        "timestamp": event.timestamp_str,
                        "event_id": event.event_id,
                        "computer": event.computer,
                        "username": event.username or event.target_username,
                    }]
                    alerts.append(Alert(
                        rule_name=self.name,
                        severity=self._severity,
                        description=self.description,
                        timestamp=event.timestamp,
                        evidence=evidence,
                        mitre_tactic=self.mitre_tactic,
                        mitre_technique=self.mitre_technique,
                        recommendation=self._recommendation,
                    ))
            elif len(matching) >= self._threshold:
                evidence = [
                    {
                        "timestamp": e.timestamp_str,
                        "event_id": e.event_id,
                        "computer": e.computer,
                        "username": e.username or e.target_username,
                    }
                    for e in matching[:10]
                ]
                alerts.append(Alert(
                    rule_name=self.name,
                    severity=self._severity,
                    description=(
                        f"{self.description} — {len(matching)} matching event(s)"
                    ),
                    timestamp=matching[0].timestamp,
                    evidence=evidence,
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    recommendation=self._recommendation,
                ))

        return alerts


def load_yaml_rules(rules_path: Path) -> list[YamlRule]:
    """Load custom detection rules from a YAML file or directory."""
    rules: list[YamlRule] = []

    if rules_path.is_dir():
        yaml_files = sorted(rules_path.glob("*.yaml")) + sorted(rules_path.glob("*.yml"))
    elif rules_path.is_file():
        yaml_files = [rules_path]
    else:
        return []

    for yaml_file in yaml_files:
        try:
            with open(yaml_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data:
                continue

            # Support single rule or list of rules
            if isinstance(data, dict):
                if "rules" in data:
                    rule_list = data["rules"]
                else:
                    rule_list = [data]
            elif isinstance(data, list):
                rule_list = data
            else:
                continue

            for rule_def in rule_list:
                if isinstance(rule_def, dict) and "conditions" in rule_def:
                    rules.append(YamlRule(rule_def))
        except Exception as e:
            print(f"  Warning: Failed to load rules from {yaml_file}: {e}", file=sys.stderr)

    return rules
