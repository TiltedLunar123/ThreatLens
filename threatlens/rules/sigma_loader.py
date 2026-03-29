"""Sigma rule compatibility layer for ThreatLens.

Parses Sigma rule YAML files and converts them into ThreatLens detection rules.
Supports the core Sigma specification: logsource, detection (selection/filter/condition),
and standard metadata fields.

Reference: https://github.com/SigmaHQ/sigma-specification
"""

from __future__ import annotations

import logging
import re
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


def _tokenize(condition_str: str) -> list[str]:
    """Tokenize a Sigma condition string."""
    tokens: list[str] = []
    i = 0
    s = condition_str.strip()
    while i < len(s):
        # Skip whitespace
        if s[i].isspace():
            i += 1
            continue
        # Parentheses
        if s[i] in ("(", ")"):
            tokens.append(s[i])
            i += 1
            continue
        # Try to match keywords and compound expressions
        rest = s[i:]
        rest_lower = rest.lower()
        # Match "1 of <name>*" or "all of <name>*" or "1 of them" / "all of them"
        of_match = re.match(r"(1|all)\s+of\s+(\w+\*|them)", rest_lower)
        if of_match:
            length = of_match.end()
            tokens.append(rest[:length])
            i += length
            continue
        # Match keywords (and, or, not)
        for kw in ("and", "or", "not"):
            if rest_lower.startswith(kw) and (
                len(rest) == len(kw) or not rest[len(kw)].isalnum()
            ):
                tokens.append(kw)
                i += len(kw)
                break
        else:
            # Identifier (selection name)
            m = re.match(r"\w+", rest)
            if m:
                tokens.append(m.group())
                i += m.end()
            else:
                i += 1  # skip unknown character
    return tokens


def _parse_condition(condition_str: str, selections: dict[str, dict], event: LogEvent) -> bool:
    """Evaluate a Sigma condition expression against an event.

    Uses a recursive-descent parser with correct operator precedence:
      OR (lowest) < AND < NOT (highest)
    """
    tokens = _tokenize(condition_str)
    if not tokens:
        return False
    result, _ = _eval_or(tokens, 0, selections, event)
    return result


def _eval_or(tokens: list[str], pos: int, selections: dict, event: LogEvent) -> tuple[bool, int]:
    """OR has lowest precedence."""
    left, pos = _eval_and(tokens, pos, selections, event)
    while pos < len(tokens) and tokens[pos] == "or":
        pos += 1  # consume 'or'
        right, pos = _eval_and(tokens, pos, selections, event)
        left = left or right
    return left, pos


def _eval_and(tokens: list[str], pos: int, selections: dict, event: LogEvent) -> tuple[bool, int]:
    """AND has higher precedence than OR."""
    left, pos = _eval_not(tokens, pos, selections, event)
    while pos < len(tokens) and tokens[pos] == "and":
        pos += 1  # consume 'and'
        right, pos = _eval_not(tokens, pos, selections, event)
        left = left and right
    return left, pos


def _eval_not(tokens: list[str], pos: int, selections: dict, event: LogEvent) -> tuple[bool, int]:
    """NOT has highest precedence."""
    if pos < len(tokens) and tokens[pos] == "not":
        pos += 1  # consume 'not'
        result, pos = _eval_not(tokens, pos, selections, event)
        return not result, pos
    return _eval_atom(tokens, pos, selections, event)


def _eval_atom(tokens: list[str], pos: int, selections: dict, event: LogEvent) -> tuple[bool, int]:
    """Atom: selection name, '1 of X*', 'all of them', or '(' expr ')'."""
    if pos >= len(tokens):
        return False, pos

    token = tokens[pos]

    # Parenthesized expression
    if token == "(":
        pos += 1  # consume '('
        result, pos = _eval_or(tokens, pos, selections, event)
        if pos < len(tokens) and tokens[pos] == ")":
            pos += 1  # consume ')'
        return result, pos

    # "1 of X*" or "all of them"
    token_lower = token.lower()
    of_match = re.match(r"(1|all)\s+of\s+(\w+\*|them)", token_lower)
    if of_match:
        quantifier, target = of_match.groups()
        pos += 1
        if target == "them":
            if quantifier == "1":
                return any(_selection_matches(event, sel) for sel in selections.values()), pos
            else:
                return all(_selection_matches(event, sel) for sel in selections.values()), pos
        else:
            prefix = target.rstrip("*")
            matching = {k: v for k, v in selections.items() if k.startswith(prefix)}
            if not matching:
                return False, pos
            if quantifier == "1":
                return any(_selection_matches(event, sel) for sel in matching.values()), pos
            else:
                return all(_selection_matches(event, sel) for sel in matching.values()), pos

    # Direct selection reference
    pos += 1
    if token in selections:
        return _selection_matches(event, selections[token]), pos

    return False, pos


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
            except Exception:
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
            logging.getLogger("threatlens").warning("Failed to load Sigma rule %s: %s", yaml_file, e)

    return rules
