"""Data models for ThreatLens log events and detection alerts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __str__(self) -> str:
        return self.value


class EventCategory(Enum):
    AUTHENTICATION = "authentication"
    PROCESS = "process"
    NETWORK = "network"
    PRIVILEGE = "privilege"
    FILE = "file"
    REGISTRY = "registry"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value


@dataclass
class LogEvent:
    """Represents a single parsed log event."""

    timestamp: datetime
    event_id: int
    source: str
    category: EventCategory
    computer: str
    raw: dict[str, Any]

    # Optional fields populated depending on event type
    username: str = ""
    domain: str = ""
    source_ip: str = ""
    process_name: str = ""
    command_line: str = ""
    logon_type: int = 0
    status: str = ""
    parent_process: str = ""
    target_username: str = ""

    @property
    def timestamp_str(self) -> str:
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class Alert:
    """Represents a detection alert raised by an analysis rule."""

    rule_name: str
    severity: Severity
    description: str
    timestamp: datetime
    evidence: list[dict[str, Any]] = field(default_factory=list)
    mitre_tactic: str = ""
    mitre_technique: str = ""
    recommendation: str = ""

    @property
    def timestamp_str(self) -> str:
        return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "severity": str(self.severity),
            "description": self.description,
            "timestamp": self.timestamp_str,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "recommendation": self.recommendation,
            "evidence_count": len(self.evidence),
            "evidence": self.evidence[:10],
            "evidence_truncated": len(self.evidence) > 10,
        }
