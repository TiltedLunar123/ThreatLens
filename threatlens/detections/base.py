"""Base class for all ThreatLens detection rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from threatlens.models import Alert, LogEvent


class DetectionRule(ABC):
    """Abstract base class that all detection rules must implement."""

    name: str = "Unnamed Rule"
    description: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @abstractmethod
    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        """Run detection logic against a list of events. Return any alerts."""
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.name}>"
