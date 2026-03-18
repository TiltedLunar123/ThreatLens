"""Unified parser interface for ThreatLens."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from threatlens.models import LogEvent
from threatlens.parsers.json_parser import load_json_events, stream_json_events


def detect_format(path: Path, forced_format: str | None = None) -> str:
    """Detect the input file format based on extension or forced override."""
    if forced_format:
        return forced_format

    suffix = path.suffix.lower()
    format_map = {
        ".json": "json",
        ".ndjson": "json",
        ".jsonl": "json",
        ".evtx": "evtx",
        ".log": "syslog",
        ".syslog": "syslog",
        ".cef": "cef",
    }
    return format_map.get(suffix, "json")


def load_events(path: Path, input_format: str | None = None) -> list[LogEvent]:
    """Load all events from a file, auto-detecting format."""
    fmt = detect_format(path, input_format)

    if fmt == "evtx":
        from threatlens.parsers.evtx_parser import load_evtx_events
        return load_evtx_events(path)
    elif fmt in ("syslog", "cef"):
        from threatlens.parsers.syslog_parser import load_syslog_events
        return load_syslog_events(path, fmt)
    else:
        return load_json_events(path)


def stream_events(path: Path, input_format: str | None = None) -> Iterator[LogEvent]:
    """Stream events one at a time, auto-detecting format."""
    fmt = detect_format(path, input_format)

    if fmt == "evtx":
        from threatlens.parsers.evtx_parser import stream_evtx_events
        yield from stream_evtx_events(path)
    elif fmt in ("syslog", "cef"):
        from threatlens.parsers.syslog_parser import stream_syslog_events
        yield from stream_syslog_events(path, fmt)
    else:
        yield from stream_json_events(path)
