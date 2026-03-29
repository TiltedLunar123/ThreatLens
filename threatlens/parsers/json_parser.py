"""JSON/NDJSON log parser — extracted from the original parser module."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from threatlens.models import EventCategory, LogEvent

# Map Windows Security Event IDs to categories
EVENT_CATEGORY_MAP: dict[int, EventCategory] = {
    4624: EventCategory.AUTHENTICATION,
    4625: EventCategory.AUTHENTICATION,
    4634: EventCategory.AUTHENTICATION,
    4648: EventCategory.AUTHENTICATION,
    4776: EventCategory.AUTHENTICATION,
    1: EventCategory.PROCESS,
    4688: EventCategory.PROCESS,
    4689: EventCategory.PROCESS,
    4672: EventCategory.PRIVILEGE,
    4673: EventCategory.PRIVILEGE,
    4674: EventCategory.PRIVILEGE,
    3: EventCategory.NETWORK,
    5156: EventCategory.NETWORK,
    5157: EventCategory.NETWORK,
    11: EventCategory.FILE,
    4663: EventCategory.FILE,
    12: EventCategory.REGISTRY,
    13: EventCategory.REGISTRY,
}


def classify_event(event_id: int) -> EventCategory:
    return EVENT_CATEGORY_MAP.get(event_id, EventCategory.UNKNOWN)


def parse_timestamp(raw_ts: str) -> datetime:
    """Parse common timestamp formats from log sources."""
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(raw_ts, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unable to parse timestamp: {raw_ts}")


def _extract_field(entry: dict, *keys: str, default: str = "") -> str:
    """Try multiple possible field names, return first match."""
    for key in keys:
        val = entry.get(key)
        if val is not None:
            return str(val)
        event_data = entry.get("EventData", {})
        if isinstance(event_data, dict):
            val = event_data.get(key)
            if val is not None:
                return str(val)
    return default


def parse_event(entry: dict) -> LogEvent:
    """Parse a single raw JSON log entry into a LogEvent."""
    event_id = int(_extract_field(entry, "EventID", "event_id", "EventId", default="0"))
    category = classify_event(event_id)

    ts_raw = _extract_field(
        entry, "TimeCreated", "timestamp", "Timestamp", "@timestamp", "time"
    )
    try:
        timestamp = parse_timestamp(ts_raw)
    except ValueError:
        timestamp = datetime.min

    return LogEvent(
        timestamp=timestamp,
        event_id=event_id,
        source=_extract_field(entry, "Source", "source", "Provider", "Channel"),
        category=category,
        computer=_extract_field(entry, "Computer", "computer", "ComputerName"),
        raw=entry,
        username=_extract_field(entry, "SubjectUserName", "User", "username"),
        domain=_extract_field(entry, "TargetDomainName", "SubjectDomainName", "Domain", "domain"),
        source_ip=_extract_field(entry, "IpAddress", "SourceAddress", "source_ip", "src_ip"),
        process_name=_extract_field(entry, "NewProcessName", "Image", "ProcessName", "process"),
        command_line=_extract_field(entry, "CommandLine", "command_line", "ParentCommandLine"),
        logon_type=int(_extract_field(entry, "LogonType", "logon_type", default="0")),
        status=_extract_field(entry, "Status", "status", "Keywords"),
        parent_process=_extract_field(entry, "ParentImage", "ParentProcessName", "parent_process"),
        target_username=_extract_field(entry, "TargetUserName", "target_user"),
    )


def load_json_events(log_path: Path) -> list[LogEvent]:
    """Load and parse all events from a JSON log file."""
    text = log_path.read_text(encoding="utf-8")
    entries: list[dict] = []

    text_stripped = text.strip()
    if text_stripped.startswith("["):
        entries = json.loads(text_stripped)
    else:
        for line_num, line in enumerate(text_stripped.splitlines(), 1):
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    logging.getLogger("threatlens").warning(
                        "Skipping malformed JSON on line %d: %s%s",
                        line_num, line[:80], "..." if len(line) > 80 else "",
                    )

    events = [parse_event(e) for e in entries]
    events.sort(key=lambda e: e.timestamp)
    return events


def stream_json_events(log_path: Path) -> Iterator[LogEvent]:
    """Stream events one at a time for memory-efficient processing."""
    with open(log_path, encoding="utf-8") as f:
        first_char = f.read(1)
        f.seek(0)

        if first_char == "[":
            entries = json.load(f)
            for entry in entries:
                yield parse_event(entry)
        else:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield parse_event(json.loads(line))
                    except json.JSONDecodeError:
                        continue
