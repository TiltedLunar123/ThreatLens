"""Native Windows EVTX file parser for ThreatLens.

Requires the optional ``python-evtx`` package::

    pip install threatlens[evtx]
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from threatlens.models import LogEvent
from threatlens.parsers.json_parser import classify_event, parse_timestamp

# XML namespace used in Windows Event Log XML
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _xml_to_dict(record_xml: str) -> dict:
    """Convert a Windows Event Log XML record to a flat dictionary."""
    try:
        root = ET.fromstring(record_xml)
    except ET.ParseError:
        return {}

    result: dict = {}

    # System block
    system = root.find(f"{NS}System")
    if system is not None:
        provider = system.find(f"{NS}Provider")
        if provider is not None:
            result["Source"] = provider.get("Name", "")

        event_id_el = system.find(f"{NS}EventID")
        if event_id_el is not None:
            result["EventID"] = event_id_el.text or "0"

        time_el = system.find(f"{NS}TimeCreated")
        if time_el is not None:
            result["TimeCreated"] = time_el.get("SystemTime", "")

        computer_el = system.find(f"{NS}Computer")
        if computer_el is not None:
            result["Computer"] = computer_el.text or ""

        channel_el = system.find(f"{NS}Channel")
        if channel_el is not None:
            result["Channel"] = channel_el.text or ""

    # EventData block — extract named Data elements
    event_data: dict = {}
    ed = root.find(f"{NS}EventData")
    if ed is not None:
        for data_el in ed.findall(f"{NS}Data"):
            name = data_el.get("Name")
            if name:
                event_data[name] = data_el.text or ""

    if event_data:
        result["EventData"] = event_data

    # UserData block (alternative to EventData in some events)
    ud = root.find(f"{NS}UserData")
    if ud is not None and not event_data:
        user_data: dict = {}
        for child in ud:
            for el in child:
                tag = el.tag.split("}")[-1] if "}" in el.tag else el.tag
                user_data[tag] = el.text or ""
        if user_data:
            result["EventData"] = user_data

    return result


def _parse_evtx_record(record_dict: dict) -> LogEvent:
    """Convert an EVTX record dict into a LogEvent."""
    event_id_raw = record_dict.get("EventID", "0")
    try:
        event_id = int(event_id_raw)
    except (ValueError, TypeError):
        event_id = 0

    category = classify_event(event_id)

    ts_raw = record_dict.get("TimeCreated", "")
    try:
        timestamp = parse_timestamp(ts_raw)
    except ValueError:
        timestamp = datetime.min

    event_data = record_dict.get("EventData", {})

    def _get(*keys: str, default: str = "") -> str:
        for k in keys:
            val = record_dict.get(k)
            if val is not None:
                return str(val)
            if isinstance(event_data, dict):
                val = event_data.get(k)
                if val is not None:
                    return str(val)
        return default

    return LogEvent(
        timestamp=timestamp,
        event_id=event_id,
        source=record_dict.get("Source", ""),
        category=category,
        computer=record_dict.get("Computer", ""),
        raw=record_dict,
        username=_get("SubjectUserName", "User"),
        domain=_get("TargetDomainName", "SubjectDomainName"),
        source_ip=_get("IpAddress", "SourceAddress"),
        process_name=_get("NewProcessName", "Image", "ProcessName"),
        command_line=_get("CommandLine"),
        logon_type=int(_get("LogonType", default="0")),
        status=_get("Status", "Keywords"),
        parent_process=_get("ParentImage", "ParentProcessName"),
        target_username=_get("TargetUserName"),
    )


def _ensure_evtx_available() -> bool:
    """Check if python-evtx is installed."""
    try:
        import Evtx  # noqa: F401
        return True
    except ImportError:
        logging.getLogger("threatlens").error(
            "python-evtx is required for .evtx file parsing. "
            "Install it with: pip install python-evtx"
        )
        return False


def load_evtx_events(evtx_path: Path) -> list[LogEvent]:
    """Load all events from a native Windows EVTX file."""
    if not _ensure_evtx_available():
        return []

    import Evtx.Evtx as evtx

    events: list[LogEvent] = []
    with evtx.Evtx(str(evtx_path)) as log:
        for record in log.records():
            try:
                record_dict = _xml_to_dict(record.xml())
                if record_dict:
                    events.append(_parse_evtx_record(record_dict))
            except Exception:
                continue

    events.sort(key=lambda e: e.timestamp)
    return events


def stream_evtx_events(evtx_path: Path) -> Iterator[LogEvent]:
    """Stream events from an EVTX file one at a time."""
    if not _ensure_evtx_available():
        return

    import Evtx.Evtx as evtx

    with evtx.Evtx(str(evtx_path)) as log:
        for record in log.records():
            try:
                record_dict = _xml_to_dict(record.xml())
                if record_dict:
                    yield _parse_evtx_record(record_dict)
            except Exception:
                continue
