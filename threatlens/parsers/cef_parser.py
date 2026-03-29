"""Dedicated CEF (Common Event Format) parser for ThreatLens.

Parses CEF format:
  CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity|Extensions

Extension key=value pairs support escaped characters (\\=, \\\\, \\n).
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from threatlens.models import EventCategory, LogEvent

# CEF header pattern
_CEF_RE = re.compile(
    r"^CEF:(\d+)\|"       # version
    r"([^|]*)\|"           # vendor
    r"([^|]*)\|"           # product
    r"([^|]*)\|"           # device version
    r"([^|]*)\|"           # signature id
    r"([^|]*)\|"           # name
    r"([^|]*)\|"           # severity
    r"(.*)$"               # extension
)

# Extension key=value parser (handles escaped characters)
_CEF_KV_RE = re.compile(r"(\w+)=((?:[^\\=]|\\.)*?)(?=\s+\w+=|$)")

# CEF severity to EventCategory mapping
_CEF_SEVERITY_MAP = {
    "0": EventCategory.UNKNOWN, "1": EventCategory.UNKNOWN,
    "2": EventCategory.UNKNOWN, "3": EventCategory.AUTHENTICATION,
    "4": EventCategory.AUTHENTICATION, "5": EventCategory.NETWORK,
    "6": EventCategory.PROCESS, "7": EventCategory.PRIVILEGE,
    "8": EventCategory.PRIVILEGE, "9": EventCategory.PRIVILEGE,
    "10": EventCategory.PRIVILEGE,
}

# CEF field to LogEvent field mapping
_CEF_FIELD_MAP = {
    "src": "source_ip",
    "sourceAddress": "source_ip",
    "dst": "destination",
    "destinationAddress": "destination",
    "dhost": "computer",
    "shost": "computer",
    "duser": "target_username",
    "suser": "username",
    "act": "command_line",
    "dproc": "process_name",
    "sproc": "process_name",
    "dntdom": "domain",
}

# Month abbreviation lookup
_MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

_RFC3164_TS_RE = re.compile(
    r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$"
)


def _unescape_cef_value(value: str) -> str:
    """Unescape CEF extension values."""
    return (
        value
        .replace("\\=", "=")
        .replace("\\\\", "\\")
        .replace("\\n", "\n")
        .replace("\\r", "\r")
    )


def _parse_cef_timestamp(ts_str: str) -> datetime:
    """Parse a CEF timestamp from various formats."""
    if not ts_str:
        return datetime.min

    ts_str = ts_str.strip()

    # Try epoch milliseconds
    try:
        epoch_ms = int(ts_str)
        return datetime.utcfromtimestamp(epoch_ms / 1000)
    except (ValueError, OSError):
        pass

    # Try RFC 3164 format
    m = _RFC3164_TS_RE.match(ts_str)
    if m:
        month_abbr, day, hour, minute, second = m.groups()
        month = _MONTH_MAP.get(month_abbr.lower())
        if month:
            return datetime(
                year=datetime.now().year,
                month=month,
                day=int(day),
                hour=int(hour),
                minute=int(minute),
                second=int(second),
            )

    # Try ISO formats
    clean = re.sub(r"[+-]\d{2}:\d{2}$", "", ts_str)
    clean = re.sub(r"Z$", "", clean)
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%b %d %Y %H:%M:%S",
    ]:
        try:
            return datetime.strptime(clean, fmt)
        except ValueError:
            continue

    return datetime.min


def parse_cef_line(line: str) -> LogEvent | None:
    """Parse a single CEF line into a LogEvent.

    Handles CEF lines that may be embedded in a syslog header.
    """
    line = line.strip()
    if not line:
        return None

    # Find CEF start (may have syslog prefix)
    cef_start = line.find("CEF:")
    if cef_start < 0:
        return None

    syslog_header = line[:cef_start].strip() if cef_start > 0 else ""
    cef_part = line[cef_start:]

    match = _CEF_RE.match(cef_part)
    if not match:
        return None

    (cef_version, vendor, product, dev_version,
     sig_id, name, severity, extension) = match.groups()

    # Parse extension key=value pairs
    ext_data: dict[str, str] = {}
    for kv_match in _CEF_KV_RE.finditer(extension):
        key = kv_match.group(1)
        value = _unescape_cef_value(kv_match.group(2).strip())
        ext_data[key] = value

    # Extract hostname
    hostname = ext_data.get("dhost", ext_data.get("shost", ""))
    if not hostname and syslog_header:
        parts = syslog_header.split()
        if len(parts) >= 2:
            hostname = parts[1] if len(parts) > 1 else parts[0]

    # Extract timestamp
    ts_str = ext_data.get("rt", ext_data.get("end", ext_data.get("start", "")))
    if not ts_str and syslog_header:
        ts_match = re.search(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", syslog_header)
        if ts_match:
            ts_str = ts_match.group(1)

    timestamp = _parse_cef_timestamp(ts_str)
    category = _CEF_SEVERITY_MAP.get(severity, EventCategory.UNKNOWN)

    # Build raw dict
    raw = {
        "cef_version": cef_version,
        "vendor": vendor,
        "product": product,
        "device_version": dev_version,
        "signature_id": sig_id,
        "name": name,
        "severity": severity,
        "extension": ext_data,
        "format": "cef",
    }

    try:
        event_id = int(sig_id)
    except (ValueError, TypeError):
        event_id = 0

    return LogEvent(
        timestamp=timestamp,
        event_id=event_id,
        source=f"{vendor}/{product}",
        category=category,
        computer=hostname,
        raw=raw,
        username=ext_data.get("suser", ""),
        source_ip=ext_data.get("src", ext_data.get("sourceAddress", "")),
        process_name=ext_data.get("dproc", ext_data.get("sproc", "")),
        command_line=ext_data.get("act", ext_data.get("cs1", name)),
        target_username=ext_data.get("duser", ""),
        domain=ext_data.get("dntdom", ""),
    )


def load_cef_events(log_path: Path) -> list[LogEvent]:
    """Load all events from a CEF file."""
    events: list[LogEvent] = []
    with open(log_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_cef_line(line)
            if event:
                events.append(event)

    events.sort(key=lambda e: e.timestamp)
    return events
