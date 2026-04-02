"""Syslog (RFC 3164/5424) and CEF format parser for ThreatLens."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from threatlens.models import EventCategory, LogEvent
from threatlens.parsers.cef_parser import parse_cef_line

# RFC 3164 pattern: <PRI>TIMESTAMP HOSTNAME APP[PID]: MESSAGE
_RFC3164_RE = re.compile(
    r"^(?:<(\d{1,3})>)?"               # optional priority
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(\S+)\s+"                         # hostname
    r"(\S+?)(?:\[(\d+)\])?:\s+"         # app[pid]
    r"(.*)$"                            # message
)

# RFC 5424 pattern: <PRI>VERSION TIMESTAMP HOSTNAME APP PID MSGID MSG
_RFC5424_RE = re.compile(
    r"^<(\d{1,3})>"                     # priority
    r"(\d+)\s+"                         # version
    r"(\S+)\s+"                         # timestamp
    r"(\S+)\s+"                         # hostname
    r"(\S+)\s+"                         # app
    r"(\S+)\s+"                         # procid
    r"(\S+)\s+"                         # msgid
    r"(.*)$"                            # message + structured data
)

# Month abbreviation lookup for manual RFC 3164 timestamp parsing
_MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# Regex for RFC 3164 timestamp: "Jan  5 08:30:01" or "Jan 15 08:30:01"
_RFC3164_TS_RE = re.compile(
    r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$"
)

# Keywords in syslog messages to categorize events
_CATEGORY_KEYWORDS = {
    EventCategory.AUTHENTICATION: [
        "auth", "login", "logon", "logoff", "password", "pam", "sshd",
        "sudo", "su:", "failed", "accepted", "session opened", "session closed",
    ],
    EventCategory.PROCESS: [
        "process", "exec", "command", "started", "stopped", "killed", "fork",
    ],
    EventCategory.NETWORK: [
        "connection", "connect", "listen", "port", "firewall", "iptables",
        "tcp", "udp", "dns",
    ],
    EventCategory.PRIVILEGE: [
        "privilege", "sudo", "root", "admin", "escalat",
    ],
    EventCategory.FILE: [
        "file", "open", "read", "write", "delete", "created", "modified",
    ],
}

# IP address extraction pattern
_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

# Username extraction patterns for common syslog messages
_USER_PATTERNS = [
    re.compile(r"user[= ]+['\"]?(\w+)", re.IGNORECASE),
    re.compile(r"for (?:invalid user )?(\w+)\s+from", re.IGNORECASE),
    re.compile(r"session (?:opened|closed) for user (\w+)", re.IGNORECASE),
    re.compile(r"(?:Accepted|Failed) \S+ for (\w+)\s+from", re.IGNORECASE),
]


def _categorize_message(message: str) -> EventCategory:
    """Determine event category from syslog message content."""
    msg_lower = message.lower()
    for category, keywords in _CATEGORY_KEYWORDS.items():
        if any(kw in msg_lower for kw in keywords):
            return category
    return EventCategory.UNKNOWN


def _extract_ip(message: str) -> str:
    """Extract first IP address from a message."""
    match = _IP_RE.search(message)
    return match.group(1) if match else ""


def _extract_username(message: str) -> str:
    """Extract username from common syslog message patterns."""
    for pattern in _USER_PATTERNS:
        match = pattern.search(message)
        if match:
            return match.group(1)
    return ""


def _parse_syslog_timestamp(ts_str: str) -> datetime:
    """Parse a syslog timestamp, using current year since syslog omits it.

    RFC 3164 timestamps lack a year, so we parse month/day/time manually
    and inject the current year.  This avoids the ``datetime.strptime``
    deprecation warning for year-less format strings (Python 3.12+).
    """
    stripped = ts_str.strip()

    # Try RFC 3164 manual parse first (avoids strptime deprecation)
    m = _RFC3164_TS_RE.match(stripped)
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

    # Try ISO format (RFC 5424)
    clean = re.sub(r"[+-]\d{2}:\d{2}$", "", stripped)
    clean = re.sub(r"Z$", "", clean)
    for fmt in ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
        try:
            return datetime.strptime(clean, fmt)
        except ValueError:
            continue

    return datetime.min


def _parse_rfc3164(line: str) -> LogEvent | None:
    """Parse a RFC 3164 syslog line."""
    match = _RFC3164_RE.match(line)
    if not match:
        return None

    priority, ts_str, hostname, app, pid, message = match.groups()
    timestamp = _parse_syslog_timestamp(ts_str)
    category = _categorize_message(message)

    raw = {
        "priority": int(priority) if priority else 0,
        "hostname": hostname,
        "app": app,
        "pid": pid or "",
        "message": message,
        "format": "rfc3164",
    }

    return LogEvent(
        timestamp=timestamp,
        event_id=int(priority) if priority else 0,
        source=app,
        category=category,
        computer=hostname,
        raw=raw,
        username=_extract_username(message),
        source_ip=_extract_ip(message),
        process_name=app,
        command_line=message,
    )


def _parse_rfc5424(line: str) -> LogEvent | None:
    """Parse a RFC 5424 syslog line."""
    match = _RFC5424_RE.match(line)
    if not match:
        return None

    priority, version, ts_str, hostname, app, procid, msgid, message = match.groups()
    timestamp = _parse_syslog_timestamp(ts_str)
    category = _categorize_message(message)

    raw = {
        "priority": int(priority),
        "version": int(version),
        "hostname": hostname,
        "app": app,
        "procid": procid,
        "msgid": msgid,
        "message": message,
        "format": "rfc5424",
    }

    return LogEvent(
        timestamp=timestamp,
        event_id=int(priority),
        source=app,
        category=category,
        computer=hostname,
        raw=raw,
        username=_extract_username(message),
        source_ip=_extract_ip(message),
        process_name=app,
        command_line=message,
    )


def _parse_cef(line: str) -> LogEvent | None:
    """Parse a CEF (Common Event Format) line.

    Delegates to the dedicated CEF parser to avoid code duplication.
    """
    return parse_cef_line(line)


def _parse_line(line: str, fmt: str) -> LogEvent | None:
    """Parse a single line in the specified format."""
    line = line.strip()
    if not line:
        return None

    if fmt == "cef":
        return _parse_cef(line)

    # Auto-detect between RFC 3164 and 5424
    if line.startswith("<") and len(line) > 3:
        # Check for RFC 5424 (has version number after priority)
        after_pri = re.match(r"<\d{1,3}>(\d+)\s", line)
        if after_pri:
            event = _parse_rfc5424(line)
            if event:
                return event

    # Try RFC 3164
    event = _parse_rfc3164(line)
    if event:
        return event

    # Also try CEF in case it's mixed
    event = _parse_cef(line)
    if event:
        return event

    return None


def load_syslog_events(log_path: Path, fmt: str = "syslog") -> list[LogEvent]:
    """Load all events from a syslog or CEF file."""
    events: list[LogEvent] = []
    with open(log_path, encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, 1):
            try:
                event = _parse_line(line, fmt)
                if event:
                    events.append(event)
            except Exception:
                logging.getLogger("threatlens").warning(
                    "Skipping malformed line %d: %s%s",
                    line_num, line[:80].strip(), "..." if len(line) > 80 else "",
                )

    events.sort(key=lambda e: e.timestamp)
    return events


def stream_syslog_events(log_path: Path, fmt: str = "syslog") -> Iterator[LogEvent]:
    """Stream events from a syslog or CEF file."""
    with open(log_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                event = _parse_line(line, fmt)
                if event:
                    yield event
            except Exception:
                continue
