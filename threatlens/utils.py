"""Shared utility functions for ThreatLens."""

from __future__ import annotations

import ipaddress
from collections import Counter
from collections.abc import Sequence

from threatlens.models import LogEvent, Severity

# Terminal color helpers (ANSI)
COLORS = {
    Severity.CRITICAL: "\033[91m",  # Red
    Severity.HIGH: "\033[93m",      # Yellow
    Severity.MEDIUM: "\033[96m",    # Cyan
    Severity.LOW: "\033[92m",       # Green
}
RESET = "\033[0m"
BOLD = "\033[1m"

# Global flag; set to True to suppress all ANSI escapes
_no_color = False


def set_no_color(enabled: bool) -> None:
    global _no_color
    _no_color = enabled


def colorize(text: str, severity: Severity) -> str:
    if _no_color:
        return text
    return f"{COLORS.get(severity, '')}{text}{RESET}"


def bold(text: str) -> str:
    if _no_color:
        return text
    return f"{BOLD}{text}{RESET}"


def group_by_time_window(
    events: Sequence[LogEvent],
    window_seconds: int = 300,
) -> list[list[LogEvent]]:
    """Group events into time windows of the given size."""
    if not events:
        return []

    groups: list[list[LogEvent]] = []
    current_group: list[LogEvent] = [events[0]]

    for event in events[1:]:
        if (event.timestamp - current_group[0].timestamp).total_seconds() <= window_seconds:
            current_group.append(event)
        else:
            groups.append(current_group)
            current_group = [event]

    groups.append(current_group)
    return groups


def count_by_field(events: Sequence[LogEvent], field: str) -> Counter:
    """Count occurrences of a specific field value across events."""
    return Counter(getattr(e, field, "") for e in events if getattr(e, field, ""))


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    if not ip or ip == "-":
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved
    except ValueError:
        return False


def format_table(headers: list[str], rows: list[list[str]], max_width: int = 40) -> str:
    """Format data as a simple ASCII table."""
    def truncate(val: str) -> str:
        return (val[:max_width - 3] + "...") if len(val) > max_width else val

    truncated_rows = [[truncate(str(cell)) for cell in row] for row in rows]

    col_widths = [len(h) for h in headers]
    for row in truncated_rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(cell))

    separator = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"

    def format_row(cells: list[str]) -> str:
        padded = [cell.ljust(col_widths[i]) for i, cell in enumerate(cells)]
        return "| " + " | ".join(padded) + " |"

    lines = [separator, format_row(headers), separator]
    for row in truncated_rows:
        lines.append(format_row(row))
    lines.append(separator)
    return "\n".join(lines)
