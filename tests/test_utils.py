"""Tests for utility functions."""

from datetime import datetime, timedelta

from threatlens.models import EventCategory, LogEvent, Severity
from threatlens.utils import (
    bold,
    colorize,
    count_by_field,
    format_table,
    group_by_time_window,
    is_private_ip,
    set_no_color,
)


def _make_event(ts: datetime, computer: str = "WS-01") -> LogEvent:
    return LogEvent(
        timestamp=ts,
        event_id=4624,
        source="Security",
        category=EventCategory.AUTHENTICATION,
        computer=computer,
        raw={},
    )


class TestColorize:
    def test_colorize_includes_ansi(self):
        set_no_color(False)
        result = colorize("test", Severity.CRITICAL)
        assert "\033[" in result
        assert "test" in result

    def test_no_color_mode(self):
        set_no_color(True)
        result = colorize("test", Severity.HIGH)
        assert result == "test"
        set_no_color(False)

    def test_bold_includes_ansi(self):
        set_no_color(False)
        result = bold("test")
        assert "\033[1m" in result

    def test_bold_no_color(self):
        set_no_color(True)
        result = bold("test")
        assert result == "test"
        set_no_color(False)


class TestGroupByTimeWindow:
    def test_single_window(self):
        base = datetime(2025, 1, 15, 8, 0, 0)
        events = [_make_event(base + timedelta(seconds=i * 10)) for i in range(5)]
        groups = group_by_time_window(events, window_seconds=300)
        assert len(groups) == 1
        assert len(groups[0]) == 5

    def test_multiple_windows(self):
        base = datetime(2025, 1, 15, 8, 0, 0)
        events = [
            _make_event(base),
            _make_event(base + timedelta(seconds=10)),
            _make_event(base + timedelta(seconds=600)),  # new window
        ]
        groups = group_by_time_window(events, window_seconds=300)
        assert len(groups) == 2

    def test_empty_input(self):
        assert group_by_time_window([]) == []


class TestCountByField:
    def test_counts_computers(self):
        base = datetime(2025, 1, 15, 8, 0, 0)
        events = [
            _make_event(base, "WS-01"),
            _make_event(base, "WS-01"),
            _make_event(base, "WS-02"),
        ]
        counts = count_by_field(events, "computer")
        assert counts["WS-01"] == 2
        assert counts["WS-02"] == 1


class TestIsPrivateIp:
    def test_private_ips(self):
        assert is_private_ip("10.0.1.50") is True
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("127.0.0.1") is True

    def test_public_ips(self):
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.2.3.4") is False

    def test_empty_or_dash(self):
        assert is_private_ip("") is True
        assert is_private_ip("-") is True

    def test_invalid_ip(self):
        assert is_private_ip("not-an-ip") is False


class TestFormatTable:
    def test_basic_table(self):
        headers = ["Name", "Value"]
        rows = [["foo", "bar"], ["baz", "qux"]]
        result = format_table(headers, rows)
        assert "Name" in result
        assert "foo" in result
        assert "+" in result  # separator

    def test_truncation(self):
        headers = ["Data"]
        rows = [["x" * 100]]
        result = format_table(headers, rows, max_width=20)
        assert "..." in result
