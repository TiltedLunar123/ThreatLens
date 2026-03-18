"""Tests for log parsers: JSON, syslog/CEF, format detection, streaming."""

import tempfile
from pathlib import Path

import pytest

from threatlens.models import EventCategory, LogEvent
from threatlens.parsers import detect_format, load_events, stream_events
from threatlens.parsers.json_parser import (
    classify_event,
    load_json_events,
    parse_event,
    parse_timestamp,
    stream_json_events,
)


class TestTimestampParsing:
    def test_iso_utc(self):
        ts = parse_timestamp("2025-01-15T08:30:01Z")
        assert ts.year == 2025
        assert ts.hour == 8

    def test_iso_fractional(self):
        ts = parse_timestamp("2025-01-15T08:30:01.123456Z")
        assert ts.microsecond == 123456

    def test_iso_no_z(self):
        ts = parse_timestamp("2025-01-15T08:30:01")
        assert ts.year == 2025

    def test_date_space_time(self):
        ts = parse_timestamp("2025-01-15 08:30:01")
        assert ts.hour == 8

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_timestamp("not-a-timestamp")


class TestClassifyEvent:
    def test_known_ids(self):
        assert classify_event(4625) == EventCategory.AUTHENTICATION
        assert classify_event(4688) == EventCategory.PROCESS
        assert classify_event(4672) == EventCategory.PRIVILEGE
        assert classify_event(5156) == EventCategory.NETWORK
        assert classify_event(4663) == EventCategory.FILE
        assert classify_event(13) == EventCategory.REGISTRY

    def test_unknown_id(self):
        assert classify_event(99999) == EventCategory.UNKNOWN


class TestJsonParser:
    def test_parse_event_basic(self):
        raw = {
            "TimeCreated": "2025-01-15T08:30:01Z",
            "EventID": 4625,
            "Source": "Security",
            "Computer": "WS-PC01",
            "EventData": {
                "TargetUserName": "admin",
                "IpAddress": "10.0.1.50",
                "LogonType": 3,
            },
        }
        event = parse_event(raw)
        assert event.event_id == 4625
        assert event.target_username == "admin"
        assert event.source_ip == "10.0.1.50"

    def test_parse_event_missing_timestamp(self):
        raw = {"EventID": 4624}
        event = parse_event(raw)
        assert event.event_id == 4624
        # Should not crash; timestamp defaults to min

    def test_load_sample_data(self):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if sample.exists():
            events = load_events(sample)
            assert len(events) > 0
            assert all(isinstance(e, LogEvent) for e in events)

    def test_load_ndjson(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ndjson", delete=False, encoding="utf-8"
        ) as f:
            f.write('{"EventID": 4624, "TimeCreated": "2025-01-15T08:30:01Z", "Computer": "WS-01"}\n')
            f.write('{"EventID": 4625, "TimeCreated": "2025-01-15T08:30:05Z", "Computer": "WS-01"}\n')
            f.flush()
            events = load_json_events(Path(f.name))

        assert len(events) == 2
        assert events[0].event_id == 4624

    def test_ndjson_with_malformed_line(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ndjson", delete=False, encoding="utf-8"
        ) as f:
            f.write('{"EventID": 4624, "TimeCreated": "2025-01-15T08:30:01Z"}\n')
            f.write('not valid json\n')
            f.write('{"EventID": 4625, "TimeCreated": "2025-01-15T08:30:05Z"}\n')
            f.flush()
            events = load_json_events(Path(f.name))

        assert len(events) == 2  # malformed line skipped

    def test_stream_json_array(self):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if sample.exists():
            events = list(stream_json_events(sample))
            assert len(events) > 0

    def test_stream_ndjson(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".ndjson", delete=False, encoding="utf-8"
        ) as f:
            f.write('{"EventID": 4624, "TimeCreated": "2025-01-15T08:30:01Z"}\n')
            f.write('{"EventID": 4625, "TimeCreated": "2025-01-15T08:30:05Z"}\n')
            f.flush()
            events = list(stream_json_events(Path(f.name)))

        assert len(events) == 2


class TestFormatDetection:
    def test_json_extensions(self):
        assert detect_format(Path("test.json")) == "json"
        assert detect_format(Path("test.ndjson")) == "json"
        assert detect_format(Path("test.jsonl")) == "json"

    def test_evtx(self):
        assert detect_format(Path("test.evtx")) == "evtx"

    def test_syslog(self):
        assert detect_format(Path("test.log")) == "syslog"
        assert detect_format(Path("test.syslog")) == "syslog"

    def test_cef(self):
        assert detect_format(Path("test.cef")) == "cef"

    def test_forced_override(self):
        assert detect_format(Path("test.json"), forced_format="syslog") == "syslog"

    def test_unknown_extension_defaults_json(self):
        assert detect_format(Path("test.txt")) == "json"


class TestStreamEvents:
    def test_stream_json(self):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if sample.exists():
            events = list(stream_events(sample, "json"))
            assert len(events) > 0

    def test_stream_syslog(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "<34>Jan 15 08:30:01 server01 sshd[1234]: "
                "Failed password for admin from 10.0.1.50 port 22 ssh2\n"
            )
            f.flush()
            events = list(stream_events(Path(f.name), "syslog"))

        assert len(events) == 1

    def test_stream_evtx_route(self):
        """Verify stream_events routes evtx format through the evtx parser."""
        from unittest.mock import MagicMock, patch

        mock_gen = MagicMock(return_value=iter([]))
        with patch("threatlens.parsers.evtx_parser.stream_evtx_events", mock_gen):
            list(stream_events(Path("fake.evtx"), "evtx"))
        mock_gen.assert_called_once()


class TestLoadEventsRouting:
    def test_load_evtx_route(self):
        from unittest.mock import MagicMock, patch

        mock_load = MagicMock(return_value=[])
        with patch("threatlens.parsers.evtx_parser.load_evtx_events", mock_load):
            load_events(Path("fake.evtx"), "evtx")
        mock_load.assert_called_once()

    def test_load_syslog_route(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "<34>Jan 15 08:30:01 server01 sshd[1234]: "
                "test message\n"
            )
            f.flush()
            events = load_events(Path(f.name), "syslog")
        assert len(events) == 1

    def test_load_cef_route(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cef", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "CEF:0|Vendor|Product|1.0|100|Alert|5|src=10.0.0.1\n"
            )
            f.flush()
            events = load_events(Path(f.name), "cef")
        assert len(events) == 1


class TestSyslogParser:
    def test_rfc3164(self):
        from threatlens.parsers.syslog_parser import load_syslog_events

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "<34>Jan 15 08:30:01 server01 sshd[1234]: "
                "Failed password for admin from 10.0.1.50 port 22 ssh2\n"
            )
            f.write(
                "<34>Jan 15 08:30:05 server01 sshd[1234]: "
                "Accepted password for jdoe from 10.0.1.10 port 22 ssh2\n"
            )
            f.flush()
            events = load_syslog_events(Path(f.name))

        assert len(events) == 2
        assert events[0].source_ip == "10.0.1.50"
        assert events[0].category == EventCategory.AUTHENTICATION

    def test_cef(self):
        from threatlens.parsers.syslog_parser import load_syslog_events

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cef", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "CEF:0|Security|IDS|1.0|100|Intrusion Detected|7|"
                "src=10.0.1.50 duser=admin dhost=server01\n"
            )
            f.flush()
            events = load_syslog_events(Path(f.name), "cef")

        assert len(events) == 1
        assert events[0].source_ip == "10.0.1.50"
        assert events[0].username == "admin"

    def test_rfc3164_no_deprecation_warning(self):
        """Ensure the year-less timestamp path uses manual parsing, not strptime."""
        import warnings

        from threatlens.parsers.syslog_parser import _parse_syslog_timestamp

        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            dt = _parse_syslog_timestamp("Jan 15 08:30:01")

        assert dt.month == 1
        assert dt.day == 15
        assert dt.hour == 8

    def test_rfc5424_iso_timestamp(self):
        from threatlens.parsers.syslog_parser import _parse_syslog_timestamp

        dt = _parse_syslog_timestamp("2025-01-15T08:30:01.000Z")
        assert dt.year == 2025
        assert dt.hour == 8

    def test_syslog_username_extraction(self):
        from threatlens.parsers.syslog_parser import _extract_username

        assert _extract_username("Failed password for admin from 10.0.1.50") == "admin"
        assert _extract_username("Accepted password for jdoe from 10.0.1.10") == "jdoe"
        assert _extract_username("session opened for user root") == "root"

    def test_syslog_ip_extraction(self):
        from threatlens.parsers.syslog_parser import _extract_ip

        assert _extract_ip("Failed password from 10.0.1.50 port 22") == "10.0.1.50"
        assert _extract_ip("no ip here") == ""

    def test_categorize_message(self):
        from threatlens.parsers.syslog_parser import _categorize_message

        assert _categorize_message("Failed password for admin") == EventCategory.AUTHENTICATION
        assert _categorize_message("process started") == EventCategory.PROCESS
        assert _categorize_message("firewall rule added") == EventCategory.NETWORK
        assert _categorize_message("nothing special") == EventCategory.UNKNOWN

    def test_extract_username_no_match(self):
        from threatlens.parsers.syslog_parser import _extract_username

        assert _extract_username("something with no username patterns") == ""

    def test_parse_syslog_timestamp_iso_with_tz(self):
        from threatlens.parsers.syslog_parser import _parse_syslog_timestamp

        dt = _parse_syslog_timestamp("2025-01-15T08:30:01+05:00")
        assert dt.year == 2025
        assert dt.hour == 8

    def test_parse_syslog_timestamp_iso_no_fractional(self):
        from threatlens.parsers.syslog_parser import _parse_syslog_timestamp

        dt = _parse_syslog_timestamp("2025-01-15T08:30:01")
        assert dt.year == 2025

    def test_parse_syslog_timestamp_space_format(self):
        from threatlens.parsers.syslog_parser import _parse_syslog_timestamp

        dt = _parse_syslog_timestamp("2025-01-15 08:30:01")
        assert dt.year == 2025

    def test_parse_syslog_timestamp_invalid(self):
        from datetime import datetime as dt_cls

        from threatlens.parsers.syslog_parser import _parse_syslog_timestamp

        dt = _parse_syslog_timestamp("not-a-timestamp")
        assert dt == dt_cls.min

    def test_rfc3164_no_match(self):
        from threatlens.parsers.syslog_parser import _parse_rfc3164

        result = _parse_rfc3164("this is not a syslog line")
        assert result is None

    def test_rfc5424_full_parse(self):
        from threatlens.parsers.syslog_parser import load_syslog_events

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "<165>1 2025-01-15T08:30:01Z server01 sshd 1234 ID47 "
                "Failed password for admin from 10.0.1.50 port 22\n"
            )
            f.flush()
            events = load_syslog_events(Path(f.name))

        assert len(events) == 1
        assert events[0].computer == "server01"
        assert events[0].source == "sshd"

    def test_rfc5424_no_match(self):
        from threatlens.parsers.syslog_parser import _parse_rfc5424

        result = _parse_rfc5424("this is not rfc5424")
        assert result is None

    def test_cef_no_cef_marker(self):
        from threatlens.parsers.syslog_parser import _parse_cef

        result = _parse_cef("no cef marker here")
        assert result is None

    def test_cef_invalid_after_marker(self):
        from threatlens.parsers.syslog_parser import _parse_cef

        result = _parse_cef("CEF:broken format no pipes")
        assert result is None

    def test_cef_hostname_from_extension(self):
        from threatlens.parsers.syslog_parser import _parse_cef

        line = (
            "Jan 15 08:30:01 firewall01 "
            "CEF:0|Vendor|Product|1.0|100|Alert|5|src=10.0.0.1 dhost=firewall01"
        )
        event = _parse_cef(line)
        assert event is not None
        assert event.computer == "firewall01"

    def test_cef_hostname_from_syslog_header_fallback(self):
        from threatlens.parsers.syslog_parser import _parse_cef

        # No dhost/shost in extension, so hostname comes from syslog header parts[1]
        line = (
            "host01 firewall01 "
            "CEF:0|Vendor|Product|1.0|100|Alert|5|src=10.0.0.1"
        )
        event = _parse_cef(line)
        assert event is not None
        assert event.computer == "firewall01"

    def test_cef_timestamp_from_syslog_header(self):
        from threatlens.parsers.syslog_parser import _parse_cef

        line = (
            "Jan 15 08:30:01 firewall01 "
            "CEF:0|Vendor|Product|1.0|100|Alert|5|src=10.0.0.1"
        )
        event = _parse_cef(line)
        assert event is not None
        assert event.timestamp.month == 1
        assert event.timestamp.day == 15

    def test_cef_non_integer_sig_id(self):
        from threatlens.parsers.syslog_parser import _parse_cef

        line = "CEF:0|Vendor|Product|1.0|NOT_INT|Alert|5|src=10.0.0.1"
        event = _parse_cef(line)
        assert event is not None
        assert event.event_id == 0

    def test_parse_line_empty(self):
        from threatlens.parsers.syslog_parser import _parse_line

        result = _parse_line("", "syslog")
        assert result is None

    def test_parse_line_rfc5424_auto_detect(self):
        from threatlens.parsers.syslog_parser import _parse_line

        line = (
            "<165>1 2025-01-15T08:30:01Z server01 sshd 1234 ID47 "
            "Failed password for admin from 10.0.1.50"
        )
        result = _parse_line(line, "syslog")
        assert result is not None
        assert result.computer == "server01"

    def test_parse_line_cef_fallback_in_syslog_mode(self):
        from threatlens.parsers.syslog_parser import _parse_line

        line = "CEF:0|Vendor|Product|1.0|100|Alert|5|src=10.0.0.1"
        result = _parse_line(line, "syslog")
        assert result is not None
        assert result.source_ip == "10.0.0.1"

    def test_parse_line_unparseable(self):
        from threatlens.parsers.syslog_parser import _parse_line

        result = _parse_line("random garbage line", "syslog")
        assert result is None

    def test_load_syslog_malformed_line(self):
        from unittest.mock import patch

        from threatlens.parsers.syslog_parser import load_syslog_events

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "<34>Jan 15 08:30:01 server01 sshd[1234]: Normal message\n"
            )
            f.flush()
            path = Path(f.name)

        # Force _parse_line to raise on one call
        original_parse = __import__("threatlens.parsers.syslog_parser", fromlist=["_parse_line"])._parse_line
        call_count = [0]

        def flaky_parse(line, fmt):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("simulated parse error")
            return original_parse(line, fmt)

        with patch("threatlens.parsers.syslog_parser._parse_line", side_effect=flaky_parse):
            events = load_syslog_events(path)
        # The exception line is skipped
        assert isinstance(events, list)

    def test_stream_syslog_malformed_line(self):
        from unittest.mock import patch

        from threatlens.parsers.syslog_parser import stream_syslog_events

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "<34>Jan 15 08:30:01 server01 sshd[1234]: Normal message\n"
                "<34>Jan 15 08:30:02 server01 sshd[1234]: Another message\n"
            )
            f.flush()
            path = Path(f.name)

        original_parse = __import__("threatlens.parsers.syslog_parser", fromlist=["_parse_line"])._parse_line
        call_count = [0]

        def flaky_parse(line, fmt):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("simulated error")
            return original_parse(line, fmt)

        with patch("threatlens.parsers.syslog_parser._parse_line", side_effect=flaky_parse):
            events = list(stream_syslog_events(path))
        # First line errored, second should parse
        assert len(events) == 1
