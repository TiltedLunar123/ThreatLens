"""Tests for follow (real-time tailing) functionality."""

import tempfile
from datetime import datetime, timedelta
from unittest.mock import patch

from tests.conftest import make_failed_logon
from threatlens.follower import _flush_follow_buffer
from threatlens.models import Alert, Severity


class StaticDetector:
    name = "Static"

    def __init__(self, alerts):
        self.alerts = alerts

    def analyze(self, events):
        return self.alerts


class TestFlushFollowBuffer:
    def test_flush_prints_alerts(self, capsys):
        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, i)) for i in range(6)]
        from threatlens.detections.brute_force import BruteForceDetector
        detectors = [BruteForceDetector()]
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        seen: set = set()
        _flush_follow_buffer(events, detectors, severity_order, 0, seen)
        output = capsys.readouterr().out
        assert "Brute-Force" in output or "MEDIUM" in output

    def test_flush_deduplicates(self, capsys):
        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, i)) for i in range(6)]
        from threatlens.detections.brute_force import BruteForceDetector
        detectors = [BruteForceDetector()]
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        seen: set = set()
        _flush_follow_buffer(events, detectors, severity_order, 0, seen)
        first_output = capsys.readouterr().out

        # Second flush with same events should produce no new output
        _flush_follow_buffer(events, detectors, severity_order, 0, seen)
        second_output = capsys.readouterr().out
        assert len(second_output) < len(first_output) or second_output == ""

    def test_flush_respects_min_severity(self, capsys):
        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, i)) for i in range(6)]
        from threatlens.detections.brute_force import BruteForceDetector
        detectors = [BruteForceDetector()]
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        seen: set = set()
        # min_index=3 means only CRITICAL
        _flush_follow_buffer(events, detectors, severity_order, 3, seen)
        output = capsys.readouterr().out
        assert "Brute-Force" not in output

    def test_flush_handles_broken_detector(self, capsys):
        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, 0))]

        class BrokenDetector:
            name = "Broken"
            def analyze(self, events):
                raise RuntimeError("boom")

        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        seen: set = set()
        # Should not raise
        _flush_follow_buffer(events, [BrokenDetector()], severity_order, 0, seen)

    def test_flush_keeps_distinct_alerts_from_same_rule_and_second(self, capsys):
        timestamp = datetime(2025, 1, 15, 8, 30, 0)
        alerts = [
            Alert(
                rule_name="Repeated Login Failures",
                severity=Severity.MEDIUM,
                description="Repeated login failures",
                timestamp=timestamp,
                evidence=[{"timestamp": timestamp.isoformat(), "source_ip": "10.0.1.50"}],
            ),
            Alert(
                rule_name="Repeated Login Failures",
                severity=Severity.MEDIUM,
                description="Repeated login failures",
                timestamp=timestamp,
                evidence=[{"timestamp": timestamp.isoformat(), "source_ip": "10.0.1.51"}],
            ),
        ]
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        seen: set = set()

        _flush_follow_buffer([], [StaticDetector(alerts)], severity_order, 0, seen)

        output = capsys.readouterr().out
        assert "10.0.1.50" in output
        assert "10.0.1.51" in output

    def test_flush_deduplicates_same_alert_with_different_second(self, capsys):
        timestamp = datetime(2025, 1, 15, 8, 30, 0)
        repeated_timestamp = timestamp + timedelta(seconds=1)
        base_alert = Alert(
            rule_name="Repeated Login Failures",
            severity=Severity.MEDIUM,
            description="5 failed logons from 10.0.1.50",
            timestamp=timestamp,
            evidence=[{"timestamp": timestamp.isoformat(), "source_ip": "10.0.1.50"}],
        )
        repeated_alert = Alert(
            rule_name="Repeated Login Failures",
            severity=Severity.MEDIUM,
            description="5 failed logons from 10.0.1.50",
            timestamp=repeated_timestamp,
            evidence=[{"timestamp": repeated_timestamp.isoformat(), "source_ip": "10.0.1.50"}],
        )
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        seen: set = set()

        _flush_follow_buffer([], [StaticDetector([base_alert])], severity_order, 0, seen)
        first_output = capsys.readouterr().out
        _flush_follow_buffer([], [StaticDetector([repeated_alert])], severity_order, 0, seen)
        second_output = capsys.readouterr().out

        assert "10.0.1.50" in first_output
        assert second_output == ""


class TestFollowWithMockAppends:
    def test_follow_mock_file_append(self, capsys):
        """Test follow with a mock file that simulates appended lines."""
        import json

        from threatlens.cli import build_parser
        from threatlens.follower import run_follow

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            # Write some initial content
            f.write(json.dumps({
                "EventID": 4625,
                "TimeCreated": "2025-01-15T08:30:01Z",
                "Computer": "WS-PC01",
                "EventData": {
                    "TargetUserName": "admin",
                    "IpAddress": "10.0.1.50",
                    "LogonType": 3,
                },
            }) + "\n")
            f.flush()
            tmppath = f.name

        parser = build_parser()
        args = parser.parse_args(["follow", tmppath])

        # Mock the file reading to raise KeyboardInterrupt quickly
        original_open = open
        call_count = [0]

        class FakeFile:
            def __init__(self, *a, **kw):
                self._real = original_open(*a, **kw)

            def read(self, *a, **kw):
                return self._real.read(*a, **kw)

            def seek(self, *a):
                return self._real.seek(*a)

            def readline(self):
                call_count[0] += 1
                if call_count[0] > 2:
                    raise KeyboardInterrupt()
                return ""

            def __enter__(self):
                return self

            def __exit__(self, *a):
                self._real.close()

        def selective_open(*a, **kw):
            path_arg = str(a[0]) if a else ""
            norm_tmp = tmppath.replace("\\", "/")
            norm_arg = path_arg.replace("\\", "/")
            if norm_tmp in norm_arg or norm_arg == norm_tmp:
                return FakeFile(*a, **kw)
            return original_open(*a, **kw)

        with patch("builtins.open", selective_open):
            result = run_follow(args)
        assert result == 0
        output = capsys.readouterr().out
        assert "Stopped" in output
