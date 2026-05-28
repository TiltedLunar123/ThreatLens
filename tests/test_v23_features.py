"""Tests for v2.3.0 additions: markdown output, --exclude, summary, DNS detector."""

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from threatlens.cli import build_parser, run_scan, run_summary
from threatlens.config import _build_detectors
from threatlens.detections.dns_exfiltration import (
    DnsExfiltrationDetector,
    _shannon_entropy,
)
from threatlens.models import Alert, EventCategory, LogEvent, Severity
from threatlens.outputs.markdown import export_markdown


def _alerts() -> list[Alert]:
    return [
        Alert(
            rule_name="Critical Thing",
            severity=Severity.CRITICAL,
            description="A critical | pipe | with chars",
            timestamp=datetime(2025, 1, 15, 8, 30, 0),
            mitre_tactic="Execution",
            mitre_technique="T1059",
            recommendation="Investigate immediately",
            evidence=[{"username": "admin", "host": "DC-01"}],
        ),
        Alert(
            rule_name="Low Thing",
            severity=Severity.LOW,
            description="benign",
            timestamp=datetime(2025, 1, 15, 9, 0, 0),
        ),
    ]


class TestMarkdownExport:
    def test_export_contains_summary_and_alerts(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            out = Path(f.name)
        export_markdown(_alerts(), out, total_events=42, elapsed=0.5)
        content = out.read_text(encoding="utf-8")
        assert "# ThreatLens Report" in content
        assert "Critical Thing" in content
        assert "Low Thing" in content
        assert "T1059" in content
        assert "Investigate immediately" in content
        # Pipe chars in description should be escaped to avoid breaking the
        # markdown table.
        assert "\\|" in content

    def test_export_empty(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            out = Path(f.name)
        export_markdown([], out, total_events=0)
        content = out.read_text(encoding="utf-8")
        assert "Clean scan" in content

    def test_no_em_dashes_in_output(self):
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            out = Path(f.name)
        export_markdown(_alerts(), out, total_events=10)
        content = out.read_text(encoding="utf-8")
        assert "—" not in content
        assert "&mdash;" not in content

    def test_scan_with_md_format_smoke(self):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            out = f.name
        parser = build_parser()
        args = parser.parse_args(
            ["scan", str(sample), "--quiet", "-o", out, "-f", "md"]
        )
        run_scan(args)
        content = Path(out).read_text(encoding="utf-8")
        assert "# ThreatLens Report" in content
        assert "## Summary" in content


class TestExcludeFlag:
    def test_exclude_removes_detector_by_class_name(self):
        parser = build_parser()
        args = parser.parse_args(
            ["scan", "x.json", "--exclude", "BruteForceDetector"]
        )
        detectors = _build_detectors(args, {})
        names = {type(d).__name__ for d in detectors}
        assert "BruteForceDetector" not in names

    def test_exclude_removes_detector_by_display_name_substring(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "x.json", "--exclude", "brute"])
        detectors = _build_detectors(args, {})
        names = {type(d).__name__ for d in detectors}
        assert "BruteForceDetector" not in names

    def test_multiple_excludes(self):
        parser = build_parser()
        args = parser.parse_args([
            "scan", "x.json",
            "--exclude", "brute",
            "--exclude", "LateralMovementDetector",
        ])
        detectors = _build_detectors(args, {})
        names = {type(d).__name__ for d in detectors}
        assert "BruteForceDetector" not in names
        assert "LateralMovementDetector" not in names

    def test_exclude_keeps_other_detectors(self):
        parser = build_parser()
        args = parser.parse_args(
            ["scan", "x.json", "--exclude", "BruteForceDetector"]
        )
        detectors = _build_detectors(args, {})
        # Should still have several built-ins left.
        assert len(detectors) >= 5

    def test_no_exclude_keeps_all(self):
        parser = build_parser()
        args_default = parser.parse_args(["scan", "x.json"])
        args_excluded = parser.parse_args(
            ["scan", "x.json", "--exclude", "Brute"]
        )
        assert len(_build_detectors(args_default, {})) > len(
            _build_detectors(args_excluded, {})
        )


class TestSummaryCommand:
    def test_summary_prints_breakdown(self, capsys):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = f.name
        parser = build_parser()
        args = parser.parse_args(
            ["scan", str(sample), "--quiet", "-o", out, "-f", "json"]
        )
        run_scan(args)
        # Now run the summary subcommand
        summary_args = parser.parse_args(["summary", out])
        result = run_summary(summary_args)
        assert result == 0
        captured = capsys.readouterr().out
        assert "Severity breakdown" in captured
        assert "CRITICAL" in captured
        assert "Top rules" in captured

    def test_summary_missing_file(self):
        parser = build_parser()
        args = parser.parse_args(["summary", "/nonexistent/report.json"])
        result = run_summary(args)
        assert result == 1

    def test_summary_malformed_json(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write("{not valid json")
            f.flush()
            parser = build_parser()
            args = parser.parse_args(["summary", f.name])
            result = run_summary(args)
        assert result == 1

    def test_main_routes_to_summary(self):
        from threatlens.cli import main
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write(json.dumps({
                "report_metadata": {
                    "tool": "ThreatLens",
                    "version": "test",
                    "total_events_analyzed": 100,
                    "total_alerts": 1,
                },
                "severity_summary": {"critical": 0, "high": 1, "medium": 0, "low": 0},
                "alerts": [{"rule_name": "Test", "severity": "high"}],
            }))
            f.flush()
            with patch("sys.argv", ["threatlens", "summary", f.name]):
                result = main()
        assert result == 0


class TestDnsExfiltrationDetector:
    def _dns_event(
        self,
        ts: datetime,
        query: str,
        computer: str = "WS-01",
    ) -> LogEvent:
        return LogEvent(
            timestamp=ts,
            event_id=22,
            source="Sysmon",
            category=EventCategory.NETWORK,
            computer=computer,
            raw={"QueryName": query},
        )

    def test_shannon_entropy(self):
        assert _shannon_entropy("") == 0.0
        # Uniform 16-char hex string should be > 3 bits of entropy
        assert _shannon_entropy("0123456789abcdef") > 3.0
        # Lowercase a*N has 0 entropy
        assert _shannon_entropy("aaaaaaaa") == 0.0

    def test_detects_high_entropy_burst(self):
        base = datetime(2025, 1, 15, 8, 0, 0)
        events = [
            self._dns_event(
                base + timedelta(seconds=i),
                f"{('abcdef0123456789' * 3)[i:i+30]}.exfil.example.com",
            )
            for i in range(30)
        ]
        det = DnsExfiltrationDetector()
        alerts = det.analyze(events)
        assert len(alerts) >= 1
        assert "DNS Exfiltration" in alerts[0].rule_name
        assert alerts[0].severity in (Severity.HIGH, Severity.CRITICAL)

    def test_ignores_normal_queries(self):
        base = datetime(2025, 1, 15, 8, 0, 0)
        events = [
            self._dns_event(base + timedelta(seconds=i), "www.google.com")
            for i in range(50)
        ]
        det = DnsExfiltrationDetector()
        alerts = det.analyze(events)
        assert alerts == []

    def test_ignores_non_dns_event_ids(self):
        base = datetime(2025, 1, 15, 8, 0, 0)
        events = []
        for i in range(30):
            ev = self._dns_event(
                base + timedelta(seconds=i),
                "abcdef0123456789xyzabcdef.exfil.example.com",
            )
            ev.event_id = 4624  # not a DNS event id
            events.append(ev)
        det = DnsExfiltrationDetector()
        alerts = det.analyze(events)
        assert alerts == []

    def test_threshold_below_minimum_no_alert(self):
        base = datetime(2025, 1, 15, 8, 0, 0)
        events = [
            self._dns_event(
                base + timedelta(seconds=i),
                f"abcdef0123456789xyzabcdef{i:03d}.exfil.example.com",
            )
            for i in range(5)
        ]
        det = DnsExfiltrationDetector()
        alerts = det.analyze(events)
        assert alerts == []

    def test_listed_in_run_rules(self, capsys):
        from threatlens.cli import run_rules
        run_rules()
        out = capsys.readouterr().out
        assert "DNS Exfiltration" in out


class TestFindDenseWindowsSlidingWindow:
    """Validate the O(n) sliding-window implementation."""

    def _ev(self, ts: datetime) -> LogEvent:
        return LogEvent(
            timestamp=ts,
            event_id=4625,
            source="Security",
            category=EventCategory.AUTHENTICATION,
            computer="WS-01",
            raw={},
        )

    def test_returns_non_overlapping_windows(self):
        from threatlens.utils import find_dense_windows
        base = datetime(2025, 1, 15, 8, 0, 0)
        # Two distinct bursts separated by a gap.
        events = (
            [self._ev(base + timedelta(seconds=i)) for i in range(6)]
            + [self._ev(base + timedelta(seconds=400 + i)) for i in range(6)]
        )
        windows = find_dense_windows(events, window_seconds=60, min_count=5)
        assert len(windows) == 2
        assert {len(w) for w in windows} == {6}

    def test_handles_large_input_quickly(self):
        from threatlens.utils import find_dense_windows
        base = datetime(2025, 1, 15, 8, 0, 0)
        # 5000 events all within window. Old O(n^2) impl spent ~25M ops.
        events = [self._ev(base + timedelta(seconds=i * 0.01)) for i in range(5000)]
        windows = find_dense_windows(events, window_seconds=60, min_count=5)
        # Exactly one big burst is expected.
        assert len(windows) >= 1
        assert sum(len(w) for w in windows) == 5000

    def test_empty(self):
        from threatlens.utils import find_dense_windows
        assert find_dense_windows([], 60, 5) == []

    def test_below_threshold(self):
        from threatlens.utils import find_dense_windows
        base = datetime(2025, 1, 15, 8, 0, 0)
        events = [self._ev(base + timedelta(seconds=i)) for i in range(3)]
        assert find_dense_windows(events, 60, 5) == []
