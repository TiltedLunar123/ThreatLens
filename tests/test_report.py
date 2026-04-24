"""Tests for report generation (terminal output, JSON/CSV export)."""

import json
import tempfile
from datetime import datetime
from pathlib import Path

from threatlens.models import Alert, Severity
from threatlens.report import (
    export_csv,
    export_json,
    print_alerts,
    print_banner,
    print_summary,
)


def _sample_alerts() -> list[Alert]:
    return [
        Alert(
            rule_name="Brute-Force Detected",
            severity=Severity.HIGH,
            description="7 failed logons from 10.0.1.50",
            timestamp=datetime(2025, 1, 15, 8, 30, 0),
            mitre_tactic="Credential Access",
            mitre_technique="T1110",
            recommendation="Block the IP",
            evidence=[
                {"timestamp": "2025-01-15 08:30:00", "source_ip": "10.0.1.50", "username": "admin"},
            ],
        ),
        Alert(
            rule_name="SAM Dump",
            severity=Severity.CRITICAL,
            description="reg save HKLM\\SAM",
            timestamp=datetime(2025, 1, 15, 9, 15, 0),
            mitre_tactic="Credential Access",
            mitre_technique="T1003.002",
        ),
        Alert(
            rule_name="Priv Enum",
            severity=Severity.LOW,
            description="whoami /priv",
            timestamp=datetime(2025, 1, 15, 10, 0, 0),
        ),
    ]


class TestPrintBanner:
    def test_banner_outputs(self, capsys):
        print_banner()
        output = capsys.readouterr().out
        assert "Threat Hunting" in output
        from threatlens import __version__
        assert f"v{__version__}" in output


class TestPrintSummary:
    def test_summary_shows_counts(self, capsys):
        alerts = _sample_alerts()
        print_summary(alerts, total_events=100, elapsed=0.5)
        output = capsys.readouterr().out
        assert "100" in output
        assert "3" in output  # total alerts
        assert "CRITICAL" in output
        assert "HIGH" in output


class TestPrintAlerts:
    def test_alerts_sorted_by_severity(self, capsys):
        alerts = _sample_alerts()
        print_alerts(alerts)
        output = capsys.readouterr().out
        # CRITICAL should appear before HIGH
        crit_pos = output.index("CRITICAL")
        high_pos = output.index("HIGH")
        assert crit_pos < high_pos

    def test_verbose_shows_evidence(self, capsys):
        alerts = _sample_alerts()
        print_alerts(alerts, verbose=True)
        output = capsys.readouterr().out
        assert "Evidence" in output
        assert "source_ip" in output

    def test_no_alerts_message(self, capsys):
        print_alerts([])
        output = capsys.readouterr().out
        assert "No threats detected" in output

    def test_mitre_shown_when_present(self, capsys):
        alerts = _sample_alerts()
        print_alerts(alerts)
        output = capsys.readouterr().out
        assert "T1110" in output

    def test_recommendation_shown(self, capsys):
        alerts = _sample_alerts()
        print_alerts(alerts)
        output = capsys.readouterr().out
        assert "Block the IP" in output


class TestExportJson:
    def test_json_structure(self):
        alerts = _sample_alerts()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = Path(f.name)
        export_json(alerts, out, total_events=100)

        report = json.loads(out.read_text(encoding="utf-8"))
        assert report["report_metadata"]["tool"] == "ThreatLens"
        assert report["report_metadata"]["total_events_analyzed"] == 100
        assert report["report_metadata"]["total_alerts"] == 3
        assert report["severity_summary"]["critical"] == 1
        assert report["severity_summary"]["high"] == 1
        assert len(report["alerts"]) == 3

    def test_json_empty_alerts(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = Path(f.name)
        export_json([], out, total_events=0)

        report = json.loads(out.read_text(encoding="utf-8"))
        assert report["report_metadata"]["total_alerts"] == 0
        assert report["alerts"] == []


class TestExportCsv:
    def test_csv_has_headers_and_rows(self):
        alerts = _sample_alerts()
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            out = Path(f.name)
        export_csv(alerts, out, total_events=100)

        content = out.read_text(encoding="utf-8")
        lines = content.strip().split("\n")
        assert len(lines) == 4  # header + 3 alert rows (no comment row)
        assert "Timestamp" in lines[0]
        assert "Severity" in lines[0]
        assert not lines[0].startswith("#")

    def test_csv_empty(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            out = Path(f.name)
        export_csv([], out)

        content = out.read_text(encoding="utf-8")
        lines = content.strip().split("\n")
        assert len(lines) == 1  # header only (no comment row)
        assert lines[0].startswith("Timestamp")
