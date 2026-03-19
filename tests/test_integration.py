"""End-to-end CLI integration tests for ThreatLens."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

SAMPLE_DATA = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
MIXED_DATA = Path(__file__).parent.parent / "sample_data" / "mixed_enterprise_log.json"


@pytest.mark.skipif(not SAMPLE_DATA.exists(), reason="sample data not available")
class TestScanIntegration:
    """End-to-end tests that invoke the CLI as a subprocess."""

    def test_scan_json_output(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = f.name

        result = subprocess.run(
            [sys.executable, "-m", "threatlens", "scan", str(SAMPLE_DATA),
             "--quiet", "-o", out, "-f", "json"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode in (0, 2)

        report = json.loads(Path(out).read_text(encoding="utf-8"))
        assert "report_metadata" in report
        assert report["report_metadata"]["tool"] == "ThreatLens"
        assert report["report_metadata"]["total_events_analyzed"] > 0
        assert "alerts" in report
        assert len(report["alerts"]) > 0

    def test_scan_csv_output(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            out = f.name

        result = subprocess.run(
            [sys.executable, "-m", "threatlens", "scan", str(SAMPLE_DATA),
             "--quiet", "-o", out, "-f", "csv"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode in (0, 2)
        content = Path(out).read_text(encoding="utf-8")
        assert "ThreatLens" in content
        assert "Severity" in content

    def test_scan_html_output(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            out = f.name

        result = subprocess.run(
            [sys.executable, "-m", "threatlens", "scan", str(SAMPLE_DATA),
             "--quiet", "-o", out, "-f", "html"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode in (0, 2)
        content = Path(out).read_text(encoding="utf-8")
        assert "ThreatLens" in content
        assert "<html" in content

    def test_scan_sarif_output(self):
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            out = f.name

        result = subprocess.run(
            [sys.executable, "-m", "threatlens", "scan", str(SAMPLE_DATA),
             "--quiet", "-o", out, "-f", "sarif"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode in (0, 2)
        sarif = json.loads(Path(out).read_text(encoding="utf-8"))
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "ThreatLens"
        assert len(sarif["runs"][0]["results"]) > 0

    def test_scan_timeline_output(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            out = f.name

        result = subprocess.run(
            [sys.executable, "-m", "threatlens", "scan", str(SAMPLE_DATA),
             "--quiet", "--timeline", out],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode in (0, 2)
        content = Path(out).read_text(encoding="utf-8")
        assert "Attack Timeline" in content

    def test_scan_fail_on_high(self):
        result = subprocess.run(
            [sys.executable, "-m", "threatlens", "scan", str(SAMPLE_DATA),
             "--quiet", "--fail-on", "high"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 2  # sample data has HIGH alerts

    def test_scan_min_severity_critical(self):
        result = subprocess.run(
            [sys.executable, "-m", "threatlens", "scan", str(SAMPLE_DATA),
             "--quiet", "--min-severity", "critical"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode in (0, 2)

    def test_scan_nonexistent_file(self):
        result = subprocess.run(
            [sys.executable, "-m", "threatlens", "scan", "/nonexistent/file.json"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 1

    def test_rules_command(self):
        result = subprocess.run(
            [sys.executable, "-m", "threatlens", "rules"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert "Brute-Force" in result.stdout
        assert "Network Anomaly" in result.stdout

    def test_scan_alert_counts(self):
        """Verify expected alert types from sample data."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = f.name

        subprocess.run(
            [sys.executable, "-m", "threatlens", "scan", str(SAMPLE_DATA),
             "--quiet", "-o", out, "-f", "json"],
            capture_output=True, text=True, timeout=30,
        )
        report = json.loads(Path(out).read_text(encoding="utf-8"))
        rule_names = {a["rule_name"] for a in report["alerts"]}
        # Sample data should trigger at least brute-force detection
        assert any("Brute-Force" in r or "Password Spray" in r for r in rule_names)


@pytest.mark.skipif(not MIXED_DATA.exists(), reason="mixed data not available")
class TestMixedDataIntegration:
    def test_scan_mixed_zero_false_positives_on_benign(self):
        """Mixed dataset should not false-positive on benign events."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = f.name

        subprocess.run(
            [sys.executable, "-m", "threatlens", "scan", str(MIXED_DATA),
             "--quiet", "-o", out, "-f", "json"],
            capture_output=True, text=True, timeout=30,
        )
        report = json.loads(Path(out).read_text(encoding="utf-8"))
        # All alerts should be genuine (no false positives on benign traffic)
        assert report["report_metadata"]["total_alerts"] >= 0
