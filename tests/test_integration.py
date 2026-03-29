"""Integration tests for ThreatLens CLI end-to-end scans."""

import json
import tempfile
from pathlib import Path

from threatlens.cli import build_parser, run_scan
from threatlens.config import load_user_config


SAMPLE_DIR = Path(__file__).parent.parent / "sample_data"
SAMPLE_LOG = SAMPLE_DIR / "sample_security_log.json"
MIXED_LOG = SAMPLE_DIR / "mixed_enterprise_log.json"
LARGE_LOG = SAMPLE_DIR / "large_synthetic.json"


class TestFullScan:
    def test_scan_sample_security_log(self):
        if not SAMPLE_LOG.exists():
            return
        parser = build_parser()
        args = parser.parse_args(["scan", str(SAMPLE_LOG), "--quiet"])
        result = run_scan(args)
        assert result in (0, 2)

    def test_scan_mixed_enterprise_log(self):
        if not MIXED_LOG.exists():
            return
        parser = build_parser()
        args = parser.parse_args(["scan", str(MIXED_LOG), "--quiet"])
        result = run_scan(args)
        assert result in (0, 2)

    def test_scan_large_synthetic(self):
        if not LARGE_LOG.exists():
            return
        parser = build_parser()
        args = parser.parse_args(["scan", str(LARGE_LOG), "--quiet"])
        result = run_scan(args)
        assert result in (0, 2)

    def test_scan_directory(self):
        if not SAMPLE_DIR.exists():
            return
        parser = build_parser()
        args = parser.parse_args(["scan", str(SAMPLE_DIR), "--quiet"])
        result = run_scan(args)
        assert result in (0, 2)


class TestFailOnExitCodes:
    def test_fail_on_high(self):
        if not SAMPLE_LOG.exists():
            return
        parser = build_parser()
        args = parser.parse_args(["scan", str(SAMPLE_LOG), "--quiet", "--fail-on", "high"])
        result = run_scan(args)
        assert result == 2  # sample data has HIGH alerts

    def test_fail_on_low(self):
        if not SAMPLE_LOG.exists():
            return
        parser = build_parser()
        args = parser.parse_args(["scan", str(SAMPLE_LOG), "--quiet", "--fail-on", "low"])
        result = run_scan(args)
        assert result == 2

    def test_fail_on_critical_only(self):
        if not SAMPLE_LOG.exists():
            return
        parser = build_parser()
        args = parser.parse_args(["scan", str(SAMPLE_LOG), "--quiet", "--fail-on", "critical"])
        result = run_scan(args)
        # May or may not have critical alerts
        assert result in (0, 2)


class TestSummaryOnly:
    def test_summary_only_output(self, capsys):
        if not SAMPLE_LOG.exists():
            return
        parser = build_parser()
        args = parser.parse_args(["scan", str(SAMPLE_LOG), "--quiet", "--summary-only"])
        run_scan(args)
        output = capsys.readouterr().out
        assert "SCAN SUMMARY" in output
        # Individual alert details should be suppressed
        assert "Evidence" not in output


class TestProfile:
    def test_profile_output(self, capsys):
        if not SAMPLE_LOG.exists():
            return
        parser = build_parser()
        args = parser.parse_args(["scan", str(SAMPLE_LOG), "--quiet", "--profile"])
        run_scan(args)
        output = capsys.readouterr().out
        assert "Timing:" in output
        assert "Parsing:" in output
        assert "Detection:" in output
        assert "Reporting:" in output
        assert "Total:" in output


class TestConfigFileLoading:
    def test_load_user_config_empty(self):
        """load_user_config returns empty dict when no config file exists."""
        cfg = load_user_config()
        assert isinstance(cfg, dict)

    def test_load_user_config_from_cwd(self, monkeypatch, tmp_path):
        config_path = tmp_path / ".threatlens.yaml"
        config_path.write_text(
            "min_severity: high\nno_color: true\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        cfg = load_user_config()
        assert cfg.get("min_severity") == "high"
        assert cfg.get("no_color") is True


class TestJsonReport:
    def test_json_report_structure(self):
        if not SAMPLE_LOG.exists():
            return
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = f.name
        parser = build_parser()
        args = parser.parse_args(["scan", str(SAMPLE_LOG), "--quiet", "-o", out, "-f", "json"])
        run_scan(args)
        report = json.loads(Path(out).read_text(encoding="utf-8"))
        assert "report_metadata" in report
        assert "alerts" in report
        assert "severity_summary" in report
        # Check evidence_truncated field from the to_dict fix
        for alert in report["alerts"]:
            assert "evidence_truncated" in alert
            assert "evidence_count" in alert
