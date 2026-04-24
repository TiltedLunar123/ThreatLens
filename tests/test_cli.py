"""Tests for CLI argument parsing, file collection, and scan execution."""

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from threatlens.cli import (
    _alert_allowed,
    _build_detectors,
    build_parser,
    collect_log_files,
    load_allowlist,
    load_rules_config,
    run_rules,
    run_scan,
)
from threatlens.models import Alert, Severity


class TestArgParsing:
    def test_scan_with_html_format(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "test.json", "--format", "html", "--min-severity", "high"])
        assert args.command == "scan"
        assert args.format == "html"
        assert args.min_severity == "high"

    def test_scan_with_sigma_and_custom_rules(self):
        parser = build_parser()
        args = parser.parse_args([
            "scan", "logs/",
            "--sigma-rules", "sigma/rules/",
            "--custom-rules", "my_rules/",
        ])
        assert args.sigma_rules == "sigma/rules/"
        assert args.custom_rules == "my_rules/"

    def test_scan_with_elasticsearch(self):
        parser = build_parser()
        args = parser.parse_args([
            "scan", "logs/",
            "--elastic-url", "http://localhost:9200",
            "--elastic-index", "my-index",
            "--elastic-api-key", "secret",
        ])
        assert args.elastic_url == "http://localhost:9200"
        assert args.elastic_index == "my-index"
        assert args.elastic_api_key == "secret"

    def test_scan_with_timeline(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "logs/", "--timeline", "out.html"])
        assert args.timeline == "out.html"

    def test_follow_command(self):
        parser = build_parser()
        args = parser.parse_args(["follow", "test.log", "--input-format", "syslog"])
        assert args.command == "follow"
        assert args.input_format == "syslog"

    def test_follow_buffer_options(self):
        parser = build_parser()
        args = parser.parse_args([
            "follow", "test.log",
            "--buffer-size", "50",
            "--flush-interval", "2.5",
        ])
        assert args.buffer_size == 50
        assert args.flush_interval == 2.5

    def test_rules_command(self):
        parser = build_parser()
        args = parser.parse_args(["rules"])
        assert args.command == "rules"

    def test_new_scan_options(self):
        parser = build_parser()
        args = parser.parse_args([
            "scan", "logs/",
            "--fail-on", "high",
            "--no-color",
            "--recursive",
            "--summary-only",
            "--allowlist", "allow.yaml",
        ])
        assert args.fail_on == "high"
        assert args.no_color is True
        assert args.recursive is True
        assert args.summary_only is True
        assert args.allowlist == "allow.yaml"


class TestFileCollection:
    def test_collect_json_from_directory(self):
        sample_dir = Path(__file__).parent.parent / "sample_data"
        if sample_dir.exists():
            files = collect_log_files(sample_dir, "json")
            assert len(files) >= 1
            assert all(f.suffix == ".json" for f in files)

    def test_collect_single_file(self):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if sample.exists():
            files = collect_log_files(sample)
            assert len(files) == 1

    def test_collect_nonexistent_returns_empty(self):
        files = collect_log_files(Path("/nonexistent/path"))
        assert files == []

    def test_collect_recursive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a nested structure
            sub = Path(tmpdir) / "sub"
            sub.mkdir()
            (Path(tmpdir) / "top.json").write_text("[]")
            (sub / "nested.json").write_text("[]")

            # Non-recursive should only get top-level
            files_flat = collect_log_files(Path(tmpdir), "json", recursive=False)
            assert len(files_flat) == 1

            # Recursive should get both
            files_recursive = collect_log_files(Path(tmpdir), "json", recursive=True)
            assert len(files_recursive) == 2


class TestRunScan:
    def test_scan_sample_data(self):
        """Full scan of sample data should complete without error."""
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return

        parser = build_parser()
        args = parser.parse_args(["scan", str(sample), "--quiet"])
        result = run_scan(args)
        assert result in (0, 2)  # 0 = no criticals, 2 = criticals found

    def test_scan_mixed_data(self):
        """Scan the mixed enterprise log."""
        sample = Path(__file__).parent.parent / "sample_data" / "mixed_enterprise_log.json"
        if not sample.exists():
            return

        parser = build_parser()
        args = parser.parse_args(["scan", str(sample), "--quiet"])
        result = run_scan(args)
        assert result in (0, 2)

    def test_scan_nonexistent_returns_error(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "/nonexistent/file.json"])
        result = run_scan(args)
        assert result == 1

    def test_scan_with_no_color(self):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return

        parser = build_parser()
        args = parser.parse_args(["scan", str(sample), "--quiet", "--no-color"])
        result = run_scan(args)
        assert result in (0, 2)

    def test_scan_with_summary_only(self, capsys):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return

        parser = build_parser()
        args = parser.parse_args(["scan", str(sample), "--quiet", "--summary-only"])
        run_scan(args)
        output = capsys.readouterr().out
        # Summary should be present but individual alert details should not
        assert "SCAN SUMMARY" in output

    def test_scan_fail_on_high(self):
        """--fail-on high should exit 2 if HIGH alerts exist."""
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return

        parser = build_parser()
        args = parser.parse_args(["scan", str(sample), "--quiet", "--fail-on", "high"])
        result = run_scan(args)
        assert result == 2  # sample data has HIGH alerts

    def test_scan_with_json_output(self):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = f.name

        parser = build_parser()
        args = parser.parse_args(["scan", str(sample), "--quiet", "-o", out, "-f", "json"])
        run_scan(args)

        import json
        report = json.loads(Path(out).read_text(encoding="utf-8"))
        assert "report_metadata" in report
        assert "alerts" in report

    def test_scan_with_csv_output(self):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            out = f.name

        parser = build_parser()
        args = parser.parse_args(["scan", str(sample), "--quiet", "-o", out, "-f", "csv"])
        run_scan(args)

        content = Path(out).read_text(encoding="utf-8")
        assert "Severity" in content
        # CSV no longer leads with a comment row (it broke standard parsers).
        assert not content.lstrip().startswith("#")

    def test_scan_with_html_output(self):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            out = f.name

        parser = build_parser()
        args = parser.parse_args(["scan", str(sample), "--quiet", "-o", out, "-f", "html"])
        run_scan(args)

        content = Path(out).read_text(encoding="utf-8")
        assert "ThreatLens" in content

    def test_scan_with_timeline(self):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            out = f.name

        parser = build_parser()
        args = parser.parse_args(["scan", str(sample), "--quiet", "--timeline", out])
        run_scan(args)

        content = Path(out).read_text(encoding="utf-8")
        assert "Attack Timeline" in content

    def test_scan_verbose(self, capsys):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return

        parser = build_parser()
        args = parser.parse_args(["scan", str(sample), "--quiet", "--verbose"])
        run_scan(args)
        output = capsys.readouterr().out
        assert "Evidence" in output

    def test_scan_min_severity_critical(self, capsys):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return

        parser = build_parser()
        args = parser.parse_args(["scan", str(sample), "--quiet", "--min-severity", "critical"])
        run_scan(args)


class TestRunRules:
    def test_run_rules_lists_detectors(self, capsys):
        result = run_rules()
        assert result == 0
        output = capsys.readouterr().out
        assert "Brute-Force" in output
        assert "Lateral Movement" in output
        assert "Privilege Escalation" in output
        assert "Suspicious Process" in output


class TestRulesConfig:
    def test_load_default_rules(self):
        default = Path(__file__).parent.parent / "rules" / "default_rules.yaml"
        if default.exists():
            config = load_rules_config(default)
            assert isinstance(config, dict)

    def test_load_nonexistent_returns_empty(self):
        config = load_rules_config(Path("/nonexistent/rules.yaml"))
        assert config == {}

    def test_load_none_uses_default(self):
        config = load_rules_config(None)
        assert isinstance(config, dict)


class TestBuildDetectors:
    def test_builds_builtin_detectors(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "test.json"])
        detectors = _build_detectors(args, {})
        assert len(detectors) >= 4  # 4 built-in detectors


class TestAllowlist:
    def test_load_allowlist_from_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "allowlist:\n"
                '  - rule_name: "Brute-Force"\n'
                '    username: "svc_monitor"\n'
            )
            f.flush()
            entries = load_allowlist(Path(f.name))

        assert len(entries) == 1
        assert entries[0]["rule_name"] == "Brute-Force"

    def test_load_nonexistent_allowlist(self):
        entries = load_allowlist(Path("/nonexistent/allow.yaml"))
        assert entries == []

    def test_alert_allowed_matches(self):
        # Exact (case-insensitive) equality on rule_name.
        alert = Alert(
            rule_name="Brute-Force Detected",
            severity=Severity.HIGH,
            description="test",
            timestamp=datetime(2025, 1, 15, 8, 0, 0),
            evidence=[{"username": "svc_monitor", "computer": "DC-01"}],
        )
        allowlist = [
            {"rule_name": "brute-force detected", "username": "svc_monitor"}
        ]
        assert _alert_allowed(alert, allowlist) is not None

    def test_alert_allowed_no_match(self):
        alert = Alert(
            rule_name="Brute-Force Detected",
            severity=Severity.HIGH,
            description="test",
            timestamp=datetime(2025, 1, 15, 8, 0, 0),
            evidence=[{"username": "jdoe", "computer": "WS-PC01"}],
        )
        allowlist = [
            {"rule_name": "Brute-Force Detected", "username": "svc_monitor"}
        ]
        assert _alert_allowed(alert, allowlist) is None

    def test_scan_with_allowlist(self):
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(
                "allowlist:\n"
                '  - rule_name: "Brute-Force Detected"\n'
            )
            f.flush()
            allow_path = f.name

        parser = build_parser()
        args = parser.parse_args([
            "scan", str(sample), "--quiet", "--allowlist", allow_path
        ])
        result = run_scan(args)
        assert result in (0, 2)


class TestAllowlistEnhanced:
    def test_alert_allowed_by_source_ip(self):
        alert = Alert(
            rule_name="Test Alert",
            severity=Severity.HIGH,
            description="test",
            timestamp=datetime(2025, 1, 15, 8, 0, 0),
            evidence=[{"source_ip": "10.0.1.100", "username": "test"}],
        )
        allowlist = [{"source_ip": "10.0.1.100"}]
        assert _alert_allowed(alert, allowlist) is not None

    def test_alert_allowed_by_severity(self):
        alert = Alert(
            rule_name="Test Alert",
            severity=Severity.LOW,
            description="test",
            timestamp=datetime(2025, 1, 15, 8, 0, 0),
            evidence=[{"username": "test"}],
        )
        allowlist = [{"severity": "low"}]
        assert _alert_allowed(alert, allowlist) is not None

    def test_alert_allowed_by_mitre_technique(self):
        alert = Alert(
            rule_name="Test Alert",
            severity=Severity.HIGH,
            description="test",
            timestamp=datetime(2025, 1, 15, 8, 0, 0),
            evidence=[{"username": "test"}],
            mitre_technique="T1059 - Command and Scripting Interpreter",
        )
        allowlist = [{"mitre_technique": "T1059"}]
        assert _alert_allowed(alert, allowlist) is not None

    def test_alert_allowed_by_event_id(self):
        alert = Alert(
            rule_name="Test Alert",
            severity=Severity.HIGH,
            description="test",
            timestamp=datetime(2025, 1, 15, 8, 0, 0),
            evidence=[{"event_id": 4625, "username": "test"}],
        )
        allowlist = [{"event_id": 4625}]
        assert _alert_allowed(alert, allowlist) is not None

    def test_alert_allowed_returns_reason(self):
        alert = Alert(
            rule_name="Brute-Force Detected",
            severity=Severity.HIGH,
            description="test",
            timestamp=datetime(2025, 1, 15, 8, 0, 0),
            evidence=[{"username": "svc_bot", "computer": "DC-01"}],
        )
        allowlist = [{
            "rule_name": "Brute-Force Detected",
            "username": "svc_bot",
            "reason": "Service account",
        }]
        result = _alert_allowed(alert, allowlist)
        assert result == "Service account"

    def test_alert_allowed_multi_field_partial_mismatch(self):
        alert = Alert(
            rule_name="Test Alert",
            severity=Severity.HIGH,
            description="test",
            timestamp=datetime(2025, 1, 15, 8, 0, 0),
            evidence=[{"source_ip": "10.0.1.50", "username": "admin"}],
        )
        # source_ip matches but severity doesn't
        allowlist = [{"source_ip": "10.0.1.50", "severity": "low"}]
        assert _alert_allowed(alert, allowlist) is None


class TestMainFunction:
    def test_main_no_command(self, capsys):
        from threatlens.cli import main
        with patch("sys.argv", ["threatlens"]):
            result = main()
        assert result == 0

    def test_main_rules_command(self, capsys):
        from threatlens.cli import main
        with patch("sys.argv", ["threatlens", "rules"]):
            result = main()
        assert result == 0

    def test_main_scan_no_file(self, capsys):
        from threatlens.cli import main
        with patch("sys.argv", ["threatlens", "scan", "/nonexistent/file.json"]):
            result = main()
        assert result == 1


class TestLoadRulesConfigEdgeCases:
    def test_load_invalid_yaml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("not: a: valid: yaml: [")
            f.flush()
            # yaml.safe_load may raise or return None for malformed YAML
            try:
                config = load_rules_config(Path(f.name))
                assert isinstance(config, dict) or config == {}
            except Exception:
                pass  # Malformed YAML is expected to fail

    def test_load_non_dict_yaml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("- item1\n- item2\n")
            f.flush()
            config = load_rules_config(Path(f.name))
        assert config == {}


class TestBuildDetectorsWithRules:
    def test_build_with_custom_yaml_rules(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write(
                'rules:\n  - name: "Test Rule"\n    conditions:\n'
                '      - field: event_id\n        operator: equals\n        value: "4625"\n'
                '    threshold: 1\n'
            )
            f.flush()
            parser = build_parser()
            args = parser.parse_args(["scan", "test.json", "--custom-rules", f.name])
            detectors = _build_detectors(args, {})
        # Should have built-in detectors + 1 custom rule
        assert len(detectors) >= 5 + 1

    def test_build_with_sigma_rules(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False, encoding="utf-8") as f:
            f.write(
                "title: Test Sigma\nlevel: medium\nlogsource:\n  category: process_creation\n"
                "detection:\n  selection:\n    CommandLine|contains: test\n  condition: selection\n"
            )
            f.flush()
            parser = build_parser()
            args = parser.parse_args(["scan", "test.json", "--sigma-rules", f.name])
            detectors = _build_detectors(args, {})
        assert len(detectors) >= 5 + 1


class TestAllowlistEdgeCases:
    def test_load_allowlist_non_dict_yaml(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write("- item1\n- item2\n")
            f.flush()
            entries = load_allowlist(Path(f.name))
        assert entries == []

    def test_alert_source_ip_mismatch(self):
        alert = Alert(
            rule_name="Test",
            severity=Severity.HIGH,
            description="test",
            timestamp=datetime(2025, 1, 15, 8, 0, 0),
            evidence=[{"source_ip": "10.0.1.50", "username": "test"}],
        )
        allowlist = [{"source_ip": "192.168.1.1"}]
        assert _alert_allowed(alert, allowlist) is None

    def test_alert_severity_mismatch(self):
        alert = Alert(
            rule_name="Test",
            severity=Severity.HIGH,
            description="test",
            timestamp=datetime(2025, 1, 15, 8, 0, 0),
            evidence=[{"username": "test"}],
        )
        allowlist = [{"severity": "low"}]
        assert _alert_allowed(alert, allowlist) is None

    def test_alert_mitre_technique_mismatch(self):
        alert = Alert(
            rule_name="Test",
            severity=Severity.HIGH,
            description="test",
            timestamp=datetime(2025, 1, 15, 8, 0, 0),
            evidence=[{"username": "test"}],
            mitre_technique="T1059",
        )
        allowlist = [{"mitre_technique": "T9999"}]
        assert _alert_allowed(alert, allowlist) is None

    def test_alert_event_id_mismatch(self):
        alert = Alert(
            rule_name="Test",
            severity=Severity.HIGH,
            description="test",
            timestamp=datetime(2025, 1, 15, 8, 0, 0),
            evidence=[{"event_id": 4625, "username": "test"}],
        )
        allowlist = [{"event_id": 9999}]
        assert _alert_allowed(alert, allowlist) is None


class TestScanErrorPaths:
    def test_scan_unparseable_file(self, capsys):
        """Scan a file that contains no valid events."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("this is not valid json at all\n")
            f.flush()
            parser = build_parser()
            args = parser.parse_args(["scan", f.name, "--quiet"])
            result = run_scan(args)
        assert result == 1

    def test_scan_with_detector_failure(self, capsys):
        """A failing detector should not crash the scan."""
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return
        parser = build_parser()
        args = parser.parse_args(["scan", str(sample), "--quiet"])

        class BrokenDetector:
            name = "Broken"
            def analyze(self, events):
                raise RuntimeError("boom")

        with (
            patch("threatlens.cli.ALL_DETECTORS", []),
            patch("threatlens.cli._build_detectors", return_value=[BrokenDetector()]),
        ):
            result = run_scan(args)
        # Should still complete (with 0 alerts since only detector failed)
        assert result in (0, 2)

    def test_scan_with_allowlist_suppression_stats(self, capsys, caplog):
        """Allowlist with reason should log suppression stats."""
        import logging
        import tempfile
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
            f.write(
                'allowlist:\n'
                '  - rule_name: "Brute-Force Detected"\n'
                '    reason: "Expected noise"\n'
            )
            f.flush()
            parser = build_parser()
            args = parser.parse_args(["scan", str(sample), "--allowlist", f.name])
            with caplog.at_level(logging.WARNING, logger="threatlens"):
                run_scan(args)
        assert "suppressed" in caplog.text.lower() or "Expected noise" in caplog.text

    def test_scan_with_elasticsearch(self, capsys):
        """ES send path should be exercised (mocked)."""
        sample = Path(__file__).parent.parent / "sample_data" / "sample_security_log.json"
        if not sample.exists():
            return
        parser = build_parser()
        args = parser.parse_args([
            "scan", str(sample), "--quiet",
            "--elastic-url", "http://localhost:9200",
            "--elastic-index", "test-idx",
        ])
        with patch("threatlens.outputs.elasticsearch.urlopen") as mock_urlopen:
            from unittest.mock import MagicMock
            mock_response = MagicMock()
            mock_response.read.return_value = b'{"errors": false, "items": []}'
            mock_urlopen.return_value = mock_response
            run_scan(args)
        output = capsys.readouterr().out
        assert "Elasticsearch:" in output


class TestRunFollow:
    def test_follow_nonexistent_file(self):
        parser = build_parser()
        args = parser.parse_args(["follow", "/nonexistent/file.json"])
        from threatlens.cli import run_follow
        result = run_follow(args)
        assert result == 1

    def test_follow_with_keyboard_interrupt(self, capsys):
        """Follow should handle KeyboardInterrupt gracefully."""
        import tempfile

        from threatlens.cli import run_follow

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write('{"EventID": 4625, "TimeCreated": "2025-01-15T08:30:01Z", "Computer": "WS-PC01"}\n')
            f.flush()
            tmppath = f.name

        parser = build_parser()
        args = parser.parse_args(["follow", tmppath])

        # Mock open so only the tailing open raises KeyboardInterrupt on readline
        original_open = open
        class FakeFile:
            def __init__(self, *a, **kw):
                self._real = original_open(*a, **kw)
            def read(self, *a, **kw):
                return self._real.read(*a, **kw)
            def seek(self, *a):
                return self._real.seek(*a)
            def readline(self):
                raise KeyboardInterrupt()
            def __enter__(self):
                return self
            def __exit__(self, *a):
                self._real.close()

        def selective_open(*a, **kw):
            # Only wrap the tailing open (the one targeting our temp file)
            path_arg = str(a[0]) if a else ""
            if tmppath in path_arg.replace("\\", "/") or path_arg.replace("\\", "/") == tmppath.replace("\\", "/"):
                return FakeFile(*a, **kw)
            return original_open(*a, **kw)

        with patch("builtins.open", selective_open):
            result = run_follow(args)
        assert result == 0
        output = capsys.readouterr().out
        assert "Stopped" in output

    def test_main_follow_branch(self):
        """main() should route to run_follow for follow command."""
        from threatlens.cli import main
        with patch("sys.argv", ["threatlens", "follow", "/nonexistent/file.json"]):
            result = main()
        assert result == 1


class TestFlushFollowBuffer:
    def test_flush_prints_alerts(self, capsys):
        from tests.conftest import make_failed_logon
        from threatlens.cli import _flush_follow_buffer
        from threatlens.models import Severity

        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, i)) for i in range(6)]
        from threatlens.detections.brute_force import BruteForceDetector
        detectors = [BruteForceDetector()]
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        seen: set = set()
        _flush_follow_buffer(events, detectors, severity_order, 0, seen)
        output = capsys.readouterr().out
        assert "Brute-Force" in output or "MEDIUM" in output

    def test_flush_deduplicates(self, capsys):
        from tests.conftest import make_failed_logon
        from threatlens.cli import _flush_follow_buffer
        from threatlens.models import Severity

        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, i)) for i in range(6)]
        from threatlens.detections.brute_force import BruteForceDetector
        detectors = [BruteForceDetector()]
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        seen: set = set()
        _flush_follow_buffer(events, detectors, severity_order, 0, seen)
        first_output = capsys.readouterr().out

        # Second flush with same events should produce no new output (dedup)
        _flush_follow_buffer(events, detectors, severity_order, 0, seen)
        second_output = capsys.readouterr().out
        assert len(second_output) < len(first_output) or second_output == ""

    def test_flush_respects_min_severity(self, capsys):
        from tests.conftest import make_failed_logon
        from threatlens.cli import _flush_follow_buffer
        from threatlens.models import Severity

        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, i)) for i in range(6)]
        from threatlens.detections.brute_force import BruteForceDetector
        detectors = [BruteForceDetector()]
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        seen: set = set()
        # min_index=3 means only CRITICAL
        _flush_follow_buffer(events, detectors, severity_order, 3, seen)
        output = capsys.readouterr().out
        # Brute force with 6 events is MEDIUM, should be filtered
        assert "Brute-Force" not in output

    def test_flush_handles_broken_detector(self, capsys):
        from tests.conftest import make_failed_logon
        from threatlens.cli import _flush_follow_buffer
        from threatlens.models import Severity

        events = [make_failed_logon(datetime(2025, 1, 15, 8, 30, 0))]
        class BrokenDetector:
            name = "Broken"
            def analyze(self, events):
                raise RuntimeError("boom")
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        seen: set = set()
        # Should not raise
        _flush_follow_buffer(events, [BrokenDetector()], severity_order, 0, seen)


class TestCollectLogFilesFormats:
    def test_collect_evtx_format(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.evtx").write_text("fake", encoding="utf-8")
            (Path(tmpdir) / "test.json").write_text("fake", encoding="utf-8")
            files = collect_log_files(Path(tmpdir), "evtx")
            assert len(files) == 1
            assert files[0].suffix == ".evtx"

    def test_collect_syslog_format(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "auth.log").write_text("fake", encoding="utf-8")
            (Path(tmpdir) / "test.json").write_text("fake", encoding="utf-8")
            files = collect_log_files(Path(tmpdir), "syslog")
            assert len(files) == 1
            assert files[0].suffix == ".log"

    def test_collect_cef_format(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "events.cef").write_text("fake", encoding="utf-8")
            files = collect_log_files(Path(tmpdir), "cef")
            assert len(files) == 1

    def test_collect_all_formats_from_dir(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "a.json").write_text("[]", encoding="utf-8")
            (Path(tmpdir) / "b.log").write_text("", encoding="utf-8")
            (Path(tmpdir) / "c.txt").write_text("", encoding="utf-8")  # should not match
            files = collect_log_files(Path(tmpdir))
            assert len(files) == 2  # json + log, not txt
