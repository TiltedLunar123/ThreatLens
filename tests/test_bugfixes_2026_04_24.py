"""Regression tests for the 2026-04-24 bundle of bug fixes.

Covers:
- #24 syslog _extract_ip rejects invalid octets
- #27 is_private_ip logs malformed input at debug level
- #11 CEF epoch-ms path no longer uses deprecated datetime.utcfromtimestamp
- #10 RFC 3164 year-boundary heuristic in both syslog and CEF parsers
- #15 print_banner() honors --no-color
- #18 export_csv does not emit a leading comment row
- #8 run_follow() returns 0 on fallthrough
- #9 / #25 allowlist rule_name uses exact equality (case-insensitive)
"""

from __future__ import annotations

import csv
import logging
from datetime import datetime
from unittest.mock import patch

from threatlens.allowlist import _alert_allowed
from threatlens.models import Alert, Severity
from threatlens.parsers.cef_parser import _parse_cef_timestamp
from threatlens.parsers.syslog_parser import (
    _extract_ip,
    _parse_syslog_timestamp,
)
from threatlens.report import export_csv, print_banner
from threatlens.utils import is_private_ip, set_no_color

# ---------------------------------------------------------------------------
# #24 syslog IP extraction rejects invalid octets
# ---------------------------------------------------------------------------

class TestSyslogExtractIpRejectsInvalidOctets:
    def test_invalid_octet_is_skipped(self):
        assert _extract_ip("login attempt from 999.999.999.999 failed") == ""

    def test_invalid_octet_then_valid_returns_valid(self):
        msg = "sshd: failed 999.1.1.1 then accepted from 10.0.0.5"
        assert _extract_ip(msg) == "10.0.0.5"

    def test_valid_octet_returns_first(self):
        assert _extract_ip("from 192.168.1.2 and 10.0.0.1") == "192.168.1.2"

    def test_no_ip_returns_empty(self):
        assert _extract_ip("no addresses here") == ""


# ---------------------------------------------------------------------------
# #27 is_private_ip logs invalid input
# ---------------------------------------------------------------------------

class TestIsPrivateIpMalformed:
    def test_logs_debug_on_invalid(self, caplog):
        with caplog.at_level(logging.DEBUG, logger="threatlens"):
            result = is_private_ip("999.999.999.999")
        assert result is False
        assert any(
            "invalid address" in rec.getMessage().lower()
            for rec in caplog.records
        )

    def test_valid_public_does_not_log(self, caplog):
        with caplog.at_level(logging.DEBUG, logger="threatlens"):
            result = is_private_ip("8.8.8.8")
        assert result is False
        assert not any(
            "invalid address" in rec.getMessage().lower()
            for rec in caplog.records
        )


# ---------------------------------------------------------------------------
# #11 CEF epoch-ms uses timezone-aware fromtimestamp
# ---------------------------------------------------------------------------

class TestCefEpochMsNotDeprecated:
    def test_epoch_ms_converts_cleanly(self):
        from datetime import timezone
        target = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        epoch_ms = int(target.timestamp() * 1000)
        result = _parse_cef_timestamp(str(epoch_ms))
        assert result.year == 2026
        assert result.month == 1
        assert result.day == 2
        assert result.hour == 3
        assert result.minute == 4
        assert result.second == 5
        # Stored as naive datetime to match the rest of the pipeline.
        assert result.tzinfo is None

    def test_epoch_ms_path_runs_without_deprecation(self, recwarn):
        _parse_cef_timestamp("1700000000000")
        assert not any(
            "utcfromtimestamp" in str(w.message).lower() for w in recwarn
        )


# ---------------------------------------------------------------------------
# #10 RFC 3164 year-boundary heuristic
# ---------------------------------------------------------------------------

class _FrozenDateTime(datetime):
    _frozen: datetime = datetime(2026, 1, 5, 12, 0, 0)

    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        return cls._frozen


class TestRfc3164YearBoundarySyslog:
    def test_december_log_in_january_rolls_back(self):
        with patch("threatlens.parsers.syslog_parser.datetime", _FrozenDateTime):
            ts = _parse_syslog_timestamp("Dec 28 08:30:01")
        assert ts.year == 2025
        assert ts.month == 12

    def test_early_january_log_keeps_current_year(self):
        with patch("threatlens.parsers.syslog_parser.datetime", _FrozenDateTime):
            ts = _parse_syslog_timestamp("Jan  3 08:30:01")
        assert ts.year == 2026
        assert ts.month == 1


class TestRfc3164YearBoundaryCef:
    def test_december_log_in_january_rolls_back(self):
        with patch("threatlens.parsers.cef_parser.datetime", _FrozenDateTime):
            ts = _parse_cef_timestamp("Dec 31 23:59:59")
        assert ts.year == 2025
        assert ts.month == 12

    def test_past_or_present_log_keeps_current_year(self):
        with patch("threatlens.parsers.cef_parser.datetime", _FrozenDateTime):
            ts = _parse_cef_timestamp("Jan  5 11:00:00")
        assert ts.year == 2026


# ---------------------------------------------------------------------------
# #15 print_banner honors --no-color
# ---------------------------------------------------------------------------

class TestPrintBannerNoColor:
    def test_banner_has_ansi_in_color_mode(self, capsys):
        set_no_color(False)
        try:
            print_banner()
        finally:
            pass
        out = capsys.readouterr().out
        assert "\033[" in out

    def test_banner_strips_ansi_when_no_color(self, capsys):
        set_no_color(True)
        try:
            print_banner()
        finally:
            set_no_color(False)
        out = capsys.readouterr().out
        # No ANSI escape sequences anywhere in the banner output.
        assert "\033[96m" not in out
        assert "\033[1m" not in out


# ---------------------------------------------------------------------------
# #18 export_csv has no comment row
# ---------------------------------------------------------------------------

class TestExportCsvNoCommentRow:
    def test_first_row_is_header(self, tmp_path):
        out = tmp_path / "r.csv"
        export_csv([], out, total_events=42)
        with open(out, encoding="utf-8", newline="") as f:
            rows = list(csv.reader(f))
        assert rows[0][0] == "Timestamp"
        assert not rows[0][0].startswith("#")

    def test_roundtrip_with_pandas_style_dictreader(self, tmp_path):
        alert = Alert(
            rule_name="Test",
            severity=Severity.HIGH,
            description="desc",
            timestamp=datetime(2026, 1, 2, 3, 4, 5),
            evidence=[{"k": "v"}],
            mitre_tactic="TA0001",
            mitre_technique="T1078",
            recommendation="rec",
        )
        out = tmp_path / "r.csv"
        export_csv([alert], out, total_events=1)
        with open(out, encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 1
        assert rows[0]["Severity"] == "high"
        assert rows[0]["Rule"] == "Test"


# ---------------------------------------------------------------------------
# #8 run_follow fallthrough return (use static analysis via AST-free compile)
# ---------------------------------------------------------------------------

class TestRunFollowHasTrailingReturn:
    def test_source_has_trailing_return_zero(self):
        import inspect

        from threatlens import follower
        src = inspect.getsource(follower.run_follow)
        lines = [line.rstrip() for line in src.splitlines() if line.strip()]
        # Last non-blank line of the function body should be a return 0.
        assert lines[-1].strip() == "return 0"


# ---------------------------------------------------------------------------
# #9 / #25 allowlist rule_name is exact equality (case-insensitive)
# ---------------------------------------------------------------------------

def _alert(name: str) -> Alert:
    return Alert(
        rule_name=name,
        severity=Severity.HIGH,
        description="d",
        timestamp=datetime(2026, 1, 2, 3, 4, 5),
        evidence=[{"username": "u"}],
    )


class TestAllowlistExactRuleName:
    def test_substring_no_longer_matches(self):
        # Old substring semantics would have suppressed this; now it must not.
        allowlist = [{"rule_name": "Brute"}]
        assert _alert_allowed(_alert("Brute-Force Detected"), allowlist) is None

    def test_exact_match_case_insensitive(self):
        allowlist = [{"rule_name": "brute-force detected"}]
        assert (
            _alert_allowed(_alert("Brute-Force Detected"), allowlist)
            is not None
        )

    def test_unrelated_name_unmatched(self):
        allowlist = [{"rule_name": "Brute-Force Detected"}]
        assert _alert_allowed(_alert("Password Spray Detected"), allowlist) is None
