"""Property-based tests using Hypothesis for ThreatLens parsers and detectors."""

from __future__ import annotations

from datetime import datetime

from hypothesis import given, settings
from hypothesis import strategies as st

from threatlens.models import EventCategory, LogEvent
from threatlens.parsers.json_parser import parse_event, parse_timestamp

# --- Timestamp parsing ---

@given(st.sampled_from([
    "2025-01-15T08:30:01Z",
    "2025-01-15T08:30:01.123456Z",
    "2025-01-15T08:30:01",
    "2025-01-15 08:30:01",
    "01/15/2025 08:30:01 AM",
]))
def test_parse_timestamp_valid_formats(ts_str: str) -> None:
    """All supported timestamp formats should parse without error."""
    result = parse_timestamp(ts_str)
    assert isinstance(result, datetime)
    assert result.year == 2025


@given(st.text(min_size=1, max_size=50))
def test_parse_timestamp_never_crashes(ts_str: str) -> None:
    """parse_timestamp should raise ValueError for bad input, never crash."""
    try:
        result = parse_timestamp(ts_str)
        assert isinstance(result, datetime)
    except ValueError:
        pass  # expected for invalid timestamps


# --- JSON event parsing ---

@given(
    event_id=st.integers(min_value=0, max_value=99999),
    computer=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("L", "N"))),
    username=st.text(min_size=0, max_size=30, alphabet=st.characters(whitelist_categories=("L", "N"))),
)
@settings(max_examples=50)
def test_parse_event_arbitrary_fields(event_id: int, computer: str, username: str) -> None:
    """parse_event should handle arbitrary field values without crashing."""
    entry = {
        "EventID": event_id,
        "TimeCreated": "2025-01-15T08:30:01Z",
        "Computer": computer,
        "EventData": {"TargetUserName": username},
    }
    event = parse_event(entry)
    assert isinstance(event, LogEvent)
    assert event.event_id == event_id
    assert event.computer == computer


@given(st.dictionaries(
    keys=st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L",))),
    values=st.one_of(st.text(max_size=50), st.integers(), st.none()),
    min_size=0,
    max_size=10,
))
@settings(max_examples=50)
def test_parse_event_random_dicts(entry: dict) -> None:
    """parse_event should handle random dictionaries without crashing."""
    event = parse_event(entry)
    assert isinstance(event, LogEvent)


# --- Detection rules ---

def _make_event(
    event_id: int = 4625,
    username: str = "admin",
    source_ip: str = "10.0.1.50",
    ts: datetime | None = None,
) -> LogEvent:
    return LogEvent(
        timestamp=ts or datetime(2025, 1, 15, 8, 30, 0),
        event_id=event_id,
        source="Security",
        category=EventCategory.AUTHENTICATION,
        computer="WS-PC01",
        raw={"EventID": event_id},
        username=username,
        target_username=username,
        source_ip=source_ip,
        logon_type=3,
    )


@given(st.integers(min_value=0, max_value=50))
@settings(max_examples=20)
def test_brute_force_threshold_property(n_events: int) -> None:
    """Brute-force detector should only alert when event count >= threshold."""
    from threatlens.detections.brute_force import BruteForceDetector

    detector = BruteForceDetector(config={"brute_force_threshold": 5})
    events = [
        _make_event(ts=datetime(2025, 1, 15, 8, 30, i % 60))
        for i in range(n_events)
    ]
    alerts = detector.analyze(events)

    if n_events < 5:
        assert len(alerts) == 0
    else:
        assert len(alerts) >= 1


@given(st.lists(
    st.sampled_from(["admin", "root", "jdoe", "svc_acct", "guest"]),
    min_size=0,
    max_size=20,
))
@settings(max_examples=20)
def test_brute_force_never_crashes(usernames: list[str]) -> None:
    """Brute-force detector should never crash regardless of input."""
    from threatlens.detections.brute_force import BruteForceDetector

    detector = BruteForceDetector()
    events = [
        _make_event(username=u, ts=datetime(2025, 1, 15, 8, 30, i % 60))
        for i, u in enumerate(usernames)
    ]
    alerts = detector.analyze(events)
    assert isinstance(alerts, list)


# --- YAML rule validation ---

@given(st.fixed_dictionaries({
    "name": st.text(min_size=1, max_size=30),
    "conditions": st.just([{"field": "event_id", "operator": "equals", "value": "4625"}]),
    "severity": st.sampled_from(["low", "medium", "high", "critical"]),
}))
@settings(max_examples=20)
def test_yaml_rule_valid_definitions(rule_def: dict) -> None:
    """Valid YAML rule definitions should always parse successfully."""
    from threatlens.rules.yaml_rules import YamlRule
    rule = YamlRule(rule_def)
    assert rule.name == rule_def["name"]


@given(st.dictionaries(
    keys=st.text(min_size=1, max_size=10),
    values=st.one_of(st.text(max_size=20), st.integers(), st.none()),
    min_size=0,
    max_size=5,
))
@settings(max_examples=30)
def test_yaml_rule_rejects_invalid(rule_def: dict) -> None:
    """Invalid rule definitions should raise RuleValidationError, not crash."""
    import contextlib

    from threatlens.rules.yaml_rules import RuleValidationError, YamlRule
    with contextlib.suppress(RuleValidationError, ValueError, TypeError):
        YamlRule(rule_def)


# --- Network anomaly detector ---

@given(st.text(min_size=0, max_size=100))
def test_shannon_entropy_never_crashes(s: str) -> None:
    """Shannon entropy should handle any string."""
    from threatlens.detections.network_anomaly import _shannon_entropy
    result = _shannon_entropy(s)
    assert isinstance(result, float)
    assert result >= 0


# --- Syslog parser ---

@given(st.text(min_size=0, max_size=200))
@settings(max_examples=50)
def test_syslog_parse_line_never_crashes(line: str) -> None:
    """Syslog parser should handle arbitrary input without crashing."""
    from threatlens.parsers.syslog_parser import _parse_line
    result = _parse_line(line, "syslog")
    assert result is None or isinstance(result, LogEvent)
