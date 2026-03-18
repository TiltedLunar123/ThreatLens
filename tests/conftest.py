"""Shared test fixtures for ThreatLens."""

from datetime import datetime

import pytest

from threatlens.models import EventCategory, LogEvent


@pytest.fixture()
def base_time() -> datetime:
    return datetime(2025, 1, 15, 8, 30, 0)


def make_failed_logon(
    ts: datetime, source_ip: str = "10.0.1.50", user: str = "admin"
) -> LogEvent:
    return LogEvent(
        timestamp=ts,
        event_id=4625,
        source="Security",
        category=EventCategory.AUTHENTICATION,
        computer="WS-PC01",
        raw={"EventID": 4625},
        username=user,
        target_username=user,
        source_ip=source_ip,
        logon_type=3,
    )


def make_network_logon(
    ts: datetime, user: str, computer: str, logon_type: int = 3
) -> LogEvent:
    return LogEvent(
        timestamp=ts,
        event_id=4624,
        source="Security",
        category=EventCategory.AUTHENTICATION,
        computer=computer,
        raw={"EventID": 4624},
        username=user,
        target_username=user,
        source_ip="10.0.1.50",
        logon_type=logon_type,
    )


def make_priv_event(ts: datetime, user: str, privs: str) -> LogEvent:
    return LogEvent(
        timestamp=ts,
        event_id=4672,
        source="Security",
        category=EventCategory.PRIVILEGE,
        computer="DC-01",
        raw={"EventID": 4672, "EventData": {"PrivilegeList": privs}},
        username=user,
    )


def make_process_event(
    ts: datetime, process: str, cmd: str, user: str = "jdoe"
) -> LogEvent:
    return LogEvent(
        timestamp=ts,
        event_id=1,
        source="Sysmon",
        category=EventCategory.PROCESS,
        computer="WS-PC01",
        raw={"EventID": 1},
        username=user,
        process_name=process,
        command_line=cmd,
        parent_process="C:\\Windows\\System32\\cmd.exe",
    )
