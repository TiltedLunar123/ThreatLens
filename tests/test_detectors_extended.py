"""Tests for detectors not covered by test_detections.py.

Covers: DefenseEvasionDetector, DiscoveryDetector, ExfiltrationDetector,
KerberosAttackDetector, PersistenceDetector, PrivilegeEscalationDetector,
and AttackChainDetector.
"""

from datetime import datetime, timedelta

from threatlens.detections.attack_chain import AttackChainDetector
from threatlens.detections.defense_evasion import DefenseEvasionDetector
from threatlens.detections.discovery import DiscoveryDetector
from threatlens.detections.exfiltration import ExfiltrationDetector
from threatlens.detections.kerberos_attacks import KerberosAttackDetector
from threatlens.detections.persistence import PersistenceDetector
from threatlens.detections.privilege_escalation import PrivilegeEscalationDetector
from threatlens.models import EventCategory, LogEvent, Severity

BASE_TIME = datetime(2025, 3, 15, 10, 0, 0)


def _evt(
    event_id: int = 0,
    category: EventCategory = EventCategory.UNKNOWN,
    username: str = "",
    target_username: str = "",
    computer: str = "WS-01",
    source_ip: str = "",
    process_name: str = "",
    command_line: str = "",
    logon_type: int = 0,
    raw: dict | None = None,
    ts_offset_s: int = 0,
) -> LogEvent:
    """Helper to build a LogEvent for testing."""
    return LogEvent(
        timestamp=BASE_TIME + timedelta(seconds=ts_offset_s),
        event_id=event_id,
        source="Security",
        category=category,
        computer=computer,
        raw=raw or {},
        username=username,
        source_ip=source_ip,
        process_name=process_name,
        command_line=command_line,
        logon_type=logon_type,
        target_username=target_username,
    )


# ── Defense Evasion ──────────────────────────────────────────────────────────


class TestDefenseEvasionDetector:
    def test_log_cleared_1102(self):
        events = [_evt(event_id=1102, username="attacker")]
        alerts = DefenseEvasionDetector().analyze(events)
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.HIGH
        assert "Log Clearing" in alerts[0].rule_name

    def test_log_cleared_104(self):
        events = [_evt(event_id=104, username="attacker")]
        alerts = DefenseEvasionDetector().analyze(events)
        assert len(alerts) == 1

    def test_defender_disabled(self):
        events = [_evt(event_id=5001, username="admin")]
        alerts = DefenseEvasionDetector().analyze(events)
        assert len(alerts) == 1
        assert "Defender" in alerts[0].rule_name

    def test_audit_policy_change(self):
        events = [_evt(event_id=4719, username="admin")]
        alerts = DefenseEvasionDetector().analyze(events)
        assert len(alerts) == 1
        assert "Audit Policy" in alerts[0].rule_name

    def test_firewall_modification(self):
        events = [_evt(
            event_id=1,
            command_line="netsh advfirewall set allprofiles state off",
            category=EventCategory.PROCESS,
        )]
        alerts = DefenseEvasionDetector().analyze(events)
        assert len(alerts) == 1
        assert "Firewall" in alerts[0].rule_name

    def test_benign_events_no_alert(self):
        events = [_evt(event_id=4624, username="user")]
        alerts = DefenseEvasionDetector().analyze(events)
        assert len(alerts) == 0


# ── Discovery ────────────────────────────────────────────────────────────────


class TestDiscoveryDetector:
    def test_recon_burst_triggers(self):
        """3 recon commands within the window should trigger."""
        events = [
            _evt(process_name="whoami.exe", username="attacker", ts_offset_s=0),
            _evt(process_name="ipconfig.exe", username="attacker", ts_offset_s=5),
            _evt(process_name="systeminfo.exe", username="attacker", ts_offset_s=10),
        ]
        alerts = DiscoveryDetector().analyze(events)
        assert len(alerts) == 1
        assert "Reconnaissance" in alerts[0].rule_name

    def test_below_threshold_no_alert(self):
        """Only 2 recon commands should NOT trigger (threshold=3)."""
        events = [
            _evt(process_name="whoami.exe", username="attacker", ts_offset_s=0),
            _evt(process_name="ipconfig.exe", username="attacker", ts_offset_s=5),
        ]
        alerts = DiscoveryDetector().analyze(events)
        assert len(alerts) == 0

    def test_different_users_not_grouped(self):
        """Commands from different users should not combine."""
        events = [
            _evt(process_name="whoami.exe", username="user1", ts_offset_s=0),
            _evt(process_name="ipconfig.exe", username="user2", ts_offset_s=5),
            _evt(process_name="systeminfo.exe", username="user1", ts_offset_s=10),
        ]
        alerts = DiscoveryDetector().analyze(events)
        assert len(alerts) == 0

    def test_non_recon_commands_ignored(self):
        events = [
            _evt(process_name="notepad.exe", username="user", ts_offset_s=0),
            _evt(process_name="chrome.exe", username="user", ts_offset_s=5),
            _evt(process_name="explorer.exe", username="user", ts_offset_s=10),
        ]
        alerts = DiscoveryDetector().analyze(events)
        assert len(alerts) == 0


# ── Exfiltration ─────────────────────────────────────────────────────────────


class TestExfiltrationDetector:
    def test_archive_targeting_sensitive_path(self):
        events = [_evt(
            command_line="7z a backup.7z c:\\users\\admin\\documents",
            category=EventCategory.PROCESS,
        )]
        alerts = ExfiltrationDetector().analyze(events)
        assert len(alerts) >= 1
        assert any("Archive" in a.rule_name for a in alerts)

    def test_staging_to_network_share(self):
        events = [_evt(
            command_line=r"robocopy c:\sensitive smb://exfil-server/share",
            category=EventCategory.PROCESS,
        )]
        alerts = ExfiltrationDetector().analyze(events)
        assert len(alerts) >= 1

    def test_benign_command_no_alert(self):
        events = [_evt(
            command_line="dir c:\\temp",
            category=EventCategory.PROCESS,
        )]
        alerts = ExfiltrationDetector().analyze(events)
        assert len(alerts) == 0

    def test_empty_command_line_skipped(self):
        events = [_evt(command_line="", category=EventCategory.PROCESS)]
        alerts = ExfiltrationDetector().analyze(events)
        assert len(alerts) == 0


# ── Kerberos Attacks ─────────────────────────────────────────────────────────


class TestKerberosAttackDetector:
    def test_kerberoasting_tgs_rc4(self):
        events = [_evt(
            event_id=4769,
            target_username="svc_sql",
            raw={"TicketEncryptionType": "0x17"},
        )]
        alerts = KerberosAttackDetector().analyze(events)
        assert len(alerts) == 1
        assert "Kerberoasting" in alerts[0].rule_name

    def test_kerberoasting_machine_account_filtered(self):
        """Machine accounts (ending with $) should not trigger."""
        events = [_evt(
            event_id=4769,
            target_username="DC01$",
            raw={"TicketEncryptionType": "0x17"},
        )]
        alerts = KerberosAttackDetector().analyze(events)
        assert len(alerts) == 0

    def test_asrep_roasting(self):
        events = [_evt(
            event_id=4768,
            target_username="vuln_user",
            raw={"TicketEncryptionType": "0x17"},
        )]
        alerts = KerberosAttackDetector().analyze(events)
        assert len(alerts) == 1
        assert "AS-REP" in alerts[0].rule_name

    def test_normal_kerberos_no_alert(self):
        """Non-RC4 encryption should not trigger."""
        events = [_evt(
            event_id=4769,
            target_username="svc_sql",
            raw={"TicketEncryptionType": "0x12"},  # AES256
        )]
        alerts = KerberosAttackDetector().analyze(events)
        assert len(alerts) == 0


# ── Persistence ──────────────────────────────────────────────────────────────


class TestPersistenceDetector:
    def test_new_service_created(self):
        events = [_evt(event_id=7045, username="admin", raw={"ServiceName": "evilsvc"})]
        alerts = PersistenceDetector().analyze(events)
        assert len(alerts) >= 1
        assert any("Service" in a.rule_name for a in alerts)

    def test_new_service_with_powershell_is_critical(self):
        events = [_evt(
            event_id=7045,
            username="admin",
            raw={"ServiceFileName": "powershell.exe -enc ..."},
        )]
        alerts = PersistenceDetector().analyze(events)
        assert any(a.severity == Severity.CRITICAL for a in alerts)

    def test_scheduled_task_created(self):
        events = [_evt(event_id=4698, username="admin")]
        alerts = PersistenceDetector().analyze(events)
        assert len(alerts) >= 1
        assert any("Scheduled Task" in a.rule_name for a in alerts)

    def test_registry_run_key_modified(self):
        events = [_evt(
            event_id=13,
            raw={"TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\backdoor"},
        )]
        alerts = PersistenceDetector().analyze(events)
        assert len(alerts) >= 1
        assert any("Registry Run Key" in a.rule_name for a in alerts)

    def test_benign_event_no_alert(self):
        events = [_evt(event_id=4624)]
        alerts = PersistenceDetector().analyze(events)
        assert len(alerts) == 0


# ── Privilege Escalation ─────────────────────────────────────────────────────


class TestPrivilegeEscalationDetector:
    def test_debug_privilege_high_severity(self):
        events = [_evt(
            event_id=4672,
            username="attacker",
            raw={"PrivilegeList": "SeDebugPrivilege"},
        )]
        alerts = PrivilegeEscalationDetector().analyze(events)
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.HIGH

    def test_non_debug_sensitive_privilege(self):
        events = [_evt(
            event_id=4672,
            username="attacker",
            raw={"PrivilegeList": "SeTcbPrivilege"},
        )]
        alerts = PrivilegeEscalationDetector().analyze(events)
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.MEDIUM

    def test_system_account_filtered(self):
        """SYSTEM and service accounts should not trigger."""
        events = [_evt(
            event_id=4672,
            username="SYSTEM",
            raw={"PrivilegeList": "SeDebugPrivilege"},
        )]
        alerts = PrivilegeEscalationDetector().analyze(events)
        assert len(alerts) == 0

    def test_no_sensitive_privilege_no_alert(self):
        events = [_evt(
            event_id=4672,
            username="user",
            raw={"PrivilegeList": "SeChangeNotifyPrivilege"},
        )]
        alerts = PrivilegeEscalationDetector().analyze(events)
        assert len(alerts) == 0

    def test_dedup_per_user(self):
        """Multiple events for the same user should produce one alert."""
        events = [
            _evt(event_id=4672, username="attacker", raw={"PrivilegeList": "SeDebugPrivilege"}, ts_offset_s=0),
            _evt(event_id=4672, username="attacker", raw={"PrivilegeList": "SeDebugPrivilege"}, ts_offset_s=5),
            _evt(event_id=4672, username="attacker", raw={"PrivilegeList": "SeTcbPrivilege"}, ts_offset_s=10),
        ]
        alerts = PrivilegeEscalationDetector().analyze(events)
        assert len(alerts) == 1
        assert "SeDebugPrivilege" in alerts[0].description
        assert "SeTcbPrivilege" in alerts[0].description


# ── Attack Chain (flagship feature) ──────────────────────────────────────────


class TestAttackChainDetector:
    def _make_chain(self, within_window: bool = True) -> list[LogEvent]:
        """Build a realistic multi-stage attack chain."""
        gap = 300 if within_window else 7200  # 5min vs 2h between stages
        return [
            # Stage 1: Credential Access (brute force)
            _evt(event_id=4625, target_username="admin", computer="DC-01", ts_offset_s=0),
            _evt(event_id=4625, target_username="admin", computer="DC-01", ts_offset_s=30),
            # Stage 2: Privilege Escalation
            _evt(event_id=4672, target_username="admin", computer="DC-01",
                 raw={"PrivilegeList": "SeDebugPrivilege"}, ts_offset_s=gap),
            # Stage 3: Lateral Movement (network logon)
            _evt(event_id=4624, target_username="admin", computer="WS-02",
                 logon_type=3, ts_offset_s=gap + 120),
            # Stage 4: Execution
            _evt(event_id=1, target_username="admin", computer="WS-02",
                 process_name="powershell.exe", command_line="Invoke-Mimikatz",
                 category=EventCategory.PROCESS, ts_offset_s=gap + 180),
        ]

    def test_full_chain_detected(self):
        """4-stage attack chain within the window should produce a CRITICAL alert."""
        events = self._make_chain(within_window=True)
        alerts = AttackChainDetector().analyze(events)
        assert len(alerts) >= 1
        critical = [a for a in alerts if a.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert "admin" in critical[0].description

    def test_two_stage_chain_detected(self):
        """2 stages should still trigger (default min_stages=2)."""
        events = [
            _evt(event_id=4625, target_username="admin", ts_offset_s=0),
            _evt(event_id=4672, target_username="admin",
                 raw={"PrivilegeList": "SeDebugPrivilege"}, ts_offset_s=60),
        ]
        alerts = AttackChainDetector().analyze(events)
        assert len(alerts) >= 1

    def test_single_stage_no_alert(self):
        """Only credential access events should NOT form a chain."""
        events = [
            _evt(event_id=4625, target_username="victim", ts_offset_s=0),
            _evt(event_id=4625, target_username="victim", ts_offset_s=30),
        ]
        alerts = AttackChainDetector().analyze(events)
        assert len(alerts) == 0

    def test_system_accounts_filtered(self):
        """SYSTEM and ANONYMOUS LOGON should not form chains."""
        events = [
            _evt(event_id=4625, target_username="SYSTEM", ts_offset_s=0),
            _evt(event_id=4672, target_username="SYSTEM",
                 raw={"PrivilegeList": "SeDebugPrivilege"}, ts_offset_s=60),
            _evt(event_id=4624, target_username="SYSTEM", logon_type=3, ts_offset_s=120),
        ]
        alerts = AttackChainDetector().analyze(events)
        assert len(alerts) == 0

    def test_outside_window_no_alert(self):
        """Events spread over hours with default 1h window should not chain."""
        events = [
            _evt(event_id=4625, target_username="admin", ts_offset_s=0),
            _evt(event_id=4672, target_username="admin",
                 raw={"PrivilegeList": "SeDebugPrivilege"}, ts_offset_s=7200),
        ]
        alerts = AttackChainDetector(config={"chain_window": 600}).analyze(events)
        assert len(alerts) == 0

    def test_custom_min_stages(self):
        """Setting min_stages=3 should require 3 distinct stages."""
        events = [
            _evt(event_id=4625, target_username="admin", ts_offset_s=0),
            _evt(event_id=4672, target_username="admin",
                 raw={"PrivilegeList": "SeDebugPrivilege"}, ts_offset_s=60),
        ]
        alerts = AttackChainDetector(config={"chain_min_stages": 3}).analyze(events)
        assert len(alerts) == 0

    def test_different_users_separate_chains(self):
        """Events from different users should not be correlated."""
        events = [
            _evt(event_id=4625, target_username="alice", ts_offset_s=0),
            _evt(event_id=4672, target_username="bob",
                 raw={"PrivilegeList": "SeDebugPrivilege"}, ts_offset_s=60),
        ]
        alerts = AttackChainDetector().analyze(events)
        assert len(alerts) == 0

    def test_sliding_window_finds_subchain(self):
        """Events that span beyond the window should still be detected via sliding window."""
        # First event far in the past, but stages 2-4 are within window
        events = [
            _evt(event_id=4625, target_username="admin", ts_offset_s=0),
            # Long gap
            _evt(event_id=4625, target_username="admin", ts_offset_s=3500),
            _evt(event_id=4672, target_username="admin",
                 raw={"PrivilegeList": "SeDebugPrivilege"}, ts_offset_s=3550),
            _evt(event_id=4624, target_username="admin", logon_type=3, ts_offset_s=3600),
        ]
        alerts = AttackChainDetector(config={"chain_window": 3600}).analyze(events)
        # Should find the chain in the latter window
        assert len(alerts) >= 1

    def test_empty_events_no_crash(self):
        alerts = AttackChainDetector().analyze([])
        assert alerts == []
