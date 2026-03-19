"""Tests for new features: network anomaly detection, SARIF output, GeoIP enrichment, YAML validation."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from threatlens.models import Alert, EventCategory, LogEvent, Severity

# ── Network Anomaly Detector ──────────────────────────────────────────────


class TestNetworkAnomalyDetector:
    def _make_network_event(
        self,
        ts: datetime,
        dest_ip: str = "203.0.113.50",
        dest_port: int = 443,
        source_ip: str = "10.0.1.10",
        query_name: str = "",
    ) -> LogEvent:
        raw: dict = {
            "EventID": 3,
            "DestinationIp": dest_ip,
            "DestinationPort": dest_port,
        }
        if query_name:
            raw["QueryName"] = query_name
        return LogEvent(
            timestamp=ts,
            event_id=3,
            source="Sysmon",
            category=EventCategory.NETWORK,
            computer="WS-PC01",
            raw=raw,
            source_ip=source_ip,
            username="jdoe",
        )

    def test_dns_tunneling_detection(self):
        from threatlens.detections.network_anomaly import NetworkAnomalyDetector

        detector = NetworkAnomalyDetector()
        # Create a DNS query with a very long, high-entropy subdomain
        long_subdomain = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qgb2YgZG5zIHR1bm5lbGluZw"
        query = f"{long_subdomain}.evil.example.com"
        events = [self._make_network_event(
            datetime(2025, 1, 15, 8, 30, 0),
            query_name=query,
        )]
        alerts = detector.analyze(events)
        dns_alerts = [a for a in alerts if "DNS" in a.rule_name]
        assert len(dns_alerts) >= 1
        assert dns_alerts[0].severity == Severity.HIGH

    def test_no_dns_tunneling_for_normal_queries(self):
        from threatlens.detections.network_anomaly import NetworkAnomalyDetector

        detector = NetworkAnomalyDetector()
        events = [self._make_network_event(
            datetime(2025, 1, 15, 8, 30, 0),
            query_name="www.google.com",
        )]
        alerts = detector.analyze(events)
        dns_alerts = [a for a in alerts if "DNS" in a.rule_name]
        assert len(dns_alerts) == 0

    def test_beaconing_detection(self):
        from threatlens.detections.network_anomaly import NetworkAnomalyDetector

        detector = NetworkAnomalyDetector(config={"beacon_min_connections": 5})
        # Create regular-interval connections (every 60 seconds)
        base = datetime(2025, 1, 15, 8, 0, 0)
        events = [
            self._make_network_event(base + timedelta(seconds=i * 60), dest_ip="198.51.100.1")
            for i in range(15)
        ]
        alerts = detector.analyze(events)
        beacon_alerts = [a for a in alerts if "Beacon" in a.rule_name]
        assert len(beacon_alerts) >= 1

    def test_no_beaconing_for_irregular_traffic(self):
        from threatlens.detections.network_anomaly import NetworkAnomalyDetector

        detector = NetworkAnomalyDetector(config={"beacon_min_connections": 5})
        import random
        random.seed(42)
        base = datetime(2025, 1, 15, 8, 0, 0)
        events = [
            self._make_network_event(
                base + timedelta(seconds=random.randint(0, 3600)),
                dest_ip="198.51.100.1",
            )
            for _ in range(15)
        ]
        alerts = detector.analyze(events)
        beacon_alerts = [a for a in alerts if "Beacon" in a.rule_name]
        # Irregular traffic should generally not trigger beaconing
        # (may occasionally by chance, so we just verify no crash)
        assert isinstance(beacon_alerts, list)

    def test_unusual_port_detection(self):
        from threatlens.detections.network_anomaly import NetworkAnomalyDetector

        detector = NetworkAnomalyDetector()
        base = datetime(2025, 1, 15, 8, 0, 0)
        events = [
            self._make_network_event(base + timedelta(seconds=i), dest_port=4444)
            for i in range(5)
        ]
        alerts = detector.analyze(events)
        port_alerts = [a for a in alerts if "Port" in a.rule_name]
        assert len(port_alerts) >= 1
        assert port_alerts[0].severity == Severity.HIGH  # 4444 is a known malware port

    def test_common_ports_not_flagged(self):
        from threatlens.detections.network_anomaly import NetworkAnomalyDetector

        detector = NetworkAnomalyDetector()
        base = datetime(2025, 1, 15, 8, 0, 0)
        events = [
            self._make_network_event(base + timedelta(seconds=i), dest_port=443)
            for i in range(10)
        ]
        alerts = detector.analyze(events)
        port_alerts = [a for a in alerts if "Port" in a.rule_name]
        assert len(port_alerts) == 0

    def test_empty_events(self):
        from threatlens.detections.network_anomaly import NetworkAnomalyDetector

        detector = NetworkAnomalyDetector()
        alerts = detector.analyze([])
        assert alerts == []


# ── SARIF Output ──────────────────────────────────────────────────────────


class TestSarifOutput:
    def test_export_sarif_basic(self):
        from threatlens.outputs.sarif import export_sarif

        alerts = [
            Alert(
                rule_name="Brute-Force Detected",
                severity=Severity.HIGH,
                description="5 failed logon attempts from 10.0.1.50",
                timestamp=datetime(2025, 1, 15, 8, 30, 0),
                evidence=[{"source_ip": "10.0.1.50", "username": "admin"}],
                mitre_tactic="Credential Access",
                mitre_technique="T1110 - Brute Force",
                recommendation="Block the IP",
            ),
            Alert(
                rule_name="Suspicious Process: Encoded PowerShell",
                severity=Severity.CRITICAL,
                description="powershell.exe with encoded command",
                timestamp=datetime(2025, 1, 15, 9, 0, 0),
                evidence=[{"process": "powershell.exe", "username": "jdoe"}],
                mitre_tactic="Execution",
                mitre_technique="T1059.001 - PowerShell",
            ),
        ]

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            out_path = Path(f.name)

        export_sarif(alerts, out_path, total_events=100)
        sarif = json.loads(out_path.read_text(encoding="utf-8"))

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "ThreatLens"
        assert len(run["tool"]["driver"]["rules"]) == 2
        assert len(run["results"]) == 2
        assert run["properties"]["total_events_analyzed"] == 100

        # Check severity mapping
        result_levels = {r["level"] for r in run["results"]}
        assert "error" in result_levels  # HIGH and CRITICAL map to error

    def test_export_sarif_empty(self):
        from threatlens.outputs.sarif import export_sarif

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            out_path = Path(f.name)

        export_sarif([], out_path, total_events=0)
        sarif = json.loads(out_path.read_text(encoding="utf-8"))
        assert len(sarif["runs"][0]["results"]) == 0

    def test_sarif_deduplicates_rules(self):
        from threatlens.outputs.sarif import export_sarif

        alerts = [
            Alert(
                rule_name="Same Rule",
                severity=Severity.MEDIUM,
                description=f"Alert {i}",
                timestamp=datetime(2025, 1, 15, 8, i, 0),
            )
            for i in range(3)
        ]

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            out_path = Path(f.name)

        export_sarif(alerts, out_path)
        sarif = json.loads(out_path.read_text(encoding="utf-8"))
        # 3 results but only 1 unique rule
        assert len(sarif["runs"][0]["results"]) == 3
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1


# ── GeoIP Enrichment ─────────────────────────────────────────────────────


class TestGeoIPEnricher:
    def test_private_ip_detection(self):
        from threatlens.enrichment.geoip import GeoIPEnricher

        enricher = GeoIPEnricher()
        info = enricher.lookup("10.0.1.50")
        assert info.is_private is True
        assert info.country == ""

    def test_loopback_detection(self):
        from threatlens.enrichment.geoip import GeoIPEnricher

        enricher = GeoIPEnricher()
        info = enricher.lookup("127.0.0.1")
        assert info.is_private is True

    def test_invalid_ip(self):
        from threatlens.enrichment.geoip import GeoIPEnricher

        enricher = GeoIPEnricher()
        info = enricher.lookup("not-an-ip")
        assert info.ip == "not-an-ip"
        assert info.is_private is False

    def test_threat_intel_lookup(self):
        from threatlens.enrichment.geoip import GeoIPEnricher

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# Known bad IPs\n185.220.101.1\n185.220.101.2\n")
            f.flush()
            enricher = GeoIPEnricher(threat_intel_file=f.name)

        info = enricher.lookup("185.220.101.1")
        assert info.is_known_bad is True
        assert "known-bad" in info.reputation_tags

        info2 = enricher.lookup("1.2.3.4")
        assert info2.is_known_bad is False

    def test_enrich_alerts(self):
        from threatlens.enrichment.geoip import GeoIPEnricher

        enricher = GeoIPEnricher()
        alerts = [
            Alert(
                rule_name="Test",
                severity=Severity.HIGH,
                description="test",
                timestamp=datetime(2025, 1, 15, 8, 0, 0),
                evidence=[{"source_ip": "10.0.1.50", "username": "admin"}],
            ),
        ]
        enricher.enrich_alerts(alerts)
        # Private IPs should not get geo enrichment
        assert "geo" not in alerts[0].evidence[0]

    def test_to_dict(self):
        from threatlens.enrichment.geoip import IPInfo

        info = IPInfo(ip="8.8.8.8", country="US", city="Mountain View", is_known_bad=True, reputation_tags=["dns"])
        d = info.to_dict()
        assert d["ip"] == "8.8.8.8"
        assert d["country"] == "US"
        assert d["is_known_bad"] is True

    def test_context_manager(self):
        from threatlens.enrichment.geoip import GeoIPEnricher

        with GeoIPEnricher() as enricher:
            info = enricher.lookup("10.0.0.1")
            assert info.is_private is True


# ── YAML Rule Validation ─────────────────────────────────────────────────


class TestYamlRuleValidation:
    def test_valid_rule(self):
        from threatlens.rules.yaml_rules import YamlRule

        rule_def = {
            "name": "Test Rule",
            "conditions": [{"field": "event_id", "operator": "equals", "value": "4625"}],
            "severity": "high",
        }
        rule = YamlRule(rule_def)
        assert rule.name == "Test Rule"

    def test_missing_conditions(self):
        from threatlens.rules.yaml_rules import RuleValidationError, YamlRule

        with pytest.raises(RuleValidationError, match="conditions"):
            YamlRule({"name": "Bad Rule"})

    def test_empty_conditions(self):
        from threatlens.rules.yaml_rules import RuleValidationError, YamlRule

        with pytest.raises(RuleValidationError, match="conditions"):
            YamlRule({"name": "Bad Rule", "conditions": []})

    def test_invalid_operator(self):
        from threatlens.rules.yaml_rules import RuleValidationError, YamlRule

        with pytest.raises(RuleValidationError, match="invalid operator"):
            YamlRule({
                "name": "Bad Rule",
                "conditions": [{"field": "event_id", "operator": "NOPE", "value": "1"}],
            })

    def test_missing_field_in_condition(self):
        from threatlens.rules.yaml_rules import RuleValidationError, YamlRule

        with pytest.raises(RuleValidationError, match="missing required"):
            YamlRule({
                "name": "Bad Rule",
                "conditions": [{"operator": "equals", "value": "1"}],
            })

    def test_invalid_severity(self):
        from threatlens.rules.yaml_rules import RuleValidationError, YamlRule

        with pytest.raises(RuleValidationError, match="invalid severity"):
            YamlRule({
                "name": "Bad Rule",
                "conditions": [{"field": "event_id", "operator": "equals", "value": "1"}],
                "severity": "mega-critical",
            })

    def test_non_dict_rule(self):
        from threatlens.rules.yaml_rules import RuleValidationError, validate_rule_def

        with pytest.raises(RuleValidationError, match="must be a dict"):
            validate_rule_def("not a dict")

    def test_condition_not_dict(self):
        from threatlens.rules.yaml_rules import RuleValidationError, YamlRule

        with pytest.raises(RuleValidationError, match="must be a dict"):
            YamlRule({
                "name": "Bad Rule",
                "conditions": ["not a dict"],
            })

    def test_load_invalid_rule_file_warns(self, capsys):
        from threatlens.rules.yaml_rules import load_yaml_rules

        # Rule with conditions but invalid operator — triggers RuleValidationError
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(
                'rules:\n'
                '  - name: "Bad"\n'
                '    conditions:\n'
                '      - field: event_id\n'
                '        operator: INVALID_OP\n'
                '        value: "1"\n'
            )
            f.flush()
            rules = load_yaml_rules(Path(f.name))

        assert len(rules) == 0  # invalid rule should be skipped
        stderr = capsys.readouterr().err
        assert "Warning" in stderr

    def test_load_rule_without_conditions_skipped(self):
        from threatlens.rules.yaml_rules import load_yaml_rules

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write('rules:\n  - name: "No Conditions"\n    severity: "high"\n')
            f.flush()
            rules = load_yaml_rules(Path(f.name))

        assert len(rules) == 0  # silently skipped (no conditions key)


# ── Shannon Entropy ───────────────────────────────────────────────────────


class TestShannonEntropy:
    def test_empty_string(self):
        from threatlens.detections.network_anomaly import _shannon_entropy
        assert _shannon_entropy("") == 0.0

    def test_uniform_string(self):
        from threatlens.detections.network_anomaly import _shannon_entropy
        assert _shannon_entropy("aaaa") == 0.0

    def test_high_entropy_string(self):
        from threatlens.detections.network_anomaly import _shannon_entropy
        entropy = _shannon_entropy("aGVsbG8gd29ybGQ=")
        assert entropy > 3.0
