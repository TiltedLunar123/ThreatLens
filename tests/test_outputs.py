"""Tests for output modules: HTML, timeline, Elasticsearch."""

import tempfile
from datetime import datetime
from pathlib import Path

from threatlens.models import Alert, Severity
from threatlens.outputs.elasticsearch import _build_doc
from threatlens.outputs.html_report import export_html
from threatlens.outputs.timeline import export_timeline


def _sample_alerts() -> list[Alert]:
    return [
        Alert(
            rule_name="Alert 1",
            severity=Severity.CRITICAL,
            description="Critical finding",
            timestamp=datetime(2025, 1, 15, 8, 30, 0),
            mitre_tactic="Execution",
            mitre_technique="T1059",
        ),
        Alert(
            rule_name="Alert 2",
            severity=Severity.LOW,
            description="Low finding",
            timestamp=datetime(2025, 1, 15, 9, 0, 0),
        ),
    ]


class TestHTMLReport:
    def test_export_contains_alerts(self):
        alerts = _sample_alerts()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            out = Path(f.name)
        export_html(alerts, out, total_events=100, elapsed=0.5)
        content = out.read_text(encoding="utf-8")
        assert "ThreatLens" in content
        assert "Alert 1" in content
        assert "T1059" in content

    def test_export_empty_alerts(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            out = Path(f.name)
        export_html([], out, total_events=0)
        content = out.read_text(encoding="utf-8")
        assert "No threats detected" in content


class TestTimeline:
    def test_export_with_alerts(self):
        alerts = _sample_alerts()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            out = Path(f.name)
        export_timeline(alerts, out, total_events=50)
        content = out.read_text(encoding="utf-8")
        assert "Attack Timeline" in content
        assert "Alert 1" in content
        assert "Alert 2" in content

    def test_export_empty(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            out = Path(f.name)
        export_timeline([], out)
        content = out.read_text(encoding="utf-8")
        assert "No alerts" in content


class TestElasticsearchDoc:
    def test_build_doc_structure(self):
        alert = Alert(
            rule_name="Test Alert",
            severity=Severity.HIGH,
            description="Test",
            timestamp=datetime(2025, 1, 15, 9, 0, 0),
        )
        doc = _build_doc(alert, total_events=100)
        assert doc["rule_name"] == "Test Alert"
        assert doc["severity"] == "high"
        assert doc["total_events_analyzed"] == 100
        assert doc["tool"] == "threatlens"
        assert "@timestamp" in doc
        assert "ingested_at" in doc


class TestElasticsearchSend:
    def test_send_empty_alerts(self):
        from threatlens.outputs.elasticsearch import send_to_elasticsearch
        success, errors = send_to_elasticsearch([], "http://localhost:9200")
        assert success == 0
        assert errors == 0

    def test_send_http_error(self):
        from unittest.mock import MagicMock, patch
        from urllib.error import HTTPError

        from threatlens.outputs.elasticsearch import send_to_elasticsearch
        alerts = _sample_alerts()
        mock_error = HTTPError("http://localhost", 400, "Bad Request", {}, MagicMock(read=MagicMock(return_value=b"error")))
        with patch("threatlens.outputs.elasticsearch.urlopen", side_effect=mock_error):
            success, errors = send_to_elasticsearch(alerts, "http://localhost:9200")
        assert success == 0
        assert errors == len(alerts)

    def test_send_url_error(self):
        from unittest.mock import patch
        from urllib.error import URLError

        from threatlens.outputs.elasticsearch import send_to_elasticsearch
        alerts = _sample_alerts()
        with patch("threatlens.outputs.elasticsearch.urlopen", side_effect=URLError("Connection refused")):
            success, errors = send_to_elasticsearch(alerts, "http://localhost:9200")
        assert success == 0
        assert errors == len(alerts)

    def test_send_success(self):
        from unittest.mock import MagicMock, patch

        from threatlens.outputs.elasticsearch import send_to_elasticsearch
        alerts = _sample_alerts()
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"errors": false, "items": []}'
        with patch("threatlens.outputs.elasticsearch.urlopen", return_value=mock_response):
            success, errors = send_to_elasticsearch(alerts, "http://localhost:9200")
        assert success == len(alerts)
        assert errors == 0

    def test_send_partial_errors(self):
        import json
        from unittest.mock import MagicMock, patch

        from threatlens.outputs.elasticsearch import send_to_elasticsearch
        alerts = _sample_alerts()
        result = {
            "errors": True,
            "items": [
                {"index": {"status": 201}},
                {"index": {"error": {"type": "mapper_parsing_exception"}}},
            ],
        }
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(result).encode()
        with patch("threatlens.outputs.elasticsearch.urlopen", return_value=mock_response):
            success, errors = send_to_elasticsearch(alerts, "http://localhost:9200")
        assert success == 1
        assert errors == 1

    def test_send_with_api_key(self):
        from unittest.mock import MagicMock, patch

        from threatlens.outputs.elasticsearch import send_to_elasticsearch
        alerts = _sample_alerts()
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"errors": false, "items": []}'
        with patch("threatlens.outputs.elasticsearch.urlopen", return_value=mock_response) as mock_urlopen:
            send_to_elasticsearch(alerts, "http://localhost:9200", api_key="test-key")
            req = mock_urlopen.call_args[0][0]
            assert "ApiKey test-key" in req.get_header("Authorization")

    def test_send_with_ssl_disabled(self):
        from unittest.mock import MagicMock, patch

        from threatlens.outputs.elasticsearch import send_to_elasticsearch
        alerts = _sample_alerts()
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"errors": false, "items": []}'
        with patch("threatlens.outputs.elasticsearch.urlopen", return_value=mock_response):
            success, _errors = send_to_elasticsearch(alerts, "https://localhost:9200", verify_ssl=False)
        assert success == len(alerts)


class TestEnsureIndexTemplate:
    def test_ensure_template_success(self):
        from unittest.mock import MagicMock, patch

        from threatlens.outputs.elasticsearch import ensure_index_template
        with patch("threatlens.outputs.elasticsearch.urlopen", return_value=MagicMock()):
            assert ensure_index_template("http://localhost:9200") is True

    def test_ensure_template_failure(self):
        from unittest.mock import patch

        from threatlens.outputs.elasticsearch import ensure_index_template
        with patch("threatlens.outputs.elasticsearch.urlopen", side_effect=Exception("fail")):
            assert ensure_index_template("http://localhost:9200") is False

    def test_ensure_template_with_api_key(self):
        from unittest.mock import MagicMock, patch

        from threatlens.outputs.elasticsearch import ensure_index_template
        with patch("threatlens.outputs.elasticsearch.urlopen", return_value=MagicMock()) as mock_urlopen:
            ensure_index_template("http://localhost:9200", api_key="secret")
            req = mock_urlopen.call_args[0][0]
            assert "ApiKey secret" in req.get_header("Authorization")


class TestWazuhOutput:
    def test_build_event_structure(self):
        from threatlens.outputs.wazuh import _build_event

        alert = Alert(
            rule_name="Brute Force",
            severity=Severity.HIGH,
            description="oops",
            timestamp=datetime(2025, 1, 15, 8, 30, 0),
            mitre_tactic="Credential Access",
            mitre_technique="T1110",
        )
        event = _build_event(alert, total_events=42)
        assert event["rule"]["level"] == 12
        assert "threatlens" in event["rule"]["groups"]
        assert event["data"]["mitre_technique"] == "T1110"
        assert event["data"]["total_events_analyzed"] == 42

    def test_send_empty_alerts(self):
        from threatlens.outputs.wazuh import send_to_wazuh

        success, errors = send_to_wazuh([], "https://wazuh:55000")
        assert success == 0
        assert errors == 0

    def test_send_with_token_success(self):
        from unittest.mock import MagicMock, patch

        from threatlens.outputs.wazuh import send_to_wazuh
        with patch(
            "threatlens.outputs.wazuh.urlopen",
            return_value=MagicMock(read=MagicMock(return_value=b"{}")),
        ):
            success, errors = send_to_wazuh(
                _sample_alerts(),
                "https://wazuh:55000",
                auth_token="t0k3n",
            )
        assert success == 2
        assert errors == 0

    def test_send_missing_auth(self):
        from threatlens.outputs.wazuh import send_to_wazuh

        success, errors = send_to_wazuh(_sample_alerts(), "https://wazuh:55000")
        assert success == 0
        assert errors == 2


class TestSplunkOutput:
    def test_build_event_structure(self):
        from threatlens.outputs.splunk import _build_event

        alert = Alert(
            rule_name="Bad",
            severity=Severity.CRITICAL,
            description="bad",
            timestamp=datetime(2025, 1, 15, 8, 30, 0),
        )
        ev = _build_event(alert, total_events=10, index="main",
                          sourcetype="threatlens:alert", host="h", source="s")
        assert ev["index"] == "main"
        assert ev["sourcetype"] == "threatlens:alert"
        assert ev["event"]["rule_name"] == "Bad"
        assert ev["event"]["tool"] == "threatlens"

    def test_send_empty_alerts(self):
        from threatlens.outputs.splunk import send_to_splunk

        success, errors = send_to_splunk([], "https://splunk:8088", token="t")
        assert success == 0
        assert errors == 0

    def test_send_appends_collector_path(self):
        from unittest.mock import MagicMock, patch

        from threatlens.outputs.splunk import send_to_splunk
        with patch(
            "threatlens.outputs.splunk.urlopen",
            return_value=MagicMock(read=MagicMock(return_value=b'{"code": 0}')),
        ) as mock_open:
            send_to_splunk(_sample_alerts(), "https://splunk:8088", token="t")
            req = mock_open.call_args[0][0]
            assert req.full_url.endswith("/services/collector/event")
            assert req.get_header("Authorization") == "Splunk t"

    def test_send_non_zero_code(self):
        from unittest.mock import MagicMock, patch

        from threatlens.outputs.splunk import send_to_splunk
        with patch(
            "threatlens.outputs.splunk.urlopen",
            return_value=MagicMock(read=MagicMock(return_value=b'{"code": 8}')),
        ):
            success, errors = send_to_splunk(_sample_alerts(), "https://splunk:8088", token="t")
        assert success == 0
        assert errors == 2


class TestNavigatorOutput:
    def test_layer_structure(self):
        from threatlens.outputs.navigator import build_navigator_layer

        alerts = _sample_alerts()
        alerts[0].mitre_technique = "T1059.001"
        alerts[1].mitre_technique = "T1110"
        layer = build_navigator_layer(alerts)
        assert layer["versions"]["layer"] == "4.5"
        assert layer["domain"] == "enterprise-attack"
        tids = {t["techniqueID"] for t in layer["techniques"]}
        assert "T1059.001" in tids
        assert "T1110" in tids

    def test_export_round_trip(self):
        import json

        from threatlens.outputs.navigator import export_navigator_layer
        alerts = _sample_alerts()
        alerts[0].mitre_technique = "T1003"
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = Path(f.name)
        export_navigator_layer(alerts, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["name"] == "ThreatLens Scan"
        assert any(t["techniqueID"] == "T1003" for t in data["techniques"])


class TestStixOutput:
    def test_bundle_structure(self):
        from threatlens.outputs.stix import build_stix_bundle

        alerts = _sample_alerts()
        alerts[0].mitre_technique = "T1059"
        alerts[0].evidence = [{"source_ip": "198.51.100.5", "username": "admin"}]
        bundle = build_stix_bundle(alerts)
        assert bundle["type"] == "bundle"
        types = {o["type"] for o in bundle["objects"]}
        assert "identity" in types
        assert "indicator" in types
        assert "sighting" in types
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert indicator["spec_version"] == "2.1"
        assert "198.51.100.5" in indicator["pattern"]
        assert indicator["external_references"][0]["external_id"] == "T1059"

    def test_export_round_trip(self):
        import json

        from threatlens.outputs.stix import export_stix_bundle
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = Path(f.name)
        export_stix_bundle(_sample_alerts(), out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["type"] == "bundle"
        assert len(data["objects"]) >= 3
