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
