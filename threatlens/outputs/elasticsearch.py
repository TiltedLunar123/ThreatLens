"""Elasticsearch output connector for ThreatLens."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from threatlens.models import Alert


def _build_doc(alert: Alert, total_events: int) -> dict[str, Any]:
    """Convert an Alert into an Elasticsearch-compatible document."""
    return {
        "@timestamp": alert.timestamp.isoformat(),
        "rule_name": alert.rule_name,
        "severity": alert.severity.value,
        "description": alert.description,
        "mitre_tactic": alert.mitre_tactic,
        "mitre_technique": alert.mitre_technique,
        "recommendation": alert.recommendation,
        "evidence_count": len(alert.evidence),
        "evidence": alert.evidence[:10],
        "total_events_analyzed": total_events,
        "tool": "threatlens",
        "ingested_at": datetime.now().isoformat(),
    }


def send_to_elasticsearch(
    alerts: list[Alert],
    es_url: str,
    index: str = "threatlens-alerts",
    total_events: int = 0,
    api_key: str | None = None,
    verify_ssl: bool = True,
) -> tuple[int, int]:
    """Send alerts to Elasticsearch using the bulk API.

    Uses only stdlib (urllib) so there's no hard dependency on the
    elasticsearch-py client library.

    Returns (success_count, error_count).
    """
    if not alerts:
        return 0, 0

    bulk_url = f"{es_url.rstrip('/')}/_bulk"

    # Build NDJSON bulk payload
    lines: list[str] = []
    for alert in alerts:
        action = json.dumps({"index": {"_index": index}})
        doc = json.dumps(_build_doc(alert, total_events), default=str)
        lines.append(action)
        lines.append(doc)

    body = "\n".join(lines) + "\n"

    headers: dict[str, str] = {"Content-Type": "application/x-ndjson"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"

    import ssl

    if verify_ssl:
        context = None  # use default
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    req = Request(bulk_url, data=body.encode("utf-8"), headers=headers, method="POST")

    try:
        response = urlopen(req, context=context, timeout=30)
        result = json.loads(response.read().decode("utf-8"))
    except HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        logging.getLogger("threatlens").error(
            "Elasticsearch error (HTTP %s): %s", e.code, error_body[:200]
        )
        return 0, len(alerts)
    except URLError as e:
        logging.getLogger("threatlens").error("Elasticsearch connection error: %s", e.reason)
        return 0, len(alerts)

    if result.get("errors"):
        errors = sum(
            1
            for item in result.get("items", [])
            if "error" in item.get("index", {})
        )
        return len(alerts) - errors, errors

    return len(alerts), 0


def ensure_index_template(
    es_url: str,
    index_pattern: str = "threatlens-*",
    api_key: str | None = None,
) -> bool:
    """Create an index template with appropriate field mappings.

    Returns True on success, False on failure.
    """
    template = {
        "index_patterns": [index_pattern],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "rule_name": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "description": {"type": "text"},
                    "mitre_tactic": {"type": "keyword"},
                    "mitre_technique": {"type": "keyword"},
                    "recommendation": {"type": "text"},
                    "evidence_count": {"type": "integer"},
                    "total_events_analyzed": {"type": "integer"},
                    "tool": {"type": "keyword"},
                    "ingested_at": {"type": "date"},
                }
            },
        },
    }

    url = f"{es_url.rstrip('/')}/_index_template/threatlens"
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"

    body = json.dumps(template).encode("utf-8")
    req = Request(url, data=body, headers=headers, method="PUT")

    try:
        urlopen(req, timeout=10)
        return True
    except Exception as e:
        logging.getLogger("threatlens").warning("Could not create index template: %s", e)
        return False
