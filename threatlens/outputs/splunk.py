"""Splunk HTTP Event Collector (HEC) output connector for ThreatLens.

Posts alerts to a Splunk indexer via the HEC endpoint. HEC accepts one
or more events in a single POST body separated by newlines; this module
batches all alerts into a single request to minimize round-trips.

Docs: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
"""

from __future__ import annotations

import json
import logging
import ssl
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from threatlens.models import Alert


def _build_event(
    alert: Alert,
    total_events: int,
    index: str,
    sourcetype: str,
    host: str,
    source: str,
) -> dict[str, Any]:
    """Wrap an Alert into a HEC event envelope."""
    return {
        "time": alert.timestamp.timestamp(),
        "host": host,
        "source": source,
        "sourcetype": sourcetype,
        "index": index,
        "event": {
            "rule_name": alert.rule_name,
            "severity": str(alert.severity),
            "description": alert.description,
            "mitre_tactic": alert.mitre_tactic,
            "mitre_technique": alert.mitre_technique,
            "recommendation": alert.recommendation,
            "evidence_count": len(alert.evidence),
            "evidence": alert.evidence[:10],
            "total_events_analyzed": total_events,
            "ingested_at": time.time(),
            "tool": "threatlens",
        },
    }


def send_to_splunk(
    alerts: list[Alert],
    hec_url: str,
    token: str,
    index: str = "main",
    sourcetype: str = "threatlens:alert",
    host: str = "threatlens",
    source: str = "threatlens",
    total_events: int = 0,
    verify_ssl: bool = True,
    timeout: float = 30.0,
) -> tuple[int, int]:
    """Send alerts to a Splunk HEC endpoint.

    Returns (success_count, error_count). On a single failed POST the
    function reports all alerts in the batch as errored - HEC is
    all-or-nothing per request.
    """
    if not alerts:
        return 0, 0

    if not hec_url.endswith("/services/collector") and not hec_url.endswith("/services/collector/event"):
        hec_url = hec_url.rstrip("/") + "/services/collector/event"

    body_parts = []
    for alert in alerts:
        body_parts.append(
            json.dumps(
                _build_event(alert, total_events, index, sourcetype, host, source),
                default=str,
            )
        )
    body = "\n".join(body_parts).encode("utf-8")

    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json",
    }

    if verify_ssl:
        context: ssl.SSLContext | None = None
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    req = Request(hec_url, data=body, headers=headers, method="POST")
    try:
        resp = urlopen(req, context=context, timeout=timeout)
        result = json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        logging.getLogger("threatlens").error(
            "Splunk HEC error (HTTP %s): %s", e.code, error_body[:200]
        )
        return 0, len(alerts)
    except URLError as e:
        logging.getLogger("threatlens").error("Splunk HEC connection error: %s", e.reason)
        return 0, len(alerts)

    if result.get("code") == 0:
        return len(alerts), 0

    logging.getLogger("threatlens").error(
        "Splunk HEC returned non-zero code: %s", result
    )
    return 0, len(alerts)
