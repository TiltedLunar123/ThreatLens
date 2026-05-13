"""Wazuh manager output connector for ThreatLens.

Posts alerts to a Wazuh manager via the REST API. Wazuh accepts custom
alerts at the `/events` endpoint when an integrator is registered; the
generic and most portable surface is to ingest into a logcollector socket
or the API's custom-events route.

This module sends one JSON document per alert to the Wazuh API
`POST /events` endpoint, which is the same surface used by the
``wazuh-logtest`` tooling and by external integrations. The Wazuh side
rule that converts these into alerts is shown in the SECURITY.md example.
"""

from __future__ import annotations

import json
import logging
import ssl
from datetime import datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from threatlens.models import Alert

# Wazuh severity scale runs 0 (lowest) through 15 (highest critical).
_WAZUH_LEVEL = {
    "low": 3,
    "medium": 7,
    "high": 12,
    "critical": 15,
}


def _build_event(alert: Alert, total_events: int) -> dict[str, Any]:
    """Convert an Alert into a Wazuh custom-event payload."""
    return {
        "timestamp": alert.timestamp.isoformat(),
        "rule": {
            "level": _WAZUH_LEVEL.get(str(alert.severity), 5),
            "description": alert.description,
            "id": f"threatlens-{abs(hash(alert.rule_name)) % 100000}",
            "groups": ["threatlens", alert.mitre_tactic or "uncategorized"],
        },
        "agent": {
            "name": "threatlens",
            "id": "000",
        },
        "data": {
            "rule_name": alert.rule_name,
            "severity": str(alert.severity),
            "mitre_tactic": alert.mitre_tactic,
            "mitre_technique": alert.mitre_technique,
            "recommendation": alert.recommendation,
            "evidence_count": len(alert.evidence),
            "evidence": alert.evidence[:10],
            "total_events_analyzed": total_events,
        },
        "@timestamp": datetime.now().isoformat(),
    }


def send_to_wazuh(
    alerts: list[Alert],
    wazuh_url: str,
    total_events: int = 0,
    auth_token: str | None = None,
    username: str | None = None,
    password: str | None = None,
    verify_ssl: bool = True,
    timeout: float = 30.0,
) -> tuple[int, int]:
    """Send alerts to a Wazuh manager.

    Returns (success_count, error_count).

    Authentication can be supplied either via an existing bearer token
    (``auth_token``) or by username/password, in which case this function
    first hits ``/security/user/authenticate`` to obtain a token.
    """
    if not alerts:
        return 0, 0

    if verify_ssl:
        context: ssl.SSLContext | None = None
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    base = wazuh_url.rstrip("/")
    log = logging.getLogger("threatlens")

    if auth_token is None and username and password:
        auth_url = f"{base}/security/user/authenticate"
        import base64

        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        req = Request(
            auth_url,
            headers={"Authorization": f"Basic {creds}"},
            method="POST",
        )
        try:
            resp = urlopen(req, context=context, timeout=timeout)
            body = json.loads(resp.read().decode("utf-8"))
            auth_token = body.get("data", {}).get("token")
        except (HTTPError, URLError) as e:
            log.error("Wazuh auth failed: %s", e)
            return 0, len(alerts)

    if not auth_token:
        log.error("Wazuh: no auth token available")
        return 0, len(alerts)

    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
    }

    success = 0
    errors = 0
    events_url = f"{base}/events"

    for alert in alerts:
        payload = json.dumps({"events": [_build_event(alert, total_events)]}).encode("utf-8")
        req = Request(events_url, data=payload, headers=headers, method="POST")
        try:
            urlopen(req, context=context, timeout=timeout)
            success += 1
        except HTTPError as e:
            log.error("Wazuh post failed (HTTP %s): %s", e.code, e.reason)
            errors += 1
        except URLError as e:
            log.error("Wazuh connection error: %s", e.reason)
            errors += 1
            break

    return success, errors
