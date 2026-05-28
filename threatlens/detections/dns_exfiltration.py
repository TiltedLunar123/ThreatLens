"""Detect DNS-based exfiltration and tunneling patterns."""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, LogEvent, Severity
from threatlens.utils import find_dense_windows


def _shannon_entropy(label: str) -> float:
    """Return the Shannon entropy of a domain label in bits."""
    if not label:
        return 0.0
    counts: dict[str, int] = {}
    for ch in label:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(label)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _extract_query(event: LogEvent) -> str:
    """Pull a DNS query string from common log shapes."""
    raw = event.raw or {}
    for key in ("QueryName", "query_name", "query", "dns_query", "Name", "name"):
        value = raw.get(key)
        if value:
            return str(value)
    event_data = raw.get("EventData") or {}
    if isinstance(event_data, dict):
        for key in ("QueryName", "Query", "Name"):
            value = event_data.get(key)
            if value:
                return str(value)
    return ""


# Sysmon DNS query and common DNS server event IDs.
_DNS_EVENT_IDS = {22, 5353}


class DnsExfiltrationDetector(DetectionRule):
    """Detects bursts of high-entropy DNS queries from a single host.

    A burst of long, high-entropy subdomains targeting an unusual number of
    distinct second-level domains is a classic signal of DNS tunneling or
    data exfiltration via DNS (MITRE T1048.003 / T1071.004).
    """

    name = "DNS Exfiltration / Tunneling"
    description = "High-entropy DNS query burst from a single host"
    mitre_tactic = "Exfiltration"
    mitre_technique = "T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.threshold = int(self.config.get("dns_query_threshold", 25))
        self.window_seconds = int(self.config.get("dns_window_seconds", 60))
        self.min_label_length = int(self.config.get("dns_min_label_length", 20))
        self.min_entropy_bits = float(self.config.get("dns_min_entropy_bits", 3.5))

    def _is_suspicious_query(self, query: str) -> bool:
        if not query or "." not in query:
            return False
        label = query.split(".", 1)[0]
        if len(label) < self.min_label_length:
            return False
        return _shannon_entropy(label) >= self.min_entropy_bits

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        suspicious: list[LogEvent] = []
        queries_by_event: dict[int, str] = {}

        for event in events:
            if event.event_id not in _DNS_EVENT_IDS:
                continue
            query = _extract_query(event)
            if not self._is_suspicious_query(query):
                continue
            suspicious.append(event)
            queries_by_event[id(event)] = query

        if not suspicious:
            return []

        by_host: dict[str, list[LogEvent]] = defaultdict(list)
        for event in suspicious:
            host = event.computer or "unknown"
            by_host[host].append(event)

        alerts: list[Alert] = []
        for host, host_events in by_host.items():
            windows = find_dense_windows(host_events, self.window_seconds, self.threshold)
            for window in windows:
                queries = [queries_by_event[id(e)] for e in window]
                parents = {q.split(".", 1)[1] for q in queries if "." in q}
                severity = (
                    Severity.CRITICAL
                    if len(window) >= self.threshold * 3
                    else Severity.HIGH
                )

                evidence = [
                    {
                        "timestamp": e.timestamp_str,
                        "computer": e.computer,
                        "username": e.username,
                        "query": queries_by_event[id(e)][:200],
                        "event_id": e.event_id,
                    }
                    for e in window[:10]
                ]

                parent_label = (
                    ", ".join(sorted(parents)[:3])
                    if parents
                    else "unknown parent domain(s)"
                )
                alerts.append(
                    Alert(
                        rule_name="DNS Exfiltration Burst",
                        severity=severity,
                        description=(
                            f"{len(window)} high-entropy DNS queries from {host} "
                            f"in {self.window_seconds}s spanning "
                            f"{len(parents)} parent domain(s): {parent_label}"
                        ),
                        timestamp=window[0].timestamp,
                        evidence=evidence,
                        mitre_tactic=self.mitre_tactic,
                        mitre_technique=self.mitre_technique,
                        recommendation=(
                            f"Inspect outbound DNS from {host}. High-entropy "
                            "subdomains often encode exfiltrated data. Block "
                            "the parent domain(s) at the resolver and isolate "
                            "the host pending review."
                        ),
                    )
                )

        return alerts
