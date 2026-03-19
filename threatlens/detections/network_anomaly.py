"""Detect network anomalies: DNS tunneling, beaconing, and unusual ports."""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Any

from threatlens.detections.base import DetectionRule
from threatlens.models import Alert, EventCategory, LogEvent, Severity

# Common DNS tunneling indicators
_DNS_TUNNEL_SUBDOMAIN_LEN = 40  # subdomains longer than this are suspicious
_DNS_TUNNEL_ENTROPY_THRESHOLD = 3.5  # high entropy in subdomain suggests encoding

# Beaconing detection
_BEACON_MIN_CONNECTIONS = 10  # minimum connections to analyze for beaconing
_BEACON_JITTER_THRESHOLD = 0.15  # max coefficient of variation for regular intervals

# Unusual ports (non-standard for outbound)
_COMMON_PORTS = {
    80, 443, 53, 22, 25, 110, 143, 993, 995, 587, 8080, 8443, 3389, 445, 139, 135,
    389, 636, 88, 464, 123, 161, 162, 514, 5060, 5061,
}


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    import math
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class NetworkAnomalyDetector(DetectionRule):
    """Detects DNS tunneling, beaconing patterns, and unusual port usage.

    Analyzes network events for:
    - DNS queries with abnormally long or high-entropy subdomains (tunneling)
    - Regular-interval connections to the same destination (beaconing / C2)
    - Outbound connections on unusual ports
    """

    name = "Network Anomaly Detection"
    description = "DNS tunneling, beaconing, or unusual port activity"
    mitre_tactic = "Command and Control"
    mitre_technique = "T1071 - Application Layer Protocol"

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.beacon_min_connections = int(
            self.config.get("beacon_min_connections", _BEACON_MIN_CONNECTIONS)
        )
        self.beacon_jitter_threshold = float(
            self.config.get("beacon_jitter_threshold", _BEACON_JITTER_THRESHOLD)
        )

    def analyze(self, events: list[LogEvent]) -> list[Alert]:
        alerts: list[Alert] = []
        alerts.extend(self._detect_dns_tunneling(events))
        alerts.extend(self._detect_beaconing(events))
        alerts.extend(self._detect_unusual_ports(events))
        return alerts

    def _detect_dns_tunneling(self, events: list[LogEvent]) -> list[Alert]:
        """Detect potential DNS tunneling via long/high-entropy subdomains."""
        alerts: list[Alert] = []
        dns_events = [
            e for e in events
            if e.category == EventCategory.NETWORK
            and self._get_query_name(e)
        ]

        for event in dns_events:
            query = self._get_query_name(event)
            if not query:
                continue

            # Extract subdomain (everything before the last two labels)
            parts = query.split(".")
            if len(parts) < 3:
                continue

            subdomain = ".".join(parts[:-2])
            if len(subdomain) >= _DNS_TUNNEL_SUBDOMAIN_LEN:
                entropy = _shannon_entropy(subdomain)
                if entropy >= _DNS_TUNNEL_ENTROPY_THRESHOLD:
                    alerts.append(Alert(
                        rule_name="DNS Tunneling Suspected",
                        severity=Severity.HIGH,
                        description=(
                            f"High-entropy DNS query detected: {query[:80]}... "
                            f"(subdomain length={len(subdomain)}, entropy={entropy:.2f})"
                        ),
                        timestamp=event.timestamp,
                        evidence=[{
                            "timestamp": event.timestamp_str,
                            "query": query[:200],
                            "subdomain_length": len(subdomain),
                            "entropy": round(entropy, 2),
                            "computer": event.computer,
                            "username": event.username,
                        }],
                        mitre_tactic="Command and Control",
                        mitre_technique="T1071.004 - DNS",
                        recommendation=(
                            "Investigate the DNS query for data exfiltration. "
                            "Check if the domain is legitimate or associated with C2 infrastructure."
                        ),
                    ))

        return alerts

    def _detect_beaconing(self, events: list[LogEvent]) -> list[Alert]:
        """Detect regular-interval connections suggesting C2 beaconing."""
        alerts: list[Alert] = []

        # Group network events by (source -> destination) pairs
        connections: dict[str, list[LogEvent]] = defaultdict(list)
        for event in events:
            if event.category != EventCategory.NETWORK:
                continue
            dest_ip = event.raw.get("DestinationIp", event.raw.get("dest_ip", ""))
            if not dest_ip:
                continue
            key = f"{event.source_ip or event.computer}->{dest_ip}"
            connections[key].append(event)

        for conn_key, conn_events in connections.items():
            if len(conn_events) < self.beacon_min_connections:
                continue

            # Calculate inter-arrival times
            sorted_events = sorted(conn_events, key=lambda e: e.timestamp)
            intervals = [
                (sorted_events[i + 1].timestamp - sorted_events[i].timestamp).total_seconds()
                for i in range(len(sorted_events) - 1)
            ]

            if not intervals or max(intervals) == 0:
                continue

            mean_interval = statistics.mean(intervals)
            if mean_interval < 1:
                continue  # too fast, likely normal traffic

            stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
            cv = stdev / mean_interval if mean_interval > 0 else float("inf")

            if cv <= self.beacon_jitter_threshold:
                alerts.append(Alert(
                    rule_name="C2 Beaconing Detected",
                    severity=Severity.HIGH,
                    description=(
                        f"Regular-interval connections detected: {conn_key} "
                        f"({len(conn_events)} connections, interval ~{mean_interval:.1f}s, "
                        f"jitter={cv:.3f})"
                    ),
                    timestamp=sorted_events[0].timestamp,
                    evidence=[{
                        "timestamp": e.timestamp_str,
                        "source": conn_key.split("->")[0],
                        "destination": conn_key.split("->")[1],
                        "computer": e.computer,
                    } for e in sorted_events[:10]],
                    mitre_tactic="Command and Control",
                    mitre_technique="T1071 - Application Layer Protocol",
                    recommendation=(
                        "Investigate the destination IP for C2 infrastructure. "
                        "Check for known malware families using this beacon interval."
                    ),
                ))

        return alerts

    def _detect_unusual_ports(self, events: list[LogEvent]) -> list[Alert]:
        """Detect outbound connections on unusual ports."""
        alerts: list[Alert] = []
        unusual_by_port: dict[int, list[LogEvent]] = defaultdict(list)

        for event in events:
            if event.category != EventCategory.NETWORK:
                continue
            dest_port = event.raw.get("DestinationPort", event.raw.get("dest_port", 0))
            try:
                port = int(dest_port)
            except (ValueError, TypeError):
                continue

            if port > 0 and port not in _COMMON_PORTS:
                unusual_by_port[port].append(event)

        for port, port_events in unusual_by_port.items():
            if len(port_events) < 3:
                continue  # ignore one-off connections

            severity = Severity.MEDIUM
            if port in {4444, 5555, 6666, 1337, 31337, 12345}:
                severity = Severity.HIGH  # commonly used by malware

            alerts.append(Alert(
                rule_name="Unusual Port Activity",
                severity=severity,
                description=(
                    f"{len(port_events)} outbound connections on unusual port {port}"
                ),
                timestamp=port_events[0].timestamp,
                evidence=[{
                    "timestamp": e.timestamp_str,
                    "port": port,
                    "computer": e.computer,
                    "source_ip": e.source_ip,
                    "username": e.username,
                } for e in port_events[:10]],
                mitre_tactic="Command and Control",
                mitre_technique="T1571 - Non-Standard Port",
                recommendation=(
                    f"Investigate outbound traffic on port {port}. "
                    "Verify if this is legitimate application traffic or potential C2."
                ),
            ))

        return alerts

    @staticmethod
    def _get_query_name(event: LogEvent) -> str:
        """Extract DNS query name from event."""
        return (
            event.raw.get("QueryName", "")
            or event.raw.get("query", "")
            or event.raw.get("dns_query", "")
            or event.raw.get("qname", "")
        )
