"""GeoIP and threat intelligence enrichment for ThreatLens.

Provides IP-to-location lookup and known-bad IP reputation checks.
GeoIP requires the optional ``geoip2`` package and a MaxMind GeoLite2 database.
Threat intel uses a bundled set of public abuse feeds (no external dependency).
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class IPInfo:
    """Enrichment data for a single IP address."""

    ip: str
    country: str = ""
    city: str = ""
    asn: str = ""
    org: str = ""
    is_private: bool = False
    is_known_bad: bool = False
    reputation_tags: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"ip": self.ip}
        if self.country:
            result["country"] = self.country
        if self.city:
            result["city"] = self.city
        if self.asn:
            result["asn"] = self.asn
        if self.org:
            result["org"] = self.org
        result["is_private"] = self.is_private
        if self.is_known_bad:
            result["is_known_bad"] = True
            result["reputation_tags"] = self.reputation_tags or []
        return result


class GeoIPEnricher:
    """Enrich IP addresses with geolocation and threat reputation data.

    Usage::

        enricher = GeoIPEnricher(geoip_db="/path/to/GeoLite2-City.mmdb")
        info = enricher.lookup("8.8.8.8")
        print(info.country, info.city)

    If no GeoIP database is provided, only private-IP detection and threat
    intel lookups are performed (no external dependency required).
    """

    def __init__(
        self,
        geoip_db: str | Path | None = None,
        threat_intel_file: str | Path | None = None,
    ) -> None:
        self._reader: Any = None
        self._known_bad: set[str] = set()

        # Load GeoIP database (optional)
        if geoip_db:
            db_path = Path(geoip_db)
            if db_path.exists():
                try:
                    import geoip2.database  # type: ignore[import-untyped]

                    self._reader = geoip2.database.Reader(str(db_path))
                    logger.info("GeoIP database loaded: %s", db_path)
                except ImportError:
                    logger.warning(
                        "geoip2 package not installed. Install with: pip install threatlens[enrichment]"
                    )
                except Exception as exc:
                    logger.warning("Failed to load GeoIP database %s: %s", db_path, exc)
            else:
                logger.warning("GeoIP database not found: %s", db_path)

        # Load threat intel feed (plain text, one IP per line)
        if threat_intel_file:
            ti_path = Path(threat_intel_file)
            if ti_path.exists():
                for line in ti_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._known_bad.add(line)
                logger.info("Loaded %d threat intel IPs from %s", len(self._known_bad), ti_path)

    def lookup(self, ip: str) -> IPInfo:
        """Look up enrichment data for a single IP address."""
        info = IPInfo(ip=ip)

        # Check if private
        try:
            addr = ipaddress.ip_address(ip)
            info.is_private = addr.is_private or addr.is_loopback or addr.is_reserved
        except ValueError:
            return info

        if info.is_private:
            return info

        # GeoIP lookup
        if self._reader:
            try:
                response = self._reader.city(ip)
                info.country = response.country.iso_code or ""
                info.city = response.city.name or ""
                if hasattr(response, "traits"):
                    info.asn = str(getattr(response.traits, "autonomous_system_number", ""))
                    info.org = getattr(response.traits, "autonomous_system_organization", "") or ""
            except Exception:
                pass  # IP not in database

        # Threat intel check
        if ip in self._known_bad:
            info.is_known_bad = True
            info.reputation_tags = ["known-bad"]

        return info

    def enrich_alerts(self, alerts: list) -> list:
        """Add GeoIP info to alert evidence that contains source_ip fields."""
        for alert in alerts:
            for ev in alert.evidence:
                ip = ev.get("source_ip", "")
                if ip and ip != "-":
                    ip_info = self.lookup(ip)
                    if not ip_info.is_private:
                        ev["geo"] = ip_info.to_dict()
        return alerts

    def close(self) -> None:
        if self._reader:
            self._reader.close()

    def __enter__(self) -> GeoIPEnricher:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
