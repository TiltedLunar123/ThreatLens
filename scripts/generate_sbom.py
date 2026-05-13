"""Generate a CycloneDX 1.5 SBOM for ThreatLens using only the stdlib.

The script enumerates every distribution currently importable in the
environment, derives PURLs for each, captures hashes when available
through importlib.metadata, and emits a CycloneDX JSON document.

Usage:
    python scripts/generate_sbom.py [--output sbom.json] [--include-self]

The output is intentionally minimal but conforms to the CycloneDX 1.5
schema and is consumable by Grype, Trivy, Dependency-Track, and the
GitHub Dependency Submission API.

Reference: https://cyclonedx.org/docs/1.5/json/
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from importlib.metadata import Distribution, distributions
from pathlib import Path
from typing import Any


def _purl(name: str, version: str) -> str:
    """Build a PURL for a Python distribution."""
    return f"pkg:pypi/{name.lower().replace('_', '-')}@{version}"


def _file_hashes(dist: Distribution) -> list[dict[str, str]]:
    """Compute SHA-256 hashes of the distribution's wheel record entries when accessible."""
    files = dist.files or []
    hashes: list[dict[str, str]] = []
    for f in files[:50]:
        try:
            path = Path(str(f.locate()))
            if path.is_file():
                h = hashlib.sha256(path.read_bytes()).hexdigest()
                hashes.append({"alg": "SHA-256", "content": h})
                break
        except (FileNotFoundError, OSError):
            continue
    return hashes


def _component(dist: Distribution) -> dict[str, Any]:
    """Build one CycloneDX component dict for a distribution."""
    meta = dist.metadata
    name = meta.get("Name", "unknown")
    version = meta.get("Version", "0.0.0")
    homepage = meta.get("Home-page", "")
    license_field = meta.get("License", "")
    summary = meta.get("Summary", "")
    author = meta.get("Author", "")

    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": f"pkg:pypi/{name}@{version}",
        "name": name,
        "version": version,
        "purl": _purl(name, version),
        "scope": "required",
    }
    if summary:
        component["description"] = summary
    if homepage:
        component["externalReferences"] = [{"type": "website", "url": homepage}]
    if license_field:
        component["licenses"] = [{"license": {"name": license_field}}]
    if author:
        component["author"] = author
    hashes = _file_hashes(dist)
    if hashes:
        component["hashes"] = hashes
    return component


def build_sbom(include_self: bool = True) -> dict[str, Any]:
    """Build a CycloneDX 1.5 SBOM dict for the current Python environment."""
    components: list[dict[str, Any]] = []
    self_component: dict[str, Any] | None = None

    for dist in distributions():
        comp = _component(dist)
        if comp["name"].lower() == "threatlens":
            self_component = comp
            continue
        components.append(comp)

    components.sort(key=lambda c: (c["name"].lower(), c["version"]))

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "tools": [{
                "vendor": "ThreatLens",
                "name": "generate_sbom.py",
                "version": "1.0",
            }],
        },
        "components": components,
    }

    if include_self and self_component:
        self_component["type"] = "application"
        bom["metadata"]["component"] = self_component

    return bom


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("sbom.cdx.json"),
        help="Output file (default: sbom.cdx.json)",
    )
    parser.add_argument(
        "--no-self",
        action="store_true",
        help="Do not include the ThreatLens project itself as the SBOM metadata component",
    )
    args = parser.parse_args()

    bom = build_sbom(include_self=not args.no_self)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(bom, indent=2), encoding="utf-8")

    print(
        f"Wrote {args.output} with {len(bom['components'])} component(s)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
