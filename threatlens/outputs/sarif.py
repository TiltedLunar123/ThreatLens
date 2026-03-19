"""SARIF output format for GitHub Security tab integration."""

from __future__ import annotations

import json
from pathlib import Path

from threatlens import __version__
from threatlens.models import Alert, Severity

# Map ThreatLens severity to SARIF level
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def export_sarif(
    alerts: list[Alert],
    output_path: Path,
    total_events: int = 0,
) -> None:
    """Export alerts as a SARIF 2.1.0 JSON file.

    SARIF (Static Analysis Results Interchange Format) is supported natively
    by GitHub's Security tab and VS Code's SARIF Viewer extension.
    """
    rules: list[dict] = []
    rule_ids: dict[str, int] = {}
    results: list[dict] = []

    for alert in alerts:
        # Deduplicate rules by name
        if alert.rule_name not in rule_ids:
            rule_ids[alert.rule_name] = len(rules)
            rule_entry: dict = {
                "id": alert.rule_name.replace(" ", "-").lower(),
                "name": alert.rule_name,
                "shortDescription": {"text": alert.rule_name},
                "fullDescription": {"text": alert.description},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(alert.severity, "warning"),
                },
            }
            if alert.mitre_technique:
                rule_entry["helpUri"] = (
                    f"https://attack.mitre.org/techniques/{alert.mitre_technique.split(' ')[0].replace('.', '/')}/"
                )
            if alert.recommendation:
                rule_entry["help"] = {"text": alert.recommendation}
            rules.append(rule_entry)

        rule_index = rule_ids[alert.rule_name]

        result: dict = {
            "ruleId": rules[rule_index]["id"],
            "ruleIndex": rule_index,
            "level": _SARIF_LEVEL.get(alert.severity, "warning"),
            "message": {"text": alert.description},
            "properties": {
                "severity": alert.severity.value,
                "timestamp": alert.timestamp_str,
                "evidence_count": len(alert.evidence),
            },
        }
        if alert.mitre_tactic:
            result["properties"]["mitre_tactic"] = alert.mitre_tactic
        if alert.mitre_technique:
            result["properties"]["mitre_technique"] = alert.mitre_technique

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ThreatLens",
                        "version": __version__,
                        "informationUri": "https://github.com/TiltedLunar123/ThreatLens",
                        "rules": rules,
                    },
                },
                "results": results,
                "properties": {
                    "total_events_analyzed": total_events,
                },
            },
        ],
    }

    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
