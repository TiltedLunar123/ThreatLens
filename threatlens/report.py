"""Report generation for ThreatLens scan results."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from threatlens import __version__
from threatlens.models import Alert, Severity
from threatlens.utils import bold, colorize


def print_banner() -> None:
    banner = r"""
  _____ _                    _   _
 |_   _| |__  _ __ ___  __ _| |_| |    ___ _ __  ___
   | | | '_ \| '__/ _ \/ _` | __| |   / _ \ '_ \/ __|
   | | | | | | | |  __/ (_| | |_| |__|  __/ | | \__ \
   |_| |_| |_|_|  \___|\__,_|\__|_____\___|_| |_|___/
    """
    print(f"\033[96m{banner}\033[0m")
    from threatlens import __version__
    print(f"  {bold('Log Analysis & Threat Hunting CLI')} v{__version__}\n")


def print_summary(alerts: list[Alert], total_events: int, elapsed: float) -> None:
    """Print a summary table of scan results to the terminal."""
    severity_counts = {s: 0 for s in Severity}
    for alert in alerts:
        severity_counts[alert.severity] += 1

    print(f"\n{'='*60}")
    print(bold("  SCAN SUMMARY"))
    print(f"{'='*60}")
    print(f"  Events analyzed:   {total_events:,}")
    print(f"  Alerts generated:  {len(alerts)}")
    print(f"  Scan duration:     {elapsed:.2f}s")
    print()

    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = severity_counts[severity]
        label = colorize(f"  {severity.value.upper():<12}", severity)
        print(f"{label} {count}")

    print(f"{'='*60}\n")


def print_alerts(alerts: list[Alert], verbose: bool = False) -> None:
    """Print individual alerts to the terminal."""
    if not alerts:
        print(colorize("  [+] No threats detected. Clean scan!", Severity.LOW))
        return

    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    sorted_alerts = sorted(
        alerts,
        key=lambda a: severity_order.get(a.severity, 99),
    )

    for _i, alert in enumerate(sorted_alerts, 1):
        severity_tag = colorize(f"[{alert.severity.value.upper()}]", alert.severity)
        print(f"  {severity_tag} {bold(alert.rule_name)}")
        print(f"    Time:       {alert.timestamp_str}")
        print(f"    Detail:     {alert.description}")

        if alert.mitre_technique:
            print(f"    MITRE:      {alert.mitre_tactic} / {alert.mitre_technique}")

        if alert.recommendation:
            print(f"    Action:     {alert.recommendation}")

        if verbose and alert.evidence:
            print(f"    Evidence ({len(alert.evidence)} items):")
            for ev in alert.evidence[:3]:
                for k, v in ev.items():
                    print(f"      {k}: {v}")
                print()

        print()


def export_json(alerts: list[Alert], output_path: Path, total_events: int) -> None:
    """Export alerts to a structured JSON report file."""
    report = {
        "report_metadata": {
            "tool": "ThreatLens",
            "version": __version__,
            "generated_at": datetime.now().isoformat(),
            "total_events_analyzed": total_events,
            "total_alerts": len(alerts),
        },
        "severity_summary": {
            s.value: sum(1 for a in alerts if a.severity == s)
            for s in Severity
        },
        "alerts": [a.to_dict() for a in alerts],
    }

    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def export_csv(alerts: list[Alert], output_path: Path, total_events: int = 0) -> None:
    """Export alerts to CSV format."""
    import csv

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # Write metadata row
        writer.writerow(["# ThreatLens Report", f"Total Events: {total_events}", f"Total Alerts: {len(alerts)}"])
        writer.writerow([
            "Timestamp", "Severity", "Rule", "Description",
            "MITRE Tactic", "MITRE Technique", "Recommendation", "Evidence Count",
        ])
        for alert in alerts:
            writer.writerow([
                alert.timestamp_str,
                alert.severity.value,
                alert.rule_name,
                alert.description,
                alert.mitre_tactic,
                alert.mitre_technique,
                alert.recommendation,
                len(alert.evidence),
            ])
