"""ThreatLens command-line interface."""

from __future__ import annotations

import argparse
import logging
import sys

# Re-export symbols that existing code and tests import from cli
from threatlens import __version__
from threatlens.allowlist import _alert_allowed, load_allowlist  # noqa: F401
from threatlens.config import (  # noqa: F401
    _FORMAT_EXTENSIONS,
    _build_detectors,
    collect_log_files,
    load_rules_config,
)
from threatlens.detections import ALL_DETECTORS
from threatlens.follower import _flush_follow_buffer, run_follow  # noqa: F401
from threatlens.report import print_banner
from threatlens.scanner import run_scan

logger = logging.getLogger("threatlens")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatlens",
        description="ThreatLens - Log Analysis & Threat Hunting CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  threatlens scan logs/security.json\n"
            "  threatlens scan logs/evidence.evtx\n"
            "  threatlens scan logs/ --output report.html --format html\n"
            "  threatlens scan events.json --min-severity high --verbose\n"
            "  threatlens scan logs/ --sigma-rules sigma/rules/windows/\n"
            "  threatlens scan logs/ --custom-rules my_rules/\n"
            "  threatlens scan logs/ --elastic-url http://localhost:9200\n"
            "  threatlens scan logs/ --timeline attack_timeline.html\n"
            "  threatlens follow /var/log/syslog --input-format syslog\n"
            "  threatlens rules\n"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"threatlens {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan command ---
    scan_parser = subparsers.add_parser("scan", help="Analyze log files for threats")
    scan_parser.add_argument("path", type=str, help="Path to a log file or directory of log files")
    scan_parser.add_argument("--output", "-o", type=str, default=None, help="Output file path for the report")
    scan_parser.add_argument("--format", "-f", choices=["json", "csv", "html", "md"], default="json", help="Output format (default: json)")
    scan_parser.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default="low", help="Minimum severity level to report (default: low)")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed evidence for each alert")
    scan_parser.add_argument("--quiet", "-q", action="store_true", help="Suppress banner and only show alerts")
    scan_parser.add_argument("--rules-file", type=str, default=None, help="Path to a YAML rules configuration file (default: rules/default_rules.yaml)")
    scan_parser.add_argument("--input-format", choices=["json", "evtx", "syslog", "cef"], default=None, help="Force input format instead of auto-detecting from extension")
    scan_parser.add_argument("--custom-rules", type=str, default=None, help="Path to a YAML custom rules file or directory")
    scan_parser.add_argument("--sigma-rules", type=str, default=None, help="Path to a Sigma rule file or directory of Sigma rules")
    scan_parser.add_argument("--elastic-url", type=str, default=None, help="Elasticsearch URL to send alerts to (e.g. http://localhost:9200)")
    scan_parser.add_argument("--elastic-index", type=str, default="threatlens-alerts", help="Elasticsearch index name (default: threatlens-alerts)")
    scan_parser.add_argument("--elastic-api-key", type=str, default=None, help="Elasticsearch API key for authentication")
    scan_parser.add_argument("--timeline", type=str, default=None, help="Output path for HTML attack timeline visualization")
    scan_parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default=None, help="Exit with code 2 if any alert meets or exceeds this severity")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored output (useful for CI/piped output)")
    scan_parser.add_argument("--recursive", "-r", action="store_true", help="Recursively scan subdirectories for log files")
    scan_parser.add_argument("--summary-only", action="store_true", help="Show only the summary table, suppress individual alerts")
    scan_parser.add_argument("--allowlist", type=str, default=None, help="Path to a YAML allowlist file for suppressing known-good alerts")
    scan_parser.add_argument("--profile", action="store_true", help="Output timing for each scan phase")
    scan_parser.add_argument("--plugin-dir", type=str, default=None, help="Path to a directory of custom Python detector plugins")
    scan_parser.add_argument("--exclude", action="append", default=None, metavar="DETECTOR", help="Disable a built-in detector by name (may be repeated). Match is case-insensitive substring against detector class or display name.")
    scan_parser.add_argument("--wazuh-url", type=str, default=None, help="Wazuh manager API URL (e.g. https://wazuh:55000)")
    scan_parser.add_argument("--wazuh-user", type=str, default=None, help="Wazuh API username")
    scan_parser.add_argument("--wazuh-password", type=str, default=None, help="Wazuh API password")
    scan_parser.add_argument("--wazuh-token", type=str, default=None, help="Pre-issued Wazuh API bearer token (use instead of user/password)")
    scan_parser.add_argument("--splunk-url", type=str, default=None, help="Splunk HEC URL (e.g. https://splunk:8088)")
    scan_parser.add_argument("--splunk-token", type=str, default=None, help="Splunk HEC token")
    scan_parser.add_argument("--splunk-index", type=str, default="main", help="Splunk HEC index (default: main)")
    scan_parser.add_argument("--splunk-sourcetype", type=str, default="threatlens:alert", help="Splunk sourcetype")
    scan_parser.add_argument("--navigator-layer", type=str, default=None, help="Write an ATT&CK Navigator JSON layer to this path")
    scan_parser.add_argument("--stix", type=str, default=None, help="Write a STIX 2.1 bundle to this path")
    scan_parser.add_argument("--insecure", action="store_true", help="Skip TLS verification for Wazuh / Splunk / Elasticsearch")

    # --- follow command ---
    follow_parser = subparsers.add_parser("follow", help="Real-time log tailing mode (like tail -f with detection)")
    follow_parser.add_argument("path", type=str, help="Path to a log file to tail")
    follow_parser.add_argument("--input-format", choices=["json", "syslog", "cef"], default=None, help="Force input format (default: auto-detect from extension)")
    follow_parser.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default="low", help="Minimum severity level to report (default: low)")
    follow_parser.add_argument("--rules-file", type=str, default=None, help="Path to a YAML rules configuration file")
    follow_parser.add_argument("--custom-rules", type=str, default=None, help="Path to custom YAML rules file or directory")
    follow_parser.add_argument("--sigma-rules", type=str, default=None, help="Path to a Sigma rule file or directory")
    follow_parser.add_argument("--buffer-size", type=int, default=100, help="Number of events to buffer before running detection (default: 100)")
    follow_parser.add_argument("--flush-interval", type=float, default=5.0, help="Seconds between detection flushes (default: 5.0)")

    # --- rules command ---
    subparsers.add_parser("rules", help="List all available detection rules")

    # --- summary command ---
    summary_parser = subparsers.add_parser(
        "summary",
        help="Print a summary of a previously generated JSON report",
    )
    summary_parser.add_argument("report", type=str, help="Path to a ThreatLens JSON report")
    summary_parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    # --- dashboard command ---
    dash_parser = subparsers.add_parser("dashboard", help="Launch the Streamlit dashboard for a JSON report")
    dash_parser.add_argument("report", type=str, help="Path to a ThreatLens JSON report")
    dash_parser.add_argument("--port", type=int, default=8501, help="Port to bind the dashboard to (default: 8501)")
    dash_parser.add_argument("--headless", action="store_true", help="Run Streamlit in headless mode (no browser auto-open)")
    dash_parser.add_argument("--workdir", type=str, default=None, help="Directory to materialize the dashboard app into")

    return parser


def run_rules() -> int:
    """List all available detection rules."""
    print_banner()
    print("  Available Detection Rules:\n")
    for detector_cls in ALL_DETECTORS:
        d = detector_cls()
        print(f"  - {d.name}")
        print(f"    {d.description}")
        if d.mitre_technique:
            print(f"    MITRE: {d.mitre_tactic} / {d.mitre_technique}")
        print()
    return 0


def run_summary(args: argparse.Namespace) -> int:
    """Print a brief summary of an existing JSON report without re-scanning."""
    import json
    from pathlib import Path

    from threatlens.utils import set_no_color

    if getattr(args, "no_color", False):
        set_no_color(True)

    report_path = Path(args.report)
    if not report_path.is_file():
        logger.error("Report file not found: %s", report_path)
        return 1

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to read JSON report %s: %s", report_path, exc)
        return 1

    meta = data.get("report_metadata", {}) if isinstance(data, dict) else {}
    severity_summary = (
        data.get("severity_summary", {}) if isinstance(data, dict) else {}
    )
    alerts = data.get("alerts", []) if isinstance(data, dict) else []

    print_banner()
    print(f"  Report:        {report_path}")
    if meta.get("generated_at"):
        print(f"  Generated:     {meta['generated_at']}")
    if meta.get("version"):
        print(f"  Tool version:  {meta['version']}")
    total_events = meta.get("total_events_analyzed", "?")
    total_alerts = meta.get("total_alerts", len(alerts))
    print(f"  Events:        {total_events}")
    print(f"  Alerts:        {total_alerts}")
    print()
    print("  Severity breakdown:")
    for sev in ("critical", "high", "medium", "low"):
        count = severity_summary.get(sev, 0)
        print(f"    {sev.upper():<10} {count}")
    print()

    # Top rules by frequency
    rule_counts: dict[str, int] = {}
    for alert in alerts:
        name = alert.get("rule_name", "Unknown") if isinstance(alert, dict) else "Unknown"
        rule_counts[name] = rule_counts.get(name, 0) + 1

    if rule_counts:
        print("  Top rules:")
        ranked = sorted(rule_counts.items(), key=lambda x: -x[1])[:5]
        for name, count in ranked:
            print(f"    {count:>4}  {name}")
        print()
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Configure logging based on --verbose
    log_level = logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    if args.command == "scan":
        return run_scan(args)
    elif args.command == "follow":
        return run_follow(args)
    elif args.command == "rules":
        return run_rules()
    elif args.command == "summary":
        return run_summary(args)
    elif args.command == "dashboard":
        from threatlens.dashboard import run_dashboard
        return run_dashboard(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
