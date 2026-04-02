"""ThreatLens command-line interface."""

from __future__ import annotations

import argparse
import logging
import sys

# Re-export symbols that existing code and tests import from cli
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
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan command ---
    scan_parser = subparsers.add_parser("scan", help="Analyze log files for threats")
    scan_parser.add_argument("path", type=str, help="Path to a log file or directory of log files")
    scan_parser.add_argument("--output", "-o", type=str, default=None, help="Output file path for the report")
    scan_parser.add_argument("--format", "-f", choices=["json", "csv", "html"], default="json", help="Output format (default: json)")
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
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
