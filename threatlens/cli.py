"""ThreatLens command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from threatlens.detections import ALL_DETECTORS
from threatlens.models import Severity
from threatlens.parsers import detect_format, load_events
from threatlens.report import (
    export_csv,
    export_json,
    print_alerts,
    print_banner,
    print_summary,
)

# File extensions recognized per input format
_FORMAT_EXTENSIONS: dict[str, list[str]] = {
    "json": ["*.json", "*.ndjson", "*.jsonl"],
    "evtx": ["*.evtx"],
    "syslog": ["*.log", "*.syslog"],
    "cef": ["*.cef"],
}


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
    scan_parser.add_argument(
        "path",
        type=str,
        help="Path to a log file or directory of log files",
    )
    scan_parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output file path for the report",
    )
    scan_parser.add_argument(
        "--format", "-f",
        choices=["json", "csv", "html"],
        default="json",
        help="Output format (default: json)",
    )
    scan_parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity level to report (default: low)",
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed evidence for each alert",
    )
    scan_parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress banner and only show alerts",
    )
    scan_parser.add_argument(
        "--rules-file",
        type=str,
        default=None,
        help="Path to a YAML rules configuration file (default: rules/default_rules.yaml)",
    )
    scan_parser.add_argument(
        "--input-format",
        choices=["json", "evtx", "syslog", "cef"],
        default=None,
        help="Force input format instead of auto-detecting from extension",
    )
    scan_parser.add_argument(
        "--custom-rules",
        type=str,
        default=None,
        help="Path to a YAML custom rules file or directory",
    )
    scan_parser.add_argument(
        "--sigma-rules",
        type=str,
        default=None,
        help="Path to a Sigma rule file or directory of Sigma rules",
    )
    scan_parser.add_argument(
        "--elastic-url",
        type=str,
        default=None,
        help="Elasticsearch URL to send alerts to (e.g. http://localhost:9200)",
    )
    scan_parser.add_argument(
        "--elastic-index",
        type=str,
        default="threatlens-alerts",
        help="Elasticsearch index name (default: threatlens-alerts)",
    )
    scan_parser.add_argument(
        "--elastic-api-key",
        type=str,
        default=None,
        help="Elasticsearch API key for authentication",
    )
    scan_parser.add_argument(
        "--timeline",
        type=str,
        default=None,
        help="Output path for HTML attack timeline visualization",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Exit with code 2 if any alert meets or exceeds this severity",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (useful for CI/piped output)",
    )
    scan_parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Recursively scan subdirectories for log files",
    )
    scan_parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Show only the summary table, suppress individual alerts",
    )
    scan_parser.add_argument(
        "--allowlist",
        type=str,
        default=None,
        help="Path to a YAML allowlist file for suppressing known-good alerts",
    )

    # --- follow command ---
    follow_parser = subparsers.add_parser(
        "follow", help="Real-time log tailing mode (like tail -f with detection)"
    )
    follow_parser.add_argument(
        "path",
        type=str,
        help="Path to a log file to tail",
    )
    follow_parser.add_argument(
        "--input-format",
        choices=["json", "syslog", "cef"],
        default=None,
        help="Force input format (default: auto-detect from extension)",
    )
    follow_parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity level to report (default: low)",
    )
    follow_parser.add_argument(
        "--rules-file",
        type=str,
        default=None,
        help="Path to a YAML rules configuration file",
    )
    follow_parser.add_argument(
        "--custom-rules",
        type=str,
        default=None,
        help="Path to custom YAML rules file or directory",
    )
    follow_parser.add_argument(
        "--sigma-rules",
        type=str,
        default=None,
        help="Path to a Sigma rule file or directory",
    )
    follow_parser.add_argument(
        "--buffer-size",
        type=int,
        default=100,
        help="Number of events to buffer before running detection (default: 100)",
    )
    follow_parser.add_argument(
        "--flush-interval",
        type=float,
        default=5.0,
        help="Seconds between detection flushes (default: 5.0)",
    )

    # --- rules command ---
    subparsers.add_parser("rules", help="List all available detection rules")

    return parser


def load_rules_config(rules_path: Path | None) -> dict[str, Any]:
    """Load detection rule configuration from a YAML file."""
    if rules_path is None:
        default = Path(__file__).parent.parent / "rules" / "default_rules.yaml"
        if default.exists():
            rules_path = default
        else:
            return {}

    if not rules_path.exists():
        print(f"Warning: Rules file not found: {rules_path}", file=sys.stderr)
        return {}

    with open(rules_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}


def collect_log_files(
    path: Path,
    input_format: str | None = None,
    recursive: bool = False,
) -> list[Path]:
    """Gather log files from a file or directory path."""
    if path.is_file():
        return [path]
    if path.is_dir():
        if input_format and input_format in _FORMAT_EXTENSIONS:
            globs = _FORMAT_EXTENSIONS[input_format]
        else:
            globs = [g for exts in _FORMAT_EXTENSIONS.values() for g in exts]
        files: list[Path] = []
        for pattern in globs:
            if recursive:
                # rglob needs pattern like "*.json", same as glob
                files.extend(sorted(path.rglob(pattern)))
            else:
                files.extend(sorted(path.glob(pattern)))
        return sorted(set(files))
    return []


def _build_detectors(
    args: argparse.Namespace,
    rules_config: dict[str, Any],
) -> list[Any]:
    """Build the list of detectors: built-in + custom YAML + Sigma."""
    detectors: list[Any] = []

    # Built-in detectors
    for detector_cls in ALL_DETECTORS:
        flat_config: dict[str, Any] = {}
        for section in rules_config.values():
            if isinstance(section, dict):
                flat_config.update(section)
        detectors.append(detector_cls(config=flat_config))

    # Custom YAML rules
    custom_path = getattr(args, "custom_rules", None)
    if custom_path:
        from threatlens.rules.yaml_rules import load_yaml_rules
        yaml_rules = load_yaml_rules(Path(custom_path))
        detectors.extend(yaml_rules)

    # Sigma rules
    sigma_path = getattr(args, "sigma_rules", None)
    if sigma_path:
        from threatlens.rules.sigma_loader import load_sigma_rules
        sigma_rules = load_sigma_rules(Path(sigma_path))
        detectors.extend(sigma_rules)

    return detectors


def load_allowlist(path: Path) -> list[dict[str, Any]]:
    """Load suppression rules from a YAML allowlist file.

    Each entry may specify ``rule_name``, ``username``, and/or
    ``computer`` — an alert is suppressed when all specified fields match.
    """
    if not path.exists():
        print(f"Warning: Allowlist file not found: {path}", file=sys.stderr)
        return []
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if isinstance(data, dict):
        return data.get("allowlist", [])
    return []


def _alert_allowed(alert: Any, allowlist: list[dict[str, Any]]) -> str | None:
    """Return the reason string if the alert matches any allowlist entry (should be suppressed).

    Returns None if not suppressed.
    """
    for entry in allowlist:
        match = True
        if "rule_name" in entry and entry["rule_name"].lower() not in alert.rule_name.lower():
            match = False
        if "username" in entry:
            usernames = {ev.get("username", "") for ev in alert.evidence}
            if entry["username"].lower() not in {u.lower() for u in usernames}:
                match = False
        if "computer" in entry:
            computers = {ev.get("computer", "") for ev in alert.evidence}
            if entry["computer"].lower() not in {c.lower() for c in computers}:
                match = False
        if "source_ip" in entry:
            ips = {ev.get("source_ip", "") for ev in alert.evidence}
            if entry["source_ip"] not in ips:
                match = False
        if "severity" in entry:
            if entry["severity"].lower() != alert.severity.value.lower():
                match = False
        if "mitre_technique" in entry:
            if entry["mitre_technique"].upper() not in alert.mitre_technique.upper():
                match = False
        if "event_id" in entry:
            event_ids = {str(ev.get("event_id", "")) for ev in alert.evidence}
            if str(entry["event_id"]) not in event_ids:
                match = False
        if match:
            return entry.get("reason", "allowlisted")
    return None


def run_scan(args: argparse.Namespace) -> int:
    """Execute the scan command."""
    # Handle --no-color
    if getattr(args, "no_color", False):
        from threatlens.utils import set_no_color
        set_no_color(True)

    target = Path(args.path)
    input_format = getattr(args, "input_format", None)
    recursive = getattr(args, "recursive", False)
    log_files = collect_log_files(target, input_format, recursive=recursive)

    if not log_files:
        print(f"Error: No log files found at '{args.path}'", file=sys.stderr)
        return 1

    if not args.quiet:
        print_banner()
        print(f"  Scanning {len(log_files)} file(s)...\n")

    # Parse all events
    all_events = []
    for log_file in log_files:
        try:
            events = load_events(log_file, input_format)
            all_events.extend(events)
            if not args.quiet:
                print(f"  Parsed {len(events):>6,} events from {log_file.name}")
        except Exception as e:
            print(f"  Warning: Failed to parse {log_file.name}: {e}", file=sys.stderr)

    if not all_events:
        print("Error: No events could be parsed from the input files.", file=sys.stderr)
        return 1

    all_events.sort(key=lambda e: e.timestamp)

    # Load rules configuration
    rules_file = Path(args.rules_file) if args.rules_file else None
    rules_config = load_rules_config(rules_file)

    # Build detectors (built-in + custom + sigma)
    detectors = _build_detectors(args, rules_config)

    # Run detections
    start_time = time.time()
    all_alerts = []

    for detector in detectors:
        try:
            alerts = detector.analyze(all_events)
            all_alerts.extend(alerts)
        except Exception as e:
            name = getattr(detector, "name", detector.__class__.__name__)
            print(f"  Warning: Detector '{name}' failed: {e}", file=sys.stderr)

    elapsed = time.time() - start_time

    # Filter by minimum severity
    severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_sev = Severity(args.min_severity)
    min_index = severity_order.index(min_sev)
    filtered = [a for a in all_alerts if severity_order.index(a.severity) >= min_index]

    # Apply allowlist suppression
    allowlist_path = getattr(args, "allowlist", None)
    suppression_stats: dict[str, int] = {}
    if allowlist_path:
        allowlist = load_allowlist(Path(allowlist_path))
        if allowlist:
            kept: list = []
            for a in filtered:
                reason = _alert_allowed(a, allowlist)
                if reason is not None:
                    suppression_stats[reason] = suppression_stats.get(reason, 0) + 1
                else:
                    kept.append(a)
            suppressed_count = len(filtered) - len(kept)
            filtered = kept
            if suppressed_count and not args.quiet:
                print(f"  Allowlist suppressed {suppressed_count} alert(s):", file=sys.stderr)
                for reason, count in sorted(suppression_stats.items()):
                    print(f"    - {reason}: {count}", file=sys.stderr)
                print(file=sys.stderr)

    # Display results
    print_summary(filtered, len(all_events), elapsed)
    if not getattr(args, "summary_only", False):
        print_alerts(filtered, verbose=args.verbose)

    # Export report if requested
    if args.output:
        output_path = Path(args.output)
        if args.format == "csv":
            export_csv(filtered, output_path, len(all_events))
        elif args.format == "html":
            from threatlens.outputs.html_report import export_html
            export_html(filtered, output_path, len(all_events), elapsed)
        else:
            export_json(filtered, output_path, len(all_events))
        print(f"  Report saved to {output_path}\n")

    # Export timeline if requested
    if args.timeline:
        from threatlens.outputs.timeline import export_timeline
        timeline_path = Path(args.timeline)
        export_timeline(filtered, timeline_path, len(all_events))
        print(f"  Timeline saved to {timeline_path}\n")

    # Send to Elasticsearch if requested
    if args.elastic_url:
        from threatlens.outputs.elasticsearch import send_to_elasticsearch
        success, errors = send_to_elasticsearch(
            filtered,
            es_url=args.elastic_url,
            index=args.elastic_index,
            total_events=len(all_events),
            api_key=args.elastic_api_key,
        )
        print(f"  Elasticsearch: {success} indexed, {errors} errors\n")

    # Determine exit code based on --fail-on threshold (defaults to critical)
    fail_on = getattr(args, "fail_on", None) or "critical"
    fail_sev = Severity(fail_on)
    fail_index = severity_order.index(fail_sev)
    has_actionable = any(severity_order.index(a.severity) >= fail_index for a in filtered)
    return 2 if has_actionable else 0


def run_follow(args: argparse.Namespace) -> int:
    """Execute the follow (real-time tailing) command."""
    from threatlens.parsers.json_parser import parse_event
    from threatlens.parsers.syslog_parser import _parse_line

    target = Path(args.path)
    if not target.is_file():
        print(f"Error: File not found: {args.path}", file=sys.stderr)
        return 1

    input_format = args.input_format or detect_format(target)
    rules_file = Path(args.rules_file) if args.rules_file else None
    rules_config = load_rules_config(rules_file)
    detectors = _build_detectors(args, rules_config)

    severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_sev = Severity(args.min_severity)
    min_index = severity_order.index(min_sev)

    print_banner()
    print(f"  Tailing {target.name} (format: {input_format}) — Ctrl+C to stop\n")

    buffer = []
    last_flush = time.time()
    seen_alerts: set[str] = set()

    try:
        with open(target, encoding="utf-8", errors="replace") as f:
            # Seek to end of file
            f.seek(0, 2)

            while True:
                line = f.readline()
                if not line:
                    now = time.time()
                    if buffer and (now - last_flush) >= args.flush_interval:
                        _flush_follow_buffer(
                            buffer, detectors, severity_order, min_index, seen_alerts
                        )
                        buffer.clear()
                        last_flush = now
                    time.sleep(0.1)
                    continue

                line = line.strip()
                if not line:
                    continue

                event = None
                try:
                    if input_format in ("syslog", "cef"):
                        event = _parse_line(line, input_format)
                    else:
                        entry = json.loads(line)
                        event = parse_event(entry)
                except Exception:
                    continue

                if event:
                    buffer.append(event)

                if len(buffer) >= args.buffer_size:
                    _flush_follow_buffer(
                        buffer, detectors, severity_order, min_index, seen_alerts
                    )
                    buffer.clear()
                    last_flush = time.time()

    except KeyboardInterrupt:
        if buffer:
            _flush_follow_buffer(
                buffer, detectors, severity_order, min_index, seen_alerts
            )
        print("\n  Stopped.\n")
        return 0


def _flush_follow_buffer(
    events: list,
    detectors: list,
    severity_order: list,
    min_index: int,
    seen_alerts: set[str],
) -> None:
    """Run detectors against buffered events and print new alerts."""
    from threatlens.utils import bold, colorize

    for detector in detectors:
        try:
            alerts = detector.analyze(events)
        except Exception:
            continue

        for alert in alerts:
            if severity_order.index(alert.severity) < min_index:
                continue

            alert_key = f"{alert.rule_name}|{alert.timestamp_str}"
            if alert_key in seen_alerts:
                continue
            seen_alerts.add(alert_key)

            sev_tag = colorize(f"[{alert.severity.value.upper()}]", alert.severity)
            print(f"  {sev_tag} {bold(alert.rule_name)}")
            print(f"    {alert.description}")
            if alert.mitre_technique:
                print(f"    MITRE: {alert.mitre_tactic} / {alert.mitre_technique}")
            print()


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
