"""Scan command implementation for ThreatLens."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from threatlens.allowlist import _alert_allowed, load_allowlist
from threatlens.config import (
    _build_detectors,
    collect_log_files,
    load_rules_config,
    load_user_config,
)
from threatlens.models import Severity
from threatlens.parsers import load_events
from threatlens.report import (
    export_csv,
    export_json,
    print_alerts,
    print_banner,
    print_summary,
)

logger = logging.getLogger("threatlens")


def _merge_user_config(args: Any) -> None:
    """Merge user config file values into args (CLI takes precedence)."""
    user_cfg = load_user_config()
    if not user_cfg:
        return

    defaults = {
        "min_severity": "low",
        "custom_rules": None,
        "sigma_rules": None,
        "elastic_url": None,
        "elastic_index": "threatlens-alerts",
        "allowlist": None,
        "no_color": False,
        "recursive": False,
        "plugin_dir": None,
    }

    for key, default_val in defaults.items():
        # Only apply config file value if CLI didn't override
        current = getattr(args, key, default_val)
        if current == default_val and key in user_cfg:
            setattr(args, key, user_cfg[key])


def run_scan(args: Any) -> int:
    """Execute the scan command."""
    # Ensure logging is configured (in case we're called outside main())
    if not logging.getLogger("threatlens").handlers and not logging.root.handlers:
        logging.basicConfig(
            level=logging.WARNING,
            format="%(levelname)s: %(message)s",
        )

    # Merge config file settings
    _merge_user_config(args)

    # Handle --no-color
    if getattr(args, "no_color", False):
        from threatlens.utils import set_no_color
        set_no_color(True)

    target = Path(args.path)
    input_format = getattr(args, "input_format", None)
    recursive = getattr(args, "recursive", False)
    log_files = collect_log_files(target, input_format, recursive=recursive)

    if not log_files:
        logger.error("No log files found at '%s'", args.path)
        return 1

    do_profile = getattr(args, "profile", False)

    if not args.quiet:
        print_banner()
        print(f"  Scanning {len(log_files)} file(s)...\n")

    # Parse all events
    t_parse_start = time.time()
    all_events: list = []
    for log_file in log_files:
        try:
            events = load_events(log_file, input_format)
            all_events.extend(events)
            if not args.quiet:
                print(f"  Parsed {len(events):>6,} events from {log_file.name}")
        except Exception as e:
            logger.warning("Failed to parse %s: %s", log_file.name, e)

    if not all_events:
        logger.error("No events could be parsed from the input files.")
        return 1

    all_events.sort(key=lambda e: e.timestamp)
    t_parse_end = time.time()

    # Load rules configuration
    rules_file = Path(args.rules_file) if args.rules_file else None
    rules_config = load_rules_config(rules_file)

    # Build detectors (built-in + custom + sigma + plugins)
    detectors = _build_detectors(args, rules_config)

    # Run detections
    t_detect_start = time.time()
    all_alerts: list = []
    detector_timings: list[tuple[str, float, int]] = []

    for detector in detectors:
        try:
            dt_start = time.time()
            alerts = detector.analyze(all_events)
            dt_elapsed = time.time() - dt_start
            all_alerts.extend(alerts)
            name = getattr(detector, "name", detector.__class__.__name__)
            detector_timings.append((name, dt_elapsed, len(alerts)))
        except Exception as e:
            name = getattr(detector, "name", detector.__class__.__name__)
            logger.warning("Detector '%s' failed: %s", name, e)

    t_detect_end = time.time()

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
                logger.warning("Allowlist suppressed %d alert(s):", suppressed_count)
                for reason, count in sorted(suppression_stats.items()):
                    logger.warning("  - %s: %d", reason, count)

    # Display results
    t_report_start = time.time()
    elapsed = t_detect_end - t_parse_start
    print_summary(filtered, len(all_events), elapsed)
    if not getattr(args, "summary_only", False):
        print_alerts(filtered, verbose=args.verbose)
    t_report_end = time.time()

    # Profile output
    if do_profile:
        parse_time = t_parse_end - t_parse_start
        detect_time = t_detect_end - t_detect_start
        report_time = t_report_end - t_report_start
        total_time = t_report_end - t_parse_start
        print()
        print("  Timing:")
        print(f"    Parsing:         {parse_time:.2f}s")
        print(f"    Detection:       {detect_time:.2f}s")
        for name, dt, count in detector_timings:
            print(f"      {name + ':':<25} {dt:.2f}s  ({count} alerts)")
        print(f"    Reporting:       {report_time:.2f}s")
        print(f"    Total:           {total_time:.2f}s")
        print()

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
