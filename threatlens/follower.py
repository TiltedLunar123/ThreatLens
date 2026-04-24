"""Real-time log tailing mode for ThreatLens."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from threatlens.config import _build_detectors, load_rules_config
from threatlens.models import Severity
from threatlens.parsers import detect_format
from threatlens.report import print_banner
from threatlens.utils import bold, colorize

logger = logging.getLogger("threatlens")


def run_follow(args: Any) -> int:
    """Execute the follow (real-time tailing) command."""
    from threatlens.parsers.json_parser import parse_event
    from threatlens.parsers.syslog_parser import _parse_line

    target = Path(args.path)
    if not target.is_file():
        logger.error("File not found: %s", args.path)
        return 1

    input_format = args.input_format or detect_format(target)
    rules_file = Path(args.rules_file) if args.rules_file else None
    rules_config = load_rules_config(rules_file)
    detectors = _build_detectors(args, rules_config)

    severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_sev = Severity(args.min_severity)
    min_index = severity_order.index(min_sev)

    print_banner()
    print(f"  Tailing {target.name} (format: {input_format}) -- Ctrl+C to stop\n")

    buffer: list = []
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

    # Safety net: the tail loop above is `while True`, so execution only
    # reaches here when the loop is broken out of in the future without
    # raising KeyboardInterrupt. Keeps the declared -> int return honest.
    return 0


def _flush_follow_buffer(
    events: list,
    detectors: list,
    severity_order: list,
    min_index: int,
    seen_alerts: set[str],
) -> None:
    """Run detectors against buffered events and print new alerts."""
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
