"""Streamlit dashboard for ThreatLens scan reports.

Launches a local Streamlit app that loads a ThreatLens JSON report and
provides interactive filters by severity, MITRE tactic, host, and rule.
The dashboard is intentionally minimal - it reads the same JSON that
``threatlens scan -f json -o report.json`` produces, so there is no
state outside the file the user pointed at.

Run with:

    threatlens dashboard report.json
    threatlens dashboard report.json --port 8502
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

_APP_SOURCE = '''
"""ThreatLens dashboard - Streamlit app entry point."""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

import streamlit as st


def _load_report(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


REPORT_PATH = os.environ.get("THREATLENS_REPORT")
if not REPORT_PATH:
    st.error("THREATLENS_REPORT environment variable is not set.")
    st.stop()

report_path = Path(REPORT_PATH)
if not report_path.exists():
    st.error(f"Report not found: {report_path}")
    st.stop()

report = _load_report(report_path)
alerts = report.get("alerts", [])
total_events = report.get("total_events", 0)

st.set_page_config(page_title="ThreatLens Dashboard", layout="wide")
st.title("ThreatLens Dashboard")
st.caption(f"Loaded {len(alerts)} alerts from {report_path.name} ({total_events:,} events analyzed)")

with st.sidebar:
    st.header("Filters")
    all_sevs = sorted({a.get("severity", "low") for a in alerts})
    sev_filter = st.multiselect("Severity", all_sevs, default=all_sevs)
    all_tactics = sorted({a.get("mitre_tactic", "") for a in alerts if a.get("mitre_tactic")})
    tactic_filter = st.multiselect("MITRE tactic", all_tactics, default=all_tactics)
    all_hosts = sorted({
        e.get("computer", "")
        for a in alerts
        for e in a.get("evidence", []) or []
        if e.get("computer")
    })
    host_filter = st.multiselect("Host", all_hosts, default=all_hosts)
    all_rules = sorted({a.get("rule_name", "") for a in alerts})
    rule_filter = st.multiselect("Rule", all_rules, default=all_rules)

def _matches(alert: dict) -> bool:
    if alert.get("severity") not in sev_filter:
        return False
    tactic = alert.get("mitre_tactic", "")
    if all_tactics and tactic and tactic not in tactic_filter:
        return False
    if alert.get("rule_name") not in rule_filter:
        return False
    if host_filter:
        ev_hosts = {e.get("computer") for e in alert.get("evidence", []) or []}
        if ev_hosts and not (ev_hosts & set(host_filter)):
            return False
    return True

filtered = [a for a in alerts if _matches(a)]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Alerts shown", len(filtered))
sev_counts = Counter(a.get("severity") for a in filtered)
c2.metric("Critical", sev_counts.get("critical", 0))
c3.metric("High", sev_counts.get("high", 0))
c4.metric("Medium + Low", sev_counts.get("medium", 0) + sev_counts.get("low", 0))

st.subheader("Severity distribution")
sev_data = {s: sev_counts.get(s, 0) for s in ["critical", "high", "medium", "low"]}
st.bar_chart(sev_data)

st.subheader("MITRE tactic spread")
tactic_counts = Counter(a.get("mitre_tactic") or "Uncategorized" for a in filtered)
st.bar_chart(dict(tactic_counts))

st.subheader("Alerts")
if not filtered:
    st.info("No alerts match the current filter set.")
else:
    for alert in filtered:
        sev = (alert.get("severity") or "").upper()
        icon = {"CRITICAL": ":red_circle:", "HIGH": ":large_orange_circle:",
                "MEDIUM": ":large_yellow_circle:", "LOW": ":large_blue_circle:"}.get(sev, "")
        with st.expander(f"{icon} [{sev}] {alert.get('rule_name')} - {alert.get('description')}"):
            cols = st.columns(3)
            cols[0].markdown(f"**Time:** {alert.get('timestamp')}")
            cols[1].markdown(f"**MITRE:** {alert.get('mitre_tactic')} / {alert.get('mitre_technique')}")
            cols[2].markdown(f"**Evidence count:** {alert.get('evidence_count')}")
            if alert.get("recommendation"):
                st.markdown(f"**Recommendation:** {alert.get('recommendation')}")
            if alert.get("evidence"):
                st.json(alert["evidence"], expanded=False)
'''


def _ensure_streamlit_available() -> bool:
    """Return True if the streamlit module is importable."""
    try:
        import streamlit  # noqa: F401
    except ImportError:
        return False
    return True


def _materialize_app(target_dir: Path) -> Path:
    """Write the Streamlit app source to disk so streamlit run can launch it."""
    target_dir.mkdir(parents=True, exist_ok=True)
    app_path = target_dir / "_threatlens_dashboard_app.py"
    app_path.write_text(_APP_SOURCE.lstrip(), encoding="utf-8")
    return app_path


def run_dashboard(args: Any) -> int:
    """Entry point invoked by the CLI dispatcher."""
    report_path = Path(args.report).resolve()
    if not report_path.exists():
        print(f"Report not found: {report_path}", file=sys.stderr)
        return 1

    if not _ensure_streamlit_available():
        print(
            "Streamlit is not installed. Install with:\n"
            "    pip install 'threatlens[dashboard]'",
            file=sys.stderr,
        )
        return 1

    target_dir = Path(args.workdir) if getattr(args, "workdir", None) else Path.home() / ".threatlens" / "dashboard"
    app_path = _materialize_app(target_dir)

    env = os.environ.copy()
    env["THREATLENS_REPORT"] = str(report_path)

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path),
        "--server.port",
        str(getattr(args, "port", 8501)),
        "--server.headless",
        "true" if getattr(args, "headless", False) else "false",
    ]
    print(
        f"Starting ThreatLens dashboard on port {getattr(args, 'port', 8501)} "
        f"with report {report_path.name}",
        file=sys.stderr,
    )
    return subprocess.call(cmd, env=env)


def main() -> int:
    """Allow invoking via ``python -m threatlens.dashboard``."""
    parser = argparse.ArgumentParser(description="Launch the ThreatLens Streamlit dashboard")
    parser.add_argument("report", type=str, help="Path to a ThreatLens JSON report")
    parser.add_argument("--port", type=int, default=8501)
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--workdir", type=str, default=None)
    return run_dashboard(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
