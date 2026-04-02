"""HTML report generation with severity charts for ThreatLens."""

from __future__ import annotations

import html
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from threatlens import __version__
from threatlens.models import Alert, Severity

# Color scheme for severity levels
_SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#f59e0b",
    Severity.MEDIUM: "#06b6d4",
    Severity.LOW: "#22c55e",
}


_MITRE_TACTICS = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Command and Control",
    "Impact",
]


def _build_mitre_heatmap(alerts: list[Alert]) -> str:
    """Generate an HTML heatmap grid of MITRE ATT&CK tactics and techniques."""
    # Group alerts by tactic -> technique -> count
    tactic_techniques: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for a in alerts:
        if a.mitre_tactic and a.mitre_technique:
            tactic_techniques[a.mitre_tactic][a.mitre_technique] += 1

    # If no MITRE-tagged alerts, skip the heatmap entirely
    if not tactic_techniques:
        return ""

    # Find global max count for color scaling
    max_count = max(
        count
        for techniques in tactic_techniques.values()
        for count in techniques.values()
    )

    def _cell_bg(count: int) -> str:
        """Return a background color interpolated from dim to bright cyan."""
        if max_count <= 1:
            ratio = 1.0
        else:
            ratio = count / max_count
        # Interpolate between #1e293b (0 alerts) and #0e7490 (max alerts)
        r = int(30 + (14 - 30) * ratio)
        g = int(41 + (116 - 41) * ratio)
        b = int(59 + (144 - 59) * ratio)
        return f"#{r:02x}{g:02x}{b:02x}"

    # Build column HTML
    columns_html = []
    for tactic in _MITRE_TACTICS:
        techniques = tactic_techniques.get(tactic, {})

        # Header cell
        has_hits = bool(techniques)
        header_style = (
            "background:#0f172a;color:#38bdf8;font-weight:bold;"
            if has_hits
            else "background:#0f172a;color:#475569;font-weight:bold;"
        )

        cells_html = ""
        if techniques:
            for tech_name, count in sorted(
                techniques.items(), key=lambda t: -t[1]
            ):
                bg = _cell_bg(count)
                cells_html += (
                    f'<div style="background:{bg};border-radius:4px;padding:6px 8px;'
                    f'margin-bottom:4px;font-size:0.78em;color:#e2e8f0;'
                    f'display:flex;justify-content:space-between;align-items:center;">'
                    f'<span style="overflow:hidden;text-overflow:ellipsis;'
                    f'white-space:nowrap;max-width:80%;"'
                    f' title="{html.escape(tech_name)}">{html.escape(tech_name)}</span>'
                    f'<span style="background:#0f172a;color:#38bdf8;border-radius:3px;'
                    f'padding:1px 6px;font-weight:bold;font-size:0.9em;'
                    f'flex-shrink:0;margin-left:4px;">{count}</span></div>'
                )
        else:
            cells_html = (
                '<div style="color:#334155;font-size:0.8em;'
                'text-align:center;padding:12px 0;">--</div>'
            )

        tactic_total = sum(techniques.values())
        count_badge = ""
        if tactic_total > 0:
            count_badge = (
                f'<span style="background:#38bdf8;color:#0f172a;border-radius:10px;'
                f'padding:1px 7px;font-size:0.75em;font-weight:bold;'
                f'margin-left:6px;">{tactic_total}</span>'
            )

        columns_html.append(
            f'<div style="min-width:155px;max-width:180px;flex:1 1 155px;">'
            f'<div style="{header_style}padding:8px 6px;border-radius:6px 6px 0 0;'
            f'text-align:center;font-size:0.78em;border-bottom:2px solid '
            f'{"#38bdf8" if has_hits else "#1e293b"};'
            f'white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"'
            f' title="{html.escape(tactic)}">'
            f'{html.escape(tactic)}{count_badge}</div>'
            f'<div style="padding:6px 4px;">{cells_html}</div>'
            f'</div>'
        )

    return (
        '<div style="background:#1e293b;border-radius:12px;padding:20px;'
        'margin:30px 0;">'
        '<h2 style="color:#38bdf8;margin-bottom:16px;font-size:1.25em;">'
        'MITRE ATT&amp;CK Coverage</h2>'
        '<div style="overflow-x:auto;">'
        '<div style="display:flex;gap:4px;min-width:max-content;">'
        + "".join(columns_html)
        + '</div></div></div>'
    )


def _severity_counts(alerts: list[Alert]) -> dict[str, int]:
    counts = {}
    for s in Severity:
        counts[s.value] = sum(1 for a in alerts if a.severity == s)
    return counts


def _donut_chart_svg(counts: dict[str, int], size: int = 200) -> str:
    """Generate an inline SVG donut chart for severity distribution."""
    total = sum(counts.values())
    if total == 0:
        return f'<svg width="{size}" height="{size}"><text x="50%" y="50%" text-anchor="middle" fill="#888">No alerts</text></svg>'

    cx, cy, r = size // 2, size // 2, size // 2 - 20
    inner_r = r * 0.6
    colors = {
        "critical": _SEVERITY_COLORS[Severity.CRITICAL],
        "high": _SEVERITY_COLORS[Severity.HIGH],
        "medium": _SEVERITY_COLORS[Severity.MEDIUM],
        "low": _SEVERITY_COLORS[Severity.LOW],
    }

    paths = []
    start_angle = -90  # Start from top
    import math

    for severity_name in ["critical", "high", "medium", "low"]:
        count = counts.get(severity_name, 0)
        if count == 0:
            continue

        sweep = (count / total) * 360
        end_angle = start_angle + sweep

        # Convert to radians
        start_rad = math.radians(start_angle)
        end_rad = math.radians(end_angle)

        # Outer arc points
        x1 = cx + r * math.cos(start_rad)
        y1 = cy + r * math.sin(start_rad)
        x2 = cx + r * math.cos(end_rad)
        y2 = cy + r * math.sin(end_rad)

        # Inner arc points
        x3 = cx + inner_r * math.cos(end_rad)
        y3 = cy + inner_r * math.sin(end_rad)
        x4 = cx + inner_r * math.cos(start_rad)
        y4 = cy + inner_r * math.sin(start_rad)

        large_arc = 1 if sweep > 180 else 0
        color = colors[severity_name]

        path = (
            f'<path d="M {x1:.1f} {y1:.1f} '
            f'A {r} {r} 0 {large_arc} 1 {x2:.1f} {y2:.1f} '
            f'L {x3:.1f} {y3:.1f} '
            f'A {inner_r} {inner_r} 0 {large_arc} 0 {x4:.1f} {y4:.1f} Z" '
            f'fill="{color}" stroke="white" stroke-width="2">'
            f'<title>{severity_name.upper()}: {count}</title></path>'
        )
        paths.append(path)
        start_angle = end_angle

    center_text = f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="central" font-size="24" font-weight="bold" fill="#e2e8f0">{total}</text>'

    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
        + "".join(paths)
        + center_text
        + "</svg>"
    )


def _alert_card(alert: Alert, index: int) -> str:
    """Generate HTML for a single alert card."""
    color = _SEVERITY_COLORS.get(alert.severity, "#888")
    severity_label = alert.severity.value.upper()

    evidence_html = ""
    if alert.evidence:
        rows = []
        for ev in alert.evidence[:5]:
            cells = "".join(
                f"<td>{html.escape(str(v))}</td>" for v in ev.values()
            )
            rows.append(f"<tr>{cells}</tr>")

        if rows:
            headers = "".join(
                f"<th>{html.escape(str(k))}</th>" for k in alert.evidence[0]
            )
            evidence_html = f"""
            <details>
                <summary>Evidence ({len(alert.evidence)} items)</summary>
                <table class="evidence-table">
                    <thead><tr>{headers}</tr></thead>
                    <tbody>{"".join(rows)}</tbody>
                </table>
            </details>"""

    mitre_html = ""
    if alert.mitre_technique:
        mitre_html = f'<div class="mitre-tag">MITRE: {html.escape(alert.mitre_tactic)} / {html.escape(alert.mitre_technique)}</div>'

    recommendation_html = ""
    if alert.recommendation:
        recommendation_html = f'<div class="recommendation">Recommendation: {html.escape(alert.recommendation)}</div>'

    return f"""
    <div class="alert-card" style="border-left: 4px solid {color};">
        <div class="alert-header">
            <span class="severity-badge" style="background-color: {color};">{severity_label}</span>
            <span class="alert-name">{html.escape(alert.rule_name)}</span>
            <span class="alert-time">{html.escape(alert.timestamp_str)}</span>
        </div>
        <div class="alert-description">{html.escape(alert.description)}</div>
        {mitre_html}
        {recommendation_html}
        {evidence_html}
    </div>"""


def export_html(
    alerts: list[Alert],
    output_path: Path,
    total_events: int,
    elapsed: float = 0.0,
) -> None:
    """Export alerts to a self-contained HTML report with charts."""
    counts = _severity_counts(alerts)
    donut_svg = _donut_chart_svg(counts, size=200)
    mitre_heatmap = _build_mitre_heatmap(alerts)

    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    sorted_alerts = sorted(alerts, key=lambda a: severity_order.get(a.severity, 99))
    alert_cards = "\n".join(_alert_card(a, i) for i, a in enumerate(sorted_alerts))

    legend_items = "".join(
        f'<span class="legend-item"><span class="legend-dot" style="background:{_SEVERITY_COLORS[s]};"></span>{s.value.upper()}: {counts[s.value]}</span>'
        for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    )

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ThreatLens Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
    header {{ text-align: center; padding: 40px 0 20px; }}
    header h1 {{ font-size: 2.5em; color: #38bdf8; }}
    header .subtitle {{ color: #94a3b8; margin-top: 5px; }}
    .summary {{ display: flex; gap: 30px; align-items: center; justify-content: center; margin: 30px 0; padding: 30px; background: #1e293b; border-radius: 12px; flex-wrap: wrap; }}
    .summary-stats {{ display: flex; flex-direction: column; gap: 12px; }}
    .stat {{ display: flex; justify-content: space-between; gap: 30px; }}
    .stat-label {{ color: #94a3b8; }}
    .stat-value {{ font-weight: bold; font-size: 1.1em; }}
    .legend {{ display: flex; gap: 20px; flex-wrap: wrap; justify-content: center; margin: 15px 0; }}
    .legend-item {{ display: flex; align-items: center; gap: 6px; }}
    .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; }}
    .alerts-section {{ margin-top: 30px; }}
    .alerts-section h2 {{ margin-bottom: 15px; color: #38bdf8; }}
    .alert-card {{ background: #1e293b; border-radius: 8px; padding: 16px; margin-bottom: 12px; }}
    .alert-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }}
    .severity-badge {{ padding: 3px 10px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.8em; }}
    .alert-name {{ font-weight: bold; font-size: 1.1em; }}
    .alert-time {{ color: #94a3b8; margin-left: auto; font-size: 0.9em; }}
    .alert-description {{ color: #cbd5e1; margin-bottom: 8px; }}
    .mitre-tag {{ color: #818cf8; font-size: 0.9em; margin-bottom: 4px; }}
    .recommendation {{ color: #fbbf24; font-size: 0.9em; margin-bottom: 8px; }}
    details {{ margin-top: 8px; }}
    summary {{ cursor: pointer; color: #38bdf8; font-size: 0.9em; }}
    .evidence-table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.85em; }}
    .evidence-table th {{ background: #334155; padding: 8px; text-align: left; }}
    .evidence-table td {{ padding: 6px 8px; border-bottom: 1px solid #334155; word-break: break-all; }}
    footer {{ text-align: center; margin-top: 40px; padding: 20px; color: #64748b; font-size: 0.85em; }}
    .no-alerts {{ text-align: center; color: #22c55e; font-size: 1.3em; padding: 40px; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>ThreatLens</h1>
        <div class="subtitle">Log Analysis &amp; Threat Hunting Report</div>
    </header>

    <div class="summary">
        <div>{donut_svg}</div>
        <div class="summary-stats">
            <div class="stat"><span class="stat-label">Events Analyzed</span><span class="stat-value">{total_events:,}</span></div>
            <div class="stat"><span class="stat-label">Alerts Generated</span><span class="stat-value">{len(alerts)}</span></div>
            <div class="stat"><span class="stat-label">Scan Duration</span><span class="stat-value">{elapsed:.2f}s</span></div>
            <div class="stat"><span class="stat-label">Report Generated</span><span class="stat-value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span></div>
        </div>
    </div>

    <div class="legend">{legend_items}</div>

    {mitre_heatmap}

    <div class="alerts-section">
        <h2>Alerts ({len(alerts)})</h2>
        {alert_cards if alerts else '<div class="no-alerts">No threats detected. Clean scan!</div>'}
    </div>

    <footer>
        Generated by ThreatLens v{__version__} &mdash; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </footer>
</div>
</body>
</html>"""

    output_path.write_text(report_html, encoding="utf-8")
