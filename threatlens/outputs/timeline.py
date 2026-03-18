"""Attack timeline visualization for ThreatLens.

Generates a self-contained HTML page with an interactive SVG timeline
showing alerts plotted on a time axis, color-coded by severity.
"""

from __future__ import annotations

import html
from datetime import datetime, timedelta
from pathlib import Path

from threatlens.models import Alert, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#f59e0b",
    Severity.MEDIUM: "#06b6d4",
    Severity.LOW: "#22c55e",
}

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def _format_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def export_timeline(
    alerts: list[Alert],
    output_path: Path,
    total_events: int = 0,
) -> None:
    """Generate an interactive HTML attack timeline visualization."""
    if not alerts:
        output_path.write_text(
            "<!DOCTYPE html><html><body style='background:#0f172a;color:#e2e8f0;font-family:sans-serif;'>"
            "<h1 style='text-align:center;padding:60px;'>No alerts to visualize.</h1></body></html>",
            encoding="utf-8",
        )
        return

    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
    min_time = sorted_alerts[0].timestamp
    max_time = sorted_alerts[-1].timestamp
    time_span = (max_time - min_time).total_seconds()
    if time_span == 0:
        time_span = 60  # avoid division by zero

    # Layout constants
    margin_left = 180
    margin_right = 40
    chart_width = 1000
    row_height = 56
    header_height = 80
    total_width = margin_left + chart_width + margin_right
    total_height = header_height + len(sorted_alerts) * row_height + 60

    # Build timeline rows
    rows_html = []
    for i, alert in enumerate(sorted_alerts):
        offset_sec = (alert.timestamp - min_time).total_seconds()
        x_pos = margin_left + (offset_sec / time_span) * chart_width
        y_pos = header_height + i * row_height + row_height // 2
        color = _SEVERITY_COLORS.get(alert.severity, "#888")
        sev = alert.severity.value.upper()
        name_escaped = html.escape(alert.rule_name)
        desc_escaped = html.escape(alert.description[:120])
        ts_str = _format_ts(alert.timestamp)

        mitre_str = ""
        if alert.mitre_technique:
            mitre_str = f" | MITRE: {html.escape(alert.mitre_tactic)} / {html.escape(alert.mitre_technique)}"

        # Row background stripe
        bg_color = "#1e293b" if i % 2 == 0 else "#1a2332"
        rows_html.append(
            f'<rect x="0" y="{y_pos - row_height // 2}" width="{total_width}" '
            f'height="{row_height}" fill="{bg_color}" />'
        )

        # Connector line from label to dot
        rows_html.append(
            f'<line x1="{margin_left}" y1="{y_pos}" x2="{x_pos}" y2="{y_pos}" '
            f'stroke="{color}" stroke-width="1" stroke-dasharray="4,3" opacity="0.4" />'
        )

        # Label on the left
        rows_html.append(
            f'<text x="{margin_left - 10}" y="{y_pos + 4}" text-anchor="end" '
            f'font-size="12" fill="{color}" font-weight="bold">[{sev}]</text>'
        )

        # Event dot
        mitre_attr = ""
        if alert.mitre_technique:
            mitre_val = html.escape(f"{alert.mitre_tactic} / {alert.mitre_technique}")
            mitre_attr = f' data-mitre="{mitre_val}"'
        rows_html.append(
            f'<circle cx="{x_pos}" cy="{y_pos}" r="8" fill="{color}" '
            f'stroke="white" stroke-width="2" class="event-dot" '
            f'data-name="{name_escaped}" data-desc="{desc_escaped}" '
            f'data-time="{ts_str}" data-sev="{sev}"{mitre_attr} />'
        )

        # Alert name next to dot
        rows_html.append(
            f'<text x="{x_pos + 14}" y="{y_pos + 4}" font-size="11" fill="#e2e8f0">'
            f'{name_escaped}</text>'
        )

    # Time axis ticks
    tick_count = min(8, max(3, len(sorted_alerts)))
    ticks_html = []
    for t in range(tick_count + 1):
        frac = t / tick_count
        tick_time = min_time + timedelta(seconds=frac * time_span)
        tx = margin_left + frac * chart_width
        ty = header_height - 10
        ticks_html.append(
            f'<line x1="{tx}" y1="{ty}" x2="{tx}" y2="{total_height - 40}" '
            f'stroke="#334155" stroke-width="1" />'
        )
        ticks_html.append(
            f'<text x="{tx}" y="{ty - 5}" text-anchor="middle" font-size="10" fill="#94a3b8">'
            f'{tick_time.strftime("%H:%M:%S")}</text>'
        )

    # Date range label
    date_label = min_time.strftime("%Y-%m-%d")
    if min_time.date() != max_time.date():
        date_label += f' — {max_time.strftime("%Y-%m-%d")}'

    svg_content = "\n".join(ticks_html + rows_html)

    page_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ThreatLens - Attack Timeline</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; }}
    .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
    header {{ text-align: center; padding: 30px 0 10px; }}
    header h1 {{ font-size: 2em; color: #38bdf8; }}
    header .sub {{ color: #94a3b8; margin-top: 4px; }}
    .legend {{ display: flex; gap: 20px; justify-content: center; margin: 15px 0 20px; flex-wrap: wrap; }}
    .legend span {{ display: flex; align-items: center; gap: 6px; font-size: 0.9em; }}
    .legend .dot {{ width: 12px; height: 12px; border-radius: 50%; }}
    .timeline-wrap {{ overflow-x: auto; background: #0f172a; border-radius: 8px; border: 1px solid #1e293b; }}
    svg {{ display: block; }}
    .event-dot {{ cursor: pointer; transition: r 0.15s; }}
    .event-dot:hover {{ r: 12; }}
    #tooltip {{ position: fixed; display: none; background: #1e293b; border: 1px solid #38bdf8; border-radius: 8px; padding: 12px 16px; max-width: 420px; font-size: 0.85em; z-index: 100; pointer-events: none; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }}
    #tooltip .tt-sev {{ font-weight: bold; margin-bottom: 4px; }}
    #tooltip .tt-name {{ font-size: 1.1em; font-weight: bold; margin-bottom: 6px; }}
    #tooltip .tt-desc {{ color: #cbd5e1; margin-bottom: 4px; }}
    #tooltip .tt-time {{ color: #94a3b8; font-size: 0.9em; }}
    #tooltip .tt-mitre {{ color: #818cf8; font-size: 0.9em; margin-top: 4px; }}
    footer {{ text-align: center; padding: 20px; color: #64748b; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>Attack Timeline</h1>
        <div class="sub">{html.escape(date_label)} &mdash; {len(alerts)} alert(s) from {total_events:,} events</div>
    </header>

    <div class="legend">
        <span><span class="dot" style="background:{_SEVERITY_COLORS[Severity.CRITICAL]};"></span>CRITICAL</span>
        <span><span class="dot" style="background:{_SEVERITY_COLORS[Severity.HIGH]};"></span>HIGH</span>
        <span><span class="dot" style="background:{_SEVERITY_COLORS[Severity.MEDIUM]};"></span>MEDIUM</span>
        <span><span class="dot" style="background:{_SEVERITY_COLORS[Severity.LOW]};"></span>LOW</span>
    </div>

    <div class="timeline-wrap">
        <svg width="{total_width}" height="{total_height}" viewBox="0 0 {total_width} {total_height}">
            <rect width="{total_width}" height="{total_height}" fill="#0f172a" />
            {svg_content}
        </svg>
    </div>

    <footer>Generated by ThreatLens v1.0.0 &mdash; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
</div>

<div id="tooltip">
    <div class="tt-sev"></div>
    <div class="tt-name"></div>
    <div class="tt-desc"></div>
    <div class="tt-time"></div>
    <div class="tt-mitre"></div>
</div>

<script>
const tooltip = document.getElementById('tooltip');
document.querySelectorAll('.event-dot').forEach(dot => {{
    dot.addEventListener('mouseenter', e => {{
        tooltip.querySelector('.tt-sev').textContent = e.target.dataset.sev;
        tooltip.querySelector('.tt-sev').style.color = e.target.getAttribute('fill');
        tooltip.querySelector('.tt-name').textContent = e.target.dataset.name;
        tooltip.querySelector('.tt-desc').textContent = e.target.dataset.desc;
        tooltip.querySelector('.tt-time').textContent = e.target.dataset.time;
        const mitre = e.target.dataset.mitre;
        const mitreEl = tooltip.querySelector('.tt-mitre');
        mitreEl.textContent = mitre ? 'MITRE: ' + mitre : '';
        mitreEl.style.display = mitre ? 'block' : 'none';
        tooltip.style.display = 'block';
    }});
    dot.addEventListener('mousemove', e => {{
        tooltip.style.left = (e.clientX + 15) + 'px';
        tooltip.style.top = (e.clientY + 15) + 'px';
    }});
    dot.addEventListener('mouseleave', () => {{
        tooltip.style.display = 'none';
    }});
}});
</script>
</body>
</html>"""

    output_path.write_text(page_html, encoding="utf-8")
