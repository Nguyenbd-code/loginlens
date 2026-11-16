"""Build a single-file HTML report: summary, timeline, alerts, top IPs.

Usernames and other log fields are attacker-controlled (anyone can type
"<script>" as an SSH username), so every value from the log goes through
html.escape before it lands in the page. No JavaScript, no external files,
so the report opens anywhere and can be hosted as a static page.
"""

from __future__ import annotations

import html
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from . import __version__
from .detect import SEVERITY_ORDER, Alert
from .parser import FAILURE, INVALID_USER, SUCCESS, AuthEvent


def _e(value) -> str:
    return html.escape(str(value), quote=True)


@dataclass
class Bucket:
    start: datetime
    failures: int = 0
    successes: int = 0


def timeline(events: list[AuthEvent], minutes: int = 15) -> list[Bucket]:
    """Count failed and successful logins per time slot."""
    if not events:
        return []
    if 60 % minutes:
        raise ValueError("minutes must divide 60")
    first = min(e.timestamp for e in events)
    last = max(e.timestamp for e in events)
    start = first.replace(minute=first.minute - first.minute % minutes, second=0, microsecond=0)
    step = timedelta(minutes=minutes)
    buckets = [Bucket(start + i * step) for i in range(int((last - start) / step) + 1)]
    for e in events:
        b = buckets[int((e.timestamp - start) / step)]
        if e.outcome == FAILURE:
            b.failures += 1
        elif e.outcome == SUCCESS:
            b.successes += 1
    return buckets


SEVERITY_COLOR = {"critical": "var(--crit)", "high": "var(--high)", "medium": "var(--med)", "low": "var(--low)"}


def _timeline_svg(buckets: list[Bucket], alerts: list[Alert]) -> str:
    if not buckets:
        return ""
    width, height = 960, 260
    left, right, top, bottom = 44, 12, 14, 30
    lane_h = 16
    lanes = len(alerts)
    plot_top = top + lanes * (lane_h + 4) + 6
    plot_h = height - plot_top - bottom
    plot_w = width - left - right
    t0 = buckets[0].start
    span = (buckets[-1].start - t0) + (buckets[1].start - t0 if len(buckets) > 1 else timedelta(minutes=15))
    total = span.total_seconds() or 1

    def x(t: datetime) -> float:
        return left + (t - t0).total_seconds() / total * plot_w

    peak = max(b.failures for b in buckets) or 1
    bar_w = plot_w / len(buckets)
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Failed logins over time, with attack periods marked">']

    # gridlines + y labels
    for frac in (0, 0.5, 1):
        y = plot_top + plot_h * (1 - frac)
        parts.append(f'<line x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>')
        parts.append(f'<text x="{left - 6}" y="{y + 4:.1f}" class="axis" text-anchor="end">{round(peak * frac)}</text>')

    # failure bars
    for i, b in enumerate(buckets):
        if b.failures:
            h = b.failures / peak * plot_h
            parts.append(
                f'<rect x="{left + i * bar_w + 0.5:.1f}" y="{plot_top + plot_h - h:.1f}" width="{max(bar_w - 1, 1):.1f}" '
                f'height="{h:.1f}" class="bar"><title>{b.start:%H:%M}: {b.failures} failed</title></rect>'
            )
        if b.successes:
            parts.append(f'<circle cx="{left + (i + 0.5) * bar_w:.1f}" cy="{plot_top + plot_h + 6:.1f}" r="2.5" class="ok">'
                         f'<title>{b.start:%H:%M}: {b.successes} successful</title></circle>')

    # attack bands, one lane each, and a shaded column down to the axis
    for lane, a in enumerate(sorted(alerts, key=lambda a: a.start)):
        x1, x2 = x(a.start), max(x(a.end), x(a.start) + 3)
        y = top + lane * (lane_h + 4)
        color = SEVERITY_COLOR.get(a.severity, "var(--muted)")
        parts.append(f'<rect x="{x1:.1f}" y="{plot_top:.1f}" width="{x2 - x1:.1f}" height="{plot_h:.1f}" '
                     f'fill="{color}" opacity="0.13"/>')
        parts.append(f'<rect x="{x1:.1f}" y="{y}" width="{x2 - x1:.1f}" height="{lane_h}" rx="3" fill="{color}">'
                     f'<title>{_e(a.rule)} from {_e(a.src_ip)}</title></rect>')
        label = f"{a.rule.replace('_', ' ')} · {a.src_ip}"
        anchor, lx = ("start", x2 + 6) if x2 < width * 0.7 else ("end", x1 - 6)
        parts.append(f'<text x="{lx:.1f}" y="{y + 12}" class="lane" text-anchor="{anchor}">{_e(label)}</text>')

    # x labels
    ticks = 8
    for k in range(ticks + 1):
        t = t0 + span * (k / ticks)
        fmt = "%H:%M" if span <= timedelta(days=1) else "%m/%d %H:%M"
        anchor = "start" if k == 0 else "end" if k == ticks else "middle"
        parts.append(f'<text x="{x(t):.1f}" y="{height - 8}" class="axis" text-anchor="{anchor}">{t.strftime(fmt)}</text>')
    parts.append("</svg>")
    return "".join(parts)


CSS = """
:root { --bg:#f3f5f8; --surface:#fff; --ink:#18202d; --muted:#5d6779; --line:#dde2ea; --bar:#7c8aa3;
  --crit:#c0392b; --high:#d9730d; --med:#b8900b; --low:#5d6779; --ok:#1f7a3a; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f141c; --surface:#171e29; --ink:#e6ebf2; --muted:#98a3b5;
  --line:#283244; --bar:#56637a; --crit:#f07a6c; --high:#f5a25a; --med:#e8c45a; --low:#98a3b5; --ok:#6fcf8a; } }
* { box-sizing:border-box }
body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif }
main { max-width:1040px; margin:0 auto; padding:28px 16px 48px; display:flex; flex-direction:column; gap:20px }
h1 { margin:0; font-size:28px; letter-spacing:-.01em } h2 { margin:0 0 10px; font-size:18px }
.meta { color:var(--muted); margin-top:2px }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px }
.tile { background:var(--surface); border:1px solid var(--line); border-radius:10px; padding:12px 14px }
.tile b { display:block; font-size:26px; font-variant-numeric:tabular-nums } .tile span { color:var(--muted); font-size:13px }
.tile.alert b { color:var(--crit) }
section { background:var(--surface); border:1px solid var(--line); border-radius:12px; padding:16px 18px; min-width:0 }
svg { width:100%; height:auto; display:block } .grid { stroke:var(--line) } .bar { fill:var(--bar) } .ok { fill:var(--ok) }
.axis { fill:var(--muted); font-size:11px } .lane { fill:var(--ink); font-size:11px; font-weight:600 }
.legend { display:flex; flex-wrap:wrap; gap:14px; color:var(--muted); font-size:13px; margin-top:6px }
.legend i { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:5px; vertical-align:-1px }
.scroll { overflow-x:auto }
table { width:100%; border-collapse:collapse; font-size:14px }
th { text-align:left; color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.05em }
th, td { padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top }
td.num { font-variant-numeric:tabular-nums; text-align:right } th.num { text-align:right }
code { font:13px ui-monospace, Consolas, monospace }
.sev { display:inline-block; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:.04em;
  padding:1px 8px; border-radius:99px; color:var(--surface) }
.sev.critical { background:var(--crit) } .sev.high { background:var(--high) } .sev.medium { background:var(--med) } .sev.low { background:var(--low) }
.empty { color:var(--muted) } footer { color:var(--muted); font-size:13px }
"""


def build_report(events: list[AuthEvent], alerts: list[Alert], source: str = "auth.log",
                 title: str = "LoginLens report", generated: Optional[datetime] = None) -> str:
    """Return the whole report as one HTML string."""
    generated = generated or datetime.now()
    outcomes = Counter(e.outcome for e in events)
    severities = Counter(a.severity for a in alerts)
    failures = [e for e in events if e.outcome == FAILURE]
    alerts = sorted(alerts, key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), a.start))

    if events:
        first, last = min(e.timestamp for e in events), max(e.timestamp for e in events)
        span = f"{first:%Y-%m-%d %H:%M} to {last:%Y-%m-%d %H:%M}"
    else:
        span = "no login attempts found"

    alert_note = ", ".join(f"{severities[s]} {s}" for s in ("critical", "high", "medium", "low") if severities[s]) or "none"
    tiles = [
        ("Login attempts", outcomes[SUCCESS] + outcomes[FAILURE], ""),
        ("Failed", outcomes[FAILURE], ""),
        ("Unknown usernames", outcomes[INVALID_USER], ""),
        ("Successful", outcomes[SUCCESS], ""),
        ("Source IPs", len({e.src_ip for e in events}), ""),
        (f"Alerts ({alert_note})", len(alerts), "alert" if alerts else ""),
    ]

    if alerts:
        rows = []
        for a in alerts:
            users = ", ".join(a.users[:3]) + (f" +{len(a.users) - 3} more" if len(a.users) > 3 else "")
            rows.append(
                f"<tr><td><span class='sev {_e(a.severity)}'>{_e(a.severity)}</span></td>"
                f"<td>{_e(a.rule.replace('_', ' '))}</td><td><code>{_e(a.src_ip)}</code></td>"
                f"<td>{_e(users)}</td><td>{a.start:%H:%M:%S} to {a.end:%H:%M:%S}</td>"
                f"<td>{_e(a.summary)}</td></tr>"
            )
        alerts_html = ("<div class='scroll'><table><thead><tr><th>Severity</th><th>Rule</th><th>Source IP</th>"
                       "<th>Accounts</th><th>When</th><th>What happened</th></tr></thead><tbody>"
                       + "".join(rows) + "</tbody></table></div>")
    else:
        alerts_html = "<p class='empty'>No attacks detected.</p>"

    top = Counter(e.src_ip for e in failures).most_common(10)
    flagged = {a.src_ip for a in alerts}
    if top:
        badge = "<span class='sev high'>flagged</span>"
        ip_rows = "".join(
            f"<tr><td><code>{_e(ip)}</code></td><td class='num'>{n}</td>"
            f"<td>{badge if ip in flagged else ''}</td></tr>"
            for ip, n in top
        )
        ips_html = ("<div class='scroll'><table><thead><tr><th>Source IP</th><th class='num'>Failed attempts</th>"
                    "<th></th></tr></thead><tbody>" + ip_rows + "</tbody></table></div>")
    else:
        ips_html = "<p class='empty'>No failed logins.</p>"

    buckets = timeline(events)
    chart = _timeline_svg(buckets, alerts) if buckets else "<p class='empty'>Nothing to chart.</p>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title><style>{CSS}</style></head>
<body><main>
<header><h1>{_e(title)}</h1><div class="meta">{_e(source)} · {_e(span)}</div></header>
<div class="tiles">{"".join(f'<div class="tile {cls}"><b>{n}</b><span>{_e(label)}</span></div>' for label, n, cls in tiles)}</div>
<section><h2>Failed logins over time</h2>{chart}
<div class="legend"><span><i style="background:var(--bar)"></i>Failed logins per 15 min</span>
<span><i style="background:var(--ok);border-radius:50%"></i>Successful login</span>
<span><i style="background:var(--crit)"></i>Critical</span><span><i style="background:var(--high)"></i>High</span>
<span><i style="background:var(--med)"></i>Medium</span></div></section>
<section><h2>Alerts</h2>{alerts_html}</section>
<section><h2>Top IPs by failed attempts</h2>{ips_html}</section>
<footer>Generated by LoginLens {__version__} on {generated:%Y-%m-%d %H:%M}.</footer>
</main></body></html>
"""
