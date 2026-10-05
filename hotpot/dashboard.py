from __future__ import annotations

import html
from typing import Any


def render_dashboard(snapshot: dict[str, Any], runtime: dict[str, Any]) -> str:
    def esc(value: object) -> str:
        return html.escape(str(value if value is not None else ""))

    def rows(items: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
        if not items:
            return f'<tr><td colspan="{len(columns)}" class="muted">No events yet</td></tr>'
        return "".join(
            "<tr>" + "".join(f"<td>{esc(item.get(key, ''))}</td>" for key, _ in columns) + "</tr>"
            for item in items
        )

    recent_cols = [
        ("ts", "Time"), ("ip", "IP"), ("method", "Method"), ("path", "Path"),
        ("category", "Category"), ("scanner", "Scanner"), ("severity", "Sev"),
        ("escalation_level", "Level"),
    ]
    offender_cols = [
        ("ip", "IP"), ("hits", "Hits"), ("score", "Score"),
        ("escalation_level", "Level"), ("last_category", "Last category"),
        ("last_scanner", "Scanner"), ("last_seen", "Last seen"),
    ]
    fp_cols = [
        ("fingerprint", "Fingerprint"), ("scanner_family", "Family"),
        ("category", "Category"), ("hits", "Hits"), ("unique_ips", "IPs"),
    ]

    def table(title: str, items: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
        heads = "".join(f"<th>{esc(label)}</th>" for _, label in columns)
        return f"<section><h2>{esc(title)}</h2><div class='scroll'><table><thead><tr>{heads}</tr></thead><tbody>{rows(items, columns)}</tbody></table></div></section>"

    def mini(title: str, items: list[dict[str, Any]], key: str) -> str:
        body = "".join(
            f"<li><span>{esc(item.get(key))}</span><strong>{esc(item.get('hits'))}</strong></li>"
            for item in items
        ) or "<li class='muted'>No events yet</li>"
        return f"<section><h2>{esc(title)}</h2><ul class='rank'>{body}</ul></section>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hotpot Attack Intelligence</title>
<style>
:root {{ color-scheme: dark; font-family: ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
body {{ margin:0; background:#0d1117; color:#e6edf3; }}
main {{ max-width:1400px; margin:auto; padding:24px; }}
h1 {{ margin:0 0 4px; font-size:28px; }} .sub,.muted {{ color:#8b949e; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin:22px 0; }}
.card,section {{ background:#161b22; border:1px solid #30363d; border-radius:10px; padding:16px; }}
.card strong {{ display:block; font-size:28px; margin-top:6px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr)); gap:12px; margin-bottom:12px; }}
section {{ margin-bottom:12px; }} h2 {{ font-size:16px; margin:0 0 12px; }}
table {{ width:100%; border-collapse:collapse; font-size:12px; }} th,td {{ text-align:left; padding:8px; border-bottom:1px solid #30363d; vertical-align:top; }} th {{ color:#8b949e; }}
.scroll {{ overflow:auto; }} .rank {{ list-style:none; padding:0; margin:0; }} .rank li {{ display:flex; gap:10px; justify-content:space-between; padding:7px 0; border-bottom:1px solid #21262d; }}
code {{ color:#79c0ff; }} a {{ color:#58a6ff; }}
</style></head><body><main>
<h1>🍯 Hotpot Attack Intelligence</h1>
<div class="sub">Transparent deception proxy · refresh for current data</div>
<div class="cards">
  <div class="card"><span>Total probe events</span><strong>{esc(snapshot['events'])}</strong></div>
  <div class="card"><span>Unique source IPs</span><strong>{esc(snapshot['unique_ips'])}</strong></div>
  <div class="card"><span>Runtime deceptions</span><strong>{esc(runtime.get('deceptions',0))}</strong></div>
  <div class="card"><span>Runtime tarpits</span><strong>{esc(runtime.get('tarpits',0))}</strong></div>
</div>
<div class="grid">
{mini('Top probe paths', snapshot['top_paths'], 'path')}
{mini('Top attack categories', snapshot['top_categories'], 'category')}
{mini('Scanner identification', snapshot['top_scanners'], 'scanner')}
</div>
{table('Top repeat offenders', snapshot['top_offenders'], offender_cols)}
{table('Attack fingerprints', snapshot['top_fingerprints'], fp_cols)}
{table('Recent activity', snapshot['recent'], recent_cols)}
<p class="sub">Bodies and submitted credentials are intentionally not stored.</p>
</main></body></html>"""
