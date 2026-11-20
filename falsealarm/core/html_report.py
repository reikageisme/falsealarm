"""
Self-contained HTML report (single file, no external assets, works offline).

Everything that came from a target — titles, URLs, headers, extracted values —
is attacker-controlled, so every value is HTML-escaped server-side and the page
ships a strict Content-Security-Policy. The only script is the inline filter
code below, which never builds HTML from data.
"""

from __future__ import annotations

import html
from collections import Counter
from pathlib import Path
from typing import Any

from falsealarm import __version__
from falsealarm.core.findings import SEVERITY_ORDER, collect_findings
from falsealarm.core.utils import get_timestamp

_CSS = """
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--dim:#8b949e;--accent:#f85149;
--critical:#d1242f;--high:#f85149;--medium:#d29922;--low:#3fb950;--info:#58a6ff;--unknown:#8b949e}
@media (prefers-color-scheme:light){:root{--bg:#ffffff;--panel:#f6f8fa;--line:#d0d7de;--fg:#1f2328;
--dim:#59636e;--high:#cf222e;--medium:#9a6700;--low:#1a7f37;--info:#0969da}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;flex-wrap:wrap;gap:8px 24px;align-items:baseline;border-bottom:1px solid var(--line);
padding-bottom:16px;margin-bottom:20px}
h1{font-size:22px;margin:0}h1 span{color:var(--accent)}h2{font-size:16px;margin:28px 0 10px}
.meta{color:var(--dim);font-size:13px}.meta b{color:var(--fg);font-weight:600}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
.card .n{font-size:24px;font-weight:700}.card .l{color:var(--dim);font-size:12px;text-transform:uppercase}
.card.sevc .n{color:var(--c)}
.bar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--line);margin:14px 0}
.bar i{display:block;background:var(--c)}
.tools{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.chip{border:1px solid var(--line);background:var(--panel);color:var(--fg);border-radius:999px;
padding:3px 12px;cursor:pointer;font-size:13px}.chip[aria-pressed=false]{opacity:.45}
input[type=search]{flex:1;min-width:200px;background:var(--panel);color:var(--fg);border:1px solid var(--line);
border-radius:6px;padding:6px 10px;font-size:14px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:8px;
overflow:hidden}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px;text-transform:uppercase}tr:last-child td{border-bottom:0}
td.u{word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.sev{display:inline-block;min-width:68px;text-align:center;border-radius:4px;padding:1px 6px;font-size:11px;
font-weight:700;text-transform:uppercase;color:#fff;background:var(--c)}
.id{color:var(--dim);font-size:12px;font-family:ui-monospace,monospace}
code{font-family:ui-monospace,monospace;font-size:12px;background:var(--bg);border:1px solid var(--line);
border-radius:4px;padding:0 4px;word-break:break-all}
details{margin-top:4px}summary{cursor:pointer;color:var(--dim);font-size:12px}
.empty{color:var(--dim);padding:12px}.s2{color:var(--low)}.s3{color:var(--info)}.s4{color:var(--medium)}
.s5{color:var(--high)}
@media (max-width:640px){#findings thead{display:none}#findings tr{display:block;border-bottom:1px solid var(--line)}
#findings td{display:block;border:0;padding:4px 10px}#findings td:first-child{padding-top:10px}}
footer{color:var(--dim);font-size:12px;margin-top:40px}
"""

_JS = """
(function(){
  var chips=[].slice.call(document.querySelectorAll('.chip'));
  var q=document.getElementById('q');
  var rows=[].slice.call(document.querySelectorAll('#findings tbody tr[data-sev]'));
  function apply(){
    var on={};chips.forEach(function(c){on[c.dataset.sev]=c.getAttribute('aria-pressed')==='true'});
    var term=(q.value||'').toLowerCase();
    rows.forEach(function(r){
      var ok=on[r.dataset.sev]!==false && (!term || r.textContent.toLowerCase().indexOf(term)>=0);
      r.hidden=!ok;
    });
  }
  chips.forEach(function(c){c.addEventListener('click',function(){
    c.setAttribute('aria-pressed',c.getAttribute('aria-pressed')==='true'?'false':'true');apply();});});
  q.addEventListener('input',apply);
})();
"""


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _items(results: dict[str, Any], module: str) -> list[dict[str, Any]]:
    value = results.get(module, {})
    if isinstance(value, dict) and isinstance(value.get("data"), list):
        return [i for i in value["data"] if isinstance(i, dict)]
    return []


def _status_class(status: Any) -> str:
    try:
        return f"s{int(status) // 100}"
    except (TypeError, ValueError):
        return ""


def _section(title: str, headers: list[str], rows: list[list[str]]) -> str:
    """A titled table, or nothing at all when the module produced no data."""
    if not rows:
        return ""
    return f"<h2>{_e(title)}</h2>" + _table(headers, rows, "")


def _table(headers: list[str], rows: list[list[str]], empty: str) -> str:
    if not rows:
        return f'<p class="empty">{_e(empty)}</p>'
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(cells) + "</tr>" for cells in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


class HTMLReport:
    @staticmethod
    def render(
        target: str,
        results: dict[str, Any],
        stats: Any = None,
        duration: float | None = None,
        scan_id: str | None = None,
    ) -> str:
        findings = collect_findings(results)
        counts = Counter(f.severity for f in findings)
        total = sum(counts.values())

        # ---- findings ----------------------------------------------------
        sev_cards = "".join(
            f'<div class="card sevc" style="--c:var(--{s})"><div class="n">{counts.get(s, 0)}</div>'
            f'<div class="l">{s}</div></div>'
            for s in SEVERITY_ORDER[:5]
        )
        bar = "".join(
            f'<i style="--c:var(--{s});width:{counts[s] / total * 100:.2f}%"></i>' for s in SEVERITY_ORDER if counts.get(s)
        ) if total else ""
        chips = "".join(
            f'<button class="chip" type="button" data-sev="{s}" aria-pressed="true">{s} · {counts.get(s, 0)}</button>'
            for s in SEVERITY_ORDER if counts.get(s)
        )
        f_rows = []
        for f in findings:
            evidence = "".join(f"<code>{_e(v)}</code> " for v in f.evidence)
            extra = f'<div class="id">{_e(f.detail)}</div>' if f.detail else ""
            f_rows.append(
                f'<tr data-sev="{_e(f.severity)}"><td><span class="sev" style="--c:var(--{_e(f.severity)})">'
                f'{_e(f.severity)}</span></td><td>{_e(f.title)}<div class="id">{_e(f.finding_id)} · {_e(f.module)}'
                f'</div>{extra}</td><td class="u">{_e(f.location)}</td><td>{evidence}</td></tr>'
            )
        findings_html = (
            f'<table id="findings"><thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Evidence</th>'
            f'</tr></thead><tbody>{"".join(f_rows)}</tbody></table>'
            if f_rows else '<p class="empty">No automated finding. This does not mean the target is secure.</p>'
        )

        # ---- attack surface ---------------------------------------------
        live = [i for i in _items(results, "httpprobe") if i.get("alive") is not False]
        live_rows = [[
            f'<td class="{_status_class(i.get("status"))}">{_e(i.get("status"))}</td>',
            f'<td class="u">{_e(i.get("url"))}</td>', f"<td>{_e(i.get('title'))}</td>",
            f"<td>{_e(i.get('server'))}</td>",
        ] for i in live]

        tech_rows = []
        for i in _items(results, "tech"):
            names = ", ".join(
                f"{t.get('name')}{' ' + str(t['version']) if t.get('version') else ''}" for t in i.get("technologies") or []
            )
            tech_rows.append([f'<td class="u">{_e(i.get("target"))}</td>', f"<td>{_e(names)}</td>"])

        port_rows = [[f"<td>{_e(i.get('target'))}</td>", f"<td>{_e(i.get('port'))}</td>",
                      f"<td>{_e(i.get('edge_provider') or '')}</td>"] for i in _items(results, "portscan")]
        sub_rows = [[f"<td class='u'>{_e(i.get('domain'))}</td>", f"<td>{_e(i.get('source'))}</td>"]
                    for i in _items(results, "subdomain")]
        path_rows = [[f'<td class="{_status_class(i.get("status"))}">{_e(i.get("status"))}</td>',
                      f'<td class="u">{_e(i.get("url"))}</td>', f"<td>{_e(i.get('length'))}</td>"]
                     for i in _items(results, "dirfuzz")]
        endpoints = sorted({str(e) for i in _items(results, "js_analysis") for e in i.get("endpoints") or []}
                           | {str(i.get("url")) for i in _items(results, "wayback") if i.get("url")})
        endpoint_html = (
            "<details><summary>{n} endpoints</summary><table><tbody>{rows}</tbody></table></details>".format(
                n=len(endpoints), rows="".join(f'<tr><td class="u">{_e(e)}</td></tr>' for e in endpoints[:2000]))
            if endpoints else '<p class="empty">No endpoint extracted.</p>'
        )

        traffic = ""
        if stats is not None:
            elapsed = duration if duration else stats.elapsed
            traffic = (f" · <b>{stats.requests:,}</b> requests in <b>{elapsed:.1f}s</b>"
                       + (f" · {stats.errors:,} errors" if stats.errors else ""))

        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>FalseAlarm report — {_e(target)}</title><style>{_CSS}</style></head>
<body><main>
<header><h1><span>FalseAlarm</span> report</h1>
<div class="meta">target <b>{_e(target)}</b> · {_e(get_timestamp())}{traffic}{' · scan ' + _e(scan_id) if scan_id else ''}</div></header>

<div class="cards">{sev_cards}
<div class="card"><div class="n">{len(live)}</div><div class="l">live services</div></div>
<div class="card"><div class="n">{len(endpoints)}</div><div class="l">endpoints</div></div></div>
<div class="bar">{bar}</div>

<h2>Findings</h2>
<div class="tools">{chips}<input id="q" type="search" placeholder="Filter findings…" aria-label="Filter findings"></div>
{findings_html}

<h2>Live HTTP services</h2>{_table(["Status", "URL", "Title", "Server"], live_rows, "No live HTTP service recorded.")}
{_section("Technology", ["Target", "Stack"], tech_rows)}
{_section("Open ports", ["Host", "Port", "Edge"], port_rows)}
{_section("Subdomains", ["Domain", "Source"], sub_rows)}
{_section("Discovered paths", ["Status", "URL", "Size"], path_rows)}
{"<h2>Endpoints</h2>" + endpoint_html if endpoints else ""}

<footer>Generated by FalseAlarm v{_e(__version__)}. Automated reconnaissance is evidence, not proof of security —
validate findings manually and stay within the authorised scope.</footer>
</main><script>{_JS}</script></body></html>
"""

    @classmethod
    def export(cls, target: str, results: dict[str, Any], filepath: str, **kwargs: Any) -> None:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cls.render(target, results, **kwargs), encoding="utf-8")
