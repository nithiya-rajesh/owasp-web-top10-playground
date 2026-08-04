import markdown as _markdown_lib
from fastapi.responses import HTMLResponse

_BASE_CSS = """
:root {
  --bg: #0b0e12; --panel: #12161c; --panel-2: #171c23; --border: #232a33;
  --text: #e6e9ee; --muted: #8b95a3; --amber: #f0a63a; --amber-dim: #7a5a24;
  --green: #4fd68c; --red: #ef5b6e;
  --mono: 'IBM Plex Mono', ui-monospace, monospace;
  --sans: 'Space Grotesk', ui-sans-serif, sans-serif;
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); }
a { color: var(--amber); }
.topbar { display:flex; justify-content:space-between; align-items:center; padding:14px 24px; border-bottom:1px solid var(--border); background:var(--panel); }
.topbar a.home { color:var(--text); text-decoration:none; font-weight:600; }
.flagcount { font-family:var(--mono); font-size:12px; color:var(--muted); background:var(--panel-2); border:1px solid var(--border); padding:5px 10px; border-radius:6px; }
.header { padding:20px 24px 4px; }
.owasp-chip { font-family:var(--mono); font-size:11px; font-weight:600; background:var(--panel-2); border:1px solid var(--border); color:var(--amber); padding:3px 8px; border-radius:6px; }
.header h1 { margin: 8px 0 4px; font-size:22px; }
.tagline { color:var(--muted); font-size:13.5px; margin-bottom: 12px;}
.tabs { display:flex; gap:4px; border-bottom:1px solid var(--border); padding:0 24px; }
.tabs a { padding:10px 14px; text-decoration:none; color:var(--muted); font-size:13px; border-bottom:2px solid transparent; }
.tabs a.active { color:var(--text); border-bottom-color:var(--amber); }
.content { padding:24px; max-width: 900px; }
.panel { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:20px; margin-bottom:16px; }
input, select, textarea { background:var(--panel-2); border:1px solid var(--border); color:var(--text); padding:9px 12px; border-radius:7px; font-size:14px; font-family:var(--sans); width:100%; margin-bottom:10px; }
button, .btn { background:var(--amber); color:#1a1300; border:none; font-weight:600; font-size:13px; padding:10px 18px; border-radius:8px; cursor:pointer; }
.btn-secondary { background:var(--panel-2); color:var(--text); border:1px solid var(--border); }
label { font-size:12.5px; color:var(--muted); display:block; margin-bottom:4px; }
table { width:100%; border-collapse: collapse; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border); font-size:13.5px; }
.flag-banner { background:rgba(79,214,140,.12); border:1px solid rgba(79,214,140,.4); color:var(--green); padding:12px 16px; border-radius:10px; font-family:var(--mono); font-size:13px; margin-bottom:16px; }
.muted { color:var(--muted); font-size:12.5px; }
.mono { font-family:var(--mono); }
.locked { color:var(--muted); font-style:italic; }
"""


def page(scenario, session, body_html: str, active_tab: str = "play", flag_just_captured: str | None = None) -> HTMLResponse:
    flags = session.get("flags", set()) if session else set()
    flag_html = ""
    if flag_just_captured:
        flag_html = f'<div class="flag-banner">🚩 Flag captured: {flag_just_captured}</div>'

    def tab(name, label, path=None):
        cls = "active" if active_tab == name else ""
        href = path if path is not None else f"/play/{scenario.id}/{name}"
        return f'<a class="{cls}" href="{href}">{label}</a>'

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>{scenario.title} — OWASP Web Top 10 Playground</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<style>{_BASE_CSS}</style>
</head><body>
<div class="topbar">
  <a class="home" href="/">&larr; OWASP Web Top 10 Playground</a>
  <span class="flagcount">Flags: {len(flags)} / 10</span>
</div>
<div class="header">
  <span class="owasp-chip">{scenario.owasp_id}</span>
  <h1>{scenario.title}</h1>
  <div class="tagline">{scenario.tagline}</div>
</div>
<div class="tabs">
  {tab("play", "Play", path=f"/play/{scenario.id}/")}
  {tab("objective", "Objective")}
  {tab("hints", "Hints")}
  {tab("fix", "Fix")}
</div>
<div class="content">
  {flag_html}
  {body_html}
</div>
</body></html>"""
    return HTMLResponse(html)


def markdown_page(scenario, session, md_text: str, active_tab: str) -> HTMLResponse:
    body = f'<div class="panel">{_markdown_lib.markdown(md_text)}</div>'
    return page(scenario, session, body, active_tab=active_tab)


def fix_page(scenario, session) -> HTMLResponse:
    flags = session.get("flags", set()) if session else set()
    if scenario.flag_id not in flags:
        body = '<div class="panel"><p class="locked">🔒 Capture the flag first to unlock the remediation guide.</p></div>'
    else:
        body = f'<div class="panel">{_markdown_lib.markdown(scenario.fix_md)}</div>'
    return page(scenario, session, body, active_tab="fix")
