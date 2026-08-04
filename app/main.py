from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse

from app.scenarios import all_scenarios, get_scenario
from app.core.session import get_or_create_session, get_session_readonly, reset_session, COOKIE_NAME
from app.core.layout import page, markdown_page, fix_page, _BASE_CSS

app = FastAPI(title="OWASP Web Top 10 Playground")


@app.middleware("http")
async def attach_session_cookie(request: Request, call_next):
    response = await call_next(request)
    new_sid = getattr(request.state, "new_session_id", None)
    if new_sid:
        response.set_cookie(COOKIE_NAME, new_sid, httponly=True, samesite="lax")
    return response


for scenario in all_scenarios():
    app.include_router(scenario.router, prefix=f"/play/{scenario.id}")


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, response: Response):
    session = get_or_create_session(request)
    flags = session.get("flags", set())

    cards = ""
    for s in all_scenarios():
        captured = s.flag_id in flags
        badge = "🚩" if captured else ""
        cards += f"""
        <a href="/play/{s.id}/" style="text-decoration:none;color:inherit;">
          <div class="panel" style="margin-bottom:12px;">
            <span class="owasp-chip">{s.owasp_id}</span> {badge}
            <h3 style="margin:8px 0 4px;">{s.title}</h3>
            <p class="muted" style="margin:0;">{s.tagline}</p>
          </div>
        </a>"""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>OWASP Web Top 10 Playground</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<style>{_BASE_CSS}</style>
</head><body>
<div class="topbar">
  <span style="font-weight:600;">OWASP Web Top 10 Playground <span class="muted mono" style="font-weight:400;">— 2025 · local training lab</span></span>
  <span class="flagcount">Flags: {len(flags)} / 10</span>
</div>
<div class="content" style="max-width:800px;margin:0 auto;">
  <p class="muted">Ten deliberately vulnerable real endpoints, one per OWASP Top 10:2025
  category. Click a card to attack it directly — real requests, real (fake) data,
  real exploits. Never deploy this publicly.</p>
  {cards}
</div>
</body></html>"""
    return HTMLResponse(html)


@app.get("/play/{scenario_id}/objective", response_class=HTMLResponse)
def objective(scenario_id: str, request: Request):
    scenario = get_scenario(scenario_id)
    session = get_session_readonly(request)
    return markdown_page(scenario, session, scenario.objective_md, active_tab="objective")


@app.get("/play/{scenario_id}/hints", response_class=HTMLResponse)
def hints(scenario_id: str, request: Request):
    scenario = get_scenario(scenario_id)
    session = get_session_readonly(request)
    return markdown_page(scenario, session, scenario.hints_md, active_tab="hints")


@app.get("/play/{scenario_id}/fix", response_class=HTMLResponse)
def fix(scenario_id: str, request: Request):
    scenario = get_scenario(scenario_id)
    session = get_session_readonly(request)
    return fix_page(scenario, session)


@app.post("/play/{scenario_id}/reset")
def reset(scenario_id: str, request: Request, response: Response):
    session = get_or_create_session(request)
    reset_session(session)
    return {"ok": True}


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/flags")
def api_flags(request: Request):
    session = get_session_readonly(request)
    return {"captured": sorted(session.get("flags", set())), "total": len(all_scenarios())}
