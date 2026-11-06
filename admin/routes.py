"""Built-in panel routes (Phase 1) + register(app) that mounts everything.

IMPORTANT: no `from __future__ import annotations` (FastAPI route annotations, see core.py).
"""
from pathlib import Path
from typing import Optional

from fastapi import Request
from pydantic import BaseModel, ConfigDict, Field

from . import config, core, dashboard, envcheck, service, store
from .core import AdminError, admin_route

UI = Path(__file__).parent / "ui"

# (id, title, path, built).  Later phases flip built=True and add their routes + a section renderer in panel.js.
SECTIONS = [
    ("dashboard", "Dashboard", "/admin", True),
    ("files", "Files", "/admin/files", False),
    ("bots", "Bots", "/admin/bots", False),
    ("posts", "Posts", "/admin/posts", False),
    ("copy-chats", "Copy Chats", "/admin/copy-chats", False),
    ("auto-posting", "Auto Posting", "/admin/auto-posting", False),
    ("ads", "Ads", "/admin/ads", False),
    ("settings", "Settings", "/admin/settings", True),
    ("activity", "Activity", "/admin/activity", True),
]
STATIC = {"panel.css": "text/css; charset=utf-8", "panel.js": "application/javascript; charset=utf-8",
          "login.js": "application/javascript; charset=utf-8"}


# ---------------------------------------------------------------- schemas
class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=256)
    totp: Optional[str] = Field(default=None, pattern=r"^\d{6}$")


class ActivityQuery(BaseModel):
    page: int = Field(default=1, ge=1, le=100000)
    limit: int = Field(default=50, ge=1, le=100)
    action: Optional[str] = Field(default=None, max_length=60, pattern=r"^[A-Za-z0-9_.:-]+$")
    ok: Optional[bool] = None


# ---------------------------------------------------------------- built-in API (all behind session + CSRF)
@admin_route("GET", "/session", action="session")
async def api_session(ctx, _):
    return {"csrf": ctx.session["csrf"], "expires_at": ctx.session.get("exp_t"),
            "totp_enabled": bool(ctx.settings.totp_secret),
            "sections": [{"id": i, "title": t, "path": p, "built": b} for i, t, p, b in SECTIONS]}


@admin_route("GET", "/dashboard", action="dashboard")
async def api_dashboard(ctx, _):
    return {"data": await dashboard.collect()}


@admin_route("GET", "/settings", action="settings")
async def api_settings(ctx, _):
    s = ctx.settings
    return {"env": envcheck.snapshot(),
            "panel": {"totp_enabled": bool(s.totp_secret), "session_hours": s.session_hours, "cookie_secure": s.cookie_secure,
                      "proxy_hops": s.proxy_hops, "activity_days": s.activity_days, "max_fails": s.max_fails,
                      "lockout_minutes": s.fail_window // 60}}


@admin_route("GET", "/activity", action="activity", query=ActivityQuery)
async def api_activity(ctx, q):
    total, items = await store.list_activity((q.page - 1) * q.limit, q.limit, q.action, q.ok)
    return {"total": total, "page": q.page, "limit": q.limit, "items": items}


# ---------------------------------------------------------------- mounting
def register(app, settings=None) -> bool:
    """Mount /admin. Returns False (and mounts NOTHING => every /admin/* path that is not another feature 404s)
    when ADMIN_PANEL_PASSWORD is unset."""
    settings = settings or config.load()
    if not settings.enabled:
        return False

    shell = (UI / "shell.html").read_text(encoding="utf-8")
    login_html = (UI / "login.html").read_text(encoding="utf-8").replace("__TOTP__", "1" if settings.totp_secret else "0")
    assets = {n: (UI / n).read_bytes() for n in STATIC}

    async def static_file(name: str):
        from fastapi.responses import Response
        if name not in assets:
            return Response(status_code=404)
        return Response(assets[name], media_type=STATIC[name],
                        headers={**service.SEC_HEADERS, "Cache-Control": "no-cache"})

    async def login_page(request: Request):
        req = await core.to_req(settings, request)
        if await service.authenticate(settings, req):
            return core.redirect(settings, "/admin")
        return core.html_response(settings, login_html)

    def make_page(section_id: str):
        async def page(request: Request):
            req = await core.to_req(settings, request)
            if not await service.authenticate(settings, req):
                return core.redirect(settings, "/admin/login")
            return core.html_response(settings, shell.replace("__SECTION__", section_id))
        return page

    async def api_login(request: Request):
        req = await core.to_req(settings, request)
        if core._too_big(req):
            return core.to_response(settings, service.err(413, "too_large", "Request body too large"))
        return core.to_response(settings, await service.login(settings, req, LoginBody))

    async def api_logout(request: Request):
        req = await core.to_req(settings, request)
        return core.to_response(settings, await service.logout(settings, req))

    app.add_api_route("/admin/login", login_page, methods=["GET"], include_in_schema=False)
    app.add_api_route("/admin/static/{name}", static_file, methods=["GET"], include_in_schema=False)
    app.add_api_route("/admin/api/login", api_login, methods=["POST"], include_in_schema=False)
    app.add_api_route("/admin/api/logout", api_logout, methods=["POST"], include_in_schema=False)
    for sid, _title, path, _built in SECTIONS:
        app.add_api_route(path, make_page(sid), methods=["GET"], include_in_schema=False)
    for spec, handler in core.registry():
        app.add_api_route("/admin/api" + spec.path, core.make_api_endpoint(settings, spec, handler),
                          methods=[spec.method], include_in_schema=False)
    return True
