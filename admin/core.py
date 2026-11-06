"""FastAPI glue + the one-decorator helper later phases use.

IMPORTANT: no `from __future__ import annotations` here (FastAPI must see the real `Request` class; otherwise it treats
`request` as a query parameter and every call returns HTTP 422 - see tests/test_routes_wiring.py).

Adding a route in a later phase:

    from admin.core import admin_route

    class DeleteBody(BaseModel):
        token: str = Field(pattern=r"^[A-Za-z0-9_-]{4,64}$")
        confirm: bool = False

    @admin_route("POST", "/files/delete", action="files.delete", model=DeleteBody, confirm=True)
    async def files_delete(ctx, body):
        ctx.detail = {"token": body.token}          # goes to the activity log (secret-looking keys are masked)
        ...
        return {"deleted": True}                     # merged into {"ok": true, ...}
        # or: raise AdminError("not_found", "File not found", 404)

The decorator gives: session auth (401), CSRF + same-origin (403) on non-GET, per-session rate limit, JSON-only body,
Pydantic validation (400 {ok:false, code:"validation"}), `confirm:true` gate, structured errors and an activity-log row.
Path is relative to /admin/api. Routes are mounted by routes.register().
"""
from typing import Callable, List, Tuple

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from . import service
from .service import AdminError, Ctx, Req, Resp, Spec  # noqa: F401  (re-exported for route modules)

MAX_BODY = 262144
_REGISTRY: List[Tuple[Spec, Callable]] = []


def admin_route(method: str, path: str, *, action: str, model=None, query=None, confirm: bool = False, log: bool = None):
    if not path.startswith("/"):
        raise ValueError("path must start with '/'")

    def deco(fn: Callable):
        _REGISTRY.append((Spec(method.upper(), path, action, model, confirm, log, query), fn))
        return fn

    return deco


def registry() -> list:
    return list(_REGISTRY)


async def to_req(settings, request: Request) -> Req:
    headers = {k.lower(): v for k, v in request.headers.items()}
    body = b""
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        try:
            if int(headers.get("content-length") or 0) > MAX_BODY:
                return Req(request.method, request.url.path, body=b"\x00" * (MAX_BODY + 1))
        except ValueError:
            pass
        body = await request.body()
    peer = request.client.host if request.client else ""
    return Req(method=request.method, path=request.url.path, ip=service.client_ip(settings, headers, peer),
               headers=headers, cookies=dict(request.cookies), query=dict(request.query_params), body=body)


def to_response(settings, resp: Resp) -> Response:
    out = JSONResponse(resp.data, status_code=resp.status, headers={**service.SEC_HEADERS, **resp.headers})
    if resp.cookie is not None:
        if resp.cookie["max_age"] > 0:
            out.set_cookie(settings.cookie_name, resp.cookie["value"], max_age=resp.cookie["max_age"], path="/",
                           httponly=True, secure=settings.cookie_secure, samesite="strict")
        else:
            out.delete_cookie(settings.cookie_name, path="/", httponly=True, secure=settings.cookie_secure,
                              samesite="strict")
    return out


def _too_big(req: Req) -> bool:
    return len(req.body) > MAX_BODY


def make_api_endpoint(settings, spec: Spec, handler: Callable):
    async def endpoint(request: Request):
        req = await to_req(settings, request)
        if _too_big(req):
            return to_response(settings, service.err(413, "too_large", "Request body too large"))
        return to_response(settings, await service.dispatch(settings, req, spec, handler))

    return endpoint


def html_response(settings, html: str, status: int = 200) -> Response:
    return HTMLResponse(html, status_code=status, headers=service.SEC_HEADERS)


def redirect(settings, url: str) -> Response:
    return RedirectResponse(url, status_code=303, headers=service.SEC_HEADERS)
