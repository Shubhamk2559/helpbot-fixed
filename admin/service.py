"""HTTP-independent core of the panel: login/logout, session auth, CSRF, rate limit, validation, activity log.

`dispatch()` is the one pipeline every /admin/api route goes through (core.admin_route plugs FastAPI into it).
Everything here works on plain Req/Resp objects, so it is unit-testable without FastAPI.
"""
import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from . import security, store
from .config import AdminSettings

log = logging.getLogger("admin")
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
SEC_HEADERS = {
    "Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Content-Security-Policy": CSP,
}


class AdminError(Exception):
    """Raise from a handler to return a structured error {ok:false, code, error}."""

    def __init__(self, code: str, message: str, status: int = 400, **extra):
        super().__init__(message)
        self.code, self.message, self.status, self.extra = code, message, status, extra


@dataclass
class Req:
    method: str
    path: str
    ip: str = "unknown"
    headers: dict = field(default_factory=dict)      # lower-case keys
    cookies: dict = field(default_factory=dict)
    query: dict = field(default_factory=dict)
    body: bytes = b""


@dataclass
class Resp:
    status: int = 200
    data: Any = None                  # dict -> JSON
    headers: dict = field(default_factory=dict)
    cookie: Optional[dict] = None     # {"value", "max_age"}  (max_age 0 => delete)


@dataclass
class Ctx:
    """Passed to every route handler."""
    settings: AdminSettings
    session: dict
    ip: str
    action: str
    detail: dict = field(default_factory=dict)       # handler may fill; redacted + stored in the activity log


def err(status: int, code: str, message: str, **extra) -> Resp:
    return Resp(status, {"ok": False, "code": code, "error": message, **extra})


def client_ip(settings: AdminSettings, headers: dict, peer: str) -> str:
    """Rightmost-hops X-Forwarded-For (the entry written by OUR proxy; the left side is client-controlled)."""
    if settings.proxy_hops > 0:
        parts = [p.strip() for p in (headers.get("x-forwarded-for") or "").split(",") if p.strip()]
        if len(parts) >= settings.proxy_hops:
            return parts[-settings.proxy_hops][:64]
    return (peer or "unknown")[:64]


def same_origin(settings: AdminSettings, req: Req) -> bool:
    """Reject cross-site browser requests. Non-browser clients (no Origin/Sec-Fetch-Site) fall through to the token check."""
    sfs = req.headers.get("sec-fetch-site")
    if sfs and sfs not in ("same-origin", "none"):
        return False
    origin = req.headers.get("origin")
    if origin is None:
        return True
    host = urlparse(origin).netloc.lower()
    if not host:
        return False                                           # "null" origin
    ok = {h.lower() for h in settings.allowed_hosts}
    for h in ("host", "x-forwarded-host"):
        if req.headers.get(h):
            ok.add(req.headers[h].split(",")[0].strip().lower())
    return host in ok


async def log_activity(req_ip: str, action: str, ok: bool, status: int, detail: dict = None, session: dict = None):
    try:
        await store.add_activity({"action": action, "ok": ok, "status": status, "ip": req_ip,
                                  "sid": (session or {}).get("sid_hash", "")[:8],
                                  "detail": security.redact(detail or {})})
    except Exception:  # noqa: BLE001 - a logging failure must never break the action
        log.exception("admin activity log write failed")


# ================================================================ sessions
async def authenticate(settings: AdminSettings, req: Req):
    raw = req.cookies.get(settings.cookie_name, "")
    sid = security.unsign_sid(settings.cookie_key, raw)
    if not sid:
        return None
    try:
        return await store.get_session(security.sha256_hex(sid))
    except Exception:  # noqa: BLE001
        log.exception("admin session lookup failed")
        return None


def check_csrf(session: dict, req: Req) -> bool:
    got = req.headers.get("x-csrf-token", "")
    return bool(got) and security.safe_equal(got, session.get("csrf", ""))


# ================================================================ login / logout
async def _lock_state(settings: AdminSettings, ip: str):
    """-> retry_after seconds if locked else 0."""
    since = time.time() - settings.fail_window
    mine = await store.failures(ip, since)
    if len(mine) >= settings.max_fails:
        return max(1, int(mine[len(mine) - settings.max_fails] + settings.fail_window - time.time()) + 1)
    allf = await store.failures(None, since)
    if len(allf) >= settings.global_max_fails:
        return max(1, int(allf[len(allf) - settings.global_max_fails] + settings.fail_window - time.time()) + 1)
    return 0


async def login(settings: AdminSettings, req: Req, model) -> Resp:
    if not same_origin(settings, req):
        return err(403, "bad_origin", "Cross-site request rejected")
    if "application/json" not in req.headers.get("content-type", ""):
        return err(415, "bad_content_type", "Content-Type must be application/json")
    parsed = _parse(req, model)
    if isinstance(parsed, Resp):
        return parsed
    retry = await _lock_state(settings, req.ip)
    if retry:
        await log_activity(req.ip, "login.locked", False, 429)
        return err(429, "locked", "Too many failed attempts. Try again later.", retry_after=retry)

    pw_ok = security.safe_equal(parsed.password, settings.password)
    totp_ok, step = True, None
    if settings.totp_secret:
        last = int(await store.get_meta("totp_last_step", 0) or 0)
        step = security.totp_verify(settings.totp_secret, getattr(parsed, "totp", None) or "", last_step=last)
        totp_ok = step is not None
    if not (pw_ok and totp_ok):
        await store.add_failure(req.ip)
        await log_activity(req.ip, "login.fail", False, 401, {"totp_required": bool(settings.totp_secret)})
        if settings.fail_delay:
            await asyncio.sleep(settings.fail_delay)
        return err(401, "invalid_credentials", "Invalid credentials")

    if step is not None:
        await store.set_meta("totp_last_step", step)
    await store.clear_failures(req.ip)
    sid, csrf = security.new_token(32), security.new_token(24)
    await store.create_session(security.sha256_hex(sid), csrf, req.ip, settings.session_hours * 3600)
    await log_activity(req.ip, "login.ok", True, 200, {"totp": bool(settings.totp_secret)})
    return Resp(200, {"ok": True}, cookie={"value": security.sign_sid(settings.cookie_key, sid),
                                           "max_age": settings.session_hours * 3600})


async def logout(settings: AdminSettings, req: Req) -> Resp:
    session = await authenticate(settings, req)
    if not session:
        return err(401, "unauthorized", "Login required")
    if not same_origin(settings, req) or not check_csrf(session, req):
        return err(403, "csrf", "CSRF check failed")
    await store.delete_session(session["sid_hash"])
    await log_activity(req.ip, "logout", True, 200, session=session)
    return Resp(200, {"ok": True}, cookie={"value": "", "max_age": 0})


# ================================================================ pipeline
def _parse(req: Req, model):
    """-> validated model instance, or an error Resp. Never echoes input values back."""
    try:
        raw = json.loads(req.body.decode("utf-8")) if req.body else {}
    except (ValueError, UnicodeDecodeError):
        return err(400, "bad_json", "Body must be valid JSON")
    if not isinstance(raw, dict):
        return err(400, "bad_json", "Body must be a JSON object")
    if model is None:
        return raw
    try:
        return model.model_validate(raw)
    except Exception as e:  # noqa: BLE001 - pydantic.ValidationError
        items = e.errors() if hasattr(e, "errors") else []
        fields = [{"field": ".".join(str(x) for x in i.get("loc", ())), "msg": str(i.get("msg", ""))[:120]} for i in items[:10]]
        return err(400, "validation", "Invalid input", fields=fields)


@dataclass
class Spec:
    method: str
    path: str
    action: str
    model: Any = None
    confirm: bool = False             # destructive: body must contain "confirm": true
    log: bool = None                  # None => log every non-GET
    query_model: Any = None


_rate: dict = {}


def _rate_ok(settings: AdminSettings, key: str) -> bool:
    now = time.monotonic()
    q = [t for t in _rate.get(key, []) if now - t < 60]
    if len(q) >= settings.rate_per_minute:
        _rate[key] = q
        return False
    q.append(now)
    _rate[key] = q
    if len(_rate) > 5000:
        for k in [k for k, v in _rate.items() if not v or now - v[-1] > 60][:2000]:
            _rate.pop(k, None)
    return True


async def dispatch(settings: AdminSettings, req: Req, spec: Spec, handler: Callable) -> Resp:
    session = await authenticate(settings, req)
    if not session:
        return err(401, "unauthorized", "Login required")
    state_changing = req.method not in SAFE_METHODS
    do_log = spec.log if spec.log is not None else state_changing

    if state_changing and (not same_origin(settings, req) or not check_csrf(session, req)):
        await log_activity(req.ip, f"{spec.action}.csrf_rejected", False, 403, session=session)
        return err(403, "csrf", "CSRF check failed")
    if not _rate_ok(settings, session["sid_hash"]):
        return err(429, "rate_limited", "Too many requests")

    data: Any = None
    if state_changing:
        if "application/json" not in req.headers.get("content-type", ""):
            return err(415, "bad_content_type", "Content-Type must be application/json")
        data = _parse(req, spec.model)
        if isinstance(data, Resp):
            return data
        raw_confirm = json.loads(req.body.decode() or "{}").get("confirm") if req.body else None
        if spec.confirm and raw_confirm is not True:
            return err(400, "confirm_required", "This action needs confirmation", confirm_required=True)
    elif spec.query_model is not None:
        try:
            data = spec.query_model.model_validate(req.query)
        except Exception:  # noqa: BLE001
            return err(400, "validation", "Invalid query parameters")

    ctx = Ctx(settings, session, req.ip, spec.action)
    try:
        out = await handler(ctx, data)
        resp = Resp(200, {"ok": True, **(out or {})})
    except AdminError as e:
        resp = err(e.status, e.code, e.message, **e.extra)
    except Exception:  # noqa: BLE001
        log.exception("admin handler %s crashed", spec.action)       # exception text may hold data: type only to client
        resp = err(500, "internal", "Internal error")
    if do_log:
        await log_activity(req.ip, spec.action, bool(resp.data.get("ok")), resp.status, ctx.detail, session)
    return resp
