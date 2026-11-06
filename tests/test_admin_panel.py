"""Phase 1 admin panel tests.

Layer 1 (always runs; no FastAPI / Mongo / Telegram needed): real admin.service / security / store / dashboard / envcheck
against an in-memory Mongo fake. Layer 2 (runs only when fastapi + httpx are installed): the real HTTP wiring.
"""
import ast
import asyncio
import json
import os
import time
import unittest
from pathlib import Path

from admin import dashboard, envcheck, security, service, store
from admin.config import AdminSettings
from admin.service import AdminError, Req, Spec

ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "correct horse battery staple"
SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"      # RFC 6238 test secret ("12345678901234567890")


# ---------------------------------------------------------------- tiny in-memory Mongo
def _match(doc, flt):
    for k, cond in flt.items():
        v = doc.get(k)
        if isinstance(cond, dict):
            if "$gte" in cond and not (v is not None and v >= cond["$gte"]):
                return False
        elif v != cond:
            return False
    return True


class Cursor:
    def __init__(self, docs): self.docs = docs
    def sort(self, key, d=1): self.docs = sorted(self.docs, key=lambda x: x.get(key, 0), reverse=d < 0); return self
    def skip(self, n): self.docs = self.docs[n:]; return self
    def limit(self, n): self.docs = self.docs[:n]; return self
    async def to_list(self, length=None): return [dict(d) for d in self.docs[:length]]


class Col:
    def __init__(self): self.docs = []
    async def create_index(self, *a, **k): return "ok"
    async def insert_one(self, d): self.docs.append(dict(d))
    async def find_one(self, f): return next((dict(d) for d in self.docs if _match(d, f)), None)
    async def delete_one(self, f):
        for i, d in enumerate(self.docs):
            if _match(d, f):
                del self.docs[i]; return
    async def delete_many(self, f): self.docs = [d for d in self.docs if not _match(d, f)]
    async def count_documents(self, f): return sum(1 for d in self.docs if _match(d, f))
    def find(self, f=None): return Cursor([d for d in self.docs if _match(d, f or {})])
    async def update_one(self, f, upd, upsert=False):
        d = next((d for d in self.docs if _match(d, f)), None)
        if d is None and upsert:
            d = dict(f); self.docs.append(d)
        if d is not None:
            d.update(upd.get("$set", {}))


class FakeDB(dict):
    def __missing__(self, k): self[k] = Col(); return self[k]


# ---------------------------------------------------------------- validation stand-ins (pydantic may be absent here)
class _VErr(Exception):
    def __init__(self, raw): self.raw = raw
    def errors(self): return [{"loc": ("password",), "msg": "Field required", "input": self.raw}]


class LoginStub:
    def __init__(self, password, totp=None): self.password, self.totp = password, totp
    @classmethod
    def model_validate(cls, raw):
        if not isinstance(raw.get("password"), str) or not raw["password"]:
            raise _VErr(raw)
        return cls(raw["password"], raw.get("totp"))


def run(coro):
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)


HOST = "panel.example.com"


def mk(method="GET", path="/x", ip="1.1.1.1", cookie=None, csrf=None, body=None, ctype="application/json", extra=None, S=None):
    h = {"host": HOST}
    if ctype:
        h["content-type"] = ctype
    if csrf:
        h["x-csrf-token"] = csrf
    h.update(extra or {})
    raw = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    return Req(method, path, ip, h, {(S or AdminSettings()).cookie_name: cookie} if cookie else {}, {}, raw)


class Base(unittest.TestCase):
    totp = ""

    def setUp(self):
        self.db = FakeDB()
        store.set_database(self.db)
        self.S = AdminSettings(password=PASSWORD, totp_secret=self.totp, fail_delay=0, allowed_hosts=(HOST,))
        service._rate.clear()

    def tearDown(self):
        store.set_database(None)

    def login(self, pw=PASSWORD, ip="1.1.1.1", totp=None):
        body = {"password": pw}
        if totp:
            body["totp"] = totp
        return run(service.login(self.S, mk("POST", "/admin/api/login", ip, body=body, S=self.S), LoginStub))

    def session(self, ip="1.1.1.1"):
        r = self.login(ip=ip)
        self.assertEqual(r.status, 200, r.data)
        cookie = r.cookie["value"]
        sess = run(service.authenticate(self.S, mk(cookie=cookie, S=self.S)))
        return cookie, sess["csrf"]

    def call(self, spec, handler, cookie=None, csrf=None, body=None, **kw):
        req = mk(spec.method, "/admin/api" + spec.path, cookie=cookie, csrf=csrf, body=body, S=self.S, **kw)
        return run(service.dispatch(self.S, req, spec, handler))


async def _ok_handler(ctx, body):
    ctx.detail = {"token": "SHOULD-BE-MASKED", "name": "visible"}
    return {"done": True}


POST = Spec("POST", "/things/delete", "things.delete", None, confirm=True)
GET = Spec("GET", "/things", "things.list")


class LoginTests(Base):
    def test_login_ok_sets_cookie_and_stores_only_hash(self):
        r = self.login()
        self.assertEqual((r.status, r.data), (200, {"ok": True}))
        sid = security.unsign_sid(self.S.cookie_key, r.cookie["value"])
        self.assertTrue(sid)
        doc = self.db["admin_sessions"].docs[0]
        self.assertEqual(doc["sid_hash"], security.sha256_hex(sid))
        self.assertNotIn(sid, json.dumps(doc, default=str))          # raw session id is never stored
        self.assertEqual(r.cookie["max_age"], 12 * 3600)

    def test_login_fail_is_generic_and_sets_no_cookie(self):
        r = self.login("wrong")
        self.assertEqual((r.status, r.data["code"]), (401, "invalid_credentials"))
        self.assertIsNone(r.cookie)
        self.assertEqual(self.db["admin_sessions"].docs, [])

    def test_lockout_after_max_fails_even_with_right_password(self):
        for _ in range(5):
            self.assertEqual(self.login("bad").status, 401)
        r = self.login(PASSWORD)
        self.assertEqual((r.status, r.data["code"]), (429, "locked"))
        self.assertGreater(r.data["retry_after"], 0)
        self.assertIsNone(r.cookie)

    def test_lockout_is_per_ip_until_global_cap(self):
        for _ in range(5):
            self.login("bad", ip="9.9.9.9")
        self.assertEqual(self.login(PASSWORD, ip="2.2.2.2").status, 200)

    def test_global_lockout_blocks_ip_rotation(self):
        for i in range(25):
            self.login("bad", ip=f"10.0.{i}.1")
        self.assertEqual(self.login(PASSWORD, ip="77.7.7.7").status, 429)

    def test_lockout_expires(self):
        for _ in range(5):
            self.login("bad")
        for d in self.db["admin_attempts"].docs:
            d["t"] -= self.S.fail_window + 5
        self.assertEqual(self.login(PASSWORD).status, 200)

    def test_success_clears_failures(self):
        for _ in range(3):
            self.login("bad")
        self.login()
        self.assertEqual(self.db["admin_attempts"].docs, [])

    def test_login_requires_json_and_same_origin(self):
        r = run(service.login(self.S, mk("POST", ctype="text/plain", body=b"password=x", S=self.S), LoginStub))
        self.assertEqual(r.status, 415)
        r = run(service.login(self.S, mk("POST", body={"password": PASSWORD}, extra={"origin": "https://evil.example"}, S=self.S), LoginStub))
        self.assertEqual((r.status, r.data["code"]), (403, "bad_origin"))
        r = run(service.login(self.S, mk("POST", body={"password": PASSWORD}, extra={"sec-fetch-site": "cross-site"}, S=self.S), LoginStub))
        self.assertEqual(r.status, 403)

    def test_login_validation_error_does_not_echo_input(self):
        r = run(service.login(self.S, mk("POST", body={"password": "", "secret_extra": "LEAKME"}, S=self.S), LoginStub))
        self.assertEqual((r.status, r.data["code"]), (400, "validation"))
        self.assertNotIn("LEAKME", json.dumps(r.data))

    def test_failed_and_ok_logins_are_in_activity_log_without_secrets(self):
        self.login("hunter2-wrong")
        self.login()
        dump = json.dumps(self.db["admin_activity"].docs, default=str)
        self.assertIn("login.fail", dump)
        self.assertIn("login.ok", dump)
        self.assertNotIn("hunter2-wrong", dump)
        self.assertNotIn(PASSWORD, dump)

    def test_client_ip_ignores_spoofable_left_side_of_xff(self):
        h = {"x-forwarded-for": "6.6.6.6, 203.0.113.9"}
        self.assertEqual(service.client_ip(self.S, h, "10.0.0.1"), "203.0.113.9")
        self.assertEqual(service.client_ip(AdminSettings(proxy_hops=0), h, "10.0.0.1"), "10.0.0.1")


class AuthAndCsrfTests(Base):
    def test_unauthenticated_is_401(self):
        r = self.call(GET, _ok_handler)
        self.assertEqual((r.status, r.data["code"], r.data["ok"]), (401, "unauthorized", False))

    def test_tampered_and_garbage_cookies_are_401(self):
        cookie, _ = self.session()
        for bad in (cookie[:-2] + "xx", "abc", "." + cookie.split(".")[1], cookie + "x"):
            self.assertEqual(self.call(GET, _ok_handler, cookie=bad).status, 401)

    def test_expired_session_is_401_before_mongo_ttl_runs(self):
        cookie, _ = self.session()
        self.db["admin_sessions"].docs[0]["exp_t"] = time.time() - 1
        self.assertEqual(self.call(GET, _ok_handler, cookie=cookie).status, 401)

    def test_get_needs_no_csrf(self):
        cookie, _ = self.session()
        self.assertEqual(self.call(GET, _ok_handler, cookie=cookie).status, 200)

    def test_post_without_or_with_wrong_csrf_is_rejected(self):
        cookie, csrf = self.session()
        for token in (None, "wrong", csrf[:-1]):
            r = self.call(POST, _ok_handler, cookie=cookie, csrf=token, body={"confirm": True})
            self.assertEqual((r.status, r.data["code"]), (403, "csrf"))

    def test_post_cross_origin_rejected_even_with_valid_token(self):
        cookie, csrf = self.session()
        r = self.call(POST, _ok_handler, cookie=cookie, csrf=csrf, body={"confirm": True}, extra={"origin": "https://evil.example"})
        self.assertEqual(r.status, 403)
        r = self.call(POST, _ok_handler, cookie=cookie, csrf=csrf, body={"confirm": True}, extra={"origin": "null"})
        self.assertEqual(r.status, 403)

    def test_post_same_origin_with_csrf_ok(self):
        cookie, csrf = self.session()
        r = self.call(POST, _ok_handler, cookie=cookie, csrf=csrf, body={"confirm": True}, extra={"origin": f"https://{HOST}"})
        self.assertEqual((r.status, r.data), (200, {"ok": True, "done": True}))

    def test_confirm_gate(self):
        cookie, csrf = self.session()
        for body in ({}, {"confirm": False}, {"confirm": "true"}, {"confirm": 1}):
            r = self.call(POST, _ok_handler, cookie=cookie, csrf=csrf, body=body)
            self.assertEqual((r.status, r.data["code"]), (400, "confirm_required"))

    def test_post_must_be_json_object(self):
        cookie, csrf = self.session()
        self.assertEqual(self.call(POST, _ok_handler, cookie=cookie, csrf=csrf, body=b"confirm=1", ctype="text/plain").status, 415)
        self.assertEqual(self.call(POST, _ok_handler, cookie=cookie, csrf=csrf, body=b"{oops").data["code"], "bad_json")
        self.assertEqual(self.call(POST, _ok_handler, cookie=cookie, csrf=csrf, body=b"[1]").data["code"], "bad_json")

    def test_handler_errors_are_structured(self):
        async def nf(ctx, b): raise AdminError("not_found", "File not found", 404, token_hint="x")
        async def boom(ctx, b): raise RuntimeError("secret-db-password in message")
        cookie, csrf = self.session()
        r = self.call(GET, nf, cookie=cookie)
        self.assertEqual((r.status, r.data["code"], r.data["ok"]), (404, "not_found", False))
        r = self.call(GET, boom, cookie=cookie)
        self.assertEqual((r.status, r.data), (500, {"ok": False, "code": "internal", "error": "Internal error"}))

    def test_state_changing_actions_are_logged_redacted_and_gets_are_not(self):
        cookie, csrf = self.session()
        self.call(GET, _ok_handler, cookie=cookie)
        self.call(POST, _ok_handler, cookie=cookie, csrf=csrf, body={"confirm": True})
        acts = [d for d in self.db["admin_activity"].docs if d["action"].startswith("things")]
        self.assertEqual([a["action"] for a in acts], ["things.delete"])
        self.assertEqual(acts[0]["detail"], {"token": "***", "name": "visible"})
        self.assertTrue(acts[0]["ok"])

    def test_csrf_failure_is_logged(self):
        cookie, _ = self.session()
        self.call(POST, _ok_handler, cookie=cookie, csrf="bad", body={"confirm": True})
        self.assertIn("things.delete.csrf_rejected", [d["action"] for d in self.db["admin_activity"].docs])

    def test_logout_needs_csrf_then_kills_session(self):
        cookie, csrf = self.session()
        r = run(service.logout(self.S, mk("POST", cookie=cookie, S=self.S)))
        self.assertEqual(r.status, 403)
        r = run(service.logout(self.S, mk("POST", cookie=cookie, csrf=csrf, S=self.S)))
        self.assertEqual((r.status, r.cookie["max_age"]), (200, 0))
        self.assertEqual(self.call(GET, _ok_handler, cookie=cookie).status, 401)

    def test_rate_limit_per_session(self):
        self.S = AdminSettings(password=PASSWORD, fail_delay=0, allowed_hosts=(HOST,), rate_per_minute=3)
        cookie, _ = self.session()
        codes = [self.call(GET, _ok_handler, cookie=cookie).status for _ in range(5)]
        self.assertEqual(codes, [200, 200, 200, 429, 429])


class TotpTests(Base):
    totp = SECRET_B32

    def test_rfc6238_vector(self):
        self.assertEqual(security.totp_code(SECRET_B32, 59 // 30), "287082")

    def test_login_requires_valid_totp(self):
        self.assertEqual(self.login().status, 401)                        # password only
        self.assertEqual(self.login(totp="000000").status, 401)
        code = security.totp_code(SECRET_B32, int(time.time() // 30))
        self.assertEqual(self.login(totp=code).status, 200)

    def test_totp_code_cannot_be_replayed(self):
        code = security.totp_code(SECRET_B32, int(time.time() // 30))
        self.assertEqual(self.login(totp=code).status, 200)
        self.assertEqual(self.login(totp=code).status, 401)

    def test_wrong_password_with_right_totp_fails(self):
        code = security.totp_code(SECRET_B32, int(time.time() // 30))
        self.assertEqual(self.login("bad", totp=code).status, 401)

    def test_secret_validation(self):
        self.assertTrue(security.totp_valid_secret(SECRET_B32))
        self.assertFalse(security.totp_valid_secret("short"))
        self.assertFalse(security.totp_valid_secret("not base32 !!!!!!!!!!!!"))


class SecretsNeverLeakTests(Base):
    def test_env_snapshot_has_only_booleans(self):
        env = {"MAIN_BOT_TOKEN": "123456:SECRET-BOT-TOKEN", "FERNET_KEY": "FERNET-SECRET", "MONGO_URI": "mongodb://u:pw@h",
               "ADMIN_PANEL_PASSWORD": PASSWORD, "ADMIN_PANEL_TOTP_SECRET": SECRET_B32, "OWNER_ID": "  "}
        snap = envcheck.snapshot(env)
        flat = {v["name"]: v["set"] for g in snap.values() for v in g}
        self.assertTrue(flat["MAIN_BOT_TOKEN"] and flat["FERNET_KEY"] and flat["ADMIN_PANEL_PASSWORD"])
        self.assertFalse(flat["OWNER_ID"])                                # whitespace only == unset
        self.assertFalse(flat["TG_API_HASH"])
        dump = json.dumps(snap)
        for leaked in ("SECRET-BOT-TOKEN", "FERNET-SECRET", "u:pw", PASSWORD, SECRET_B32):
            self.assertNotIn(leaked, dump)
        self.assertTrue(all(set(v) == {"name", "set"} and isinstance(v["set"], bool) for g in snap.values() for v in g))

    def test_every_documented_admin_env_is_listed(self):
        names = {v["name"] for g in envcheck.snapshot({}).values() for v in g}
        self.assertTrue({"ADMIN_PANEL_PASSWORD", "ADMIN_PANEL_TOTP_SECRET", "MAIN_BOT_TOKEN", "FERNET_KEY"} <= names)

    def test_redact(self):
        out = security.redact({"bot_token": "x", "session_string": "y", "Password": "z", "name": "ok", "n": {"api_key": "k", "v": 1},
                               "long": "a" * 999})
        self.assertEqual((out["bot_token"], out["session_string"], out["Password"], out["n"]["api_key"]), ("***",) * 4)
        self.assertEqual((out["name"], out["n"]["v"], len(out["long"])), ("ok", 1, 200))

    def test_login_responses_never_contain_password_or_cookie_key(self):
        for r in (self.login(), self.login("bad")):
            self.assertNotIn(PASSWORD, json.dumps(r.data))
            self.assertNotIn(self.S.cookie_key.hex(), json.dumps(r.data))

    def test_activity_listing_has_no_secret_fields(self):
        self.login("bad")
        total, items = run(store.list_activity(0, 50))
        self.assertEqual(total, 1)
        self.assertEqual(set(items[0]), {"t", "action", "ok", "status", "ip", "detail"})


class FakeStatsDB:
    """Stands in for db.py: same function names the bot's stats_text() uses."""
    def __init__(self):
        self.calls = []
        self.files = type("F", (), {"count_documents": staticmethod(self._cnt)})
        agg = [{"_id": "b1", "sessions": 4, "delivered": 3, "users": [1, 2, 3]}, {"_id": "main", "sessions": 1, "delivered": 0, "users": [1]}]
        self.sessions = type("S", (), {"aggregate": staticmethod(lambda p: type("A", (), {"to_list": staticmethod(self._tl(agg))}))})
    async def _cnt(self, q):
        return 7 if q.get("kind") else 2
    @staticmethod
    def _tl(v):
        async def f(length=None): return v
        return f
    async def count_files(self): return 42
    async def views_total(self): return 1000
    async def views_last_days(self, n): return [(f"2026-11-0{6 - i}", 10 - i) for i in range(n)]
    async def list_bots(self):
        return [{"bot_id": "b1", "username": "mybot", "status": "active", "added_at": 1.0, "token_enc": "gAAAA-ENCRYPTED-TOKEN"}]


class DashboardTests(unittest.TestCase):
    def test_same_numbers_as_bot_stats_and_no_token(self):
        class Rep:
            @staticmethod
            async def build(days):
                return {"totals": {"requests": 5, "shown": 4, "completed": 3, "verified": 3, "failed": 1, "fill_rate": 0.8,
                                   "completion_rate": 0.75, "confirmed_revenue_usd": None, "estimated_revenue_usd": 1.5},
                        "networks": {"monetag": {"label": "Monetag", "status": "healthy", "verified": 3, "today_verified": 1, "fill_rate": 0.8}}}
        d = run(dashboard.collect(FakeStatsDB(), ads_enabled=True, ads_report=Rep))
        self.assertEqual((d["files_total"], d["views_total"], d["views_today"]), (42, 1000, 10))
        self.assertEqual(len(d["last_7_days"]), 7)
        self.assertEqual((d["posts_total"], d["users_recent"], d["bots_active"]), (7, 3, 1))
        self.assertEqual({b["bot_id"] for b in d["bots"]}, {"b1", "main"})
        self.assertEqual(d["ads"]["totals"]["verified"], 3)
        self.assertNotIn("ENCRYPTED-TOKEN", json.dumps(d))
        self.assertNotIn("token_enc", json.dumps(d))

    def test_ads_failure_does_not_break_dashboard(self):
        class Bad:
            @staticmethod
            async def build(days): raise RuntimeError("down")
        d = run(dashboard.collect(FakeStatsDB(), ads_enabled=True, ads_report=Bad))
        self.assertEqual(d["ads"], {"error": "unavailable"})
        self.assertEqual(d["files_total"], 42)

    def test_monetag_only_mode(self):
        class M:
            @staticmethod
            async def build_report(days):
                return {"total": {"attempts": 9, "impressions": 8, "completions": 7, "failures": 1, "fill_rate": 0.9},
                        "revenue": {"confirmed_usd": 2.0, "estimated_usd": 2.5}}
        d = run(dashboard.collect(FakeStatsDB(), ads_enabled=False, monetag_store=M))
        self.assertEqual((d["ads"]["mode"], d["ads"]["totals"]["requests"]), ("monetag", 9))


class DisabledAndWiringTests(unittest.TestCase):
    def test_panel_disabled_without_password(self):
        old = os.environ.pop("ADMIN_PANEL_PASSWORD", None)
        try:
            from admin import config
            self.assertFalse(config.load().enabled)
            self.assertFalse(AdminSettings().enabled)
        finally:
            if old is not None:
                os.environ["ADMIN_PANEL_PASSWORD"] = old

    def test_malformed_totp_secret_disables_panel_fail_closed(self):
        self.assertFalse(AdminSettings(password=PASSWORD, totp_secret="not-base32!").enabled)
        self.assertTrue(AdminSettings(password=PASSWORD, totp_secret=SECRET_B32).enabled)
        self.assertTrue(AdminSettings(password=PASSWORD).enabled)

    def test_no_future_annotations_in_fastapi_modules(self):
        for name in ("core.py", "routes.py"):
            tree = ast.parse((ROOT / "admin" / name).read_text(encoding="utf-8"))
            bad = [n for n in tree.body if isinstance(n, ast.ImportFrom) and n.module == "__future__"]
            self.assertEqual(bad, [], f"{name} must not use `from __future__ import annotations` (HTTP 422 bug)")

    def test_ui_has_no_inline_script_style_or_innerhtml(self):
        for p in (ROOT / "admin" / "ui").iterdir():
            t = p.read_text(encoding="utf-8")
            if p.suffix == ".html":
                self.assertNotRegex(t, r"<script(?![^>]*\bsrc=)", p.name)
                self.assertNotIn(" style=", t, p.name)
                self.assertNotRegex(t, r"\bon\w+=", p.name)
            if p.suffix == ".js":
                self.assertNotIn("innerHTML", t, p.name)
                self.assertNotIn("eval(", t, p.name)


try:
    import fastapi  # noqa: F401
    import httpx  # noqa: F401
    import pydantic  # noqa: F401
    HAVE_HTTP = True
except ImportError:
    HAVE_HTTP = False


@unittest.skipUnless(HAVE_HTTP, "fastapi/httpx/pydantic not installed - real HTTP wiring tests skipped")
class RealHttpTests(unittest.TestCase):
    def make(self, password=PASSWORD):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from admin import routes
        self.db = FakeDB()
        store.set_database(self.db)
        service._rate.clear()
        s = AdminSettings(password=password, fail_delay=0)
        app = FastAPI()
        mounted = routes.register(app, s)
        return mounted, TestClient(app, base_url="https://testserver"), s

    def tearDown(self):
        store.set_database(None)

    def test_404_everywhere_when_password_unset(self):
        mounted, c, _ = self.make(password="")
        self.assertFalse(mounted)
        for path in ("/admin", "/admin/login", "/admin/settings", "/admin/api/session", "/admin/static/panel.js"):
            self.assertEqual(c.get(path, follow_redirects=False).status_code, 404, path)
        self.assertEqual(c.post("/admin/api/login", json={"password": "x"}).status_code, 404)

    def test_full_flow(self):
        mounted, c, s = self.make()
        self.assertTrue(mounted)
        self.assertEqual(c.get("/admin", follow_redirects=False).status_code, 303)       # page -> login
        self.assertEqual(c.get("/admin/api/session").status_code, 401)
        self.assertEqual(c.post("/admin/api/login", json={"password": "bad"}).status_code, 401)
        self.assertEqual(c.post("/admin/api/login", json={"password": ""}).status_code, 400)
        r = c.post("/admin/api/login", json={"password": PASSWORD})
        self.assertEqual(r.status_code, 200)
        sc = r.headers["set-cookie"].lower()
        for flag in ("httponly", "secure", "samesite=strict", "path=/"):
            self.assertIn(flag, sc)
        self.assertEqual(c.get("/admin", follow_redirects=False).status_code, 200)
        sess = c.get("/admin/api/session").json()
        self.assertTrue(sess["ok"] and len(sess["sections"]) == 9)
        self.assertEqual(c.post("/admin/api/logout").status_code, 403)                    # no CSRF
        env = c.get("/admin/api/settings").json()
        self.assertNotIn(PASSWORD, json.dumps(env))
        self.assertEqual(c.get("/admin/api/activity?limit=500").json()["code"], "validation")
        self.assertEqual(c.post("/admin/api/logout", headers={"X-CSRF-Token": sess["csrf"]}).status_code, 200)
        self.assertEqual(c.get("/admin/api/session").status_code, 401)

    def test_security_headers_and_422_regression(self):
        _, c, _ = self.make()
        r = c.get("/admin/login")
        self.assertEqual(r.status_code, 200)
        self.assertIn("frame-ancestors 'none'", r.headers["content-security-policy"])
        self.assertEqual(r.headers["cache-control"], "no-store")
        self.assertNotEqual(c.get("/admin/api/session").status_code, 422)

    def test_decorator_adds_route(self):
        from admin import core, routes  # noqa: F401  (routes import registers the built-ins first)
        before = len(core.registry())

        @core.admin_route("GET", "/phase2-demo", action="demo.read")
        async def demo(ctx, _):
            return {"hello": 1}
        try:
            _, c, _ = self.make()
            self.assertEqual(c.get("/admin/api/phase2-demo").status_code, 401)
            c.post("/admin/api/login", json={"password": PASSWORD})
            self.assertEqual(c.get("/admin/api/phase2-demo").json(), {"ok": True, "hello": 1})
        finally:
            core._REGISTRY[:] = core._REGISTRY[:before]


if __name__ == "__main__":
    unittest.main()
