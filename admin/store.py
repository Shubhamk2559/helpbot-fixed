"""MongoDB persistence for the admin panel. All collections are NEW (existing ones untouched):

  admin_sessions   one doc per login   {sid_hash, csrf, ip, created, expires_at}          TTL on expires_at
  admin_attempts   failed logins       {ip, t, created}                                     TTL on created
  admin_activity   audit log           {t, created, action, ok, status, ip, detail}         TTL on created
  admin_meta       tiny key/value      {_id, value}   (TOTP replay guard)

Only a SHA-256 of the session id is stored, never the id that lives in the cookie.
"""
import time
from datetime import datetime, timedelta, timezone

_DB = None


def set_database(database) -> None:
    global _DB
    _DB = database


def _c(name: str):
    global _DB
    if _DB is None:
        import db                      # lazy: tests inject a fake with set_database()
        _DB = db._db
    return _DB[name]


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


async def init_indexes(settings) -> None:
    await _c("admin_sessions").create_index("sid_hash", unique=True)
    await _c("admin_sessions").create_index("expires_at", expireAfterSeconds=0)
    await _c("admin_attempts").create_index([("ip", 1), ("t", 1)])
    await _c("admin_attempts").create_index("created", expireAfterSeconds=settings.fail_window + 60)
    await _c("admin_activity").create_index([("t", -1)])
    await _c("admin_activity").create_index("created", expireAfterSeconds=settings.activity_days * 86400)


# ---- sessions
async def create_session(sid_hash: str, csrf: str, ip: str, ttl_seconds: int) -> dict:
    now = time.time()
    doc = {"sid_hash": sid_hash, "csrf": csrf, "ip": ip, "t": now, "created": _now_dt(),
           "expires_at": _now_dt() + timedelta(seconds=ttl_seconds), "exp_t": now + ttl_seconds}
    await _c("admin_sessions").insert_one(doc)
    return doc


async def get_session(sid_hash: str):
    d = await _c("admin_sessions").find_one({"sid_hash": sid_hash})
    if d and d.get("exp_t", 0) > time.time():       # Mongo's TTL monitor runs only every ~60s, so check here too
        return d
    return None


async def delete_session(sid_hash: str) -> None:
    await _c("admin_sessions").delete_one({"sid_hash": sid_hash})


# ---- login attempts
async def add_failure(ip: str) -> None:
    await _c("admin_attempts").insert_one({"ip": ip, "t": time.time(), "created": _now_dt()})


async def failures(ip, since: float) -> list:
    """Timestamps (ascending) of failures since `since`. ip=None => all IPs."""
    q = {"t": {"$gte": since}}
    if ip is not None:
        q["ip"] = ip
    docs = await _c("admin_attempts").find(q).sort("t", 1).to_list(length=1000)
    return [d["t"] for d in docs]


async def clear_failures(ip: str) -> None:
    await _c("admin_attempts").delete_many({"ip": ip})


# ---- activity log
async def add_activity(entry: dict) -> None:
    entry = dict(entry)
    entry["t"] = time.time()
    entry["created"] = _now_dt()
    await _c("admin_activity").insert_one(entry)


async def list_activity(skip: int, limit: int, action: str = None, ok: bool = None):
    q = {}
    if action:
        q["action"] = action
    if ok is not None:
        q["ok"] = ok
    col = _c("admin_activity")
    total = await col.count_documents(q)
    docs = await col.find(q).sort("t", -1).skip(skip).limit(limit).to_list(length=limit)
    items = [{"t": d.get("t"), "action": d.get("action"), "ok": d.get("ok"), "status": d.get("status"),
              "ip": d.get("ip"), "detail": d.get("detail") or {}} for d in docs]
    return total, items


# ---- meta
async def get_meta(key: str, default=None):
    d = await _c("admin_meta").find_one({"_id": key})
    return d["value"] if d else default


async def set_meta(key: str, value) -> None:
    await _c("admin_meta").update_one({"_id": key}, {"$set": {"value": value}}, upsert=True)
