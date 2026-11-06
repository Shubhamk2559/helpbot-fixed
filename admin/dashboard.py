"""Dashboard numbers. Uses the SAME db.* functions as the Telegram bot's Stats screen (handlers.stats_text),
so both always agree: db.count_files / db.views_total / db.views_last_days.
Extra sections (users, per-bot, ads) are read-only aggregates over existing collections."""
import logging

log = logging.getLogger("admin")


async def _safe(label: str, coro, default):
    try:
        return await coro
    except Exception:  # noqa: BLE001 - one broken section must not blank the whole dashboard
        log.exception("dashboard section %s failed", label)
        return default


async def collect(db=None, ads_enabled: bool = None, ads_report=None, monetag_store=None) -> dict:
    if db is None:
        import db as _db
        db = _db
    if ads_enabled is None:
        from ads import settings as ads_settings
        ads_enabled = ads_settings.SMART_ADS_ENABLED

    # ---- identical to the bot's Stats screen
    n_files = await db.count_files()
    total = await db.views_total()
    days = await db.views_last_days(7)
    out = {
        "views_today": days[0][1] if days else 0,
        "views_total": total,
        "files_total": n_files,
        "last_7_days": [{"day": d, "views": v} for d, v in days],
    }
    # ---- extras
    out["posts_total"] = await _safe("posts", db.files.count_documents({"kind": "post"}), 0)
    out["bulk_imported"] = await _safe("bulk", db.files.count_documents({"src_chat": {"$exists": True, "$ne": None}}), 0)
    sess = await _safe("sessions", db.sessions.aggregate([
        {"$group": {"_id": "$bot_id", "sessions": {"$sum": 1}, "delivered": {"$sum": {"$cond": ["$delivered", 1, 0]}},
                    "users": {"$addToSet": "$user_id"}}}]).to_list(length=500), [])
    all_users = set()
    by_bot = {}
    for r in sess:
        users = r.get("users") or []
        all_users.update(users)
        by_bot[str(r["_id"])] = {"sessions": int(r["sessions"]), "delivered": int(r["delivered"]), "users": len(users)}
    # the DB keeps no permanent user table: this counts users with a verification session inside SESSION_TTL
    out["users_recent"] = len(all_users)
    out["users_note"] = "No permanent user table exists. 'Recent' = users with a verification session in the last SESSION_TTL window."

    bots = await _safe("bots", db.list_bots(), [])
    rows, seen = [], set()
    for b in bots:                                         # never expose token_enc
        bid = str(b.get("bot_id"))
        seen.add(bid)
        rows.append({"bot_id": bid, "username": b.get("username"), "status": b.get("status"),
                     "added_at": b.get("added_at"), **by_bot.get(bid, {"sessions": 0, "delivered": 0, "users": 0})})
    for bid, v in by_bot.items():                          # e.g. the main bot is not in the registry
        if bid not in seen:
            rows.append({"bot_id": bid, "username": None, "status": None, "added_at": None, **v})
    out["bots"] = rows
    out["bots_active"] = sum(1 for r in rows if r["status"] == "active")

    out["ads"] = await _safe("ads", _ads(ads_enabled, ads_report, monetag_store), {"error": "unavailable"})
    return out


async def _ads(enabled: bool, ads_report, monetag_store) -> dict:
    if enabled:
        if ads_report is None:
            from ads import report as ads_report
        rep = await ads_report.build(7)
        t = rep["totals"]
        return {"mode": "smart", "window_days": 7,
                "totals": {k: t.get(k) for k in ("requests", "shown", "completed", "verified", "failed", "fill_rate",
                                                 "completion_rate", "confirmed_revenue_usd", "estimated_revenue_usd")},
                "networks": {n: {"label": b["label"], "status": b["status"], "verified": b["verified"],
                                 "today_verified": b["today_verified"], "fill_rate": b["fill_rate"]}
                             for n, b in rep["networks"].items()}}
    if monetag_store is None:
        import monetag_store
    rep = await monetag_store.build_report(7)
    t = rep["total"]
    return {"mode": "monetag", "window_days": 7,
            "totals": {"requests": t["attempts"], "shown": t["impressions"], "completed": t["completions"],
                       "failed": t["failures"], "fill_rate": t["fill_rate"],
                       "confirmed_revenue_usd": rep["revenue"]["confirmed_usd"],
                       "estimated_revenue_usd": rep["revenue"]["estimated_usd"]},
            "networks": {}}
