"""Which environment variables are SET. Returns booleans only - values are never read into the response."""
import os

GROUPS = {
    "Core": ["MAIN_BOT_TOKEN", "OWNER_ID", "MONGO_URI", "DB_NAME", "FERNET_KEY", "BASE_URL", "LINK_BASE_URL",
             "WEBHOOK_SECRET", "PRIMARY_CHANNEL", "BACKUP_CHANNEL", "ROLE", "HEALTH_INTERVAL", "SYNC_INTERVAL",
             "CHANNEL_URL", "SUPPORT_URL", "STATS_TZ_OFFSET_MIN"],
    "Ads / Mini App": ["ADS_REQUIRED", "MIN_AD_SECONDS", "SESSION_TTL", "AUTO_DELETE_SECONDS", "MINIAPP_SHORT_NAME",
                       "DIRECT_MINIAPP", "AD_VERIFY_MODE", "BLOCK_NON_VALUED", "POSTBACK_WAIT_SECONDS", "VERIFY_REQUIRED",
                       "MONETAG_ZONE_ID", "MONETAG_ZONES", "MONETAG_DEFAULT_ZONE", "MONETAG_SDK_URL",
                       "MONETAG_POSTBACK_SECRET", "MONETAG_ADMIN_TOKEN", "MONETAG_GEO_HEADER", "MONETAG_OPTIMIZE"],
    "Smart Ads": ["SMART_ADS_ENABLED", "ADS_ADMIN_TOKEN", "ADSGRAM_BLOCK_ID", "ADSGRAM_REWARD_SECRET",
                  "TADS_WIDGET_ID", "TADS_ALLOW_CLIENT_REWARD"],
    "Posts / Bulk / Copy Chats": ["POST_CHANNEL", "POST_CAPTION", "POST_BUTTON_TEXT", "POST_DIRECT_LINK", "POST_MAX_VIDEOS",
                                  "BULK_MAX_RANGE", "BULK_SCAN_DELAY", "BULK_POST_DELAY", "TG_API_ID", "TG_API_HASH",
                                  "UB_BATCH", "UB_DELAY"],
    "Auto Posting": ["AP_DB_NAME", "TIMEZONE", "ADMIN_PASSWORD", "VAULT_CHAT_ID", "AP_EXTRA_ADMIN_IDS",
                     "DEFAULT_INTERVAL_MINUTES", "DEFAULT_BATCH_SIZE", "SCAN_INTERVAL_SECONDS", "RETRY_ATTEMPTS",
                     "POST_GAP_SECONDS", "LOG_RETENTION_DAYS"],
    "Admin panel": ["ADMIN_PANEL_PASSWORD", "ADMIN_PANEL_TOTP_SECRET", "ADMIN_PANEL_SESSION_HOURS",
                    "ADMIN_PANEL_COOKIE_SECURE", "ADMIN_PANEL_PROXY_HOPS", "ADMIN_PANEL_ACTIVITY_DAYS"],
}


def snapshot(environ=None) -> dict:
    env = os.environ if environ is None else environ
    return {g: [{"name": n, "set": bool((env.get(n) or "").strip())} for n in names] for g, names in GROUPS.items()}
