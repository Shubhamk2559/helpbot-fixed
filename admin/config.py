"""Admin panel settings (env only). ADMIN_PANEL_PASSWORD unset => panel is not mounted at all (every /admin/* => 404)."""
import hashlib
import logging
import os
from dataclasses import dataclass
from urllib.parse import urlparse

from . import security

log = logging.getLogger("admin")


def _int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(os.getenv(name, "").strip() or default)
    except ValueError:
        return default
    return max(lo, min(hi, v))


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    return default if not raw else raw in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class AdminSettings:
    password: str = ""
    totp_secret: str = ""
    session_hours: int = 12
    cookie_secure: bool = True          # keep true in production; false only for local http testing
    proxy_hops: int = 1                 # trusted reverse proxies in front (X-Forwarded-For[-hops]); 0 = ignore header
    max_fails: int = 5                  # failed logins per IP inside fail_window => locked
    fail_window: int = 900              # seconds (also the lockout length)
    global_max_fails: int = 25          # failed logins from ALL IPs inside fail_window => everyone locked
    fail_delay: float = 0.4             # seconds slept after a failed login
    activity_days: int = 90             # activity-log retention
    rate_per_minute: int = 120          # authenticated requests per session per minute
    allowed_hosts: tuple = ()           # extra hostnames accepted in Origin (e.g. BASE_URL host)

    @property
    def enabled(self) -> bool:
        """Fail closed: a set-but-malformed TOTP secret disables the panel instead of silently dropping 2FA."""
        return bool(self.password) and (not self.totp_secret or security.totp_valid_secret(self.totp_secret))

    @property
    def cookie_name(self) -> str:
        return "__Host-hb_admin" if self.cookie_secure else "hb_admin"

    @property
    def cookie_key(self) -> bytes:
        """HMAC key for the cookie signature. Derived, never stored; changing the password invalidates all cookies."""
        seed = f"helpbot-admin-v1|{self.password}|{os.getenv('FERNET_KEY', '')}"
        return hashlib.sha256(seed.encode()).digest()


def load() -> AdminSettings:
    password = os.getenv("ADMIN_PANEL_PASSWORD", "")
    if password and len(password) < 12:
        log.warning("ADMIN_PANEL_PASSWORD is shorter than 12 characters - use a long random one")
    totp = os.getenv("ADMIN_PANEL_TOTP_SECRET", "").strip().replace(" ", "").upper()
    if password and totp and not security.totp_valid_secret(totp):
        log.error("ADMIN_PANEL_TOTP_SECRET is not valid base32 (>=16 chars) - admin panel DISABLED")
    base = os.getenv("BASE_URL", "").strip()
    host = urlparse(base).netloc.lower() if base else ""
    return AdminSettings(
        password=password,
        totp_secret=totp,
        session_hours=_int("ADMIN_PANEL_SESSION_HOURS", 12, 1, 168),
        cookie_secure=_bool("ADMIN_PANEL_COOKIE_SECURE", True),
        proxy_hops=_int("ADMIN_PANEL_PROXY_HOPS", 1, 0, 5),
        activity_days=_int("ADMIN_PANEL_ACTIVITY_DAYS", 90, 7, 730),
        allowed_hosts=(host,) if host else (),
    )
