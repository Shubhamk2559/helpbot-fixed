"""Pure helpers: hashing, cookie signing, TOTP (RFC 6238, stdlib only), log redaction. No I/O."""
import base64
import hashlib
import hmac
import re
import secrets
import struct
import time

_SECRET_KEY_RE = re.compile(
    r"(token|secret|password|passwd|pwd|key|session|cookie|csrf|authorization|totp|otp|hash|string|phone)", re.I
)
_B32_RE = re.compile(r"^[A-Z2-7]+=*$")


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def safe_equal(a: str, b: str) -> bool:
    """Constant-time compare that also hides the length (compares digests)."""
    return hmac.compare_digest(hashlib.sha256(a.encode()).digest(), hashlib.sha256(b.encode()).digest())


def sign_sid(key: bytes, sid: str) -> str:
    sig = hmac.new(key, sid.encode(), hashlib.sha256).hexdigest()[:43]
    return f"{sid}.{sig}"


def unsign_sid(key: bytes, raw: str):
    """-> sid if the signature is valid else None."""
    if not raw or len(raw) > 200 or "." not in raw:
        return None
    sid, _, sig = raw.rpartition(".")
    good = hmac.new(key, sid.encode(), hashlib.sha256).hexdigest()[:43]
    return sid if sid and hmac.compare_digest(sig, good) else None


# ---------------------------------------------------------------- TOTP
def totp_valid_secret(secret: str) -> bool:
    s = (secret or "").replace(" ", "").upper()
    if len(s) < 16 or not _B32_RE.match(s):
        return False
    try:
        base64.b32decode(s + "=" * (-len(s) % 8))
        return True
    except Exception:  # noqa: BLE001
        return False


def totp_code(secret: str, step: int, digits: int = 6) -> str:
    key = base64.b32decode(secret.replace(" ", "").upper() + "=" * (-len(secret.replace(" ", "")) % 8))
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    num = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(num).zfill(digits)


def totp_verify(secret: str, code: str, now: float = None, last_step: int = 0, window: int = 1):
    """-> matched time-step (int) or None. Rejects a step <= last_step (replay of an already used code)."""
    if not secret or not code or not re.fullmatch(r"\d{6}", code):
        return None
    cur = int((time.time() if now is None else now) // 30)
    hit = None
    for step in range(cur - window, cur + window + 1):          # no early exit: constant work
        if hmac.compare_digest(totp_code(secret, step), code) and step > last_step:
            hit = step
    return hit


# ---------------------------------------------------------------- activity-log redaction
def redact(obj, depth: int = 0):
    """Copy of obj that is safe to persist: secret-looking keys masked, long strings cut, depth/size capped."""
    if depth > 4:
        return "…"
    if isinstance(obj, dict):
        out = {}
        for i, (k, v) in enumerate(obj.items()):
            if i >= 40:
                break
            k = str(k)[:60]
            out[k] = "***" if _SECRET_KEY_RE.search(k) else redact(v, depth + 1)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact(v, depth + 1) for v in list(obj)[:30]]
    if isinstance(obj, str):
        return obj[:200]
    if isinstance(obj, (int, float, bool)) or obj is None:
        return obj
    return str(obj)[:200]
