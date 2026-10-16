"""Security primitives: password policy, TOTP (RFC 6238), rate limiter, audit hash-chain."""
import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
from collections import defaultdict, deque
from urllib.parse import quote

# ---------------- Password policy ----------------
COMMON_PASSWORDS = {"password@123", "admin@123", "welcome@123", "qwerty@123",
                    "password1!", "p@ssw0rd", "letmein@123", "abc@12345"}


def password_errors(pw, username=""):
    errs = []
    if len(pw) < 8:
        errs.append("Password must be at least 8 characters.")
    if not re.search(r"[A-Z]", pw):
        errs.append("Password needs an uppercase letter.")
    if not re.search(r"[a-z]", pw):
        errs.append("Password needs a lowercase letter.")
    if not re.search(r"\d", pw):
        errs.append("Password needs a digit.")
    if not re.search(r"[^A-Za-z0-9]", pw):
        errs.append("Password needs a special character.")
    if username and username.lower() in pw.lower():
        errs.append("Password must not contain your username.")
    if pw.lower() in COMMON_PASSWORDS:
        errs.append("Password is too common.")
    return errs


# ---------------- TOTP (RFC 4226 / RFC 6238) ----------------
def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode()


def hotp(secret_b32, counter, digits=6):
    key = base64.b32decode(secret_b32, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(secret_b32, at=None, step=30, digits=6):
    at = time.time() if at is None else at
    return hotp(secret_b32, int(at // step), digits)


def verify_totp(secret_b32, code, last_step=0, at=None, step=30, window=1):
    """Return the matched time-step, or None. Steps <= last_step are rejected (replay protection)."""
    code = (code or "").strip().replace(" ", "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    now_step = int((time.time() if at is None else at) // step)
    matched = None
    for s in range(now_step - window, now_step + window + 1):
        if s > last_step and hmac.compare_digest(hotp(secret_b32, s), code):
            matched = s
    return matched


def provisioning_uri(secret, username, issuer="SecureGate"):
    return (f"otpauth://totp/{quote(issuer)}:{quote(username)}"
            f"?secret={secret}&issuer={quote(issuer)}")


# ---------------- Rate limiter (sliding window, in-memory) ----------------
class RateLimiter:
    def __init__(self, limit, window):
        self.limit, self.window = limit, window
        self.hits = defaultdict(deque)

    def allow(self, key, now=None):
        now = time.monotonic() if now is None else now
        q = self.hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


# ---------------- Tamper-evident audit log (hash chain) ----------------
GENESIS = "0" * 64


def chain_hash(prev_hash, username, event, ip, timestamp):
    data = "|".join([prev_hash, username or "", event, ip or "", timestamp])
    return hashlib.sha256(data.encode()).hexdigest()


def verify_chain(rows):
    """rows: iterable of dict-like audit rows ordered by id. Returns (ok, first_bad_id)."""
    prev = GENESIS
    for r in rows:
        expected = chain_hash(prev, r["username"], r["event"], r["ip"], r["timestamp"])
        if r["prev_hash"] != prev or r["entry_hash"] != expected:
            return False, r["id"]
        prev = r["entry_hash"]
    return True, None
