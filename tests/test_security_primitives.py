import security as sec

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"   # ASCII "12345678901234567890"


def test_hotp_matches_rfc4226_vectors():
    assert sec.hotp(RFC_SECRET, 0) == "755224"
    assert sec.hotp(RFC_SECRET, 1) == "287082"


def test_totp_matches_rfc6238_vector():
    assert sec.totp(RFC_SECRET, at=59, digits=8) == "94287082"


def test_totp_replay_and_window():
    code = sec.totp(RFC_SECRET, at=1000)
    step = sec.verify_totp(RFC_SECRET, code, last_step=0, at=1000)
    assert step == 1000 // 30
    assert sec.verify_totp(RFC_SECRET, code, last_step=step, at=1000) is None   # replay
    assert sec.verify_totp(RFC_SECRET, code, last_step=0, at=1000 + 300) is None  # expired
    assert sec.verify_totp(RFC_SECRET, "abc", at=1000) is None


def test_password_policy():
    assert len(sec.password_errors("abc123")) >= 3
    assert sec.password_errors("Str0ng!Pass") == []
    assert sec.password_errors("Alice@1234", "alice")


def test_rate_limiter():
    rl = sec.RateLimiter(3, 10)
    assert all(rl.allow("ip", now=t) for t in (0, 1, 2))
    assert not rl.allow("ip", now=3)
    assert rl.allow("ip", now=20)


def test_hash_chain_detects_tampering():
    rows, prev = [], sec.GENESIS
    for i, ev in enumerate(["REGISTER", "LOGIN_SUCCESS", "LOGOUT"], start=1):
        h = sec.chain_hash(prev, "bob", ev, "127.0.0.1", f"2026-10-15T10:00:0{i}")
        rows.append(dict(id=i, username="bob", event=ev, ip="127.0.0.1",
                         timestamp=f"2026-10-15T10:00:0{i}", prev_hash=prev, entry_hash=h))
        prev = h
    assert sec.verify_chain(rows) == (True, None)
    rows[1]["event"] = "NOTHING_HAPPENED"
    assert sec.verify_chain(rows) == (False, 2)
