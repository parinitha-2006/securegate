import re
import sqlite3
import time

import security as sec
from app import create_app
from helpers import login, logout, register, token


def test_register_login_dashboard(client):
    assert register(client).status_code == 302
    r = login(client, "admin1", follow=True)
    assert "Welcome, admin1" in r.get_data(as_text=True)


def test_weak_password_rejected(client):
    r = register(client, password="abc123")
    html = r.get_data(as_text=True)
    assert r.status_code == 200 and "at least 8 characters" in html


def test_sql_injection_blocked(client):
    register(client)
    r = login(client, "' OR '1'='1", password="x")
    assert "Invalid username or password." in r.get_data(as_text=True)
    assert client.get("/dashboard").status_code == 302


def test_csrf_required(client):
    assert client.post("/register", data=dict(username="eve_x")).status_code == 400
    assert client.post("/login", data=dict(username="a", password="b", csrf_token="forged")).status_code == 400


def test_xss_is_escaped(client):
    register(client, username="xss_user", email="<b>x</b>@a.com")
    r = login(client, "xss_user", follow=True)
    html = r.get_data(as_text=True)
    assert "<b>x</b>" not in html and "&lt;b&gt;" in html


def test_no_username_enumeration(client):
    register(client)
    a = login(client, "admin1", password="Wrong@1234").get_data(as_text=True)
    b = login(client, "ghost_user", password="Wrong@1234").get_data(as_text=True)
    assert "Invalid username or password." in a and "Invalid username or password." in b


def test_lockout_blocks_even_correct_password(client):
    register(client)
    for _ in range(5):
        login(client, "admin1", password="Wrong@1234")
    r = login(client, "admin1", follow=True)
    assert "locked" in r.get_data(as_text=True).lower()


def test_security_headers(client):
    h = client.get("/login").headers
    assert "default-src 'self'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY" and h["X-Content-Type-Options"] == "nosniff"


def test_change_password(client):
    register(client)
    login(client, "admin1")
    client.post("/change-password", data=dict(
        csrf_token=token(client, "/change-password"),
        current_password="Test@1234", new_password="N3w!Passw0rd"))
    logout(client)
    assert "Invalid" in login(client, "admin1").get_data(as_text=True)
    assert login(client, "admin1", password="N3w!Passw0rd").status_code == 302


def test_two_factor_flow(client):
    register(client)
    login(client, "admin1")
    client.post("/security", data=dict(csrf_token=token(client, "/security"), action="start"))
    html = client.get("/security").get_data(as_text=True)
    secret = re.search(r'<code id="secret">([A-Z2-7]+)</code>', html).group(1)
    r = client.post("/security", data=dict(csrf_token=token(client, "/security"),
                    action="enable", code=sec.totp(secret)), follow_redirects=True)
    assert "2FA is ENABLED" in r.get_data(as_text=True)
    logout(client)

    r = login(client, "admin1")
    assert "/login/2fa" in r.headers["Location"]
    assert client.get("/dashboard").status_code == 302          # password alone is not enough
    bad = client.post("/login/2fa", data=dict(csrf_token=token(client, "/login/2fa"), code="000000"))
    assert "Invalid authentication code" in bad.get_data(as_text=True)
    next_code = sec.totp(secret, at=time.time() + 30)            # next step, still inside window
    ok = client.post("/login/2fa", data=dict(csrf_token=token(client, "/login/2fa"), code=next_code))
    assert ok.status_code == 302 and "/dashboard" in ok.headers["Location"]

    logout(client)                                               # replay of a used code must fail
    login(client, "admin1")
    replay = client.post("/login/2fa", data=dict(csrf_token=token(client, "/login/2fa"), code=next_code))
    assert "Invalid authentication code" in replay.get_data(as_text=True)


def test_rbac_and_unlock(app, client):
    register(client)                                  # first account -> admin
    login(client, "admin1")
    user_client = app.test_client()
    register(user_client, "bob_user", email="b@example.com")
    login(user_client, "bob_user")
    assert user_client.get("/admin").status_code == 403
    assert app.test_client().get("/admin").status_code == 302

    for _ in range(5):                                # lock bob
        login(app.test_client(), "bob_user", password="Wrong@1234")
    assert "locked" in login(app.test_client(), "bob_user", follow=True).get_data(as_text=True).lower()
    client.post("/admin/unlock/2", data=dict(csrf_token=token(client, "/admin")))
    assert login(app.test_client(), "bob_user").status_code == 302


def test_audit_log_tamper_detected(app, client):
    register(client)
    login(client, "admin1")
    assert "VERIFIED" in client.get("/admin").get_data(as_text=True)
    con = sqlite3.connect(app.config["DATABASE"])
    con.execute("UPDATE audit_log SET event='NOTHING_HAPPENED' WHERE id=1")
    con.commit()
    con.close()
    assert "TAMPERED" in client.get("/admin").get_data(as_text=True)


def test_rate_limit(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "r.db"), "RATE_LIMIT": 3})
    c = app.test_client()
    codes = [login(c, "nobody_x", password="Wrong@1234").status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
