"""SecureGate - a hardened authentication portal (Flask + SQLite).

Features: scrypt password hashing, TOTP two-factor auth, role-based access control,
per-IP rate limiting, account lockout, CSRF protection, security headers,
and a tamper-evident (hash-chained) audit log.
"""
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import security as sec

MAX_ATTEMPTS = 5
LOCK_MINUTES = 5
PENDING_2FA_SECONDS = 300
USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,20}")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
GENERIC_LOGIN_ERROR = "Invalid username or password."
DUMMY_HASH = generate_password_hash("timing-equaliser-password")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_last_step INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    event TEXT NOT NULL,
    ip TEXT,
    timestamp TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
"""


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.path.join(app.root_path, "securegate.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FORCE_HTTPS") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
        RATE_LIMIT=10,      # auth POSTs allowed per IP ...
        RATE_WINDOW=60,     # ... per this many seconds
    )
    if test_config:
        app.config.update(test_config)

    limiter = sec.RateLimiter(app.config["RATE_LIMIT"], app.config["RATE_WINDOW"])
    log_lock = threading.Lock()

    # ---------------- Database ----------------
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"], timeout=10)
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db:
            db.close()

    boot = sqlite3.connect(app.config["DATABASE"])
    boot.executescript(SCHEMA)
    boot.commit()
    boot.close()

    def log_event(username, event):
        """Append to the hash-chained audit log."""
        db = get_db()
        with log_lock:
            row = db.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = row["entry_hash"] if row else sec.GENESIS
            ts = datetime.now().isoformat(timespec="seconds")
            username = (username or "")[:50] or None
            ip = request.remote_addr
            entry = sec.chain_hash(prev, username, event, ip, ts)
            db.execute("INSERT INTO audit_log (username,event,ip,timestamp,prev_hash,entry_hash) "
                       "VALUES (?,?,?,?,?,?)", (username, event, ip, ts, prev, entry))
            db.commit()

    # ---------------- Request hooks ----------------
    @app.before_request
    def guard():
        if request.method == "POST":
            token = session.get("csrf_token")
            if not token or not secrets.compare_digest(token, request.form.get("csrf_token", "")):
                abort(400, "CSRF validation failed.")
            if request.endpoint in ("login", "login_2fa", "register"):
                if not limiter.allow(request.remote_addr):
                    log_event(None, "RATE_LIMITED")
                    abort(429, "Too many attempts. Please wait a minute and try again.")

    @app.before_request
    def load_user():
        g.user = None
        if "user" in session:
            g.user = get_db().execute("SELECT * FROM users WHERE username=?",
                                      (session["user"],)).fetchone()
            if g.user is None:
                session.clear()

    @app.context_processor
    def inject_globals():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(16)
        return {"csrf_token": session["csrf_token"], "current_user": g.get("user")}

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if session.get("user"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def handle_error(e):
        return render_template("error.html", code=e.code, name=e.name,
                               message=e.description), e.code

    for code in (400, 403, 404, 429):
        app.register_error_handler(code, handle_error)

    # ---------------- Helpers ----------------
    def login_required(view):
        @wraps(view)
        def wrapper(*a, **kw):
            if g.user is None:
                flash("Please log in first.", "error")
                return redirect(url_for("login"))
            return view(*a, **kw)
        return wrapper

    def admin_required(view):
        @wraps(view)
        def wrapper(*a, **kw):
            if g.user is None:
                flash("Please log in first.", "error")
                return redirect(url_for("login"))
            if g.user["role"] != "admin":
                log_event(g.user["username"], "ADMIN_ACCESS_DENIED")
                abort(403, "Administrator access required.")
            return view(*a, **kw)
        return wrapper

    def is_locked(user):
        return bool(user["locked_until"]) and datetime.fromisoformat(user["locked_until"]) > datetime.now()

    def record_failure(user, username, event="LOGIN_FAILED"):
        db = get_db()
        log_event(username, event)
        if user:
            attempts = user["failed_attempts"] + 1
            locked = None
            if attempts >= MAX_ATTEMPTS:
                locked = (datetime.now() + timedelta(minutes=LOCK_MINUTES)).isoformat()
                attempts = 0
                log_event(username, "ACCOUNT_LOCKED")
            db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                       (attempts, locked, user["id"]))
            db.commit()

    def complete_login(user):
        db = get_db()
        db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
        db.commit()
        session.clear()                         # new session -> prevents session fixation
        session.permanent = True
        session["user"] = user["username"]
        session["csrf_token"] = secrets.token_hex(16)
        log_event(user["username"], "LOGIN_SUCCESS")

    # ---------------- Routes ----------------
    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            errors = []
            if not USERNAME_RE.fullmatch(username):
                errors.append("Username must be 3-20 letters, digits or underscores.")
            if not EMAIL_RE.fullmatch(email):
                errors.append("Enter a valid email address.")
            errors += sec.password_errors(password, username)
            if not errors:
                db = get_db()
                # First account becomes the administrator (demo bootstrap). Others are plain users.
                role = "admin" if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0 else "user"
                try:
                    db.execute("INSERT INTO users (username,email,password_hash,role,created_at) "
                               "VALUES (?,?,?,?,?)",
                               (username, email, generate_password_hash(password), role,
                                datetime.now().isoformat(timespec="seconds")))
                    db.commit()
                    log_event(username, f"REGISTER({role})")
                    flash("Account created. Please log in.", "success")
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    errors.append("Username already taken.")
            for e in errors:
                flash(e, "error")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and is_locked(user):
                log_event(username, "LOGIN_BLOCKED_LOCKED")
                flash(f"Account locked for {LOCK_MINUTES} minutes due to repeated failures.", "error")
            else:
                # Always run a hash check so unknown users cost the same time (no timing leak).
                ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password)
                if ok and user:
                    if user["totp_enabled"]:
                        session.clear()
                        session["pending_user"] = user["username"]
                        session["pending_at"] = time.time()
                        session["csrf_token"] = secrets.token_hex(16)
                        return redirect(url_for("login_2fa"))
                    complete_login(user)
                    return redirect(url_for("dashboard"))
                record_failure(user, username)
                flash(GENERIC_LOGIN_ERROR, "error")
        return render_template("login.html")

    @app.route("/login/2fa", methods=["GET", "POST"])
    def login_2fa():
        username = session.get("pending_user")
        if not username or time.time() - session.get("pending_at", 0) > PENDING_2FA_SECONDS:
            session.pop("pending_user", None)
            flash("Session expired. Please log in again.", "error")
            return redirect(url_for("login"))
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if request.method == "POST":
            if user is None or is_locked(user):
                session.pop("pending_user", None)
                flash("Account locked. Try again later.", "error")
                return redirect(url_for("login"))
            step = sec.verify_totp(user["totp_secret"], request.form.get("code"),
                                   user["totp_last_step"])
            if step:
                db.execute("UPDATE users SET totp_last_step=? WHERE id=?", (step, user["id"]))
                db.commit()
                complete_login(user)
                return redirect(url_for("dashboard"))
            record_failure(user, username, "2FA_FAILED")
            flash("Invalid authentication code.", "error")
        return render_template("login_2fa.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        logs = get_db().execute(
            "SELECT event, ip, timestamp FROM audit_log WHERE username=? ORDER BY id DESC LIMIT 10",
            (g.user["username"],)).fetchall()
        return render_template("dashboard.html", logs=logs)

    @app.route("/security", methods=["GET", "POST"])
    @login_required
    def security_settings():
        db = get_db()
        if request.method == "POST":
            action = request.form.get("action")
            if action == "start" and not g.user["totp_enabled"]:
                session["setup_secret"] = sec.new_totp_secret()
            elif action == "enable":
                secret = session.get("setup_secret")
                step = sec.verify_totp(secret, request.form.get("code")) if secret else None
                if step:
                    db.execute("UPDATE users SET totp_secret=?, totp_enabled=1, totp_last_step=? "
                               "WHERE id=?", (secret, step, g.user["id"]))
                    db.commit()
                    session.pop("setup_secret", None)
                    log_event(g.user["username"], "2FA_ENABLED")
                    flash("Two-factor authentication enabled.", "success")
                else:
                    flash("That code was not valid. Try again.", "error")
            elif action == "disable":
                if check_password_hash(g.user["password_hash"], request.form.get("password", "")):
                    db.execute("UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE id=?",
                               (g.user["id"],))
                    db.commit()
                    log_event(g.user["username"], "2FA_DISABLED")
                    flash("Two-factor authentication disabled.", "success")
                else:
                    flash("Incorrect password.", "error")
            return redirect(url_for("security_settings"))
        setup_secret = session.get("setup_secret")
        uri = sec.provisioning_uri(setup_secret, g.user["username"]) if setup_secret else None
        return render_template("security.html", setup_secret=setup_secret, uri=uri)

    @app.route("/change-password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            if not check_password_hash(g.user["password_hash"], current):
                log_event(g.user["username"], "PASSWORD_CHANGE_FAILED")
                flash("Current password is incorrect.", "error")
            else:
                errors = sec.password_errors(new, g.user["username"])
                if new == current:
                    errors.append("New password must differ from the current one.")
                if errors:
                    for e in errors:
                        flash(e, "error")
                else:
                    db = get_db()
                    db.execute("UPDATE users SET password_hash=? WHERE id=?",
                               (generate_password_hash(new), g.user["id"]))
                    db.commit()
                    session["csrf_token"] = secrets.token_hex(16)
                    log_event(g.user["username"], "PASSWORD_CHANGED")
                    flash("Password updated.", "success")
                    return redirect(url_for("dashboard"))
        return render_template("change_password.html")

    @app.route("/admin")
    @admin_required
    def admin():
        db = get_db()
        users = [dict(u, locked=is_locked(u)) for u in db.execute(
            "SELECT id,username,email,role,totp_enabled,failed_attempts,locked_until,created_at "
            "FROM users ORDER BY id").fetchall()]
        all_rows = db.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        chain_ok, bad_id = sec.verify_chain(all_rows)
        logs = db.execute("SELECT id,username,event,ip,timestamp FROM audit_log "
                          "ORDER BY id DESC LIMIT 25").fetchall()
        return render_template("admin.html", users=users, logs=logs,
                               chain_ok=chain_ok, bad_id=bad_id, total=len(all_rows))

    @app.route("/admin/unlock/<int:uid>", methods=["POST"])
    @admin_required
    def admin_unlock(uid):
        db = get_db()
        target = db.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
        if target is None:
            abort(404, "User not found.")
        db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (uid,))
        db.commit()
        log_event(g.user["username"], f"ADMIN_UNLOCK({target['username']})")
        flash(f"Unlocked {target['username']}.", "success")
        return redirect(url_for("admin"))

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        log_event(g.user["username"], "LOGOUT")
        session.clear()
        flash("Logged out securely.", "success")
        return redirect(url_for("login"))

    return app


if __name__ == "__main__":
    create_app().run(debug=False)
