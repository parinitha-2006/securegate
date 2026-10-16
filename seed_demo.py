"""Optional: create demo accounts for screenshots.  python seed_demo.py
Demo only - do NOT use these credentials anywhere real."""
from datetime import datetime
import sqlite3
from werkzeug.security import generate_password_hash
from app import create_app

app = create_app()
db = sqlite3.connect(app.config["DATABASE"])
for name, pw, role in [("admin", "Admin@Secure2026", "admin"), ("alice", "Alice@Secure2026", "user")]:
    if not db.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone():
        db.execute("INSERT INTO users (username,email,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                   (name, f"{name}@example.com", generate_password_hash(pw), role,
                    datetime.now().isoformat(timespec="seconds")))
db.commit()
print("Demo users ready: admin / Admin@Secure2026   alice / Alice@Secure2026")
