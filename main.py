"""
AutoPanel v2 - Production-Ready Automation Control Panel
Security Edition — v3.0

New Security Features:
- Multi-user system (alag-alag admin accounts)
- Role-based access control: Admin / Operator / Viewer
- TOTP 2FA (Google Authenticator compatible)
- IP Whitelist — sirf whitelisted IPs se login allowed

Role Permissions:
  admin    → sab kuch (users manage, IP whitelist, full control)
  operator → campaigns, workers, CSV, scripts upload/run
  viewer   → sirf read-only (stats, logs, workers dekhna)

Dependencies (add to requirements.txt):
  pyotp>=2.9.0
  qrcode[pil]>=7.4.2
"""

import json, os, shutil, secrets, csv, hashlib, hmac, time
import sqlite3, threading, io, base64
import bcrypt
import pyotp
import qrcode
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, UploadFile, File, Form, Response, Cookie, Header, Request
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import paho.mqtt.client as mqtt

app = FastAPI(title="AutoPanel v2 Secure")

# ── FOLDERS ───────────────────────────────────────
for d in ["scripts","configs","csv_data/used","csv_data/history",
          "uploads/images","uploads/ip_data","logs","static"]:
    os.makedirs(d, exist_ok=True)

# ── ENV CONFIG ────────────────────────────────────
ADMIN_USER   = os.environ.get("ADMIN_USER")
ADMIN_PASS   = os.environ.get("ADMIN_PASS")

if not ADMIN_USER or not ADMIN_PASS:
    raise RuntimeError("ADMIN_USER and ADMIN_PASS environment variables are required")

WORKER_SECRET = os.environ.get("WORKER_SECRET", secrets.token_hex(32))
SESSION_HOURS = 24
APP_NAME      = os.environ.get("APP_NAME", "AutoPanel v2")

# MQTT Config
MQTT_BROKER  = os.environ.get("MQTT_BROKER", "broker.hivemq.com")
MQTT_PORT    = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USER    = os.environ.get("MQTT_USER", "")
MQTT_PASS    = os.environ.get("MQTT_PASS", "")
MQTT_USE_TLS = os.environ.get("MQTT_TLS", "false").lower() == "true"

TOPIC_PREFIX = os.environ.get("MQTT_TOPIC_PREFIX", secrets.token_hex(8))
TOPIC_STATUS = f"{TOPIC_PREFIX}/worker/status"
TOPIC_CMD    = f"{TOPIC_PREFIX}/cmd"
TOPIC_LOG    = f"{TOPIC_PREFIX}/log"

print(f"[MQTT] Topic prefix: {TOPIC_PREFIX}")

# ── PASSWORD UTILS ────────────────────────────────
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password[:72].encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password[:72].encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

# ── SQLITE DATABASE ───────────────────────────────
DB_PATH  = "autopanel.db"
db_lock  = threading.Lock()

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def _bootstrap_admin():
    """Pehli baar — env se admin user create karo."""
    with db_lock:
        with get_db() as conn:
            exists = conn.execute("SELECT id FROM users WHERE username=?", (ADMIN_USER,)).fetchone()
            if not exists:
                conn.execute("""
                    INSERT INTO users (username, password, role, is_active, created_by)
                    VALUES (?, ?, 'admin', 1, 'bootstrap')
                """, (ADMIN_USER, hash_password(ADMIN_PASS)))
                conn.commit()
                print(f"[Security] Bootstrap admin user '{ADMIN_USER}' created.")

def init_db():
    with get_db() as conn:
        conn.executescript("""
        -- ══════════════════════════════════════
        -- SECURITY TABLES
        -- ══════════════════════════════════════

        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT UNIQUE NOT NULL,
            password  TEXT NOT NULL,
            role      TEXT NOT NULL DEFAULT 'viewer',
            totp_secret   TEXT DEFAULT NULL,
            totp_enabled  INTEGER DEFAULT 0,
            is_active     INTEGER DEFAULT 1,
            last_login    TEXT DEFAULT NULL,
            login_attempts INTEGER DEFAULT 0,
            locked_until  TEXT DEFAULT NULL,
            created_at    TEXT DEFAULT CURRENT_TIMESTAMP,
            created_by    TEXT DEFAULT 'system'
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token         TEXT PRIMARY KEY,
            user_id       INTEGER NOT NULL,
            expires_at    TEXT NOT NULL,
            ip_address    TEXT DEFAULT '',
            user_agent    TEXT DEFAULT '',
            awaiting_2fa  INTEGER DEFAULT 0,
            created_at    TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS ip_whitelist (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_cidr    TEXT NOT NULL,
            label      TEXT DEFAULT '',
            is_active  INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS security_audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            time       TEXT DEFAULT CURRENT_TIMESTAMP,
            event      TEXT NOT NULL,
            username   TEXT DEFAULT '',
            ip         TEXT DEFAULT '',
            details    TEXT DEFAULT '',
            success    INTEGER DEFAULT 1
        );

        -- ══════════════════════════════════════
        -- ORIGINAL TABLES
        -- ══════════════════════════════════════

        CREATE TABLE IF NOT EXISTS script_store (
            id INTEGER PRIMARY KEY DEFAULT 1,
            version TEXT DEFAULT '0.0',
            filename TEXT DEFAULT '',
            content TEXT DEFAULT '',
            requirements TEXT DEFAULT '',
            data_required TEXT DEFAULT '',
            uploaded_at TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS campaigns (
            id TEXT PRIMARY KEY,
            name TEXT,
            script TEXT,
            csv_file TEXT,
            url TEXT,
            status TEXT DEFAULT 'idle',
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS csv_progress (
            id INTEGER PRIMARY KEY DEFAULT 1,
            filename TEXT DEFAULT '',
            row_pointer INTEGER DEFAULT 0,
            total_rows INTEGER DEFAULT 0,
            data TEXT DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS pc_urls (
            worker_id TEXT PRIMARY KEY,
            url TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS campaign_history (
            id TEXT PRIMARY KEY,
            campaign_id TEXT,
            name TEXT,
            script TEXT,
            csv_file TEXT,
            url TEXT,
            status TEXT DEFAULT 'running',
            start_time TEXT,
            stop_time TEXT,
            duration_min INTEGER DEFAULT 0,
            total_rows INTEGER DEFAULT 0,
            success_rows INTEGER DEFAULT 0,
            failed_rows INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS campaign_history_workers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            history_id TEXT,
            worker_id TEXT,
            joined_at TEXT,
            rows_done INTEGER DEFAULT 0,
            rows_failed INTEGER DEFAULT 0,
            FOREIGN KEY (history_id) REFERENCES campaign_history(id)
        );

        CREATE TABLE IF NOT EXISTS campaign_history_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            history_id TEXT,
            time TEXT,
            level TEXT DEFAULT 'INFO',
            worker_id TEXT DEFAULT '',
            msg TEXT,
            FOREIGN KEY (history_id) REFERENCES campaign_history(id)
        );

        CREATE TABLE IF NOT EXISTS db_configs (
            key TEXT PRIMARY KEY,
            script_name TEXT DEFAULT '',
            csv_filename TEXT DEFAULT '',
            csv_data TEXT DEFAULT '[]',
            row_pointer INTEGER DEFAULT 0,
            total_rows INTEGER DEFAULT 0,
            image_pointer INTEGER DEFAULT 0,
            config TEXT DEFAULT '{}',
            status TEXT DEFAULT 'active',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS app_state (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        INSERT OR IGNORE INTO script_store (id) VALUES (1);
        INSERT OR IGNORE INTO csv_progress (id) VALUES (1);
        """)
        conn.commit()
    _bootstrap_admin()

init_db()


# ════════════════════════════════════════════════
# SECURITY — USER & ROLE SYSTEM
# ════════════════════════════════════════════════

ROLE_HIERARCHY = {"admin": 3, "operator": 2, "viewer": 1}

ROLE_PERMISSIONS = {
    "admin": {
        "manage_users", "manage_ip_whitelist",
        "view_audit_log", "view_workers", "manage_workers",
        "view_campaigns", "manage_campaigns",
        "view_csv", "upload_csv",
        "view_scripts", "upload_scripts",
        "view_images", "manage_images",
        "view_stats", "view_history", "manage_history",
        "manage_db", "view_db",
        "broadcast",
    },
    "operator": {
        "view_workers", "manage_workers",
        "view_campaigns", "manage_campaigns",
        "view_csv", "upload_csv",
        "view_scripts", "upload_scripts",
        "view_images", "manage_images",
        "view_stats", "view_history",
        "manage_db", "view_db",
        "broadcast",
    },
    "viewer": {
        "view_workers",
        "view_campaigns",
        "view_csv",
        "view_scripts",
        "view_images",
        "view_stats", "view_history",
        "view_db",
    },
}

def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())

def get_user_by_username(username: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

def get_user_by_id(user_id: int):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(row) if row else None


# ════════════════════════════════════════════════
# SECURITY — IP WHITELIST
# ════════════════════════════════════════════════

import ipaddress

def _get_whitelist_active() -> list:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT ip_cidr FROM ip_whitelist WHERE is_active=1"
        ).fetchall()
    return [r["ip_cidr"] for r in rows]

def is_ip_allowed(client_ip: str) -> bool:
    entries = _get_whitelist_active()
    if not entries:
        return True
    try:
        client = ipaddress.ip_address(client_ip)
        for entry in entries:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if client in network:
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False

def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


# ════════════════════════════════════════════════
# SECURITY — AUDIT LOG
# ════════════════════════════════════════════════

def audit_log(event: str, username: str = "", ip: str = "",
               details: str = "", success: bool = True):
    try:
        with db_lock:
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO security_audit_log (event, username, ip, details, success)
                    VALUES (?, ?, ?, ?, ?)
                """, (event, username, ip, details, 1 if success else 0))
                conn.commit()
    except Exception as e:
        print(f"[Audit] Error: {e}")


# ════════════════════════════════════════════════
# SECURITY — SESSION MANAGEMENT
# ════════════════════════════════════════════════

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES    = 15

def create_session(user_id: int, ip: str = "", user_agent: str = "",
                   awaiting_2fa: bool = False) -> str:
    token   = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(hours=SESSION_HOURS)).isoformat()
    with db_lock:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO sessions (token, user_id, expires_at, ip_address, user_agent, awaiting_2fa)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (token, user_id, expires, ip, user_agent, 1 if awaiting_2fa else 0))
            conn.commit()
    return token

def get_session(token: str) -> Optional[dict]:
    if not token:
        return None
    with db_lock:
        with get_db() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
            if not row:
                return None
            if datetime.fromisoformat(row["expires_at"]) < datetime.now():
                conn.execute("DELETE FROM sessions WHERE token=?", (token,))
                conn.commit()
                return None
    return dict(row)

def check_session(token: str) -> bool:
    s = get_session(token)
    if not s:
        return False
    return s["awaiting_2fa"] == 0

def get_session_user(token: str) -> Optional[dict]:
    s = get_session(token)
    if not s or s["awaiting_2fa"] == 1:
        return None
    return get_user_by_id(s["user_id"])

def require_session(session: Optional[str]) -> Optional[dict]:
    return get_session_user(session)

def require_permission(session: Optional[str], permission: str) -> Optional[dict]:
    user = require_session(session)
    if not user:
        return None
    if not user["is_active"]:
        return None
    if has_permission(user["role"], permission):
        return user
    return None

def delete_session(token: str):
    with db_lock:
        with get_db() as conn:
            conn.execute("DELETE FROM sessions WHERE token=?", (token,))
            conn.commit()

def cleanup_sessions():
    while True:
        time.sleep(3600)
        with db_lock:
            with get_db() as conn:
                conn.execute("DELETE FROM sessions WHERE expires_at < ?",
                             (datetime.now().isoformat(),))
                conn.commit()

threading.Thread(target=cleanup_sessions, daemon=True).start()


# ════════════════════════════════════════════════
# SECURITY — TOTP 2FA
# ════════════════════════════════════════════════

def generate_totp_secret() -> str:
    return pyotp.random_base32()

def get_totp_uri(username: str, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(
        name=username, issuer_name=APP_NAME
    )

def verify_totp(secret: str, code: str) -> bool:
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False

def generate_qr_base64(uri: str) -> str:
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img    = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()


# ════════════════════════════════════════════════
# SECURITY — ACCOUNT LOCKOUT
# ════════════════════════════════════════════════

def record_failed_login(username: str):
    with db_lock:
        with get_db() as conn:
            conn.execute("""
                UPDATE users SET login_attempts = login_attempts + 1,
                locked_until = CASE
                    WHEN login_attempts + 1 >= ? THEN ?
                    ELSE locked_until END
                WHERE username = ?
            """, (MAX_LOGIN_ATTEMPTS,
                  (datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat(),
                  username))
            conn.commit()

def record_successful_login(username: str):
    with db_lock:
        with get_db() as conn:
            conn.execute("""
                UPDATE users SET login_attempts=0, locked_until=NULL,
                last_login=? WHERE username=?
            """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username))
            conn.commit()

def is_account_locked(user: dict) -> bool:
    if not user.get("locked_until"):
        return False
    try:
        return datetime.fromisoformat(user["locked_until"]) > datetime.now()
    except:
        return False


# ════════════════════════════════════════════════
# WORKER HMAC AUTH
# ════════════════════════════════════════════════

def make_worker_token(worker_id: str) -> str:
    msg = f"{worker_id}:{int(time.time() // 300)}"
    return hmac.new(WORKER_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()

def verify_worker_token(worker_id: str, token: str) -> bool:
    for window in [0, -1]:
        msg      = f"{worker_id}:{int(time.time() // 300) + window}"
        expected = hmac.new(WORKER_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, token):
            return True
    return False


# ── MQTT ──────────────────────────────────────────
workers        = {}
logs           = {}
errors         = {}
mqtt_connected = False

mqttc = mqtt.Client(client_id=f"SERVER_{secrets.token_hex(4)}", clean_session=True)

if MQTT_USER:
    mqttc.username_pw_set(MQTT_USER, MQTT_PASS)
if MQTT_USE_TLS:
    mqttc.tls_set()

def on_connect(c, u, f, rc):
    global mqtt_connected
    if rc == 0:
        mqtt_connected = True
        print(f"[MQTT] Connected: {MQTT_BROKER}")
        c.subscribe(TOPIC_STATUS)
        c.subscribe(TOPIC_LOG)
    else:
        print(f"[MQTT] Failed rc={rc}")

def on_disconnect(c, u, rc):
    global mqtt_connected
    mqtt_connected = False

def on_message(c, u, msg):
    try:
        data = json.loads(msg.payload.decode())
    except:
        return
    if msg.topic == TOPIC_STATUS:
        wid = data.get("worker_id")
        if wid:
            data["last_seen"] = datetime.now().strftime("%H:%M:%S")
            workers[wid]      = data
            _register_worker_in_active_history(wid)
    elif msg.topic == TOPIC_LOG:
        wid   = data.get("worker_id", "?")
        level = data.get("level", "INFO")
        line  = {"time": data.get("time", ""), "level": level, "msg": data.get("msg", "")}
        if wid not in logs:   logs[wid]   = []
        if wid not in errors: errors[wid] = []
        logs[wid].append(line)
        if len(logs[wid]) > 300: logs[wid].pop(0)
        if level == "ERROR":
            errors[wid].append(line)
        _append_log_to_active_history(wid, level, line["msg"], line["time"])

mqttc.on_connect    = on_connect
mqttc.on_disconnect = on_disconnect
mqttc.on_message    = on_message

def mqtt_thread():
    while True:
        try:
            mqttc.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
            mqttc.loop_forever()
        except Exception as e:
            print(f"[MQTT] {e} — retry in 5s")
            time.sleep(5)

threading.Thread(target=mqtt_thread, daemon=True).start()

def send_cmd(worker_id: str, command: str, extra: dict = {}):
    mqttc.publish(TOPIC_CMD, json.dumps({"worker_id": worker_id, "command": command, **extra}))


# ── CSV MANAGEMENT ────────────────────────────────
csv_rw_lock = threading.Lock()

def get_csv_state():
    with get_db() as conn:
        row = conn.execute("SELECT * FROM csv_progress WHERE id=1").fetchone()
        if row:
            return {
                "filename":    row["filename"],
                "row_pointer": row["row_pointer"],
                "total_rows":  row["total_rows"],
                "data":        json.loads(row["data"])
            }
    return {"filename": "", "row_pointer": 0, "total_rows": 0, "data": []}

def save_csv_state(state: dict):
    with get_db() as conn:
        conn.execute("""
            UPDATE csv_progress SET filename=?, row_pointer=?, total_rows=?, data=?
            WHERE id=1
        """, (state["filename"], state["row_pointer"], state["total_rows"], json.dumps(state["data"])))
        conn.commit()

def get_script():
    with get_db() as conn:
        row = conn.execute("SELECT * FROM script_store WHERE id=1").fetchone()
        if row:
            return dict(row)
    return {"version": "0.0", "filename": "", "content": "",
            "requirements": "", "data_required": "", "uploaded_at": ""}

def save_script(data: dict):
    with get_db() as conn:
        conn.execute("""
            UPDATE script_store SET version=?, filename=?, content=?, requirements=?, data_required=?, uploaded_at=?
            WHERE id=1
        """, (data["version"], data["filename"], data["content"],
              data["requirements"], data["data_required"], data["uploaded_at"]))
        conn.commit()

def save_used_row(row: dict, worker_id: str, status: str):
    path     = "csv_data/used/used_records.csv"
    row_copy = dict(row)
    row_copy.update({"used_by": worker_id,
                     "used_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     "status":  status})
    exists = os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=row_copy.keys())
        if not exists: w.writeheader()
        w.writerow(row_copy)


# ── CAMPAIGN HISTORY ──────────────────────────────
def _get_active_history_id() -> Optional[str]:
    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT value FROM app_state WHERE key='active_history_id'"
            ).fetchone()
            return row["value"] if row else None
    except:
        return None

def _set_active_history_id(hid: Optional[str]):
    try:
        with db_lock:
            with get_db() as conn:
                if hid:
                    conn.execute(
                        "INSERT OR REPLACE INTO app_state (key, value) VALUES ('active_history_id', ?)",
                        (hid,)
                    )
                else:
                    conn.execute("DELETE FROM app_state WHERE key='active_history_id'")
                conn.commit()
    except:
        pass

def _recover_active_history():
    try:
        with get_db() as conn:
            row = conn.execute(
                "SELECT value FROM app_state WHERE key='active_history_id'"
            ).fetchone()
            if row and row["value"]:
                hid  = row["value"]
                hist = conn.execute(
                    "SELECT id FROM campaign_history WHERE id=? AND status='running'", (hid,)
                ).fetchone()
                if hist:
                    print(f"[History] Orphaned history {hid} — marking stopped")
                    conn.execute(
                        "UPDATE campaign_history SET status='stopped', stop_time=? WHERE id=?",
                        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), hid)
                    )
                conn.execute("DELETE FROM app_state WHERE key='active_history_id'")
                conn.commit()
    except Exception as e:
        print(f"[History] Recover error: {e}")

_recover_active_history()

def create_campaign_history(campaign_id, name, script, csv_file, url):
    hid        = secrets.token_hex(8)
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    state      = get_csv_state()
    total_rows = state.get("total_rows", 0)
    with db_lock:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO campaign_history
                    (id, campaign_id, name, script, csv_file, url, status, start_time, total_rows, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?, CURRENT_TIMESTAMP)
            """, (hid, campaign_id, name, script, csv_file, url, start_time, total_rows))
            conn.execute("""
                INSERT INTO campaign_history_logs (history_id, time, level, worker_id, msg)
                VALUES (?, ?, 'INFO', 'SERVER', ?)
            """, (hid, datetime.now().strftime("%H:%M:%S"),
                  f"Campaign '{name}' started | Script: {script} | CSV: {csv_file} | Rows: {total_rows}"))
            conn.commit()
    _set_active_history_id(hid)
    return hid

def stop_campaign_history(hid, final_status="completed"):
    stop_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with db_lock:
        with get_db() as conn:
            row = conn.execute(
                "SELECT start_time, success_rows, failed_rows, name FROM campaign_history WHERE id=?", (hid,)
            ).fetchone()
            if row:
                try:
                    st = datetime.strptime(row["start_time"], "%Y-%m-%d %H:%M:%S")
                    duration_min = int((datetime.now() - st).total_seconds() / 60)
                except:
                    duration_min = 0
                state   = get_csv_state()
                data    = state.get("data", [])
                success = sum(1 for r in data if r.get("status", "").upper() == "SUCCESS")
                failed  = sum(1 for r in data if r.get("status", "").upper() == "FAILED")
                conn.execute("""
                    UPDATE campaign_history SET status=?, stop_time=?, duration_min=?, success_rows=?, failed_rows=?
                    WHERE id=?
                """, (final_status, stop_time, duration_min, success, failed, hid))
                conn.execute("""
                    INSERT INTO campaign_history_logs (history_id, time, level, worker_id, msg)
                    VALUES (?, ?, 'INFO', 'SERVER', ?)
                """, (hid, datetime.now().strftime("%H:%M:%S"),
                      f"Campaign '{row['name']}' {final_status} | Success: {success} | Failed: {failed} | Duration: {duration_min}m"))
                conn.commit()
    _set_active_history_id(None)

def _register_worker_in_active_history(worker_id):
    hid = _get_active_history_id()
    if not hid: return
    with db_lock:
        with get_db() as conn:
            exists = conn.execute(
                "SELECT id FROM campaign_history_workers WHERE history_id=? AND worker_id=?",
                (hid, worker_id)
            ).fetchone()
            if not exists:
                conn.execute("""
                    INSERT INTO campaign_history_workers (history_id, worker_id, joined_at)
                    VALUES (?, ?, ?)
                """, (hid, worker_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                conn.commit()

def _append_log_to_active_history(worker_id, level, msg, log_time=""):
    hid = _get_active_history_id()
    if not hid: return
    if not log_time: log_time = datetime.now().strftime("%H:%M:%S")
    with db_lock:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO campaign_history_logs (history_id, time, level, worker_id, msg)
                VALUES (?, ?, ?, ?, ?)
            """, (hid, log_time, level, worker_id, msg))
            conn.commit()

def update_worker_stats_in_history(worker_id, rows_done=0, rows_failed=0):
    hid = _get_active_history_id()
    if not hid: return
    with db_lock:
        with get_db() as conn:
            conn.execute("""
                UPDATE campaign_history_workers
                SET rows_done=rows_done+?, rows_failed=rows_failed+?
                WHERE history_id=? AND worker_id=?
            """, (rows_done, rows_failed, hid, worker_id))
            conn.commit()


# ════════════════════════════════════════════════
# AUTH PAGES — LOGIN, 2FA
# ════════════════════════════════════════════════

def login_html(err="", show_2fa=False, temp_token=""):
    two_fa_block = f"""
    <div id="totp-section">
      <label>Authenticator Code</label>
      <input name="totp_code" type="text" inputmode="numeric" pattern="[0-9]{{6}}"
             maxlength="6" placeholder="6-digit code" autofocus autocomplete="one-time-code">
      <input type="hidden" name="temp_token" value="{temp_token}">
    </div>
    """ if show_2fa else ""

    submit_label = "Verify Code" if show_2fa else "Login"
    action       = "/login/2fa" if show_2fa else "/login"

    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>{APP_NAME}</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;700&display=swap');
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{
  background:#080b10;
  display:flex;align-items:center;justify-content:center;
  min-height:100vh;
  font-family:'Syne',sans-serif;
  background-image: radial-gradient(ellipse at 20% 50%, #0d1a2e 0%, transparent 60%),
                    radial-gradient(ellipse at 80% 20%, #0a1f1a 0%, transparent 60%);
}}
.box{{
  background:rgba(14,18,28,0.95);
  border:1px solid rgba(99,210,179,0.15);
  border-radius:12px;
  padding:44px 40px;
  width:100%;max-width:400px;
  box-shadow:0 24px 80px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.04);
}}
.logo{{
  display:flex;align-items:center;gap:10px;margin-bottom:32px;
}}
.logo-icon{{
  width:36px;height:36px;
  background:linear-gradient(135deg,#63d2b3,#4a90e2);
  border-radius:8px;
  display:flex;align-items:center;justify-content:center;
  font-size:16px;font-weight:700;color:#fff;font-family:'JetBrains Mono',monospace;
}}
.logo-text{{color:#e8eaf0;font-size:1.15rem;font-weight:700;letter-spacing:-0.02em;}}
.logo-badge{{
  margin-left:auto;
  background:rgba(99,210,179,0.1);
  border:1px solid rgba(99,210,179,0.2);
  color:#63d2b3;font-size:10px;font-weight:600;
  padding:3px 8px;border-radius:20px;font-family:'JetBrains Mono',monospace;
  letter-spacing:0.05em;
}}
label{{color:#8b91a8;font-size:12px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;display:block;margin-bottom:7px;}}
input[type=text],input[type=password]{{
  width:100%;
  background:rgba(255,255,255,0.04);
  border:1px solid rgba(255,255,255,0.08);
  color:#e8eaf0;border-radius:8px;
  padding:11px 14px;font-size:14px;margin-bottom:18px;
  outline:none;font-family:'JetBrains Mono',monospace;
  transition:border-color 0.2s;
}}
input:focus{{border-color:rgba(99,210,179,0.4);background:rgba(99,210,179,0.04);}}
button{{
  width:100%;
  background:linear-gradient(135deg,#63d2b3,#4a90e2);
  color:#fff;border:none;border-radius:8px;
  padding:12px;font-size:14px;cursor:pointer;
  font-weight:700;font-family:'Syne',sans-serif;
  letter-spacing:0.03em;
  transition:opacity 0.2s,transform 0.1s;
}}
button:hover{{opacity:0.9;transform:translateY(-1px);}}
button:active{{transform:translateY(0);}}
.err{{
  color:#ff6b6b;font-size:13px;
  background:rgba(255,107,107,0.08);
  border:1px solid rgba(255,107,107,0.2);
  border-radius:6px;padding:10px 14px;margin-top:14px;
  font-family:'JetBrains Mono',monospace;
}}
.divider{{height:1px;background:rgba(255,255,255,0.06);margin:20px 0;}}
.hint{{color:#4a5068;font-size:11px;text-align:center;margin-top:16px;font-family:'JetBrains Mono',monospace;}}
</style></head><body>
<div class="box">
  <div class="logo">
    <div class="logo-icon">AP</div>
    <div class="logo-text">{APP_NAME}</div>
    <span class="logo-badge">SECURE</span>
  </div>
  <form method="POST" action="{action}">
    {'<label>Username</label><input name="username" type="text" autofocus autocomplete="username">' if not show_2fa else ''}
    {'<label>Password</label><input name="password" type="password" autocomplete="current-password">' if not show_2fa else ''}
    {two_fa_block}
    <div class="divider"></div>
    <button type="submit">{submit_label}</button>
  </form>
  {"<div class='err'>" + err + "</div>" if err else ""}
  <p class="hint">🔒 Secured session · {SESSION_HOURS}h expiry</p>
</div></body></html>"""


@app.get("/login")
def login_page():
    return HTMLResponse(login_html())


@app.post("/login")
async def do_login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...)
):
    client_ip  = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")

    # ── IP Whitelist Check ─────────────────────────
    if not is_ip_allowed(client_ip):
        audit_log("login_blocked_ip", username, client_ip, "IP not in whitelist", success=False)
        return HTMLResponse(login_html(err="Access denied from this IP address."), status_code=403)

    user = get_user_by_username(username)

    if not user or not verify_password(password, user["password"]):
        if user:
            record_failed_login(username)
        audit_log("login_failed", username, client_ip, "Wrong credentials", success=False)
        return HTMLResponse(login_html(err="Invalid username or password."))

    if not user["is_active"]:
        audit_log("login_blocked", username, client_ip, "Account disabled", success=False)
        return HTMLResponse(login_html(err="Account is disabled. Contact admin."))

    if is_account_locked(user):
        audit_log("login_blocked", username, client_ip, "Account locked", success=False)
        return HTMLResponse(login_html(
            err=f"Account locked after too many attempts. Try again in {LOCKOUT_MINUTES} minutes."
        ))

    # ── 2FA Check ─────────────────────────────────
    if user["totp_enabled"] and user["totp_secret"]:
        # Create a temporary "awaiting_2fa" session
        temp_token = create_session(user["id"], client_ip, user_agent, awaiting_2fa=True)
        audit_log("login_2fa_required", username, client_ip, "Password OK, awaiting 2FA")
        return HTMLResponse(login_html(show_2fa=True, temp_token=temp_token))

    # ── Full Login ─────────────────────────────────
    record_successful_login(username)
    token = create_session(user["id"], client_ip, user_agent, awaiting_2fa=False)
    audit_log("login_success", username, client_ip, f"Role: {user['role']}")

    resp = RedirectResponse(url="/", status_code=302)
    resp.set_cookie("session", token, httponly=True, secure=False,
                    samesite="lax", max_age=SESSION_HOURS * 3600)
    return resp


@app.post("/login/2fa")
async def do_2fa(
    request: Request,
    temp_token: str = Form(...),
    totp_code: str = Form(...)
):
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")

    session = get_session(temp_token)
    if not session or session["awaiting_2fa"] != 1:
        return HTMLResponse(login_html(err="Session expired. Please login again."))

    user = get_user_by_id(session["user_id"])
    if not user:
        return HTMLResponse(login_html(err="User not found."))

    if not verify_totp(user["totp_secret"], totp_code.strip()):
        audit_log("2fa_failed", user["username"], client_ip, "Wrong TOTP code", success=False)
        return HTMLResponse(login_html(
            show_2fa=True, temp_token=temp_token,
            err="Invalid authenticator code. Try again."
        ))

    # 2FA passed — upgrade session to fully authenticated
    delete_session(temp_token)
    record_successful_login(user["username"])
    token = create_session(user["id"], client_ip, user_agent, awaiting_2fa=False)
    audit_log("login_success_2fa", user["username"], client_ip, "2FA verified")

    resp = RedirectResponse(url="/", status_code=302)
    resp.set_cookie("session", token, httponly=True, secure=False,
                    samesite="lax", max_age=SESSION_HOURS * 3600)
    return resp


@app.get("/logout")
def logout(session: Optional[str] = Cookie(None)):
    if session:
        delete_session(session)
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie("session")
    return resp


@app.get("/")
def dashboard(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return RedirectResponse(url="/login", status_code=302)
    if os.path.exists("static/index.html"):
        return HTMLResponse(open("static/index.html", encoding="utf-8").read())
    return HTMLResponse("<h1>Place index.html in static/</h1>")


# ════════════════════════════════════════════════
# API — CURRENT USER INFO
# ════════════════════════════════════════════════

@app.get("/api/me")
def get_me(session: Optional[str] = Cookie(None)):
    user = require_session(session)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return {
        "id":           user["id"],
        "username":     user["username"],
        "role":         user["role"],
        "totp_enabled": bool(user["totp_enabled"]),
        "last_login":   user["last_login"],
        "permissions":  list(ROLE_PERMISSIONS.get(user["role"], set()))
    }


# ════════════════════════════════════════════════
# API — USER MANAGEMENT (Admin only)
# ════════════════════════════════════════════════

@app.get("/api/users")
def list_users(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_users")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, role, is_active, totp_enabled, last_login, "
            "login_attempts, locked_until, created_at, created_by FROM users ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/users")
def create_user(data: dict, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_users")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)

    username = data.get("username", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "viewer")

    if not username or not password:
        return JSONResponse({"error": "username and password required"}, status_code=400)
    if role not in ROLE_HIERARCHY:
        return JSONResponse({"error": f"Invalid role. Valid: {list(ROLE_HIERARCHY.keys())}"}, status_code=400)

    # Admins cannot create users with higher role than themselves
    if ROLE_HIERARCHY.get(role, 0) > ROLE_HIERARCHY.get(user["role"], 0):
        return JSONResponse({"error": "Cannot create user with higher role than yours"}, status_code=403)

    try:
        with db_lock:
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO users (username, password, role, is_active, created_by)
                    VALUES (?, ?, ?, 1, ?)
                """, (username, hash_password(password), role, user["username"]))
                conn.commit()
        audit_log("user_created", user["username"], "", f"Created user '{username}' with role '{role}'")
        return {"ok": True, "message": f"User '{username}' created with role '{role}'"}
    except sqlite3.IntegrityError:
        return JSONResponse({"error": f"Username '{username}' already exists"}, status_code=409)


@app.put("/api/users/{user_id}")
def update_user(user_id: int, data: dict, session: Optional[str] = Cookie(None)):
    caller = require_permission(session, "manage_users")
    if not caller:
        return JSONResponse({"error": "forbidden"}, status_code=403)

    target = get_user_by_id(user_id)
    if not target:
        return JSONResponse({"error": "User not found"}, status_code=404)

    # Prevent self-demotion or deactivation
    if target["id"] == caller["id"] and "role" in data:
        if ROLE_HIERARCHY.get(data["role"], 0) < ROLE_HIERARCHY.get(caller["role"], 0):
            return JSONResponse({"error": "Cannot demote yourself"}, status_code=403)

    updates  = []
    params   = []

    if "role" in data:
        new_role = data["role"]
        if new_role not in ROLE_HIERARCHY:
            return JSONResponse({"error": "Invalid role"}, status_code=400)
        if ROLE_HIERARCHY.get(new_role, 0) > ROLE_HIERARCHY.get(caller["role"], 0):
            return JSONResponse({"error": "Cannot assign role higher than yours"}, status_code=403)
        updates.append("role=?"); params.append(new_role)

    if "password" in data and data["password"]:
        updates.append("password=?"); params.append(hash_password(data["password"]))

    if "is_active" in data:
        updates.append("is_active=?"); params.append(1 if data["is_active"] else 0)

    if "unlock" in data and data["unlock"]:
        updates.append("login_attempts=0")
        updates.append("locked_until=NULL")

    if not updates:
        return JSONResponse({"error": "Nothing to update"}, status_code=400)

    params.append(user_id)
    with db_lock:
        with get_db() as conn:
            conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id=?", params)
            conn.commit()

    audit_log("user_updated", caller["username"], "", f"Updated user id={user_id}: {list(data.keys())}")
    return {"ok": True}


@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, session: Optional[str] = Cookie(None)):
    caller = require_permission(session, "manage_users")
    if not caller:
        return JSONResponse({"error": "forbidden"}, status_code=403)

    if caller["id"] == user_id:
        return JSONResponse({"error": "Cannot delete your own account"}, status_code=403)

    target = get_user_by_id(user_id)
    if not target:
        return JSONResponse({"error": "User not found"}, status_code=404)

    if ROLE_HIERARCHY.get(target["role"], 0) >= ROLE_HIERARCHY.get(caller["role"], 0):
        return JSONResponse({"error": "Cannot delete user with equal or higher role"}, status_code=403)

    with db_lock:
        with get_db() as conn:
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
            conn.commit()

    audit_log("user_deleted", caller["username"], "", f"Deleted user '{target['username']}'")
    return {"ok": True}


# ════════════════════════════════════════════════
# API — 2FA MANAGEMENT (Self-service)
# ════════════════════════════════════════════════

@app.post("/api/2fa/setup")
def setup_2fa(session: Optional[str] = Cookie(None)):
    """Generate a new TOTP secret and QR code."""
    user = require_session(session)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    secret = generate_totp_secret()
    uri    = get_totp_uri(user["username"], secret)
    qr_b64 = generate_qr_base64(uri)

    # Store secret temporarily (not enabled yet — confirmed after verify)
    with db_lock:
        with get_db() as conn:
            conn.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, user["id"]))
            conn.commit()

    return {
        "secret": secret,
        "uri":    uri,
        "qr_png": qr_b64,  # base64 PNG for frontend
        "message": "Scan QR in Authenticator app, then call /api/2fa/verify to enable."
    }


@app.post("/api/2fa/verify")
def verify_and_enable_2fa(data: dict, session: Optional[str] = Cookie(None)):
    """Confirm TOTP code and enable 2FA."""
    user = require_session(session)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    code = data.get("code", "").strip()
    if not user["totp_secret"]:
        return JSONResponse({"error": "Run /api/2fa/setup first"}, status_code=400)

    if not verify_totp(user["totp_secret"], code):
        return JSONResponse({"error": "Invalid code. Try again."}, status_code=400)

    with db_lock:
        with get_db() as conn:
            conn.execute("UPDATE users SET totp_enabled=1 WHERE id=?", (user["id"],))
            conn.commit()

    audit_log("2fa_enabled", user["username"], "", "2FA successfully enabled")
    return {"ok": True, "message": "2FA enabled successfully! Required on next login."}


@app.post("/api/2fa/disable")
def disable_2fa(data: dict, session: Optional[str] = Cookie(None)):
    """Disable 2FA (requires current password confirmation)."""
    user = require_session(session)
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    password = data.get("password", "")
    if not verify_password(password, user["password"]):
        return JSONResponse({"error": "Wrong password"}, status_code=403)

    with db_lock:
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE id=?",
                (user["id"],)
            )
            conn.commit()

    audit_log("2fa_disabled", user["username"], "", "2FA disabled")
    return {"ok": True, "message": "2FA disabled."}


# ════════════════════════════════════════════════
# API — IP WHITELIST (Admin only)
# ════════════════════════════════════════════════

@app.get("/api/ip-whitelist")
def get_ip_whitelist(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_ip_whitelist")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, ip_cidr, label, is_active, created_at, created_by FROM ip_whitelist ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/ip-whitelist")
def add_ip_whitelist(data: dict, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_ip_whitelist")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)

    ip_cidr = data.get("ip_cidr", "").strip()
    label   = data.get("label", "").strip()

    if not ip_cidr:
        return JSONResponse({"error": "ip_cidr required"}, status_code=400)

    # Validate IP/CIDR
    try:
        ipaddress.ip_network(ip_cidr, strict=False)
    except ValueError:
        return JSONResponse({"error": f"Invalid IP/CIDR: {ip_cidr}"}, status_code=400)

    with db_lock:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO ip_whitelist (ip_cidr, label, is_active, created_by) VALUES (?, ?, 1, ?)",
                (ip_cidr, label, user["username"])
            )
            conn.commit()

    audit_log("ip_whitelist_add", user["username"], "", f"Added: {ip_cidr} ({label})")
    return {"ok": True, "message": f"IP '{ip_cidr}' added to whitelist."}


@app.delete("/api/ip-whitelist/{entry_id}")
def remove_ip_whitelist(entry_id: int, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_ip_whitelist")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)

    with db_lock:
        with get_db() as conn:
            row = conn.execute("SELECT ip_cidr FROM ip_whitelist WHERE id=?", (entry_id,)).fetchone()
            if not row:
                return JSONResponse({"error": "Entry not found"}, status_code=404)
            conn.execute("DELETE FROM ip_whitelist WHERE id=?", (entry_id,))
            conn.commit()

    audit_log("ip_whitelist_remove", user["username"], "", f"Removed: {row['ip_cidr']}")
    return {"ok": True}


@app.put("/api/ip-whitelist/{entry_id}")
def toggle_ip_whitelist(entry_id: int, data: dict, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_ip_whitelist")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)

    is_active = 1 if data.get("is_active", True) else 0
    with db_lock:
        with get_db() as conn:
            conn.execute("UPDATE ip_whitelist SET is_active=? WHERE id=?", (is_active, entry_id))
            conn.commit()
    return {"ok": True}


# ════════════════════════════════════════════════
# API — AUDIT LOG (Admin only)
# ════════════════════════════════════════════════

@app.get("/api/audit-log")
def get_audit_log(
    session: Optional[str] = Cookie(None),
    limit: int = 200,
    username: str = ""
):
    user = require_permission(session, "view_audit_log")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)

    query  = "SELECT * FROM security_audit_log"
    params = []
    if username:
        query += " WHERE username=?"; params.append(username)
    query += f" ORDER BY id DESC LIMIT {min(int(limit), 1000)}"

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


# ════════════════════════════════════════════════
# DB MANAGER — API KEY SYSTEM (unchanged, with permission checks added)
# ════════════════════════════════════════════════

db_row_lock = threading.Lock()
db_img_lock = threading.Lock()

@app.post("/api/db/generate-key")
def generate_db_key(
    session: Optional[str] = Cookie(None),
    script_name: str = Form(""),
    csv_file: UploadFile = File(None),
    config: str = Form("{}"),
):
    user = require_permission(session, "manage_db")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)

    key = secrets.token_hex(6)
    csv_data  = []
    csv_fname = ""

    if csv_file and csv_file.filename:
        content   = csv_file.file.read()
        csv_fname = csv_file.filename
        text      = content.decode("utf-8-sig", "replace")
        reader    = csv.DictReader(io.StringIO(text))
        csv_data  = [dict(row) for row in reader]
        hist_path = f"csv_data/history/{datetime.now().strftime('%Y%m%d_%H%M%S')}_{csv_fname}"
        with open(hist_path, "wb") as f:
            f.write(content)

    try:
        cfg = json.loads(config)
    except:
        cfg = {}

    fields = list(csv_data[0].keys()) if csv_data else []
    cfg["fields"] = fields

    with db_lock:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO db_configs (key, script_name, csv_filename, csv_data, row_pointer, total_rows, image_pointer, config, status, created_at)
                VALUES (?, ?, ?, ?, 0, ?, 0, ?, 'active', ?)
            """, (key, script_name, csv_fname, json.dumps(csv_data), len(csv_data), json.dumps(cfg), datetime.now().isoformat()))
            conn.commit()

    return {"key": key, "script": script_name, "csv": csv_fname,
            "total_rows": len(csv_data), "fields": fields, "config": cfg}


@app.get("/api/db/{key}/config")
def db_get_config(key: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM db_configs WHERE key=?", (key,)).fetchone()
    if not row:
        return JSONResponse({"error": "Invalid key"}, status_code=404)
    cfg = json.loads(row["config"])
    return {
        "script": row["script_name"], "form_url": cfg.get("form_url", ""),
        "headless": cfg.get("headless", False), "airplane_on": cfg.get("airplane_on", 6),
        "airplane_off": cfg.get("airplane_off", 10), "max_ip_attempts": cfg.get("max_ip_attempts", 5),
        "delay": cfg.get("delay", 2), "extra": cfg.get("extra", {}), "fields": cfg.get("fields", [])
    }


@app.get("/api/db/{key}/next")
def db_next_row(key: str, worker_id: str = "unknown"):
    with db_row_lock:
        with get_db() as conn:
            row = conn.execute("SELECT * FROM db_configs WHERE key=?", (key,)).fetchone()
            if not row:
                return JSONResponse({"error": "Invalid key"}, status_code=404)

            data = json.loads(row["csv_data"])
            if not data:
                return {"row": None, "message": "No CSV data"}

            ptr = row["row_pointer"]
            while ptr < len(data):
                s = data[ptr].get("status", "").upper()
                if s not in ("SUCCESS", "FAILED", "USED"):
                    break
                ptr += 1

            if ptr >= len(data):
                return {"row": None, "message": "All rows done!"}

            data[ptr]["_assigned_to"] = worker_id
            data[ptr]["_assigned_at"] = datetime.now().strftime("%H:%M:%S")

            conn.execute("UPDATE db_configs SET csv_data=?, row_pointer=? WHERE key=?",
                         (json.dumps(data), ptr + 1, key))
            conn.commit()

        return {"row": data[ptr], "row_index": ptr}


@app.get("/api/db/{key}/image")
def db_next_image(key: str, worker_id: str = "unknown"):
    with db_img_lock:
        images = []
        img_dir = "uploads/images"
        if os.path.exists(img_dir):
            images = sorted([f for f in os.listdir(img_dir)
                             if f.lower().endswith((".png",".jpg",".jpeg",".webp",".gif"))])
        if not images:
            return {"image": None, "message": "No images uploaded"}

        with get_db() as conn:
            row = conn.execute("SELECT image_pointer FROM db_configs WHERE key=?", (key,)).fetchone()
            if not row:
                return JSONResponse({"error": "Invalid key"}, status_code=404)
            ptr   = row["image_pointer"] % len(images)
            fname = images[ptr]
            conn.execute("UPDATE db_configs SET image_pointer=? WHERE key=?", (ptr + 1, key))
            conn.commit()

        img_path = os.path.join(img_dir, fname)
        with open(img_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()

        ext  = fname.rsplit(".", 1)[-1].lower()
        mime = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
                "webp": "image/webp", "gif": "image/gif"}.get(ext, "image/jpeg")

        return {"image": b64, "filename": fname, "mime": mime, "index": ptr, "total": len(images)}


@app.post("/api/db/{key}/done")
def db_mark_done(key: str, data: dict):
    row_index = data.get("row_index")
    status    = data.get("status", "SUCCESS").upper()
    worker_id = data.get("worker_id", "unknown")
    ip        = data.get("ip", "")
    note      = data.get("note", "")
    done_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with db_row_lock:
        with get_db() as conn:
            cfg_row = conn.execute("SELECT csv_data FROM db_configs WHERE key=?", (key,)).fetchone()
            if not cfg_row:
                return JSONResponse({"error": "Invalid key"}, status_code=404)
            rows = json.loads(cfg_row["csv_data"])
            if row_index is not None and row_index < len(rows):
                rows[row_index].update({"status": status, "_worker": worker_id,
                                        "_ip": ip, "_time": done_time, "_note": note})
                conn.execute("UPDATE db_configs SET csv_data=? WHERE key=?",
                             (json.dumps(rows), key))
                conn.commit()

    if status == "SUCCESS" and ip:
        ip_path = f"uploads/ip_data/auto_ip_{datetime.now().strftime('%Y%m%d')}.csv"
        exists  = os.path.exists(ip_path)
        with open(ip_path, "a", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["ip","worker_id","key","row_index","time"])
            if not exists: w.writeheader()
            w.writerow({"ip": ip, "worker_id": worker_id, "key": key,
                        "row_index": row_index, "time": done_time})
    return {"ok": True}


@app.get("/api/db/list")
def db_list_configs(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_db")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM db_configs ORDER BY created_at DESC").fetchall()
    result = []
    for r in rows:
        data    = json.loads(r["csv_data"])
        cfg     = json.loads(r["config"])
        success = sum(1 for x in data if x.get("status","").upper() == "SUCCESS")
        failed  = sum(1 for x in data if x.get("status","").upper() == "FAILED")
        pending = sum(1 for x in data if x.get("status","").upper() not in ("SUCCESS","FAILED","USED"))
        result.append({
            "key": r["key"], "script": r["script_name"], "csv": r["csv_filename"],
            "total": r["total_rows"], "success": success, "failed": failed, "pending": pending,
            "fields": cfg.get("fields", []), "status": r["status"], "created_at": r["created_at"]
        })
    return result


@app.get("/api/db/{key}/rows")
def db_get_rows(key: str, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_db")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with get_db() as conn:
        row = conn.execute("SELECT csv_data, config FROM db_configs WHERE key=?", (key,)).fetchone()
    if not row:
        return JSONResponse({"error": "Not found"}, status_code=404)
    data   = json.loads(row["csv_data"])
    cfg    = json.loads(row["config"])
    fields = cfg.get("fields", list(data[0].keys()) if data else [])
    return {"rows": data, "fields": fields}


@app.put("/api/db/{key}/row/{row_index}")
def db_edit_row(key: str, row_index: int, data: dict, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_db")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with db_row_lock:
        with get_db() as conn:
            cfg_row = conn.execute("SELECT csv_data FROM db_configs WHERE key=?", (key,)).fetchone()
            if not cfg_row:
                return JSONResponse({"error": "Not found"}, status_code=404)
            rows = json.loads(cfg_row["csv_data"])
            if row_index >= len(rows):
                return JSONResponse({"error": "Row index out of range"}, status_code=400)
            rows[row_index].update(data)
            conn.execute("UPDATE db_configs SET csv_data=? WHERE key=?", (json.dumps(rows), key))
            conn.commit()
    return {"ok": True}


@app.get("/api/db/{key}/download-csv")
def db_download_csv(key: str, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_db")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with get_db() as conn:
        row = conn.execute("SELECT csv_data, csv_filename FROM db_configs WHERE key=?", (key,)).fetchone()
    if not row:
        return JSONResponse({"error": "Not found"}, status_code=404)
    data = json.loads(row["csv_data"])
    if not data:
        return JSONResponse({"error": "No data"}, status_code=404)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=data[0].keys())
    writer.writeheader()
    writer.writerows(data)
    from fastapi.responses import Response as FR
    return FR(content=output.getvalue().encode("utf-8-sig"), media_type="text/csv",
              headers={"Content-Disposition": f"attachment; filename={row['csv_filename'] or 'data.csv'}"})


@app.delete("/api/db/{key}")
def db_delete_config(key: str, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_db")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with db_lock:
        with get_db() as conn:
            conn.execute("DELETE FROM db_configs WHERE key=?", (key,))
            conn.commit()
    return {"ok": True}


@app.put("/api/db/{key}/status")
def db_update_status(key: str, data: dict, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_db")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    status = data.get("status", "active")
    with db_lock:
        with get_db() as conn:
            conn.execute("UPDATE db_configs SET status=? WHERE key=?", (status, key))
            conn.commit()
    return {"ok": True}


# ── IP AUTO-FETCH FROM SUCCESS ROWS ───────────────
@app.get("/api/ip-from-csv")
def ip_from_csv(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_db")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)

    ips   = []
    state = get_csv_state()
    for i, row in enumerate(state.get("data", [])):
        if row.get("status", "").upper() == "SUCCESS":
            ip = row.get("ip") or row.get("_ip") or row.get("ip_address", "")
            if ip:
                ips.append({"ip": ip, "source": "main_csv", "row": i,
                            "time": row.get("_time",""), "worker": row.get("_worker","")})

    with get_db() as conn:
        cfgs = conn.execute("SELECT key, script_name, csv_data FROM db_configs").fetchall()
    for cfg in cfgs:
        rows = json.loads(cfg["csv_data"])
        for i, row in enumerate(rows):
            if row.get("status","").upper() == "SUCCESS":
                ip = row.get("_ip", "")
                if ip:
                    ips.append({"ip": ip, "source": cfg["script_name"], "row": i,
                                "time": row.get("_time",""), "worker": row.get("_worker","")})
    return ips


# ── CAMPAIGN HISTORY ENDPOINTS ─────────────────────

@app.get("/api/campaign-history")
def get_campaign_history(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_history")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM campaign_history ORDER BY created_at DESC LIMIT 200").fetchall()
        result = []
        for r in rows:
            hid = r["id"]
            workers_rows = conn.execute("""
                SELECT worker_id, joined_at, rows_done, rows_failed
                FROM campaign_history_workers WHERE history_id=?
            """, (hid,)).fetchall()
            log_rows = conn.execute("""
                SELECT time, level, worker_id, msg FROM campaign_history_logs
                WHERE history_id=? ORDER BY id ASC LIMIT 100
            """, (hid,)).fetchall()
            result.append({
                "id": hid, "campaign_id": r["campaign_id"], "name": r["name"],
                "script": r["script"], "csv": r["csv_file"], "url": r["url"],
                "status": r["status"], "start_time": r["start_time"], "stop_time": r["stop_time"],
                "duration_min": r["duration_min"], "total_rows": r["total_rows"],
                "success": r["success_rows"], "failed": r["failed_rows"],
                "workers": [w["worker_id"] for w in workers_rows],
                "worker_details": [dict(w) for w in workers_rows],
                "logs": [{"time": l["time"], "level": l["level"],
                          "worker_id": l["worker_id"], "msg": l["msg"]} for l in log_rows]
            })
    return JSONResponse(result)

@app.get("/api/campaign-history/{hid}")
def get_single_history(hid: str, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_history")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with get_db() as conn:
        r = conn.execute("SELECT * FROM campaign_history WHERE id=?", (hid,)).fetchone()
        if not r: return JSONResponse({"error": "Not found"}, status_code=404)
        workers_rows = conn.execute("SELECT * FROM campaign_history_workers WHERE history_id=?", (hid,)).fetchall()
        log_rows     = conn.execute("SELECT time, level, worker_id, msg FROM campaign_history_logs WHERE history_id=? ORDER BY id ASC", (hid,)).fetchall()
    return JSONResponse({
        "id": r["id"], "name": r["name"], "script": r["script"], "csv": r["csv_file"],
        "url": r["url"], "status": r["status"], "start_time": r["start_time"],
        "stop_time": r["stop_time"], "duration_min": r["duration_min"],
        "total_rows": r["total_rows"], "success": r["success_rows"], "failed": r["failed_rows"],
        "workers": [w["worker_id"] for w in workers_rows],
        "worker_details": [dict(w) for w in workers_rows],
        "logs": [{"time": l["time"], "level": l["level"], "worker_id": l["worker_id"], "msg": l["msg"]} for l in log_rows]
    })

@app.get("/api/campaign-history/{hid}/logs")
def get_history_logs(hid: str, session: Optional[str] = Cookie(None), level: str = "", last_n: int = 200):
    user = require_permission(session, "view_history")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    query  = "SELECT time, level, worker_id, msg FROM campaign_history_logs WHERE history_id=?"
    params = [hid]
    if level:
        query += " AND level=?"; params.append(level.upper())
    query += f" ORDER BY id DESC LIMIT {int(last_n)}"
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return JSONResponse([{"time": l["time"], "level": l["level"],
                          "worker_id": l["worker_id"], "msg": l["msg"]} for l in reversed(rows)])

@app.get("/api/campaign-history/{hid}/workers")
def get_history_workers(hid: str, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_history")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM campaign_history_workers WHERE history_id=? ORDER BY joined_at", (hid,)).fetchall()
    return JSONResponse([dict(r) for r in rows])

@app.delete("/api/campaign-history")
def clear_all_history(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_history")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with db_lock:
        with get_db() as conn:
            conn.execute("DELETE FROM campaign_history_logs")
            conn.execute("DELETE FROM campaign_history_workers")
            conn.execute("DELETE FROM campaign_history")
            conn.commit()
    _set_active_history_id(None)
    return {"message": "All campaign history cleared!"}

@app.delete("/api/campaign-history/{hid}")
def delete_single_history(hid: str, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_history")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with db_lock:
        with get_db() as conn:
            conn.execute("DELETE FROM campaign_history_logs WHERE history_id=?", (hid,))
            conn.execute("DELETE FROM campaign_history_workers WHERE history_id=?", (hid,))
            conn.execute("DELETE FROM campaign_history WHERE id=?", (hid,))
            conn.commit()
    return {"message": f"History {hid} deleted!"}

@app.post("/api/campaign-history/{hid}/log")
def add_history_log(hid: str, data: dict, x_worker_token: Optional[str] = Header(None)):
    worker_id = data.get("worker_id", "?")
    level     = data.get("level", "INFO").upper()
    msg       = data.get("msg", "")
    if x_worker_token and not verify_worker_token(worker_id, x_worker_token):
        return JSONResponse({"error": "invalid token"}, status_code=403)
    with db_lock:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO campaign_history_logs (history_id, time, level, worker_id, msg)
                VALUES (?, ?, ?, ?, ?)
            """, (hid, datetime.now().strftime("%H:%M:%S"), level, worker_id, msg))
            conn.commit()
    return {"ok": True}

@app.get("/api/campaign-history/active/id")
def get_active_history_id(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_history")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return {"active_history_id": _get_active_history_id()}

@app.post("/api/mark-row-complete")
def mark_row_complete(data: dict):
    worker_id   = data.get("worker_id", "?")
    rows_done   = int(data.get("rows_done", 0))
    rows_failed = int(data.get("rows_failed", 0))
    update_worker_stats_in_history(worker_id, rows_done, rows_failed)
    return {"ok": True}


# ── WORKERS ────────────────────────────────────────

@app.get("/api/workers")
def get_workers(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_workers")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return JSONResponse(workers)

@app.post("/api/worker/update")
def worker_update(data: dict, x_worker_token: Optional[str] = Header(None)):
    wid = data.get("worker_id")
    if x_worker_token and wid:
        if not verify_worker_token(wid, x_worker_token):
            return JSONResponse({"error": "invalid token"}, status_code=403)
    if wid:
        data["last_seen"] = datetime.now().strftime("%H:%M:%S")
        workers[wid]      = data
        _register_worker_in_active_history(wid)
    return {"ok": True}

@app.get("/api/worker/{worker_id}/logs")
def get_worker_logs(worker_id: str, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_workers")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return logs.get(worker_id, [])

@app.get("/api/worker/{worker_id}/errors")
def get_worker_errors(worker_id: str, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_workers")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return errors.get(worker_id, [])

@app.get("/api/worker-token/{worker_id}")
def get_worker_token(worker_id: str):
    return {"token": make_worker_token(worker_id), "topic_prefix": TOPIC_PREFIX,
            "broker": MQTT_BROKER, "port": MQTT_PORT}


# ── PC URLs ────────────────────────────────────────

@app.get("/api/pc-urls")
def get_pc_urls(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_workers")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with get_db() as conn:
        rows = conn.execute("SELECT worker_id, url FROM pc_urls").fetchall()
    return {r["worker_id"]: r["url"] for r in rows}

@app.post("/api/pc-url")
def set_pc_url(data: dict, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_workers")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    worker_id = data.get("worker_id")
    url       = data.get("url", "")
    with db_lock:
        with get_db() as conn:
            conn.execute("INSERT OR REPLACE INTO pc_urls (worker_id, url, updated_at) VALUES (?, ?, ?)",
                         (worker_id, url, datetime.now().isoformat()))
            conn.commit()
    send_cmd(worker_id, "set_url", {"url": url})
    return {"message": f"URL set for {worker_id}"}


# ── SCRIPTS ────────────────────────────────────────

@app.get("/api/version")
def get_version():
    s = get_script()
    return {"version": s["version"], "filename": s["filename"],
            "uploaded_at": s["uploaded_at"], "data_required": s["data_required"]}

@app.get("/api/script/content")
def get_script_content(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_scripts")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return {"content": get_script()["content"] or "# No script uploaded yet"}

@app.get("/api/download-script")
def download_script():
    s = get_script()
    if not s["content"]: return JSONResponse({"error": "No script"}, status_code=404)
    from fastapi.responses import Response as FR
    return FR(content=s["content"].encode("utf-8"), media_type="text/plain",
              headers={"Content-Disposition": "attachment; filename=latest.py"})

@app.get("/api/download-requirements")
def download_requirements():
    s = get_script()
    if not s["requirements"]: return JSONResponse({"error": "No requirements"}, status_code=404)
    from fastapi.responses import Response as FR
    return FR(content=s["requirements"].encode("utf-8"), media_type="text/plain",
              headers={"Content-Disposition": "attachment; filename=requirements.txt"})

@app.post("/api/upload-script")
def upload_script(
    session: Optional[str] = Cookie(None),
    file: UploadFile = File(...),
    version: str = Form("1.0"),
    requirements: str = Form(""),
    data_required: str = Form("")
):
    user = require_permission(session, "upload_scripts")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    content = file.file.read().decode("utf-8", "replace")
    save_script({"version": version, "filename": file.filename, "content": content,
                 "requirements": requirements.strip(), "data_required": data_required,
                 "uploaded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    send_cmd("ALL", "script_updated", {"version": version})
    return {"message": f"Script v{version} uploaded & pushed!"}

@app.post("/api/script/save")
def save_script_api(data: dict, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "upload_scripts")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    s = get_script()
    s.update({"content": data.get("content",""), "version": data.get("version","1.0"),
               "uploaded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    save_script(s)
    send_cmd("ALL", "script_updated", {"version": s["version"]})
    return {"message": f"Script v{s['version']} saved & pushed!"}

@app.get("/api/scripts/info")
def script_info(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_scripts")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    s = get_script()
    return {**s, "has_script": bool(s["content"]),
            "size": len(s["content"].encode("utf-8")) if s["content"] else 0}


# ── CSV ────────────────────────────────────────────

@app.post("/api/upload-csv")
def upload_csv(session: Optional[str] = Cookie(None), file: UploadFile = File(...)):
    user = require_permission(session, "upload_csv")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    content   = file.file.read()
    hist_path = f"csv_data/history/{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    with open(hist_path, "wb") as f: f.write(content)
    text   = content.decode("utf-8-sig", "replace")
    reader = csv.DictReader(io.StringIO(text))
    data   = [dict(row) for row in reader]
    with csv_rw_lock:
        save_csv_state({"filename": file.filename, "row_pointer": 0,
                        "total_rows": len(data), "data": data})
    return {"message": f"{file.filename} uploaded! {len(data)} rows loaded."}

@app.get("/api/get-next-row/{worker_id}")
def get_next_row(worker_id: str):
    with csv_rw_lock:
        state = get_csv_state()
        data  = state["data"]
        if not data: return {"row": None, "message": "CSV not uploaded"}
        ptr = state["row_pointer"]
        while ptr < len(data):
            if data[ptr].get("status","").upper() not in ("SUCCESS","USED","FAILED"): break
            ptr += 1
        if ptr >= len(data): return {"row": None, "message": "Sab rows complete!"}
        row                  = data[ptr]
        state["row_pointer"] = ptr + 1
        save_csv_state(state)
        return {"row": row, "row_index": ptr}

@app.post("/api/mark-row")
def mark_row(data: dict):
    worker_id = data.get("worker_id")
    row_index = data.get("row_index")
    status    = data.get("status","SUCCESS")
    row_data  = data.get("row_data", {})
    with csv_rw_lock:
        state = get_csv_state()
        rows  = state["data"]
        if row_index is not None and row_index < len(rows):
            rows[row_index]["status"] = status
            state["data"]             = rows
            save_csv_state(state)
    if row_data: save_used_row(row_data, worker_id, status)
    if status.upper() == "SUCCESS":
        update_worker_stats_in_history(worker_id, rows_done=1, rows_failed=0)
    elif status.upper() == "FAILED":
        update_worker_stats_in_history(worker_id, rows_done=0, rows_failed=1)
    return {"message": f"Row {row_index} marked {status}"}

@app.get("/api/csv-status")
def csv_status(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_csv")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    state = get_csv_state()
    data  = state["data"]
    if not data: return {"total": 0, "done": 0, "pending": 0, "failed": 0, "rows": []}
    rows = [{"index": i+1, "name": r.get("name","—"), "mobile": r.get("mobile","—"),
             "email": r.get("email","—"), "status": r.get("status","PENDING") or "PENDING",
             "worker": "—"} for i, r in enumerate(data)]
    return {
        "total":   len(data),
        "done":    sum(1 for r in data if r.get("status","").upper() == "SUCCESS"),
        "failed":  sum(1 for r in data if r.get("status","").upper() == "FAILED"),
        "pending": sum(1 for r in data if r.get("status","").upper() not in ("SUCCESS","FAILED","USED")),
        "rows":    rows
    }

@app.get("/api/csv-history")
def csv_history(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_csv")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    files = []
    if os.path.exists("csv_data/history"):
        for f in os.listdir("csv_data/history"):
            files.append({"name": f, "size": os.path.getsize(f"csv_data/history/{f}")})
    return sorted(files, key=lambda x: x["name"], reverse=True)

@app.delete("/api/csv-history")
def clear_csv_history(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_campaigns")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    for f in os.listdir("csv_data/history"):
        os.remove(f"csv_data/history/{f}")
    return {"message": "History cleared!"}


# ── IMAGES ─────────────────────────────────────────

@app.post("/api/upload-images")
def upload_images(session: Optional[str] = Cookie(None), files: List[UploadFile] = File(...)):
    user = require_permission(session, "manage_images")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    saved = []
    for file in files:
        with open(f"uploads/images/{file.filename}", "wb") as f:
            shutil.copyfileobj(file.file, f)
        saved.append(file.filename)
    return {"uploaded": saved, "count": len(saved)}

@app.get("/api/images")
def list_images(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_images")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    if not os.path.exists("uploads/images"): return []
    result = []
    for f in os.listdir("uploads/images"):
        if not f.lower().endswith((".png",".jpg",".jpeg",".webp",".gif")): continue
        path = f"uploads/images/{f}"
        with open(path, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode()
        ext  = f.rsplit(".",1)[-1].lower()
        mime = {"jpg":"image/jpeg","jpeg":"image/jpeg","png":"image/png",
                "webp":"image/webp","gif":"image/gif"}.get(ext,"image/jpeg")
        result.append({"name": f, "size": os.path.getsize(path), "data": b64, "mime": mime})
    return result

@app.delete("/api/images")
def clear_images(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_images")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    for f in os.listdir("uploads/images"):
        os.remove(f"uploads/images/{f}")
    return {"message": "Images cleared!"}

@app.delete("/api/images/{filename}")
def delete_single_image(filename: str, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_images")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    path = f"uploads/images/{filename}"
    if os.path.exists(path):
        os.remove(path)
    return {"ok": True}


# ── IP RECORDS ─────────────────────────────────────

@app.post("/api/upload-ip-csv")
def upload_ip_csv(session: Optional[str] = Cookie(None), file: UploadFile = File(...)):
    user = require_permission(session, "manage_campaigns")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with open(f"uploads/ip_data/{file.filename}", "wb") as f:
        shutil.copyfileobj(file.file, f)
    return {"message": f"{file.filename} uploaded!"}

@app.get("/api/ip-records")
def get_ip_records(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_campaigns")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    records = []
    if os.path.exists("uploads/ip_data"):
        for fname in os.listdir("uploads/ip_data"):
            if not fname.endswith(".csv"): continue
            with open(f"uploads/ip_data/{fname}", newline="", encoding="utf-8-sig") as f:
                for row in csv.DictReader(f):
                    records.append(dict(row))
    return records[-500:]

@app.delete("/api/ip-records")
def clear_ip_records(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_campaigns")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    for f in os.listdir("uploads/ip_data"):
        os.remove(f"uploads/ip_data/{f}")
    return {"message": "IP records cleared!"}

@app.get("/api/ip-records/download")
def download_ip_records(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_campaigns")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    records = []
    if os.path.exists("uploads/ip_data"):
        for fname in os.listdir("uploads/ip_data"):
            if not fname.endswith(".csv"): continue
            with open(f"uploads/ip_data/{fname}", newline="", encoding="utf-8-sig") as f:
                for row in csv.DictReader(f):
                    records.append(dict(row))
    if not records:
        return JSONResponse({"error": "No records"}, status_code=404)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=records[0].keys())
    writer.writeheader()
    writer.writerows(records)
    from fastapi.responses import Response as FR
    return FR(content=output.getvalue().encode("utf-8-sig"), media_type="text/csv",
              headers={"Content-Disposition": "attachment; filename=ip_records.csv"})


# ── CAMPAIGNS ──────────────────────────────────────

@app.get("/api/campaigns")
def get_campaigns(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_campaigns")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM campaigns ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/campaigns")
def create_campaign(data: dict, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_campaigns")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    cid = secrets.token_hex(4)
    with db_lock:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO campaigns (id, name, script, csv_file, url, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'idle', ?)
            """, (cid, data.get("name"), data.get("script"), data.get("csv"),
                  data.get("url"), datetime.now().isoformat()))
            conn.commit()
    return {"message": "Campaign created!", "id": cid}

@app.post("/api/campaigns/{cid}/start")
def start_campaign(cid: str, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_campaigns")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with db_lock:
        with get_db() as conn:
            camp = conn.execute("SELECT * FROM campaigns WHERE id=?", (cid,)).fetchone()
            if not camp: return JSONResponse({"error": "Campaign not found"}, status_code=404)
            conn.execute("UPDATE campaigns SET status='active' WHERE id=?", (cid,))
            conn.commit()
    hid = create_campaign_history(campaign_id=cid, name=camp["name"] or "—",
                                   script=camp["script"] or "—", csv_file=camp["csv_file"] or "—",
                                   url=camp["url"] or "—")
    send_cmd("ALL", "start")
    return {"message": "Campaign started!", "history_id": hid}

@app.post("/api/campaigns/{cid}/stop")
def stop_campaign(cid: str, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_campaigns")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with db_lock:
        with get_db() as conn:
            conn.execute("UPDATE campaigns SET status='idle' WHERE id=?", (cid,))
            conn.commit()
    hid = _get_active_history_id()
    if hid: stop_campaign_history(hid, final_status="stopped")
    send_cmd("ALL", "stop")
    return {"message": "Campaign stopped!"}

@app.post("/api/send-command")
def send_command(data: dict, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "manage_workers")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    send_cmd(data.get("worker_id"), data.get("command"), data.get("extra", {}))
    return {"message": "Command sent"}

@app.post("/api/broadcast")
def broadcast(data: dict, session: Optional[str] = Cookie(None)):
    user = require_permission(session, "broadcast")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)

    cmd_name = data.get("command")

    if cmd_name == "stop":
        hid = _get_active_history_id()
        if hid:
            stop_campaign_history(hid, final_status="stopped")

    elif cmd_name == "start":
        existing_hid = _get_active_history_id()
        if not existing_hid:
            with get_db() as conn:
                camp = conn.execute(
                    "SELECT * FROM campaigns WHERE status='active' ORDER BY created_at DESC LIMIT 1"
                ).fetchone()
                if not camp:
                    camp = conn.execute(
                        "SELECT * FROM campaigns ORDER BY created_at DESC LIMIT 1"
                    ).fetchone()
            if camp:
                with db_lock:
                    with get_db() as conn:
                        conn.execute("UPDATE campaigns SET status='active' WHERE id=?", (camp["id"],))
                        conn.commit()
                create_campaign_history(campaign_id=camp["id"], name=camp["name"] or "Manual Start",
                                         script=camp["script"] or "—", csv_file=camp["csv_file"] or "—",
                                         url=camp["url"] or "—")
            else:
                create_campaign_history(campaign_id="manual", name="Manual Start (No Campaign)",
                                         script="—", csv_file="—", url="—")

    elif cmd_name == "restart":
        hid = _get_active_history_id()
        if hid:
            stop_campaign_history(hid, final_status="stopped")
        with get_db() as conn:
            camp = conn.execute(
                "SELECT * FROM campaigns ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        if camp:
            create_campaign_history(campaign_id=camp["id"],
                                     name=f"{camp['name'] or 'Campaign'} (Restart)",
                                     script=camp["script"] or "—", csv_file=camp["csv_file"] or "—",
                                     url=camp["url"] or "—")

    send_cmd("ALL", cmd_name)
    return {"message": "Broadcast sent"}

@app.get("/api/stats")
def get_stats(session: Optional[str] = Cookie(None)):
    user = require_permission(session, "view_stats")
    if not user:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    v = list(workers.values())
    return {
        "total": len(v), "running": sum(1 for w in v if w.get("status") == "running"),
        "idle":  sum(1 for w in v if w.get("status") == "idle"),
        "error": sum(1 for w in v if w.get("status") == "error"),
        "success": sum(w.get("success", 0) for w in v),
        "failed":  sum(w.get("failed",  0) for w in v),
        "mqtt_connected": mqtt_connected, "active_history": _get_active_history_id()
    }

@app.get("/api/config")
def get_config():
    return {"delay": 2, "headless": False}

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")
