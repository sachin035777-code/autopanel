"""
AutoPanel v2 - Production-Ready Automation Control Panel
Updated:
- API Key system for scripts
- /api/db/{key}/next    — next row (locked)
- /api/db/{key}/image  — next image
- /api/db/{key}/config — settings
- /api/db/{key}/done   — status + ip + time update
- CSV row manual edit
- IP auto fetch from SUCCESS rows
"""

import json, os, shutil, secrets, csv, hashlib, hmac, time
import sqlite3, threading, io, base64
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, UploadFile, File, Form, Response, Cookie, Header
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import paho.mqtt.client as mqtt

app = FastAPI(title="AutoPanel v2")

# ── FOLDERS ───────────────────────────────────────
for d in ["scripts","configs","csv_data/used","csv_data/history",
          "uploads/images","uploads/ip_data","logs","static"]:
    os.makedirs(d, exist_ok=True)

# ── SECURITY CONFIG ───────────────────────────────
ADMIN_USER    = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS    = os.environ.get("ADMIN_PASS", "admin123")
WORKER_SECRET = os.environ.get("WORKER_SECRET", secrets.token_hex(32))
SESSION_HOURS = 24

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password[:72].encode("utf-8"), bcrypt.gensalt())

def verify_password(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password[:72].encode("utf-8"), hashed)
    except Exception:
        return False

_admin_hash = hash_password(ADMIN_PASS)

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

# ── SQLITE DATABASE ───────────────────────────────
DB_PATH = "autopanel.db"
db_lock = threading.Lock()

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

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

        -- ── DB MANAGER TABLES ──────────────────────────
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

init_db()

# ── SESSION MANAGEMENT ────────────────────────────
def create_session() -> str:
    token   = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(hours=SESSION_HOURS)).isoformat()
    with db_lock:
        with get_db() as conn:
            conn.execute("INSERT INTO sessions (token, expires_at) VALUES (?, ?)", (token, expires))
            conn.commit()
    return token

def check_session(token: str) -> bool:
    if not token:
        return False
    with db_lock:
        with get_db() as conn:
            row = conn.execute("SELECT expires_at FROM sessions WHERE token=?", (token,)).fetchone()
            if not row:
                return False
            if datetime.fromisoformat(row["expires_at"]) < datetime.now():
                conn.execute("DELETE FROM sessions WHERE token=?", (token,))
                conn.commit()
                return False
    return True

def cleanup_sessions():
    while True:
        time.sleep(3600)
        with db_lock:
            with get_db() as conn:
                conn.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.now().isoformat(),))
                conn.commit()

threading.Thread(target=cleanup_sessions, daemon=True).start()

# ── WORKER HMAC AUTH ──────────────────────────────
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
    """Server restart ke baad orphaned 'running' history ko 'stopped' mark karo."""
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
                    print(f"[History] Orphaned history {hid} — marking stopped (server restarted)")
                    conn.execute(
                        "UPDATE campaign_history SET status='stopped', stop_time=? WHERE id=?",
                        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), hid)
                    )
                    conn.execute(
                        "INSERT INTO campaign_history_logs "
                        "(history_id, time, level, worker_id, msg) VALUES (?,?,?,?,?)",
                        (hid, datetime.now().strftime("%H:%M:%S"),
                         "WARN", "SERVER", "Campaign stopped — server restarted")
                    )
                conn.execute("DELETE FROM app_state WHERE key='active_history_id'")
                conn.commit()
    except Exception as e:
        print(f"[History] Recover error: {e}")

# Startup pe orphaned histories recover karo
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
                conn.execute("""
                    INSERT INTO campaign_history_logs (history_id, time, level, worker_id, msg)
                    VALUES (?, ?, 'INFO', ?, ?)
                """, (hid, datetime.now().strftime("%H:%M:%S"), worker_id, f"Worker '{worker_id}' joined"))
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
# DB MANAGER — API KEY SYSTEM
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    key = secrets.token_hex(6)

    csv_data  = []
    csv_fname = ""

    if csv_file and csv_file.filename:
        content   = csv_file.file.read()
        csv_fname = csv_file.filename
        text      = content.decode("utf-8-sig", "replace")
        reader    = csv.DictReader(io.StringIO(text))
        csv_data  = [dict(row) for row in reader]
        # save to history too
        hist_path = f"csv_data/history/{datetime.now().strftime('%Y%m%d_%H%M%S')}_{csv_fname}"
        with open(hist_path, "wb") as f:
            f.write(content)

    try:
        cfg = json.loads(config)
    except:
        cfg = {}

    # detect fields from first row
    fields = list(csv_data[0].keys()) if csv_data else []
    cfg["fields"] = fields

    with db_lock:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO db_configs (key, script_name, csv_filename, csv_data, row_pointer, total_rows, image_pointer, config, status, created_at)
                VALUES (?, ?, ?, ?, 0, ?, 0, ?, 'active', ?)
            """, (key, script_name, csv_fname, json.dumps(csv_data), len(csv_data), json.dumps(cfg), datetime.now().isoformat()))
            conn.commit()

    return {
        "key": key,
        "script": script_name,
        "csv": csv_fname,
        "total_rows": len(csv_data),
        "fields": fields,
        "config": cfg
    }


@app.get("/api/db/{key}/config")
def db_get_config(key: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM db_configs WHERE key=?", (key,)).fetchone()
    if not row:
        return JSONResponse({"error": "Invalid key"}, status_code=404)
    cfg = json.loads(row["config"])
    return {
        "script":          row["script_name"],
        "form_url":        cfg.get("form_url", ""),
        "headless":        cfg.get("headless", False),
        "airplane_on":     cfg.get("airplane_on", 6),
        "airplane_off":    cfg.get("airplane_off", 10),
        "max_ip_attempts": cfg.get("max_ip_attempts", 5),
        "delay":           cfg.get("delay", 2),
        "extra":           cfg.get("extra", {}),
        "fields":          cfg.get("fields", [])
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

            conn.execute("""
                UPDATE db_configs SET csv_data=?, row_pointer=? WHERE key=?
            """, (json.dumps(data), ptr + 1, key))
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
            ptr = row["image_pointer"] % len(images)
            fname = images[ptr]
            conn.execute("UPDATE db_configs SET image_pointer=? WHERE key=?", (ptr + 1, key))
            conn.commit()

        img_path = os.path.join(img_dir, fname)
        with open(img_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()

        ext = fname.rsplit(".", 1)[-1].lower()
        mime = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
                "webp": "image/webp", "gif": "image/gif"}.get(ext, "image/jpeg")

        return {
            "image":    b64,
            "filename": fname,
            "mime":     mime,
            "index":    ptr,
            "total":    len(images)
        }


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
                rows[row_index]["status"]    = status
                rows[row_index]["_worker"]   = worker_id
                rows[row_index]["_ip"]       = ip
                rows[row_index]["_time"]     = done_time
                rows[row_index]["_note"]     = note

                conn.execute("UPDATE db_configs SET csv_data=? WHERE key=?",
                             (json.dumps(rows), key))
                conn.commit()

    # Save to IP records if SUCCESS
    if status == "SUCCESS" and ip:
        ip_path = f"uploads/ip_data/auto_ip_{datetime.now().strftime('%Y%m%d')}.csv"
        exists  = os.path.exists(ip_path)
        with open(ip_path, "a", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["ip", "worker_id", "key", "row_index", "time"])
            if not exists: w.writeheader()
            w.writerow({"ip": ip, "worker_id": worker_id, "key": key,
                        "row_index": row_index, "time": done_time})

    return {"ok": True}


@app.get("/api/db/list")
def db_list_configs(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM db_configs ORDER BY created_at DESC").fetchall()

    result = []
    for r in rows:
        data    = json.loads(r["csv_data"])
        cfg     = json.loads(r["config"])
        success = sum(1 for x in data if x.get("status", "").upper() == "SUCCESS")
        failed  = sum(1 for x in data if x.get("status", "").upper() == "FAILED")
        pending = sum(1 for x in data if x.get("status", "").upper() not in ("SUCCESS", "FAILED", "USED"))
        result.append({
            "key":         r["key"],
            "script":      r["script_name"],
            "csv":         r["csv_filename"],
            "total":       r["total_rows"],
            "success":     success,
            "failed":      failed,
            "pending":     pending,
            "fields":      cfg.get("fields", []),
            "status":      r["status"],
            "created_at":  r["created_at"]
        })
    return result


@app.get("/api/db/{key}/rows")
def db_get_rows(key: str, session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    return FR(
        content=output.getvalue().encode("utf-8-sig"),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={row['csv_filename'] or 'data.csv'}"}
    )


@app.delete("/api/db/{key}")
def db_delete_config(key: str, session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    with db_lock:
        with get_db() as conn:
            conn.execute("DELETE FROM db_configs WHERE key=?", (key,))
            conn.commit()
    return {"ok": True}


@app.put("/api/db/{key}/status")
def db_update_status(key: str, data: dict, session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    status = data.get("status", "active")
    with db_lock:
        with get_db() as conn:
            conn.execute("UPDATE db_configs SET status=? WHERE key=?", (status, key))
            conn.commit()
    return {"ok": True}


# ── IP AUTO-FETCH FROM SUCCESS ROWS ───────────────
@app.get("/api/ip-from-csv")
def ip_from_csv(session: Optional[str] = Cookie(None)):
    """Fetch IPs from SUCCESS rows in main CSV + all db_configs"""
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    ips = []

    # Main CSV
    state = get_csv_state()
    for i, row in enumerate(state.get("data", [])):
        if row.get("status", "").upper() == "SUCCESS":
            ip = row.get("ip") or row.get("_ip") or row.get("ip_address", "")
            if ip:
                ips.append({"ip": ip, "source": "main_csv", "row": i,
                            "time": row.get("_time", ""), "worker": row.get("_worker", "")})

    # DB configs
    with get_db() as conn:
        cfgs = conn.execute("SELECT key, script_name, csv_data FROM db_configs").fetchall()
    for cfg in cfgs:
        rows = json.loads(cfg["csv_data"])
        for i, row in enumerate(rows):
            if row.get("status", "").upper() == "SUCCESS":
                ip = row.get("_ip", "")
                if ip:
                    ips.append({"ip": ip, "source": cfg["script_name"], "row": i,
                                "time": row.get("_time", ""), "worker": row.get("_worker", "")})

    return ips


# ── EXISTING ENDPOINTS (unchanged) ────────────────

@app.get("/api/campaign-history")
def get_campaign_history(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    with get_db() as conn:
        r = conn.execute("SELECT * FROM campaign_history WHERE id=?", (hid,)).fetchone()
        if not r: return JSONResponse({"error": "Not found"}, status_code=404)
        workers_rows = conn.execute("SELECT * FROM campaign_history_workers WHERE history_id=?", (hid,)).fetchall()
        log_rows = conn.execute("SELECT time, level, worker_id, msg FROM campaign_history_logs WHERE history_id=? ORDER BY id ASC", (hid,)).fetchall()
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    query  = "SELECT time, level, worker_id, msg FROM campaign_history_logs WHERE history_id=?"
    params = [hid]
    if level:
        query += " AND level=?"; params.append(level.upper())
    query += f" ORDER BY id DESC LIMIT {int(last_n)}"
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return JSONResponse([{"time": l["time"], "level": l["level"], "worker_id": l["worker_id"], "msg": l["msg"]} for l in reversed(rows)])

@app.get("/api/campaign-history/{hid}/workers")
def get_history_workers(hid: str, session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM campaign_history_workers WHERE history_id=? ORDER BY joined_at", (hid,)).fetchall()
    return JSONResponse([dict(r) for r in rows])

@app.delete("/api/campaign-history")
def clear_all_history(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return {"active_history_id": _get_active_history_id()}

@app.post("/api/mark-row-complete")
def mark_row_complete(data: dict):
    worker_id   = data.get("worker_id", "?")
    rows_done   = int(data.get("rows_done", 0))
    rows_failed = int(data.get("rows_failed", 0))
    update_worker_stats_in_history(worker_id, rows_done, rows_failed)
    return {"ok": True}

def login_html(err=""):
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>AutoPanel v2</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:#0f1117;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:'Segoe UI',sans-serif;}}
.box{{background:#1a1d27;border:1px solid #2a2d3a;border-radius:16px;padding:40px;width:100%;max-width:380px;}}
h2{{color:#fff;text-align:center;margin-bottom:6px;font-size:1.3rem;font-weight:500;}}
p{{color:#888;text-align:center;margin-bottom:28px;font-size:13px;}}
label{{color:#aaa;font-size:13px;display:block;margin-bottom:6px;}}
input{{width:100%;background:#12151f;border:1px solid #2a2d3a;color:#fff;border-radius:8px;padding:10px 14px;font-size:14px;margin-bottom:14px;outline:none;}}
input:focus{{border-color:#4a90e2;}}
button{{width:100%;background:#4a90e2;color:#fff;border:none;border-radius:8px;padding:12px;font-size:15px;cursor:pointer;font-weight:500;}}
.err{{color:#ff6b6b;text-align:center;margin-top:12px;font-size:13px;}}
</style></head><body>
<div class="box"><h2>AutoPanel v2</h2><p>Secure Admin Login</p>
<form method="POST" action="/login">
<label>Username</label><input name="username" type="text" autofocus>
<label>Password</label><input name="password" type="password">
<button type="submit">Login</button>
</form>{"<div class='err'>Wrong credentials</div>" if err else ""}
</div></body></html>"""

@app.get("/login")
def login_page(): return HTMLResponse(login_html())

@app.post("/login")
def do_login(response: Response, username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and verify_password(password, _admin_hash):
        token = create_session()
        resp  = RedirectResponse(url="/", status_code=302)
        resp.set_cookie("session", token, httponly=True, secure=False, samesite="lax", max_age=SESSION_HOURS*3600)
        return resp
    return HTMLResponse(login_html(err=True))

@app.get("/logout")
def logout(session: Optional[str] = Cookie(None)):
    if session:
        with db_lock:
            with get_db() as conn:
                conn.execute("DELETE FROM sessions WHERE token=?", (session,))
                conn.commit()
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

@app.get("/api/workers")
def get_workers(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return logs.get(worker_id, [])

@app.get("/api/worker/{worker_id}/errors")
def get_worker_errors(worker_id: str, session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return errors.get(worker_id, [])

@app.get("/api/worker-token/{worker_id}")
def get_worker_token(worker_id: str):
    return {"token": make_worker_token(worker_id), "topic_prefix": TOPIC_PREFIX,
            "broker": MQTT_BROKER, "port": MQTT_PORT}

@app.get("/api/pc-urls")
def get_pc_urls(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    with get_db() as conn:
        rows = conn.execute("SELECT worker_id, url FROM pc_urls").fetchall()
    return {r["worker_id"]: r["url"] for r in rows}

@app.post("/api/pc-url")
def set_pc_url(data: dict, session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    worker_id = data.get("worker_id")
    url       = data.get("url", "")
    with db_lock:
        with get_db() as conn:
            conn.execute("INSERT OR REPLACE INTO pc_urls (worker_id, url, updated_at) VALUES (?, ?, ?)",
                         (worker_id, url, datetime.now().isoformat()))
            conn.commit()
    send_cmd(worker_id, "set_url", {"url": url})
    return {"message": f"URL set for {worker_id}"}

@app.get("/api/version")
def get_version():
    s = get_script()
    return {"version": s["version"], "filename": s["filename"],
            "uploaded_at": s["uploaded_at"], "data_required": s["data_required"]}

@app.get("/api/script/content")
def get_script_content(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    content = file.file.read().decode("utf-8", "replace")
    save_script({"version": version, "filename": file.filename, "content": content,
                 "requirements": requirements.strip(), "data_required": data_required,
                 "uploaded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    send_cmd("ALL", "script_updated", {"version": version})
    return {"message": f"Script v{version} uploaded & pushed!"}

@app.post("/api/script/save")
def save_script_api(data: dict, session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    s = get_script()
    s.update({"content": data.get("content", ""), "version": data.get("version", "1.0"),
               "uploaded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    save_script(s)
    send_cmd("ALL", "script_updated", {"version": s["version"]})
    return {"message": f"Script v{s['version']} saved & pushed!"}

@app.get("/api/scripts/info")
def script_info(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    s = get_script()
    return {**s, "has_script": bool(s["content"]),
            "size": len(s["content"].encode("utf-8")) if s["content"] else 0}

@app.post("/api/upload-csv")
def upload_csv(session: Optional[str] = Cookie(None), file: UploadFile = File(...)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
            if data[ptr].get("status", "").upper() not in ("SUCCESS", "USED", "FAILED"): break
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
    status    = data.get("status", "SUCCESS")
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    files = []
    if os.path.exists("csv_data/history"):
        for f in os.listdir("csv_data/history"):
            files.append({"name": f, "size": os.path.getsize(f"csv_data/history/{f}")})
    return sorted(files, key=lambda x: x["name"], reverse=True)

@app.delete("/api/csv-history")
def clear_csv_history(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    for f in os.listdir("csv_data/history"):
        os.remove(f"csv_data/history/{f}")
    return {"message": "History cleared!"}

@app.post("/api/upload-images")
def upload_images(session: Optional[str] = Cookie(None), files: List[UploadFile] = File(...)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    saved = []
    for file in files:
        with open(f"uploads/images/{file.filename}", "wb") as f:
            shutil.copyfileobj(file.file, f)
        saved.append(file.filename)
    return {"uploaded": saved, "count": len(saved)}

@app.get("/api/images")
def list_images(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if not os.path.exists("uploads/images"): return []
    result = []
    for f in os.listdir("uploads/images"):
        if not f.lower().endswith((".png",".jpg",".jpeg",".webp",".gif")): continue
        path = f"uploads/images/{f}"
        with open(path, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode()
        ext  = f.rsplit(".",1)[-1].lower()
        mime = {"jpg":"image/jpeg","jpeg":"image/jpeg","png":"image/png","webp":"image/webp","gif":"image/gif"}.get(ext,"image/jpeg")
        result.append({"name": f, "size": os.path.getsize(path), "data": b64, "mime": mime})
    return result

@app.delete("/api/images")
def clear_images(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    for f in os.listdir("uploads/images"):
        os.remove(f"uploads/images/{f}")
    return {"message": "Images cleared!"}

@app.delete("/api/images/{filename}")
def delete_single_image(filename: str, session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    path = f"uploads/images/{filename}"
    if os.path.exists(path):
        os.remove(path)
    return {"ok": True}

@app.post("/api/upload-ip-csv")
def upload_ip_csv(session: Optional[str] = Cookie(None), file: UploadFile = File(...)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    with open(f"uploads/ip_data/{file.filename}", "wb") as f:
        shutil.copyfileobj(file.file, f)
    return {"message": f"{file.filename} uploaded!"}

@app.get("/api/ip-records")
def get_ip_records(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    for f in os.listdir("uploads/ip_data"):
        os.remove(f"uploads/ip_data/{f}")
    return {"message": "IP records cleared!"}

@app.get("/api/ip-records/download")
def download_ip_records(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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

@app.get("/api/campaigns")
def get_campaigns(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM campaigns ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/campaigns")
def create_campaign(data: dict, session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    send_cmd(data.get("worker_id"), data.get("command"), data.get("extra", {}))
    return {"message": "Command sent"}

@app.post("/api/broadcast")
def broadcast(data: dict, session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    cmd_name = data.get("command")

    if cmd_name == "stop":
        hid = _get_active_history_id()
        if hid:
            stop_campaign_history(hid, final_status="stopped")

    elif cmd_name == "start":
        existing_hid = _get_active_history_id()
        if not existing_hid:
            with get_db() as conn:
                # Pehle active campaign dhundo
                camp = conn.execute(
                    "SELECT * FROM campaigns WHERE status='active' ORDER BY created_at DESC LIMIT 1"
                ).fetchone()
                if not camp:
                    # Active nahi mila to latest campaign lo
                    camp = conn.execute(
                        "SELECT * FROM campaigns ORDER BY created_at DESC LIMIT 1"
                    ).fetchone()
            if camp:
                with db_lock:
                    with get_db() as conn:
                        conn.execute("UPDATE campaigns SET status='active' WHERE id=?", (camp["id"],))
                        conn.commit()
                create_campaign_history(
                    campaign_id=camp["id"],
                    name=camp["name"] or "Manual Start",
                    script=camp["script"] or "—",
                    csv_file=camp["csv_file"] or "—",
                    url=camp["url"] or "—"
                )
            else:
                # Koi campaign nahi — phir bhi history banao
                create_campaign_history(
                    campaign_id="manual",
                    name="Manual Start (No Campaign)",
                    script="—", csv_file="—", url="—"
                )

    elif cmd_name == "restart":
        hid = _get_active_history_id()
        if hid:
            stop_campaign_history(hid, final_status="stopped")
        with get_db() as conn:
            camp = conn.execute(
                "SELECT * FROM campaigns ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        if camp:
            create_campaign_history(
                campaign_id=camp["id"],
                name=f"{camp['name'] or 'Campaign'} (Restart)",
                script=camp["script"] or "—",
                csv_file=camp["csv_file"] or "—",
                url=camp["url"] or "—"
            )

    send_cmd("ALL", cmd_name)
    return {"message": "Broadcast sent"}

@app.get("/api/stats")
def get_stats(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
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
