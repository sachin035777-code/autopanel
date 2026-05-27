"""
AutoPanel - Complete Automation Control Panel
- Login system
- System monitoring (per PC CMD output, URL, Script edit)
- Database (CSV, Images, IP Records)
- Scripts (Upload, Edit, Push)
- Campaign management
- MQTT based (no IP needed)
"""

import json, os, shutil, secrets, csv, re
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, UploadFile, File, Form, Response, Cookie
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import paho.mqtt.client as mqtt
import threading, time

app = FastAPI(title="AutoPanel")

# Folders
for d in ["scripts","configs","csv_data/used","csv_data/history",
          "uploads/images","uploads/ip_data","logs","static"]:
    os.makedirs(d, exist_ok=True)

# Default files
if not os.path.exists("configs/global_config.json"):
    with open("configs/global_config.json","w") as f:
        json.dump({"delay":2,"headless":False},f)
if not os.path.exists("scripts/version.json"):
    with open("scripts/version.json","w") as f:
        json.dump({"version":"0.0","filename":"","uploaded_at":""},f)
if not os.path.exists("configs/pc_urls.json"):
    with open("configs/pc_urls.json","w") as f:
        json.dump({},f)

# ── LOGIN ─────────────────────────────────────────
ADMIN_USER = os.environ.get("ADMIN_USER","admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS","admin123")
sessions   = {}

def create_session():
    t = secrets.token_hex(32)
    sessions[t] = datetime.now() + timedelta(hours=24)
    return t

def check_session(token):
    if not token or token not in sessions: return False
    if sessions[token] < datetime.now():
        del sessions[token]; return False
    return True

# ── MQTT ──────────────────────────────────────────
BROKER       = "broker.hivemq.com"
PORT         = 1883
TOPIC_STATUS = "myautomation/worker/status"
TOPIC_CMD    = "myautomation/cmd"
TOPIC_LOG    = "myautomation/log"

workers = {}
logs    = {}   # worker_id -> [log lines]
errors  = {}   # worker_id -> [error lines]

mqttc = mqtt.Client(client_id=f"SERVER_{secrets.token_hex(4)}", clean_session=True)

def on_connect(c, u, f, rc):
    if rc == 0:
        print("[MQTT] Connected!")
        c.subscribe(TOPIC_STATUS)
        c.subscribe(TOPIC_LOG)

def on_message(c, u, msg):
    try: data = json.loads(msg.payload.decode())
    except: return

    if msg.topic == TOPIC_STATUS:
        wid = data.get("worker_id")
        if wid:
            data["last_seen"] = datetime.now().strftime("%H:%M:%S")
            workers[wid] = data

    elif msg.topic == TOPIC_LOG:
        wid   = data.get("worker_id","?")
        level = data.get("level","INFO")
        text  = data.get("msg","")
        line  = {"time": data.get("time",""), "level": level, "msg": text}

        if wid not in logs: logs[wid] = []
        logs[wid].append(line)
        if len(logs[wid]) > 200: logs[wid].pop(0)

        if level == "ERROR":
            if wid not in errors: errors[wid] = []
            errors[wid].append(line)
            if len(errors[wid]) > 100: errors[wid].pop(0)

mqttc.on_connect = on_connect
mqttc.on_message = on_message

def mqtt_thread():
    while True:
        try:
            mqttc.connect(BROKER, PORT, keepalive=60)
            mqttc.loop_forever()
        except Exception as e:
            print(f"[MQTT] {e}")
            time.sleep(5)

threading.Thread(target=mqtt_thread, daemon=True).start()

def send_cmd(worker_id, command, extra={}):
    mqttc.publish(TOPIC_CMD, json.dumps({
        "worker_id": worker_id, "command": command, **extra
    }))

# ── CSV TRACKING ──────────────────────────────────
csv_lock    = threading.Lock()
row_pointer = 0
assigned    = {}

def load_csv(filename="master.csv"):
    path = f"csv_data/{filename}"
    if not os.path.exists(path): return []
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

def save_used_row(row, worker_id, status):
    path = "csv_data/used/used_records.csv"
    row_copy = dict(row)
    row_copy.update({"used_by": worker_id,
                     "used_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     "status": status})
    exists = os.path.exists(path)
    with open(path,"a",newline="",encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=row_copy.keys())
        if not exists: w.writeheader()
        w.writerow(row_copy)

# ── LOGIN PAGE ────────────────────────────────────
def login_html(err=""):
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>AutoPanel Login</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
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
button:hover{{background:#357abd;}}
.err{{color:#ff6b6b;text-align:center;margin-top:12px;font-size:13px;}}
</style></head><body>
<div class="box">
<h2>AutoPanel</h2>
<p>Admin Login</p>
<form method="POST" action="/login">
<label>Username</label><input name="username" type="text" placeholder="admin" autofocus>
<label>Password</label><input name="password" type="password" placeholder="password">
<button type="submit">Login</button>
</form>
{"<div class='err'>Wrong username or password</div>" if err else ""}
</div></body></html>"""

@app.get("/login")
def login_page(): return HTMLResponse(login_html())

@app.post("/login")
def do_login(response: Response, username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and password == ADMIN_PASS:
        token = create_session()
        resp  = RedirectResponse(url="/", status_code=302)
        resp.set_cookie("session", token, httponly=True, max_age=86400)
        return resp
    return HTMLResponse(login_html(err=True))

@app.get("/logout")
def logout(session: Optional[str] = Cookie(None)):
    if session and session in sessions: del sessions[session]
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie("session")
    return resp

# ── DASHBOARD ─────────────────────────────────────
@app.get("/")
def dashboard(session: Optional[str] = Cookie(None)):
    if not check_session(session):
        return RedirectResponse(url="/login", status_code=302)
    if os.path.exists("static/index.html"):
        return HTMLResponse(open("static/index.html", encoding="utf-8").read())
    return HTMLResponse("<h1>Dashboard loading...</h1>")

# ── WORKERS ───────────────────────────────────────
@app.get("/api/workers")
def get_workers(session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    return JSONResponse(workers)

@app.post("/api/worker/update")
def worker_update(data: dict):
    wid = data.get("worker_id")
    if wid:
        data["last_seen"] = datetime.now().strftime("%H:%M:%S")
        workers[wid] = data
    return {"ok": True}

@app.get("/api/worker/{worker_id}/logs")
def get_worker_logs(worker_id: str, session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    return logs.get(worker_id, [])

@app.get("/api/worker/{worker_id}/errors")
def get_worker_errors(worker_id: str, session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    return errors.get(worker_id, [])

# ── URL PER PC ────────────────────────────────────
@app.get("/api/pc-urls")
def get_pc_urls(session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    try:
        with open("configs/pc_urls.json") as f: return json.load(f)
    except: return {}

@app.post("/api/pc-url")
def set_pc_url(data: dict, session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    worker_id = data.get("worker_id")
    url       = data.get("url","")
    try:
        with open("configs/pc_urls.json") as f: urls = json.load(f)
    except: urls = {}
    urls[worker_id] = url
    with open("configs/pc_urls.json","w") as f: json.dump(urls,f,indent=2)
    send_cmd(worker_id, "set_url", {"url": url})
    return {"message": f"URL set for {worker_id}"}

# ── SCRIPT ────────────────────────────────────────
@app.get("/api/version")
def get_version():
    try:
        with open("scripts/version.json") as f: return json.load(f)
    except: return {"version":"0.0"}

@app.get("/api/script/content")
def get_script_content(session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    if os.path.exists("scripts/latest.py"):
        return {"content": open("scripts/latest.py").read()}
    return {"content": "# No script uploaded yet"}

@app.post("/api/script/save")
def save_script(data: dict, session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    content = data.get("content","")
    version = data.get("version","1.0")
    with open("scripts/latest.py","w") as f: f.write(content)
    with open("scripts/version.json","w") as f:
        json.dump({"version":version,"updated_at":str(datetime.now())},f)
    send_cmd("ALL","script_updated",{"version":version})
    return {"message":f"Script v{version} saved & pushed to all PCs"}

@app.post("/api/upload-script")
def upload_script(session: Optional[str] = Cookie(None),
                  file: UploadFile = File(...),
                  version: str = Form("1.0"),
                  requirements: str = Form(""),
                  data_required: str = Form("")):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    content = file.file.read().decode("utf-8","replace")
    with open("scripts/latest.py","w") as f: f.write(content)
    if requirements.strip():
        with open("scripts/requirements.txt","w") as f: f.write(requirements.strip())
    with open("scripts/version.json","w") as f:
        json.dump({"version":version,"filename":file.filename,
                   "uploaded_at":str(datetime.now()),
                   "data_required":data_required},f)
    send_cmd("ALL","script_updated",{"version":version})
    return {"message":f"Script v{version} uploaded & pushed!"}

@app.get("/api/download-script")
def download_script():
    from fastapi.responses import FileResponse
    if os.path.exists("scripts/latest.py"):
        return FileResponse("scripts/latest.py",filename="latest.py")
    return JSONResponse({"error":"No script"},status_code=404)

@app.get("/api/download-requirements")
def download_requirements():
    from fastapi.responses import FileResponse
    if os.path.exists("scripts/requirements.txt"):
        return FileResponse("scripts/requirements.txt")
    return JSONResponse({"error":"No requirements"},status_code=404)

# ── CSV ───────────────────────────────────────────
@app.post("/api/upload-csv")
def upload_csv(session: Optional[str] = Cookie(None), file: UploadFile = File(...)):
    global row_pointer, assigned
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    content = file.file.read()
    # History mein save karo
    hist_path = f"csv_data/history/{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    with open(hist_path,"wb") as f: f.write(content)
    with open(f"csv_data/{file.filename}","wb") as f: f.write(content)
    row_pointer = 0; assigned = {}
    return {"message":f"{file.filename} uploaded! Row pointer reset."}

@app.get("/api/csv-status")
def csv_status(session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    data = load_csv("master.csv")
    if not data: return {"total":0,"done":0,"pending":0,"failed":0,"rows":[]}
    rows = []
    for i,row in enumerate(data):
        st = row.get("status","").upper()
        worker = next((wid for wid,a in assigned.items() if a.get("row_index")==i),None)
        rows.append({"index":i+1,"name":row.get("name","—"),
                     "mobile":row.get("mobile","—"),"email":row.get("email","—"),
                     "status":st or "PENDING","worker":worker or "—"})
    return {"total":len(data),
            "done":sum(1 for r in data if r.get("status","").upper()=="SUCCESS"),
            "failed":sum(1 for r in data if r.get("status","").upper()=="FAILED"),
            "pending":sum(1 for r in data if r.get("status","").upper() not in ("SUCCESS","FAILED","USED")),
            "rows":rows}

@app.get("/api/csv-history")
def csv_history(session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    files = []
    for f in os.listdir("csv_data/history"):
        files.append({"name":f,"size":os.path.getsize(f"csv_data/history/{f}"),
                      "time":f[:15]})
    return sorted(files,key=lambda x:x["name"],reverse=True)

@app.delete("/api/csv-history")
def clear_csv_history(session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    for f in os.listdir("csv_data/history"):
        os.remove(f"csv_data/history/{f}")
    return {"message":"History cleared!"}

@app.get("/api/get-next-row/{worker_id}")
def get_next_row(worker_id: str):
    global row_pointer
    with csv_lock:
        data = load_csv("master.csv")
        if not data: return {"row":None,"message":"CSV not found"}
        while row_pointer < len(data):
            if data[row_pointer].get("status","").upper() not in ("SUCCESS","USED","FAILED"):
                break
            row_pointer += 1
        if row_pointer >= len(data):
            return {"row":None,"message":"Sab rows complete!"}
        row = data[row_pointer]
        assigned[worker_id] = {"row_index":row_pointer,"row_data":row,
                                "assigned_at":datetime.now().strftime("%H:%M:%S")}
        row_pointer += 1
        return {"row":row,"row_index":row_pointer-1}

@app.post("/api/mark-row")
def mark_row(data: dict):
    worker_id = data.get("worker_id")
    row_index = data.get("row_index")
    status    = data.get("status","SUCCESS")
    row_data  = data.get("row_data",{})
    if worker_id in assigned: assigned[worker_id]["status"] = status
    try:
        all_data = load_csv("master.csv")
        if row_index is not None and row_index < len(all_data):
            all_data[row_index]["status"] = status
            with open("csv_data/master.csv","w",newline="",encoding="utf-8-sig") as f:
                w = csv.DictWriter(f,fieldnames=all_data[0].keys())
                w.writeheader(); w.writerows(all_data)
    except: pass
    if row_data: save_used_row(row_data,worker_id,status)
    return {"message":f"Row {row_index} marked {status}"}

@app.get("/api/csv/{filename}")
def get_csv(filename: str):
    from fastapi.responses import FileResponse
    path = f"csv_data/{filename}"
    if os.path.exists(path): return FileResponse(path)
    return JSONResponse({"error":"Not found"},status_code=404)

# ── IMAGES ────────────────────────────────────────
@app.post("/api/upload-images")
def upload_images(session: Optional[str] = Cookie(None), files: List[UploadFile] = File(...)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    saved = []
    for file in files:
        with open(f"uploads/images/{file.filename}","wb") as f:
            shutil.copyfileobj(file.file,f)
        saved.append(file.filename)
    return {"uploaded":saved,"count":len(saved)}

@app.get("/api/images")
def list_images(session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    return [{"name":f,"size":os.path.getsize(f"uploads/images/{f}")}
            for f in os.listdir("uploads/images")]

@app.delete("/api/images")
def clear_images(session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    for f in os.listdir("uploads/images"): os.remove(f"uploads/images/{f}")
    return {"message":"Images cleared!"}

@app.get("/api/download-image/{filename}")
def download_image(filename: str):
    from fastapi.responses import FileResponse
    path = f"uploads/images/{filename}"
    if os.path.exists(path): return FileResponse(path,filename=filename)
    return JSONResponse({"error":"Not found"},status_code=404)

# ── IP RECORDS ────────────────────────────────────
@app.post("/api/upload-ip-csv")
def upload_ip_csv(session: Optional[str] = Cookie(None), file: UploadFile = File(...)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    path = f"uploads/ip_data/{file.filename}"
    with open(path,"wb") as f: shutil.copyfileobj(file.file,f)
    return {"message":f"{file.filename} uploaded!"}

@app.get("/api/ip-records")
def get_ip_records(session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    records = []
    for fname in os.listdir("uploads/ip_data"):
        if not fname.endswith(".csv"): continue
        with open(f"uploads/ip_data/{fname}",newline="",encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                records.append(dict(row))
    return records[-200:]

@app.delete("/api/ip-records")
def clear_ip_records(session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    for f in os.listdir("uploads/ip_data"): os.remove(f"uploads/ip_data/{f}")
    return {"message":"IP records cleared!"}

# ── CAMPAIGNS ─────────────────────────────────────
def load_campaigns():
    try:
        with open("configs/campaigns.json") as f: return json.load(f)
    except: return []

def save_campaigns(data):
    with open("configs/campaigns.json","w") as f: json.dump(data,f,indent=2)

@app.get("/api/campaigns")
def get_campaigns(session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    return load_campaigns()

@app.post("/api/campaigns")
def create_campaign(data: dict, session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    campaigns = load_campaigns()
    data["id"]         = secrets.token_hex(4)
    data["created_at"] = str(datetime.now())
    data["status"]     = "idle"
    campaigns.append(data)
    save_campaigns(campaigns)
    return {"message":"Campaign created!","id":data["id"]}

@app.post("/api/campaigns/{cid}/start")
def start_campaign(cid: str, session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    campaigns = load_campaigns()
    for c in campaigns:
        if c["id"] == cid: c["status"] = "active"
    save_campaigns(campaigns)
    send_cmd("ALL","start")
    return {"message":"Campaign started!"}

@app.post("/api/campaigns/{cid}/stop")
def stop_campaign(cid: str, session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    campaigns = load_campaigns()
    for c in campaigns:
        if c["id"] == cid: c["status"] = "idle"
    save_campaigns(campaigns)
    send_cmd("ALL","stop")
    return {"message":"Campaign stopped!"}

# ── COMMANDS ──────────────────────────────────────
@app.post("/api/send-command")
def send_command(data: dict, session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    send_cmd(data.get("worker_id"), data.get("command"), data.get("extra",{}))
    return {"message":"Command sent"}

@app.post("/api/broadcast")
def broadcast(data: dict, session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    send_cmd("ALL", data.get("command"))
    return {"message":"Broadcast sent"}

@app.get("/api/config")
def get_config():
    try:
        with open("configs/global_config.json") as f: return json.load(f)
    except: return {}

@app.get("/api/stats")
def get_stats(session: Optional[str] = Cookie(None)):
    if not check_session(session): return JSONResponse({"error":"unauthorized"},status_code=401)
    v = list(workers.values())
    return {"total":len(v),
            "running":sum(1 for w in v if w.get("status")=="running"),
            "idle":sum(1 for w in v if w.get("status")=="idle"),
            "error":sum(1 for w in v if w.get("status")=="error"),
            "success":sum(w.get("success",0) for w in v),
            "failed":sum(w.get("failed",0) for w in v)}

# Static files serve karo
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")
