#!/usr/bin/env python3
# app.py - PacketCatcher main application
import os
import json
import time
import csv
import threading
import zipfile
import secrets
import hashlib
import sqlite3
from datetime import datetime
from io import BytesIO
from functools import wraps
from werkzeug.utils import secure_filename

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, abort, jsonify
)
# SocketIO is optional, but recommended for progress push
try:
    from flask_socketio import SocketIO, emit
    SOCKET_IO_OK = True
except Exception:
    SOCKET_IO_OK = False

# Scapy optional
try:
    from scapy.all import AsyncSniffer, rdpcap, wrpcap, get_if_list
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

# ---------- Paths ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
TEMPLATES_DIR = os.path.join(WEB_DIR, "templates")
STATIC_DIR = os.path.join(WEB_DIR, "static")
CAP_DIR = os.path.join(BASE_DIR, "captures")
EXPORT_DIR = os.path.join(BASE_DIR, "exports")
DB_PATH = os.path.join(BASE_DIR, "packetcatcher.db")
STATS_PATH = os.path.join(BASE_DIR, "stats.json")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

os.makedirs(CAP_DIR, exist_ok=True)
os.makedirs(EXPORT_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# ---------- Flask ----------
app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.secret_key = os.environ.get("PACKETCATCHER_SECRET", secrets.token_hex(32))
if SOCKET_IO_OK:
    socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")
else:
    socketio = None

# ---------- DB & Auth ----------
def db_conn():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def sha256_digest(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def make_password(password: str):
    salt = secrets.token_hex(16)
    digest = sha256_digest(salt + password)
    return salt, digest

def verify_password(password: str, salt: str, digest: str) -> bool:
    return sha256_digest(salt + password) == digest

def init_db():
    con = db_conn()
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)
    con.commit()
    # ensure default admin
    cur.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
    if not cur.fetchone():
        salt, digest = make_password("admin")
        cur.execute(
            "INSERT INTO users (username, password_hash, salt, role, active, created_at) VALUES (?,?,?,?,?,?)",
            ("admin", digest, salt, "admin", 1, datetime.utcnow().isoformat())
        )
        con.commit()
        print("[init_db] Default admin created: username=admin password=admin")
    con.close()

def login_required(f):
    @wraps(f)
    def inner(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return f(*a, **kw)
    return inner

def admin_required(f):
    @wraps(f)
    def inner(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        if session.get("role") != "admin":
            flash("Admin only", "danger")
            return redirect(url_for("index"))
        return f(*a, **kw)
    return inner

# ---------- JSON helpers ----------
def safe_write_json(path: str, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)

def load_json_or_default(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

# ---------- Config & Stats ----------
def load_config():
    default = {
        "max_connections": 200,
        "firewall_backend": "auto",
        "allow_registration": True,
        "firewall_rules": [],
        "thresholds": {
            "large_packet_bytes": 100 * 1024 * 1024,
            "conn_per_min": 100,
            "conn_per_sec": 20
        },
        "last_scan": None
    }
    return load_json_or_default(CONFIG_PATH, default)

def save_config(cfg):
    safe_write_json(CONFIG_PATH, cfg)

def get_thresholds():
    return load_config().get("thresholds", {})

def set_thresholds(new):
    cfg = load_config()
    cfg["thresholds"] = new
    save_config(cfg)

def save_last_scan(iface, duration, bpf_filter=""):
    cfg = load_config()
    cfg["last_scan"] = {"iface": iface, "duration": int(duration), "filter": bpf_filter or ""}
    save_config(cfg)

def get_last_scan():
    return load_config().get("last_scan")

def load_stats():
    default = {"total_packets":0,"malicious":0,"scan_runs":0,"max_packets_in_run":0,"history":[], "connections":[]}
    return load_json_or_default(STATS_PATH, default)

def save_stats(s):
    safe_write_json(STATS_PATH, s)

# ---------- PCAP helpers ----------
def list_pcap_files():
    try:
        files = [f for f in os.listdir(CAP_DIR) if f.lower().endswith(".pcap")]
    except Exception:
        files = []
    files.sort(key=lambda x: os.path.getmtime(os.path.join(CAP_DIR, x)), reverse=True)
    return files

def latest_pcap_path():
    files = list_pcap_files()
    return os.path.join(CAP_DIR, files[0]) if files else None

def packet_to_row(pkt):
    # Flatten common fields for UI
    try:
        ts = getattr(pkt, "time", None)
    except Exception:
        ts = None
    try:
        summary = pkt.summary()
    except Exception:
        summary = str(pkt)
    src = ""
    dst = ""
    proto = "UNKNOWN"
    plen = 0
    try:
        src = getattr(pkt, "src", "") or getattr(pkt, "psrc", "") or ""
        dst = getattr(pkt, "dst", "") or getattr(pkt, "pdst", "") or ""
    except Exception:
        pass
    try:
        last = pkt.lastlayer().name if hasattr(pkt, "lastlayer") else ""
        p = (last or "").upper()
        if "TCP" in p: proto = "TCP"
        elif "UDP" in p: proto = "UDP"
        elif "ICMP" in p: proto = "ICMP"
        elif "ARP" in p: proto = "ARP"
        elif "DNS" in p: proto = "DNS"
        elif "HTTP" in p: proto = "HTTP"
        else:
            proto = p or "UNKNOWN"
    except Exception:
        proto = "UNKNOWN"
    try:
        plen = len(bytes(pkt))
    except Exception:
        try:
            plen = int(getattr(pkt, "len", 0))
        except Exception:
            plen = 0
    return {"time": ts, "summary": summary, "src": str(src), "dst": str(dst), "proto": proto, "len": plen}

def export_to_csv(pcap_file, out_path):
    pkts = rdpcap(pcap_file)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["time", "src", "dst", "proto", "len", "summary"])
        writer.writeheader()
        for p in pkts:
            writer.writerow(packet_to_row(p))

def export_to_json(pcap_file, out_path):
    pkts = rdpcap(pcap_file)
    data = [packet_to_row(p) for p in pkts]
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# ---------- Scan job state ----------
JOB = {
    "id": None,
    "status": "idle",
    "started_at": None,
    "duration": 0,
    "interface": "",
    "captured": 0,
    "pcap_path": None,
    "error": None,
    "progress": 0.0
}
JOB_LOCK = threading.Lock()
STOP_EVENT = threading.Event()
SNIFFER = None
CAPTURED_PKTS = []

def reset_job():
    global JOB, SNIFFER, CAPTURED_PKTS
    with JOB_LOCK:
        try:
            if SNIFFER and hasattr(SNIFFER, "stop"):
                SNIFFER.stop()
        except Exception:
            pass
        STOP_EVENT.set()
        JOB.update({
            "id": None, "status": "idle", "started_at": None,
            "duration": 0, "interface": "", "captured": 0,
            "pcap_path": None, "error": None, "progress": 0.0
        })
        CAPTURED_PKTS = []
        STOP_EVENT.clear()

def start_scan_thread(iface: str, duration_s: int):
    global JOB, SNIFFER, CAPTURED_PKTS
    if not SCAPY_OK:
        with JOB_LOCK:
            JOB["status"] = "error"
            JOB["error"] = "scapy not available"
        if socketio:
            socketio.emit("scan_complete", JOB)
        return

    CAPTURED_PKTS = []
    start = time.time()
    end_time = start + duration_s
    thresholds = get_thresholds()

    def on_pkt(pkt):
        CAPTURED_PKTS.append(pkt)
        with JOB_LOCK:
            JOB["captured"] = len(CAPTURED_PKTS)
            elapsed = max(0.0, time.time() - start)
            JOB["progress"] = min(100.0, (elapsed / max(1.0, duration_s)) * 100.0)
        if socketio:
            socketio.emit("scan_progress", {"captured": JOB["captured"], "progress": JOB["progress"]})

    try:
        SNIFFER = AsyncSniffer(iface=iface or None, prn=on_pkt, store=True)
        SNIFFER.start()
        with JOB_LOCK:
            JOB["status"] = "running"
        while time.time() < end_time:
            if STOP_EVENT.is_set():
                with JOB_LOCK:
                    JOB["status"] = "killed"
                break
            with JOB_LOCK:
                elapsed = max(0.0, time.time() - start)
                JOB["progress"] = min(100.0, (elapsed / max(1.0, duration_s)) * 100.0)
            if socketio:
                socketio.emit("scan_progress", {"captured": JOB["captured"], "progress": JOB["progress"]})
            time.sleep(0.35)
    except Exception as e:
        with JOB_LOCK:
            JOB["status"] = "error"
            JOB["error"] = str(e)
        if socketio:
            socketio.emit("scan_complete", JOB)
        return
    finally:
        try:
            if SNIFFER:
                SNIFFER.stop()
        except Exception:
            pass

    with JOB_LOCK:
        status = JOB["status"]
    if status == "killed":
        if socketio:
            socketio.emit("scan_complete", JOB)
        return

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    pcap_name = f"scan-{ts}.pcap"
    pcap_path = os.path.join(CAP_DIR, pcap_name)
    try:
        wrpcap(pcap_path, CAPTURED_PKTS)
    except Exception as e:
        with JOB_LOCK:
            JOB["status"] = "error"
            JOB["error"] = "failed to write pcap: " + str(e)
        if socketio:
            socketio.emit("scan_complete", JOB)
        return

    thresholds = get_thresholds()
    large_threshold = int(thresholds.get("large_packet_bytes", 100 * 1024 * 1024))
    conn_per_min = int(thresholds.get("conn_per_min", 100))
    conn_per_sec = int(thresholds.get("conn_per_sec", 20))

    suspicious_packets = 0
    src_counts = {}
    for p in CAPTURED_PKTS:
        try:
            plen = len(bytes(p))
        except Exception:
            plen = int(getattr(p, "len", 0) or 0)
        if plen >= large_threshold:
            suspicious_packets += 1
        src = getattr(p, "src", None) or getattr(p, "psrc", "") or ""
        if src:
            src_counts[src] = src_counts.get(src, 0) + 1

    suspicious_conn_count = 0
    duration_minutes = max(1.0, duration_s / 60.0)
    for src, cnt in src_counts.items():
        per_min = cnt / duration_minutes
        per_sec = cnt / max(1.0, duration_s)
        if per_min >= conn_per_min or per_sec >= conn_per_sec:
            suspicious_conn_count += 1

    total_suspicious = suspicious_packets + suspicious_conn_count

    stats = load_stats()
    stats["total_packets"] = stats.get("total_packets", 0) + len(CAPTURED_PKTS)
    stats["scan_runs"] = stats.get("scan_runs", 0) + 1
    stats["max_packets_in_run"] = max(stats.get("max_packets_in_run", 0), len(CAPTURED_PKTS))
    conn_rows = [{"src": k, "count": v} for k,v in sorted(src_counts.items(), key=lambda kv: kv[1], reverse=True)]
    stats["connections"] = conn_rows[: load_config().get("max_connections", 200)]
    stats["history"].insert(0, {"time": ts, "duration": duration_s, "iface": iface or "default", "packets": len(CAPTURED_PKTS), "file": pcap_name})
    stats["history"] = stats["history"][:200]
    stats["malicious"] = stats.get("malicious", 0) + total_suspicious
    save_stats(stats)

    with JOB_LOCK:
        JOB["status"] = "done"
        JOB["pcap_path"] = pcap_name
        JOB["progress"] = 100.0
        JOB["captured"] = len(CAPTURED_PKTS)

    if socketio:
        socketio.emit("scan_complete", JOB)

# ---------- Routes ----------
@app.route("/")
@login_required
def index():
    stats = load_stats()
    return render_template("index.html", stats=stats, pcap_files=list_pcap_files(), connections=stats.get("connections", []))

@app.route("/login", methods=["GET", "POST"])
def login():
    cfg = load_config()
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        con = db_conn()
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        u = cur.fetchone()
        con.close()
        if not u:
            flash("Invalid username or password", "danger")
        else:
            if int(u["active"]) != 1:
                flash("Account disabled", "danger")
            elif verify_password(password, u["salt"], u["password_hash"]):
                session["user_id"] = u["id"]
                session["username"] = u["username"]
                session["role"] = u["role"]
                nxt = request.args.get("next") or url_for("index")
                flash("Login successful", "success")
                return redirect(nxt)
            else:
                flash("Invalid username or password", "danger")
    return render_template("login.html", allow_register=cfg.get("allow_registration", True))

@app.route("/register", methods=["GET", "POST"])
def register():
    cfg = load_config()
    if not cfg.get("allow_registration", True):
        flash("Registration disabled", "danger")
        return redirect(url_for("login"))
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or password
        if not username or not password:
            flash("Username and password required", "danger")
        elif password != confirm:
            flash("Passwords do not match", "danger")
        else:
            try:
                con = db_conn()
                cur = con.cursor()
                salt, digest = make_password(password)
                cur.execute(
                    "INSERT INTO users (username, password_hash, salt, role, active, created_at) VALUES (?,?,?,?,?,?)",
                    (username, digest, salt, "user", 1, datetime.utcnow().isoformat())
                )
                con.commit()
                con.close()
                flash("Account created. Please login.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username already exists", "danger")
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "success")
    return redirect(url_for("login"))

@app.route("/config", methods=["GET", "POST"])
@login_required
def config():
    cfg = load_config()
    if request.method == "POST":
        try:
            maxc = int(request.form.get("max_connections", cfg.get("max_connections", 200)))
            maxc = max(100, min(300, maxc))
        except Exception:
            maxc = cfg.get("max_connections", 200)
        fw = request.form.get("firewall_backend", cfg.get("firewall_backend", "auto"))
        if fw not in ("auto", "iptables", "windows"):
            fw = "auto"
        cfg["max_connections"] = maxc
        cfg["firewall_backend"] = fw
        save_config(cfg)
        flash("Configuration saved", "success")
        return redirect(url_for("config"))
    rules = cfg.get("firewall_rules", [])
    thresholds = cfg.get("thresholds", {})
    last_scan = cfg.get("last_scan")
    return render_template("config.html", cfg=cfg, rules=rules, thresholds=thresholds, last_scan=last_scan)

@app.route("/scan")
@login_required
def scan():
    ifaces = []
    if SCAPY_OK:
        try:
            ifaces = get_if_list()
        except Exception:
            ifaces = []
    durations = [
        ("5","5 seconds"),("10","10 seconds"),("15","15 seconds"),("30","30 seconds"),
        ("60","1 minute"),("300","5 minutes"),("600","10 minutes"),("900","15 minutes"),
        ("1800","30 minutes"),("3600","1 hour"),("86400","24 hours")
    ]
    last_scan = get_last_scan()
    return render_template("scan.html", ifaces=ifaces, durations=durations, scapy_ok=SCAPY_OK, job=JOB, last_scan=last_scan)

@app.route("/results")
@login_required
def results():
    file = request.args.get("file")
    proto_filter = (request.args.get("proto") or "").upper().strip()
    if file:
        path = os.path.join(CAP_DIR, secure_filename(file))
        if not os.path.exists(path):
            flash("File not found", "danger")
            return redirect(url_for("index"))
        target = path
    else:
        target = latest_pcap_path()
        if not target:
            flash("No capture yet", "danger")
            return redirect(url_for("scan"))

    rows = []
    suspicious_alerts = []
    try:
        pkts = rdpcap(target)
        thresholds = get_thresholds()
        large_threshold = int(thresholds.get("large_packet_bytes", 100 * 1024 * 1024))
        conn_per_min = int(thresholds.get("conn_per_min", 100))
        # compute src counts
        src_counts = {}
        for p in pkts:
            src = getattr(p, "src", None) or getattr(p, "psrc", "") or ""
            if src:
                src_counts[src] = src_counts.get(src, 0) + 1
        for i, p in enumerate(pkts):
            if i > 5000:
                break
            r = packet_to_row(p)
            r["idx"] = i
            r["suspicious"] = False
            if r["len"] >= large_threshold:
                r["suspicious"] = True
                suspicious_alerts.append(f"Large packet #{i}: {r['src']} -> {r['dst']} ({r['len']} bytes)")
            if src_counts.get(r["src"], 0) >= conn_per_min:
                r["suspicious"] = True
                suspicious_alerts.append(f"High rate from {r['src']}: {src_counts.get(r['src'])} packets")
            if proto_filter and r["proto"] != proto_filter:
                continue
            rows.append(r)
    except Exception as e:
        flash(f"Failed to read pcap: {e}", "danger")
        rows = []

    # dedupe alerts
    suspicious_alerts = list(dict.fromkeys(suspicious_alerts))[:30]
    return render_template("results.html", file=os.path.basename(target), rows=rows, total=len(rows), proto_filter=proto_filter, alerts=suspicious_alerts)

@app.route("/export/csv")
@login_required
def export_csv():
    file = request.args.get("file")
    if not file:
        latest = latest_pcap_path()
        if not latest:
            abort(404)
        file = os.path.basename(latest)
    p = os.path.join(CAP_DIR, secure_filename(file))
    if not os.path.exists(p):
        abort(404)
    out = os.path.join(EXPORT_DIR, os.path.splitext(os.path.basename(p))[0] + ".csv")
    try:
        export_to_csv(p, out)
        return send_file(out, as_attachment=True, download_name=os.path.basename(out))
    except Exception as e:
        flash(f"Export failed: {e}", "danger")
        return redirect(url_for("results", file=file))

@app.route("/export/json")
@login_required
def export_json():
    file = request.args.get("file")
    if not file:
        latest = latest_pcap_path()
        if not latest:
            abort(404)
        file = os.path.basename(latest)
    p = os.path.join(CAP_DIR, secure_filename(file))
    if not os.path.exists(p):
        abort(404)
    out = os.path.join(EXPORT_DIR, os.path.splitext(os.path.basename(p))[0] + ".json")
    try:
        export_to_json(p, out)
        return send_file(out, as_attachment=True, download_name=os.path.basename(out))
    except Exception as e:
        flash(f"Export failed: {e}", "danger")
        return redirect(url_for("results", file=file))

@app.route("/export/pcap")
@login_required
def export_pcap():
    file = request.args.get("file")
    if not file:
        latest = latest_pcap_path()
        if not latest:
            abort(404)
        file = os.path.basename(latest)
    p = os.path.join(CAP_DIR, secure_filename(file))
    if not os.path.exists(p):
        abort(404)
    return send_file(p, as_attachment=True, download_name=os.path.basename(p))

# ---------- Admin ----------
@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    con = db_conn()
    cur = con.cursor()
    if request.method == "POST":
        action = request.form.get("action")
        uid = request.form.get("user_id")
        if not uid:
            flash("No user selected", "danger")
            return redirect(url_for("admin"))
        if int(uid) == int(session.get("user_id")) and action in {"delete", "deactivate"}:
            flash("Cannot delete/deactivate yourself", "danger")
            return redirect(url_for("admin"))
        if action == "role":
            new_role = request.form.get("role", "user")
            cur.execute("UPDATE users SET role=? WHERE id=?", (new_role, uid))
            con.commit()
            flash("Role updated", "success")
        elif action == "toggle":
            cur.execute("SELECT active FROM users WHERE id=?", (uid,))
            row = cur.fetchone()
            if row:
                new_val = 0 if int(row["active"]) == 1 else 1
                cur.execute("UPDATE users SET active=? WHERE id=?", (new_val, uid))
                con.commit()
                flash("Account state updated", "success")
        elif action == "resetpw":
            new_pw = secrets.token_urlsafe(10)
            salt, digest = make_password(new_pw)
            cur.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?", (digest, salt, uid))
            con.commit()
            flash(f"Password reset. Temp: {new_pw}", "success")
        elif action == "delete":
            cur.execute("DELETE FROM users WHERE id=?", (uid,))
            con.commit()
            flash("User deleted", "success")
        return redirect(url_for("admin"))

    cur.execute("SELECT id, username, role, active, created_at FROM users ORDER BY id ASC")
    users = cur.fetchall()
    con.close()
    stats = load_stats()
    live_connections = stats.get("connections", [])[:20]
    return render_template("admin.html", users=users, stats=stats, live_connections=live_connections)

@app.route("/admin/purge_pcaps", methods=["POST"])
@admin_required
def admin_purge_pcaps():
    removed = 0
    for f in list_pcap_files():
        path = os.path.join(CAP_DIR, f)
        try:
            os.remove(path)
            removed += 1
        except Exception:
            pass
    stats = load_stats()
    stats["history"] = []
    stats["connections"] = []
    save_stats(stats)
    return jsonify({"ok": True, "removed": removed})

@app.route("/admin/export_logs")
@admin_required
def admin_export_logs():
    bio = BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        if os.path.exists(STATS_PATH):
            zf.write(STATS_PATH, arcname=os.path.basename(STATS_PATH))
        if os.path.exists(CONFIG_PATH):
            zf.write(CONFIG_PATH, arcname=os.path.basename(CONFIG_PATH))
        for f in list_pcap_files():
            fp = os.path.join(CAP_DIR, f)
            if os.path.exists(fp):
                zf.write(fp, arcname=os.path.join("captures", f))
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name=f"pcatcher-export-{int(time.time())}.zip")

# ---------- API endpoints ----------
@app.route("/api/scan/start", methods=["POST"])
@login_required
def api_scan_start():
    data = request.get_json(silent=True) or request.form
    iface = (data.get("interface") or "").strip()
    duration = int(data.get("duration") or 30)
    save_last_scan(iface, duration, data.get("filter") or "")
    with JOB_LOCK:
        if JOB["status"] == "running":
            return jsonify({"ok": False, "error": "Scan already running"}), 400
        JOB.update({
            "id": secrets.token_hex(8),
            "status": "running",
            "started_at": datetime.utcnow().isoformat(),
            "duration": duration,
            "interface": iface,
            "captured": 0,
            "pcap_path": None,
            "error": None,
            "progress": 0.0
        })
    t = threading.Thread(target=start_scan_thread, args=(iface, duration), daemon=True)
    t.start()
    return jsonify({"ok": True, "job": JOB})

@app.route("/api/scan/status")
@login_required
def api_scan_status():
    with JOB_LOCK:
        return jsonify(JOB)

@app.route("/api/scan/reset", methods=["POST"])
@login_required
def api_scan_reset():
    STOP_EVENT.set()
    reset_job()
    if socketio:
        socketio.emit("scan_complete", JOB)
    return jsonify({"ok": True, "job": JOB})

@app.route("/api/thresholds", methods=["GET", "POST"])
@login_required
def api_thresholds():
    if request.method == "GET":
        return jsonify(get_thresholds())
    if session.get("role") != "admin":
        return jsonify({"error": "admin only"}), 403
    data = request.get_json(silent=True) or request.form
    new = get_thresholds()
    for key in ("large_packet_bytes", "conn_per_min", "conn_per_sec"):
        if key in data:
            try:
                new[key] = int(data[key])
            except Exception:
                pass
    set_thresholds(new)
    flash("Thresholds updated", "success")
    return jsonify(new)

@app.route("/api/firewall/rules", methods=["GET", "POST", "DELETE"])
@login_required
def api_firewall_rules():
    if request.method == "GET":
        return jsonify(load_config().get("firewall_rules", []))
    if session.get("role") != "admin":
        return jsonify({"error": "admin only"}), 403
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        rule = {
            "app_path": data.get("app_path", ""),
            "max_connections": int(data.get("max_connections", 0) or 0),
            "action": data.get("action", "limit")
        }
        cfg = load_config()
        arr = cfg.get("firewall_rules", [])
        arr.append(rule)
        cfg["firewall_rules"] = arr
        save_config(cfg)
        return jsonify({"ok": True, "rules": arr})
    if request.method == "DELETE":
        data = request.get_json(silent=True) or {}
        idx = int(data.get("index", -1))
        cfg = load_config()
        arr = cfg.get("firewall_rules", [])
        if 0 <= idx < len(arr):
            arr.pop(idx)
        cfg["firewall_rules"] = arr
        save_config(cfg)
        return jsonify({"ok": True, "rules": arr})

# ---------- SocketIO handlers ----------
if SOCKET_IO_OK:
    @socketio.on("connect")
    def _on_connect():
        emit("hello", {"msg": "connected"})

# ---------- Run ----------
if __name__ == "__main__":
    init_db()
    if not os.path.exists(STATS_PATH):
        save_stats(load_stats())
    if not os.path.exists(CONFIG_PATH):
        save_config(load_config())
    if SOCKET_IO_OK:
        socketio.run(app, host="0.0.0.0", port=5000, debug=True)
    else:
        app.run(host="0.0.0.0", port=5000, debug=True)
