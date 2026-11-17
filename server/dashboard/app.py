import eventlet
eventlet.monkey_patch()

import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import os as _os
import sqlite3
import urllib.request
import urllib.parse

import paho.mqtt.client as mqtt
import joblib
import json
import subprocess
import threading
import time
from datetime import datetime
from flask import Flask, render_template
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'fyp-dashboard-secret'
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

print("Loading model and scaler...")
model = joblib.load('../models_output/model.pkl')
scaler = joblib.load('../models_output/scaler.pkl')
print("Model loaded!\n")

FEATURE_COLS = ['duration_sec', 'total_bytes', 'total_pkts', 'bytes_per_sec',
                'pkts_per_sec', 'avg_pkt_size']

FEATURE_IMPORTANCE = sorted(
    zip(FEATURE_COLS, model.feature_importances_.tolist()),
    key=lambda x: x[1], reverse=True
)

MODEL_METRICS = {
    "accuracy": 95.36,
    "threshold": 85.0,
    "classes": {
        "Brute Force": {"precision": 93, "recall": 96, "f1": 94},
        "DDoS":        {"precision": 97, "recall": 98, "f1": 98},
        "Normal":      {"precision": 94, "recall": 90, "f1": 92},
        "Port Scan":   {"precision": 99, "recall": 98, "f1": 98},
    }
}

MQTT_BROKER = "localhost"
MQTT_TOPIC = "iot/esp32_1/data"

PORT_DIVERSITY_THRESHOLD = 5
HIGH_RATE_THRESHOLD = 30
FAILED_LOGIN_THRESHOLD = 2
PORTSCAN_MIN_PORTS = 10   # a real port scan touches many ports (per 3s window)
SLOWSCAN_MIN_PORTS = 15   # unique ports across 60s - catches slow/stealthy scans
CONFIDENCE_THRESHOLD = 0.85
BLOCK_DURATION_SEC = 300

WHITELIST = {"192.168.0.1", "192.168.0.101", "192.168.0.136", "192.168.0.137", "0.0.0.0"}

blocked_ips = {}
blocked_ips_lock = threading.RLock()
stats = {"total_events": 0, "total_attacks": 0, "total_blocked": 0}
attack_log = []
MAX_LOG = 100

START_TIME = time.time()
last_threat_time = None
response_times = []  # ms, detection->mitigation latency (live)

CONFUSION = None
try:
    with open(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'confusion.json')) as _cf:
        CONFUSION = json.load(_cf)
except Exception:
    CONFUSION = None

LOG_FILE = "mitigation.log"


def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def get_blocked_list():
    with blocked_ips_lock:
        now = time.time()
        result = []
        for ip, info in blocked_ips.items():
            remaining = max(0, int(BLOCK_DURATION_SEC - (now - info['timestamp'])))
            result.append({
                "ip": ip,
                "attack_type": info['attack_type'],
                "confidence": round(info['confidence'], 1),
                "remaining_sec": remaining
            })
        return result


def severity_level(attack_type, confidence):
    """Severity level for the SOC - based on attack type + confidence."""
    base = {"DDoS": 3, "Brute Force": 2, "Port Scan": 2, "USB Malware": 2}.get(attack_type, 1)
    if confidence >= 95:
        base += 1
    return {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}.get(min(base, 4), "Medium")


# ===== v2: dual node + persistent log + telegram =====
TOPIC_NODE = {"iot/esp32_1/data": "Node A", "iot/esp32_2/data": "Node B"}
NODE_TIMEOUT_SEC = 15
node_last_seen = {name: 0 for name in TOPIC_NODE.values()}

_BASE_DIR = _os.path.dirname(_os.path.abspath(__file__))
DB_PATH = _os.path.join(_BASE_DIR, "events.db")
BLOCKED_FILE = _os.path.join(_BASE_DIR, "blocked_ips.json")


def save_blocked():
    try:
        with blocked_ips_lock:
            json.dump(blocked_ips, open(BLOCKED_FILE, "w"))
    except Exception as e:
        print(f"[BLOCKED] save failed: {e}")


def load_blocked():
    try:
        if _os.path.exists(BLOCKED_FILE):
            data = json.load(open(BLOCKED_FILE))
            now = time.time()
            with blocked_ips_lock:
                for ip, info in data.items():
                    if now - info.get("timestamp", 0) < BLOCK_DURATION_SEC:
                        blocked_ips[ip] = info
            print(f"[BLOCKED] Reloaded {len(blocked_ips)} active block(s) - iptables rules kept, auto-unblock resumed")
    except Exception as e:
        print(f"[BLOCKED] load failed: {e}")
db_lock = threading.RLock()
db_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
EVENT_COLS = ["ts", "time", "node", "prediction", "ml_raw", "refined", "confidence",
              "pkts_per_sec", "syn_count", "unique_ports", "failed_logins", "source_ip", "action", "response_ms"]


def init_db():
    with db_lock:
        db_conn.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, time TEXT, node TEXT, prediction TEXT, ml_raw TEXT, refined INTEGER,
            confidence REAL, pkts_per_sec REAL, syn_count INTEGER, unique_ports INTEGER,
            failed_logins INTEGER, source_ip TEXT, action TEXT)""")
        try:
            db_conn.execute("ALTER TABLE events ADD COLUMN response_ms REAL")
        except Exception:
            pass  # column dah wujud
        db_conn.commit()


def save_event(ev):
    try:
        with db_lock:
            db_conn.execute(
                "INSERT INTO events (" + ",".join(EVENT_COLS) + ") VALUES (" + ",".join("?" * len(EVENT_COLS)) + ")",
                [int(ev.get(c)) if c == "refined" else ev.get(c) for c in EVENT_COLS])
            db_conn.commit()
    except Exception as e:
        print(f"[DB] save failed: {e}")


def load_from_db():
    with db_lock:
        cur = db_conn.cursor()
        total = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        attacks = cur.execute("SELECT COUNT(*) FROM events WHERE prediction != 'Normal'").fetchone()[0]
        blocked = cur.execute("SELECT COUNT(*) FROM events WHERE action = 'blocked'").fetchone()[0]
        rows = cur.execute("SELECT " + ",".join(EVENT_COLS) + " FROM events ORDER BY id DESC LIMIT ?",
                           (MAX_LOG,)).fetchall()
    stats["total_events"] = total
    stats["total_attacks"] = attacks
    stats["total_blocked"] = blocked
    attack_log.clear()
    for r in rows:
        ev = dict(zip(EVENT_COLS, r))
        ev["refined"] = bool(ev["refined"])
        attack_log.append(ev)
    print(f"[DB] Loaded history: {total} events, {attacks} attacks, {blocked} blocks")


TELEGRAM_CFG = _os.path.join(_BASE_DIR, "telegram.json")
try:
    with open(TELEGRAM_CFG) as _f:
        telegram = json.load(_f)
except Exception:
    telegram = {}


def _tg_send(text):
    try:
        url = f"https://api.telegram.org/bot{telegram['token']}/sendMessage"
        body = urllib.parse.urlencode({"chat_id": telegram["chat_id"], "text": text}).encode()
        urllib.request.urlopen(url, data=body, timeout=10).read()
    except Exception as e:
        print(f"[TELEGRAM] send failed: {e}")


def send_telegram(text):
    if telegram.get("token") and telegram.get("chat_id"):
        socketio.start_background_task(_tg_send, text)


def get_node_status():
    now = time.time()
    return {n: (now - t) < NODE_TIMEOUT_SEC for n, t in node_last_seen.items()}


def node_watch_worker():
    while True:
        socketio.sleep(3)
        socketio.emit('node_status', get_node_status())


def get_analytics():
    classes, per_node = {}, {}
    today_attacks, peak = 0, 0.0
    try:
        with db_lock:
            cur = db_conn.cursor()
            classes = dict(cur.execute(
                "SELECT prediction, COUNT(*) FROM events GROUP BY prediction").fetchall())
            for node, total, atk in cur.execute(
                "SELECT node, COUNT(*), SUM(CASE WHEN prediction!='Normal' THEN 1 ELSE 0 END) "
                "FROM events WHERE node IS NOT NULL GROUP BY node").fetchall():
                per_node[node] = {"total": total, "attacks": atk or 0}
            today_attacks = cur.execute(
                "SELECT COUNT(*) FROM events WHERE prediction!='Normal' AND ts >= ?",
                (datetime.now().strftime('%Y-%m-%d 00:00:00'),)).fetchone()[0]
            peak = cur.execute("SELECT MAX(pkts_per_sec) FROM events").fetchone()[0] or 0
    except Exception as e:
        print(f"[ANALYTICS] {e}")
    rt = response_times[-50:]
    return {
        "classes": classes,
        "per_node": per_node,
        "attacks_today": today_attacks,
        "peak_pps": round(peak, 2),
        "last_response_ms": round(response_times[-1], 1) if response_times else None,
        "avg_response_ms": round(sum(rt) / len(rt), 1) if rt else None,
    }


def analytics_worker():
    while True:
        socketio.sleep(5)
        socketio.emit('analytics_update', get_analytics())


@app.route('/export.csv')
def export_csv():
    import csv
    import io
    from flask import Response
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(EVENT_COLS)
    with db_lock:
        for row in db_conn.execute("SELECT " + ",".join(EVENT_COLS) + " FROM events ORDER BY id"):
            w.writerow(row)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=iot_soc_events.csv"})


def block_ip(ip, attack_type, confidence):
    with blocked_ips_lock:
        if ip in blocked_ips:
            blocked_ips[ip]['timestamp'] = time.time()
            return False
        try:
            subprocess.run(
                ["sudo", "/usr/sbin/iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, text=True
            )
            blocked_ips[ip] = {"timestamp": time.time(), "attack_type": attack_type, "confidence": confidence}
            log_event(f"BLOCKED {ip} | Reason: {attack_type} (confidence {confidence:.1f}%)")
            stats["total_blocked"] += 1
            save_blocked()
            socketio.emit('blocked_update', get_blocked_list())
            return True
        except subprocess.CalledProcessError as e:
            log_event(f"FAILED to block {ip}: {e.stderr}")
            return False


def unblock_ip(ip):
    try:
        subprocess.run(
            ["sudo", "/usr/sbin/iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True, text=True
        )
        log_event(f"UNBLOCKED {ip} | Reason: timeout expired ({BLOCK_DURATION_SEC}s)")
    except subprocess.CalledProcessError as e:
        log_event(f"FAILED to unblock {ip}: {e.stderr}")


def auto_unblock_worker():
    while True:
        time.sleep(5)
        now = time.time()
        with blocked_ips_lock:
            expired = [ip for ip, info in blocked_ips.items() if now - info['timestamp'] >= BLOCK_DURATION_SEC]
        for ip in expired:
            unblock_ip(ip)
            with blocked_ips_lock:
                blocked_ips.pop(ip, None)
        if expired:
            save_blocked()
        socketio.emit('blocked_update', get_blocked_list())


def extract_features(data):
    total_pkts = data.get('total_pkts', 0)
    total_bytes = data.get('total_bytes', 0)
    pkts_per_sec = data.get('pkts_per_sec', 0)
    bytes_per_sec = data.get('bytes_per_sec', 0)
    duration_sec = 3.0
    avg_pkt_size = total_bytes / (total_pkts + 1)
    return [duration_sec, total_bytes, total_pkts, bytes_per_sec, pkts_per_sec, avg_pkt_size]


def refine_prediction(ml_prediction, data):
    failed_logins = data.get('failed_logins', 0)
    unique_ports = data.get('unique_dst_ports', 0)
    pkts_per_sec = data.get('pkts_per_sec', 0)

    unique_60s = data.get('unique_ports_60s', 0)

    # Brute Force: repeated failed logins are the defining signature.
    if failed_logins >= FAILED_LOGIN_THRESHOLD:
        return "Brute Force", True

    # Slow-scan guard: many unique ports across a 60s window even when each 3s
    # window looks small. Uses the TRUE per-port count from the ESP32 (not an
    # estimate) to catch slow / stealthy scans the per-window model would miss.
    if unique_60s >= SLOWSCAN_MIN_PORTS:
        return "Port Scan", (ml_prediction != "Port Scan")

    # DDoS false-positive guard: a real DDoS is a flood with a very high packet
    # rate. If the model flags DDoS at a low packet rate, it is a normal burst,
    # so reclassify it as Normal (reduces false positives).
    if ml_prediction == "DDoS" and pkts_per_sec <= HIGH_RATE_THRESHOLD:
        return "Normal", True

    if ml_prediction == "Port Scan":
        # Few ports but a high packet rate is a DDoS flood, not a scan.
        if unique_ports <= PORT_DIVERSITY_THRESHOLD and pkts_per_sec > HIGH_RATE_THRESHOLD:
            return "DDoS", True
        # Port-scan false-positive guard: a real scan must touch many ports.
        # Few ports + low rate = normal traffic the model mislabelled -> Normal.
        if unique_ports < PORTSCAN_MIN_PORTS and pkts_per_sec <= HIGH_RATE_THRESHOLD:
            return "Normal", False
    return ml_prediction, False


def on_connect(client, userdata, flags, rc, properties=None):
    print(f"Connected to MQTT Broker (rc={rc})")
    for topic in TOPIC_NODE:
        client.subscribe(topic)
        print(f"Subscribed: {topic} ({TOPIC_NODE[topic]})")


def on_message(client, userdata, msg):
    global last_threat_time
    try:
        _t0 = time.time()
        data = json.loads(msg.payload.decode())
        features = extract_features(data)
        features_scaled = scaler.transform([features])

        ml_prediction = model.predict(features_scaled)[0]
        probabilities = model.predict_proba(features_scaled)[0]
        confidence = max(probabilities) * 100

        final_prediction, was_refined = refine_prediction(ml_prediction, data)
        source_ip = data.get('source_ip', 'N/A')
        node = TOPIC_NODE.get(msg.topic, msg.topic)
        node_last_seen[node] = time.time()

        stats["total_events"] += 1

        event = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "prediction": final_prediction,
            "ml_raw": ml_prediction,
            "refined": was_refined,
            "confidence": round(confidence, 1),
            "pkts_per_sec": data.get('pkts_per_sec', 0),
            "syn_count": data.get('syn_count', 0),
            "unique_ports": data.get('unique_dst_ports', 0),
            "failed_logins": data.get('failed_logins', 0),
            "source_ip": source_ip,
            "node": node,
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": "none",
            "severity": None
        }

        if final_prediction != "Normal":
            stats["total_attacks"] += 1
            last_threat_time = time.time()
            event["severity"] = severity_level(final_prediction, confidence)
            if source_ip in WHITELIST:
                event["action"] = "whitelisted"
            elif confidence < CONFIDENCE_THRESHOLD * 100:
                event["action"] = "low_confidence"
            else:
                was_new_block = block_ip(source_ip, final_prediction, confidence)
                event["action"] = "blocked" if was_new_block else "already_blocked"
                if was_new_block:
                    _rt = (time.time() - _t0) * 1000
                    response_times.append(_rt)
                    if len(response_times) > 200:
                        response_times.pop(0)
                    event["response_ms"] = round(_rt, 1)
                    log_event(f"RESPONSE {source_ip} | {final_prediction} | "
                              f"detect->block {_rt:.1f} ms | node {node}")
                    send_telegram(
                        f"\U0001F6A8 IoT SOC ALERT\n"
                        f"Attack: {final_prediction}\n"
                        f"Severity: {event['severity']}\n"
                        f"Source IP: {source_ip}\n"
                        f"Detected by: {node}\n"
                        f"Confidence: {confidence:.1f}%\n"
                        f"Action: BLOCKED (auto-unblock in {BLOCK_DURATION_SEC}s)\n"
                        f"Time: {event['ts']}")

        save_event(event)
        attack_log.insert(0, event)
        if len(attack_log) > MAX_LOG:
            attack_log.pop()

        socketio.emit('new_event', event)
        socketio.emit('stats_update', stats)
        if final_prediction != "Normal":
            socketio.emit('analytics_update', get_analytics())

    except Exception as e:
        print(f"Error processing message: {e}")


def mqtt_thread():
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_BROKER, 1883, 60)
    client.loop_forever()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/ml-model')
def ml_model_page():
    return render_template('ml_model.html', metrics=MODEL_METRICS, features=FEATURE_IMPORTANCE)


@socketio.on('connect')
def handle_connect():
    socketio.emit('init_data', {
        "stats": stats,
        "nodes": get_node_status(),
        "log": attack_log[:20],
        "blocked": get_blocked_list(),
        "start_time": START_TIME,
        "last_threat_time": last_threat_time,
        "analytics": get_analytics(),
        "model": {"features": FEATURE_IMPORTANCE, "metrics": MODEL_METRICS, "confusion": CONFUSION}
    })


if __name__ == '__main__':
    init_db()
    load_from_db()
    load_blocked()
    print("Telegram alerts: " + ("ON" if telegram.get("token") else "OFF (no telegram.json)"))
    send_telegram("\u2705 IoT SOC online - monitoring Node A & Node B")
    socketio.start_background_task(mqtt_thread)
    socketio.start_background_task(auto_unblock_worker)
    socketio.start_background_task(node_watch_worker)
    socketio.start_background_task(analytics_worker)
    socketio.run(app, host='0.0.0.0', port=5000)
