#!/usr/bin/env python3
"""
IoT SOC Dashboard upgrade v2
- Dual node (Node A: iot/esp32_1/data, Node B: iot/esp32_2/data) + NODE column + node online/offline pills
- Smooth 1-second unblock countdown
- Persistent event log in SQLite (events.db) - stats & log survive restart, /export.csv for Chapter 4
- Telegram alert on every new block (optional, via telegram.json)
- sklearn UserWarning silenced

Run from ~/fyp/dashboard:   python3 upgrade_dashboard.py
Backups: app.py.bak_v1, templates/index.html.bak_v1
"""
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "app.py")
HTML = os.path.join(HERE, "templates", "index.html")
MARK = "# ===== v2: dual node + persistent log + telegram ====="

# ---------------------------------------------------------------- app.py
APP_HEADER = '''eventlet.monkey_patch()

import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import os as _os
import sqlite3
import urllib.request
import urllib.parse
'''

APP_HELPERS = MARK + '''
TOPIC_NODE = {"iot/esp32_1/data": "Node A", "iot/esp32_2/data": "Node B"}
NODE_TIMEOUT_SEC = 15
node_last_seen = {name: 0 for name in TOPIC_NODE.values()}

_BASE_DIR = _os.path.dirname(_os.path.abspath(__file__))
DB_PATH = _os.path.join(_BASE_DIR, "events.db")
db_lock = threading.RLock()
db_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
EVENT_COLS = ["ts", "time", "node", "prediction", "ml_raw", "refined", "confidence",
              "pkts_per_sec", "syn_count", "unique_ports", "failed_logins", "source_ip", "action"]


def init_db():
    with db_lock:
        db_conn.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, time TEXT, node TEXT, prediction TEXT, ml_raw TEXT, refined INTEGER,
            confidence REAL, pkts_per_sec REAL, syn_count INTEGER, unique_ports INTEGER,
            failed_logins INTEGER, source_ip TEXT, action TEXT)""")
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


def block_ip('''

APP_PATCHES = [
    # (label, old, new)
    ("imports", "eventlet.monkey_patch()\n", APP_HEADER),
    ("helpers", "def block_ip(", APP_HELPERS),
    ("subscribe both topics",
     "    client.subscribe(MQTT_TOPIC)",
     "    for topic in TOPIC_NODE:\n"
     "        client.subscribe(topic)\n"
     "        print(f\"Subscribed: {topic} ({TOPIC_NODE[topic]})\")"),
    ("node detect",
     "        source_ip = data.get('source_ip', 'N/A')\n",
     "        source_ip = data.get('source_ip', 'N/A')\n"
     "        node = TOPIC_NODE.get(msg.topic, msg.topic)\n"
     "        node_last_seen[node] = time.time()\n"),
    ("event fields",
     "            \"source_ip\": source_ip,\n",
     "            \"source_ip\": source_ip,\n"
     "            \"node\": node,\n"
     "            \"ts\": datetime.now().strftime(\"%Y-%m-%d %H:%M:%S\"),\n"),
    ("telegram on block",
     "                event[\"action\"] = \"blocked\" if was_new_block else \"already_blocked\"\n",
     "                event[\"action\"] = \"blocked\" if was_new_block else \"already_blocked\"\n"
     "                if was_new_block:\n"
     "                    send_telegram(\n"
     "                        f\"\\U0001F6A8 IoT SOC ALERT\\n\"\n"
     "                        f\"Attack: {final_prediction}\\n\"\n"
     "                        f\"Source IP: {source_ip}\\n\"\n"
     "                        f\"Detected by: {node}\\n\"\n"
     "                        f\"Confidence: {confidence:.1f}%\\n\"\n"
     "                        f\"Action: BLOCKED (auto-unblock in {BLOCK_DURATION_SEC}s)\\n\"\n"
     "                        f\"Time: {event['ts']}\")\n"),
    ("save to db",
     "        attack_log.insert(0, event)\n",
     "        save_event(event)\n"
     "        attack_log.insert(0, event)\n"),
    ("init_data nodes",
     "    socketio.emit('init_data', {\n        \"stats\": stats,\n",
     "    socketio.emit('init_data', {\n        \"stats\": stats,\n        \"nodes\": get_node_status(),\n"),
    ("startup",
     "    socketio.start_background_task(mqtt_thread)\n",
     "    init_db()\n"
     "    load_from_db()\n"
     "    print(\"Telegram alerts: \" + (\"ON\" if telegram.get(\"token\") else \"OFF (no telegram.json)\"))\n"
     "    send_telegram(\"\\u2705 IoT SOC online - monitoring Node A & Node B\")\n"
     "    socketio.start_background_task(mqtt_thread)\n"),
    ("node watcher",
     "    socketio.start_background_task(auto_unblock_worker)\n",
     "    socketio.start_background_task(auto_unblock_worker)\n"
     "    socketio.start_background_task(node_watch_worker)\n"),
]

# ---------------------------------------------------------------- index.html
HTML_JS = r"""socket.on('blocked_update', renderBlocked);

// ===== v2 additions =====
setInterval(() => {
  document.querySelectorAll('.unblock-cd').forEach(el => {
    el.textContent = Math.max(0, Math.round((+el.dataset.until - Date.now()) / 1000));
  });
}, 1000);

(function addNodeHeader() {
  document.querySelectorAll('th').forEach(th => {
    if (/source\s*ip/i.test(th.textContent) && !th.dataset.nodeAdded) {
      const n = th.cloneNode(true);
      n.textContent = 'Node';
      th.parentNode.insertBefore(n, th);
      th.dataset.nodeAdded = '1';
    }
  });
})();

function findStatusItem() {
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let t;
  while ((t = walker.nextNode())) {
    const p = t.parentElement;
    if (!p || p.closest('script,style')) continue;
    if (/FIREWALL/i.test(t.textContent)) {
      let el = p;
      while (el.parentElement && !/MQTT/i.test(el.parentElement.textContent)) el = el.parentElement;
      return el;
    }
  }
  return null;
}

function renderNodes(nodes) {
  let box = document.getElementById('nodeStatus');
  if (!box) {
    const host = findStatusItem();
    if (!host) return;
    box = document.createElement('div');
    box.id = 'nodeStatus';
    box.style.cssText = 'display:inline-flex;gap:20px;align-items:center;';
    host.insertAdjacentElement('afterend', box);
  }
  box.innerHTML = Object.entries(nodes).map(([name, on]) => {
    const c = on ? '#22c55e' : '#ef4444';
    return `<span style="display:inline-flex;align-items:center;gap:6px;font-family:'JetBrains Mono',monospace;font-size:13px;">` +
      `<span style="width:7px;height:7px;border-radius:50%;background:${c}"></span>` +
      `${name.toUpperCase()}: <span style="color:${c}">${on ? 'ONLINE' : 'OFFLINE'}</span></span>`;
  }).join('');
}

socket.on('node_status', renderNodes);
socket.on('init_data', (d) => { if (d.nodes) renderNodes(d.nodes); });"""

HTML_PATCHES = [
    ("log row node column",
     '    <td class="py-1.5">${ev.source_ip}</td>',
     '    <td class="py-1.5 text-dim">${ev.node || \'-\'}</td>\n    <td class="py-1.5">${ev.source_ip}</td>'),
    ("smooth countdown",
     "Unblocks in ${b.remaining_sec}s</div>",
     'Unblocks in <span class="unblock-cd" data-until="${Date.now() + b.remaining_sec * 1000}">${b.remaining_sec}</span>s</div>'),
    ("v2 scripts", "socket.on('blocked_update', renderBlocked);", HTML_JS),
]
HTML_OPTIONAL = [
    ("hero shows node",
     "sub.textContent = `Source ${ev.source_ip}",
     "sub.textContent = `${ev.node ? ev.node + ' · ' : ''}Source ${ev.source_ip}"),
]


def apply(path, patches, optional=()):
    with open(path, encoding="utf-8") as f:
        src = f.read()
    missing = [label for label, old, _ in patches if src.count(old) != 1]
    if missing:
        print(f"[STOP] {os.path.basename(path)}: not found (or found more than once): {missing}")
        print("       No file changed. Send a screenshot of this error.")
        sys.exit(1)
    for label, old, new in patches:
        src = src.replace(old, new, 1)
        print(f"  [OK] {label}")
    for label, old, new in optional:
        if src.count(old) == 1:
            src = src.replace(old, new, 1)
            print(f"  [OK] {label}")
        else:
            print(f"  [SKIP] {label} (not critical)")
    return src


def main():
    for p in (APP, HTML):
        if not os.path.exists(p):
            print(f"[STOP] {p} not found - run this script inside ~/fyp/dashboard")
            sys.exit(1)
    with open(APP, encoding="utf-8") as f:
        if MARK in f.read():
            print("[INFO] Upgrade v2 already applied. No changes.")
            return

    print("Patching app.py ...")
    new_app = apply(APP, APP_PATCHES)
    print("Patching templates/index.html ...")
    new_html = apply(HTML, HTML_PATCHES, HTML_OPTIONAL)

    compile(new_app, "app.py", "exec")  # syntax check before writing

    shutil.copy2(APP, APP + ".bak_v1")
    shutil.copy2(HTML, HTML + ".bak_v1")
    with open(APP, "w", encoding="utf-8") as f:
        f.write(new_app)
    with open(HTML, "w", encoding="utf-8") as f:
        f.write(new_html)
    print("\nSIAP. Backup: app.py.bak_v1, templates/index.html.bak_v1")
    print("Start balik: python3 app.py")


if __name__ == "__main__":
    main()
