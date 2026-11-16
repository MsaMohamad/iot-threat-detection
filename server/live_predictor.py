import paho.mqtt.client as mqtt
import joblib
import json
import subprocess
import threading
import time
from datetime import datetime

print("Loading model and scaler...")
model = joblib.load('models_output/model.pkl')
scaler = joblib.load('models_output/scaler.pkl')
print("Model loaded! Ready for live prediction + mitigation.\n")

MQTT_BROKER = "localhost"
MQTT_TOPIC = "iot/esp32_1/data"

# Thresholds for refinement rules
PORT_DIVERSITY_THRESHOLD = 5
HIGH_RATE_THRESHOLD = 30
FAILED_LOGIN_THRESHOLD = 2

# Thresholds for mitigation
CONFIDENCE_THRESHOLD = 0.85    # only block if confidence >= 85%
BLOCK_DURATION_SEC = 300       # auto-unblock after 5 minutes

# Whitelist - IPs that must NEVER be blocked
WHITELIST = {
    "192.168.0.1",      # Router
    "192.168.0.101",    # Server sendiri
    "0.0.0.0",          # Placeholder/no data
}

# Store currently blocked IPs: {ip: block_timestamp}
blocked_ips = {}
blocked_ips_lock = threading.Lock()

LOG_FILE = "mitigation.log"

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def block_ip(ip, attack_type, confidence):
    """Block an IP via iptables, log it, and track it for auto-unblock."""
    with blocked_ips_lock:
        if ip in blocked_ips:
            # Already blocked, just refresh the timestamp (attack still ongoing)
            blocked_ips[ip] = time.time()
            return False  # not a new block

        try:
            subprocess.run(
                ["sudo", "/usr/sbin/iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, text=True
            )
            blocked_ips[ip] = time.time()
            log_event(f"BLOCKED {ip} | Reason: {attack_type} (confidence {confidence:.1f}%)")
            return True
        except subprocess.CalledProcessError as e:
            log_event(f"FAILED to block {ip}: {e.stderr}")
            return False

def unblock_ip(ip):
    """Remove the iptables rule for a given IP."""
    try:
        subprocess.run(
            ["sudo", "/usr/sbin/iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True, text=True
        )
        log_event(f"UNBLOCKED {ip} | Reason: timeout expired ({BLOCK_DURATION_SEC}s)")
    except subprocess.CalledProcessError as e:
        log_event(f"FAILED to unblock {ip}: {e.stderr}")

def auto_unblock_worker():
    """Background thread - check every 10 seconds, unblock expired IPs."""
    while True:
        time.sleep(10)
        now = time.time()
        with blocked_ips_lock:
            expired = [ip for ip, ts in blocked_ips.items() if now - ts >= BLOCK_DURATION_SEC]
            for ip in expired:
                unblock_ip(ip)
                del blocked_ips[ip]

def extract_features(data):
    total_pkts = data.get('total_pkts', 0)
    total_bytes = data.get('total_bytes', 0)
    pkts_per_sec = data.get('pkts_per_sec', 0)
    bytes_per_sec = data.get('bytes_per_sec', 0)
    
    duration_sec = 3.0
    avg_pkt_size = total_bytes / (total_pkts + 1)
    fwd_bwd_byte_ratio = 1.0
    fwd_bwd_pkt_ratio = 1.0
    
    return [
        duration_sec, total_bytes, total_pkts, bytes_per_sec,
        pkts_per_sec, avg_pkt_size, fwd_bwd_byte_ratio, fwd_bwd_pkt_ratio
    ]

def refine_prediction(ml_prediction, data):
    failed_logins = data.get('failed_logins', 0)
    unique_ports = data.get('unique_dst_ports', 0)
    pkts_per_sec = data.get('pkts_per_sec', 0)
    
    if failed_logins >= FAILED_LOGIN_THRESHOLD:
        return "Brute Force", True
    
    if ml_prediction == "Port Scan":
        if unique_ports <= PORT_DIVERSITY_THRESHOLD and pkts_per_sec > HIGH_RATE_THRESHOLD:
            return "DDoS", True
    
    return ml_prediction, False

def on_connect(client, userdata, flags, rc, properties=None):
    print(f"Connected to MQTT Broker (rc={rc})")
    client.subscribe(MQTT_TOPIC)
    print(f"Subscribed to topic: {MQTT_TOPIC}")
    print("=" * 100)
    print("WAITING FOR DATA... (run an attack from the laptop to test)")
    print("=" * 100)

def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        
        features = extract_features(data)
        features_scaled = scaler.transform([features])
        
        ml_prediction = model.predict(features_scaled)[0]
        probabilities = model.predict_proba(features_scaled)[0]
        confidence = max(probabilities) * 100
        
        final_prediction, was_refined = refine_prediction(ml_prediction, data)
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        symbol = "OK" if final_prediction == "Normal" else "ALERT"
        refine_tag = " [REFINED]" if was_refined else ""
        source_ip = data.get('source_ip', 'N/A')
        
        print(f"[{timestamp}] {symbol} Final: {final_prediction:12s}{refine_tag:10s} | "
              f"ML raw: {ml_prediction:12s} | Conf: {confidence:5.1f}% | "
              f"pkts/s: {data.get('pkts_per_sec', 0):8.2f} | "
              f"syn: {data.get('syn_count', 0):4d} | "
              f"ports: {data.get('unique_dst_ports', 0):4d} | "
              f"failed_login: {data.get('failed_logins', 0):3d} | "
              f"src_ip: {source_ip}")
        
        if final_prediction != "Normal":
            print(f"           >>> ALERT! Possible {final_prediction} attack from {source_ip}! <<<")
            
            # ===== MITIGATION LOGIC =====
            if source_ip in WHITELIST:
                print(f"           >>> Source {source_ip} is WHITELISTED - no action taken. <<<")
            elif confidence < CONFIDENCE_THRESHOLD * 100:
                print(f"           >>> Confidence below threshold ({CONFIDENCE_THRESHOLD*100:.0f}%) - no action taken. <<<")
            else:
                was_new_block = block_ip(source_ip, final_prediction, confidence)
                if was_new_block:
                    print(f"           >>> MITIGATION: {source_ip} BLOCKED for {BLOCK_DURATION_SEC}s! <<<")
        
    except Exception as e:
        print(f"Error processing message: {e}")

# Start background thread for auto-unblock
unblock_thread = threading.Thread(target=auto_unblock_worker, daemon=True)
unblock_thread.start()

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message

client.connect(MQTT_BROKER, 1883, 60)
client.loop_forever()
