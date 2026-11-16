#!/usr/bin/env python3
# ============================================================================
#  test_report.py  -  Automated Detection-Rate & False-Positive/Negative Report
#  FYP: Automated IoT Network Threat Detection & Mitigation (Decision Tree)
#  Aiman - UniKL BMI
#
#  What this script does:
#    (A) DETECTION-ENGINE VALIDATION - feeds LABELLED payloads (ground truth)
#        through the SAME pipeline the live server uses: extract_features ->
#        scaler -> model.predict -> refine_prediction -> severity_level.
#        It IMPORTS the real functions from app.py (no duplication), so the
#        results match exactly what the server produces live. Output: confusion
#        matrix, detection rate, false positives, false negatives, per class.
#    (B) LIVE-DATA SUMMARY - reads events.db (real recorded attacks) and reports
#        the prediction distribution, refinement rate, and response time.
#
#  How to run (on the server, inside the dashboard folder):
#     cd ~/fyp/dashboard
#     source ~/fyp/venv/bin/activate
#     python3 test_report.py
#  Output: printed to screen + saved to test_report_output.md and
#          test_report_cases.csv
# ============================================================================

import os, sys, csv, sqlite3
from datetime import datetime

# --- make sure importing app.py can find the model (relative '../models_output/...') ---
HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)

print("Loading the real detection pipeline from app.py ...")
import app  # noqa: E402  (this loads model+scaler; it does NOT start the server/MQTT)

model             = app.model
scaler            = app.scaler
extract_features  = app.extract_features
refine_prediction = app.refine_prediction
severity_level    = getattr(app, "severity_level", None)
FEATURE_COLS      = app.FEATURE_COLS

CLASSES = ["Normal", "Port Scan", "DDoS", "Brute Force"]

# ----------------------------------------------------------------------------
#  LABELLED TEST CASES  (ground truth)
#  Each case is a typical signature of a traffic type as the ESP32 would send.
#  Includes BOUNDARY cases the supervisor was concerned about:
#    - normal traffic must NOT become a false positive
#    - a slow scan must NOT become a false negative
# ----------------------------------------------------------------------------
TEST_CASES = [
    # ---- NORMAL (must NOT be flagged as an attack) ----
    {"name": "normal_web_browse", "label": "Normal",
     "data": {"total_pkts": 40, "total_bytes": 52000, "pkts_per_sec": 13,
              "bytes_per_sec": 17000, "unique_dst_ports": 2, "failed_logins": 0,
              "unique_ports_60s": 4, "syn_count": 2, "source_ip": "192.168.0.50"}},
    {"name": "normal_ping", "label": "Normal",
     "data": {"total_pkts": 8, "total_bytes": 640, "pkts_per_sec": 2,
              "bytes_per_sec": 160, "unique_dst_ports": 1, "failed_logins": 0,
              "unique_ports_60s": 1, "syn_count": 0, "source_ip": "192.168.0.51"}},
    {"name": "normal_email_boundary", "label": "Normal",
     "data": {"total_pkts": 25, "total_bytes": 30000, "pkts_per_sec": 8,
              "bytes_per_sec": 10000, "unique_dst_ports": 3, "failed_logins": 0,
              "unique_ports_60s": 5, "syn_count": 3, "source_ip": "192.168.0.52"}},
    {"name": "normal_video_stream", "label": "Normal",
     "data": {"total_pkts": 90, "total_bytes": 130000, "pkts_per_sec": 28,
              "bytes_per_sec": 43000, "unique_dst_ports": 2, "failed_logins": 0,
              "unique_ports_60s": 3, "syn_count": 1, "source_ip": "192.168.0.53"}},

    # ---- PORT SCAN, fast (nmap -sS -p 1-1000) ----
    {"name": "portscan_fast_full", "label": "Port Scan",
     "data": {"total_pkts": 1000, "total_bytes": 60000, "pkts_per_sec": 300,
              "bytes_per_sec": 18000, "unique_dst_ports": 1000, "failed_logins": 0,
              "unique_ports_60s": 1000, "syn_count": 1000, "source_ip": "192.168.0.60"}},
    {"name": "portscan_medium", "label": "Port Scan",
     "data": {"total_pkts": 400, "total_bytes": 24000, "pkts_per_sec": 60,
              "bytes_per_sec": 7000, "unique_dst_ports": 120, "failed_logins": 0,
              "unique_ports_60s": 300, "syn_count": 120, "source_ip": "192.168.0.61"}},

    # ---- SLOW PORT SCAN (the false-negative case we handle) ----
    {"name": "portscan_slow", "label": "Port Scan",
     "data": {"total_pkts": 15, "total_bytes": 900, "pkts_per_sec": 5,
              "bytes_per_sec": 300, "unique_dst_ports": 4, "failed_logins": 0,
              "unique_ports_60s": 22, "syn_count": 4, "source_ip": "192.168.0.62"}},
    {"name": "portscan_slow_boundary", "label": "Port Scan",
     "data": {"total_pkts": 12, "total_bytes": 720, "pkts_per_sec": 4,
              "bytes_per_sec": 240, "unique_dst_ports": 3, "failed_logins": 0,
              "unique_ports_60s": 15, "syn_count": 3, "source_ip": "192.168.0.63"}},

    # ---- DDoS (hping3 --flood) ----
    {"name": "ddos_flood", "label": "DDoS",
     "data": {"total_pkts": 15000, "total_bytes": 900000, "pkts_per_sec": 5000,
              "bytes_per_sec": 300000, "unique_dst_ports": 1, "failed_logins": 0,
              "unique_ports_60s": 1, "syn_count": 15000, "source_ip": "192.168.0.70"}},
    {"name": "ddos_syn_flood", "label": "DDoS",
     "data": {"total_pkts": 6000, "total_bytes": 240000, "pkts_per_sec": 2000,
              "bytes_per_sec": 96000, "unique_dst_ports": 1, "failed_logins": 0,
              "unique_ports_60s": 1, "syn_count": 6000, "source_ip": "192.168.0.71"}},

    # ---- BRUTE FORCE (hydra - failed logins) ----
    {"name": "bruteforce_heavy", "label": "Brute Force",
     "data": {"total_pkts": 120, "total_bytes": 14000, "pkts_per_sec": 40,
              "bytes_per_sec": 4600, "unique_dst_ports": 1, "failed_logins": 8,
              "unique_ports_60s": 1, "syn_count": 40, "source_ip": "192.168.0.80"}},
    {"name": "bruteforce_boundary", "label": "Brute Force",
     "data": {"total_pkts": 30, "total_bytes": 3500, "pkts_per_sec": 10,
              "bytes_per_sec": 1200, "unique_dst_ports": 1, "failed_logins": 2,
              "unique_ports_60s": 1, "syn_count": 10, "source_ip": "192.168.0.81"}},
]


def run_case(data):
    """Run one payload through the REAL server pipeline."""
    feats = extract_features(data)
    feats_scaled = scaler.transform([feats])
    ml_raw = str(model.predict(feats_scaled)[0])
    proba = model.predict_proba(feats_scaled)[0]
    conf = round(float(max(proba)) * 100, 1)
    final, refined = refine_prediction(ml_raw, data)
    sev = None
    if severity_level and final != "Normal":
        try:
            sev = severity_level(final, conf)
        except Exception:
            sev = None
    return ml_raw, final, bool(refined), conf, sev


def section_a():
    print("\n" + "=" * 70)
    print(" SECTION A : DETECTION-ENGINE VALIDATION (labelled ground-truth payloads)")
    print("=" * 70)

    rows = []
    # confusion[truth][pred]
    conf_mat = {t: {p: 0 for p in CLASSES} for t in CLASSES}
    correct = 0
    false_pos = []   # Normal -> flagged as an attack
    false_neg = []   # Attack -> missed (classified as Normal)
    miscls = []      # Attack -> wrong attack type

    for c in TEST_CASES:
        ml_raw, final, refined, conf, sev = run_case(c["data"])
        truth = c["label"]
        ok = (final == truth)
        if ok:
            correct += 1
        if truth in conf_mat and final in conf_mat[truth]:
            conf_mat[truth][final] += 1
        if truth == "Normal" and final != "Normal":
            false_pos.append(c["name"])
        if truth != "Normal" and final == "Normal":
            false_neg.append(c["name"])
        if truth != "Normal" and final != "Normal" and final != truth:
            miscls.append((c["name"], truth, final))

        rows.append({
            "case": c["name"], "ground_truth": truth, "ml_raw": ml_raw,
            "final": final, "refined": "yes" if refined else "no",
            "confidence": conf, "severity": sev or "-",
            "result": "OK" if ok else "MISS"
        })
        flag = "  OK " if ok else " MISS"
        print(f" [{flag}] {c['name']:<24} truth={truth:<12} ml={ml_raw:<12} "
              f"-> final={final:<12} {'(refined)' if refined else ''}")

    total = len(TEST_CASES)
    n_norm = sum(1 for c in TEST_CASES if c["label"] == "Normal")
    n_atk = total - n_norm
    detected_atk = n_atk - len(false_neg)

    print("\n  Confusion Matrix (rows = actual, columns = predicted):")
    header = "            " + "".join(f"{p[:9]:>11}" for p in CLASSES)
    print(header)
    for t in CLASSES:
        line = f"  {t:<10}" + "".join(f"{conf_mat[t][p]:>11}" for p in CLASSES)
        print(line)

    acc = round(correct / total * 100, 1)
    det_rate = round(detected_atk / n_atk * 100, 1) if n_atk else 0.0
    fpr = round(len(false_pos) / n_norm * 100, 1) if n_norm else 0.0
    fnr = round(len(false_neg) / n_atk * 100, 1) if n_atk else 0.0

    print("\n  SUMMARY:")
    print(f"    Total test cases          : {total}  ({n_atk} attack, {n_norm} normal)")
    print(f"    Correct (final==truth)    : {correct}/{total}  = {acc}%")
    print(f"    Attack detection rate     : {detected_atk}/{n_atk} = {det_rate}%")
    print(f"    False POSITIVE (normal flagged as attack) : {len(false_pos)}/{n_norm} = {fpr}%")
    if false_pos:
        print(f"        -> {', '.join(false_pos)}")
    print(f"    False NEGATIVE (attack missed)            : {len(false_neg)}/{n_atk} = {fnr}%")
    if false_neg:
        print(f"        -> {', '.join(false_neg)}")
    if miscls:
        print("    Mis-class (attack detected but wrong type):")
        for nm, t, f in miscls:
            print(f"        -> {nm}: {t} classified as {f}")

    return {
        "rows": rows, "conf_mat": conf_mat, "classes": CLASSES,
        "total": total, "correct": correct, "acc": acc,
        "n_atk": n_atk, "n_norm": n_norm, "detected_atk": detected_atk,
        "det_rate": det_rate, "false_pos": false_pos, "false_neg": false_neg,
        "fpr": fpr, "fnr": fnr, "miscls": miscls,
    }


def section_b(db_path="events.db"):
    print("\n" + "=" * 70)
    print(" SECTION B : LIVE-DATA SUMMARY (events.db - real recorded attacks)")
    print("=" * 70)
    if not os.path.exists(db_path):
        print(f"  (events.db not found at {os.path.abspath(db_path)} - skipped. "
              f"Run the server and generate attacks first to collect data.)")
        return None
    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cols = [r[1] for r in cur.execute("PRAGMA table_info(events)").fetchall()]
        total = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        print(f"  Total event records : {total}")
        if total == 0:
            con.close()
            return {"total": 0}

        print("\n  Distribution by prediction:")
        dist = {}
        for pred, n in cur.execute(
                "SELECT prediction, COUNT(*) FROM events GROUP BY prediction ORDER BY 2 DESC"):
            dist[pred] = n
            print(f"    {str(pred):<14} : {n}")

        extra = {"total": total, "dist": dist}

        if "refined" in cols:
            rf = cur.execute("SELECT COUNT(*) FROM events WHERE refined=1").fetchone()[0]
            print(f"\n  Records refined by a rule : {rf} "
                  f"({round(rf/total*100,1)}%)")
            extra["refined"] = rf
        if "response_ms" in cols:
            row = cur.execute(
                "SELECT AVG(response_ms), MIN(response_ms), MAX(response_ms) "
                "FROM events WHERE response_ms IS NOT NULL").fetchone()
            if row and row[0] is not None:
                print(f"  Response time (ms)  : avg={row[0]:.1f}  "
                      f"min={row[1]:.0f}  max={row[2]:.0f}")
                extra["resp_avg"] = round(row[0], 1)
                extra["resp_min"] = row[1]
                extra["resp_max"] = row[2]
        if "action" in cols:
            blocked = cur.execute(
                "SELECT COUNT(*) FROM events WHERE action LIKE '%block%'").fetchone()[0]
            print(f"  Records with a block action : {blocked}")
            extra["blocked"] = blocked
        con.close()
        return extra
    except Exception as e:
        print(f"  (Error reading events.db: {e})")
        return None


def write_report(a, b):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    md = []
    md.append(f"# IoT Threat Detection System - Test Report\n")
    md.append(f"**Generated:** {ts}  ")
    md.append(f"**Model:** Decision Tree (8 features) - pipeline imported directly from `app.py`\n")

    md.append("## Section A - Detection-Engine Validation (labelled ground truth)\n")
    md.append(f"- Total test cases: **{a['total']}** ({a['n_atk']} attack, {a['n_norm']} normal)")
    md.append(f"- Overall accuracy: **{a['correct']}/{a['total']} = {a['acc']}%**")
    md.append(f"- Attack detection rate: **{a['detected_atk']}/{a['n_atk']} = {a['det_rate']}%**")
    md.append(f"- False Positive (normal -> attack): **{len(a['false_pos'])}/{a['n_norm']} = {a['fpr']}%**"
              + (f" ({', '.join(a['false_pos'])})" if a['false_pos'] else ""))
    md.append(f"- False Negative (attack -> missed): **{len(a['false_neg'])}/{a['n_atk']} = {a['fnr']}%**"
              + (f" ({', '.join(a['false_neg'])})" if a['false_neg'] else ""))
    md.append("")

    md.append("### Confusion Matrix\n")
    md.append("| Actual \\ Predicted | " + " | ".join(a["classes"]) + " |")
    md.append("|" + "---|" * (len(a["classes"]) + 1))
    for t in a["classes"]:
        md.append("| **" + t + "** | " +
                  " | ".join(str(a["conf_mat"][t][p]) for p in a["classes"]) + " |")
    md.append("")

    md.append("### Per-Case Detail\n")
    md.append("| Case | Ground Truth | ML Raw | Final Verdict | Refined | Confidence % | Severity | Status |")
    md.append("|---|---|---|---|---|---|---|---|")
    for r in a["rows"]:
        md.append(f"| {r['case']} | {r['ground_truth']} | {r['ml_raw']} | {r['final']} | "
                  f"{r['refined']} | {r['confidence']} | {r['severity']} | {r['result']} |")
    md.append("")

    if b and b.get("total"):
        md.append("## Section B - Live Data (events.db)\n")
        md.append(f"- Total records: **{b['total']}**")
        if b.get("dist"):
            md.append("\n| Prediction | Count |")
            md.append("|---|---|")
            for k, v in b["dist"].items():
                md.append(f"| {k} | {v} |")
        if "refined" in b:
            md.append(f"\n- Records refined by a rule: **{b['refined']}**")
        if "resp_avg" in b:
            md.append(f"- Response time: avg **{b['resp_avg']} ms** "
                      f"(min {b['resp_min']:.0f} / max {b['resp_max']:.0f})")
        if "blocked" in b:
            md.append(f"- Records with a block action: **{b['blocked']}**")
        md.append("")

    out_md = os.path.join(HERE, "test_report_output.md")
    with open(out_md, "w") as f:
        f.write("\n".join(md))

    out_csv = os.path.join(HERE, "test_report_cases.csv")
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(a["rows"][0].keys()))
        w.writeheader()
        w.writerows(a["rows"])

    print("\n" + "=" * 70)
    print(f"  Report saved:")
    print(f"    {out_md}")
    print(f"    {out_csv}")
    print("=" * 70)


if __name__ == "__main__":
    a = section_a()
    b = section_b()
    write_report(a, b)
    # exit code: 0 if no FN and no FP, 1 otherwise (handy for a quick CI check)
    sys.exit(0 if (not a["false_neg"] and not a["false_pos"]) else 1)
