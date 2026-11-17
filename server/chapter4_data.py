"""
Chapter 4 data pack generator - collect ALL thesis data in a single run.
Run from ~/fyp :   source venv/bin/activate && python3 chapter4_data.py

Output (folder chapter4_output/):
  report.txt              - summary of all tables (copy straight into the thesis)
  dataset_composition.csv - sampel per kelas + train/test
  model_metrics.csv       - precision/recall/f1 per kelas
  confusion_matrix.csv    - confusion matrix (actual vs predicted)
  feature_importance.csv  - importance setiap feature
  live_events_summary.csv - statistics from events.db (the real system)
"""
import os, csv, json, sqlite3
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (confusion_matrix, classification_report,
                             accuracy_score, precision_recall_fscore_support)
import joblib

OUT = "chapter4_output"
os.makedirs(OUT, exist_ok=True)
FEATURES = ['duration_sec', 'total_bytes', 'total_pkts', 'bytes_per_sec',
            'pkts_per_sec', 'avg_pkt_size']
lines = []
def p(s=""):
    print(s); lines.append(str(s))

p("="*64); p("  CHAPTER 4 DATA PACK  -  IoT SOC FYP"); p("="*64)

# ---------- A. OFFLINE MODEL EVALUATION ----------
df = pd.read_csv('datasets/combined_dataset.csv')
X, y = df[FEATURES], df['label']
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
model = joblib.load('models_output/model.pkl')
scaler = joblib.load('models_output/scaler.pkl')
y_pred = model.predict(scaler.transform(X_te))
labels = sorted(y.unique())

p("\n--- TABLE 4.1: Dataset Composition ---")
p(f"{'Class':<14}{'Total':>10}{'Train':>10}{'Test':>10}")
with open(f"{OUT}/dataset_composition.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(["Class","Total","Train","Test"])
    for c in labels:
        tot=int((y==c).sum()); tr=int((y_tr==c).sum()); te=int((y_te==c).sum())
        p(f"{c:<14}{tot:>10}{tr:>10}{te:>10}"); w.writerow([c,tot,tr,te])
    p(f"{'TOTAL':<14}{len(y):>10}{len(y_tr):>10}{len(y_te):>10}")
    w.writerow(["TOTAL",len(y),len(y_tr),len(y_te)])

acc = accuracy_score(y_te, y_pred)
p(f"\n--- TABLE 4.2: Model Performance (test set) ---")
p(f"Overall accuracy: {acc*100:.2f}%")
pr,rc,f1,sup = precision_recall_fscore_support(y_te,y_pred,labels=labels,zero_division=0)
p(f"{'Class':<14}{'Precision':>11}{'Recall':>9}{'F1':>8}{'Support':>9}")
with open(f"{OUT}/model_metrics.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(["Class","Precision","Recall","F1","Support"])
    for i,c in enumerate(labels):
        p(f"{c:<14}{pr[i]*100:>10.1f}%{rc[i]*100:>8.1f}%{f1[i]*100:>7.1f}%{sup[i]:>9}")
        w.writerow([c,round(pr[i]*100,1),round(rc[i]*100,1),round(f1[i]*100,1),sup[i]])

p(f"\n--- TABLE 4.3: Confusion Matrix (rows=actual, cols=predicted) ---")
cm = confusion_matrix(y_te,y_pred,labels=labels)
hdr="actual\\pred".ljust(14)+"".join(f"{c[:10]:>12}" for c in labels)
p(hdr)
with open(f"{OUT}/confusion_matrix.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(["actual\\pred"]+labels)
    for i,c in enumerate(labels):
        p(f"{c:<14}"+"".join(f"{int(v):>12}" for v in cm[i]))
        w.writerow([c]+[int(v) for v in cm[i]])
# save confusion.json for dashboard too
json.dump({"labels":list(labels),"matrix":cm.tolist(),"accuracy":round(acc*100,2),
           "test_samples":int(len(y_te))}, open("dashboard/confusion.json","w"), indent=2)

p(f"\n--- TABLE 4.4: Feature Importance ---")
imp = sorted(zip(FEATURES, model.feature_importances_), key=lambda x:-x[1])
with open(f"{OUT}/feature_importance.csv","w",newline="") as f:
    w=csv.writer(f); w.writerow(["Feature","Importance(%)"])
    for name,v in imp:
        p(f"{name:<22}{v*100:>7.2f}%"); w.writerow([name,round(v*100,2)])

# ---------- B. LIVE SYSTEM DATA (events.db) ----------
p(f"\n--- TABLE 4.5: Live System Results (events.db) ---")
try:
    con = sqlite3.connect("dashboard/events.db")
    cur = con.cursor()
    total = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    p(f"Total events processed (live): {total}")
    p(f"\nPer-class detections:")
    with open(f"{OUT}/live_events_summary.csv","w",newline="") as f:
        w=csv.writer(f); w.writerow(["Metric","Value"]); w.writerow(["total_events",total])
        for cls,n in cur.execute("SELECT prediction,COUNT(*) FROM events GROUP BY prediction ORDER BY COUNT(*) DESC"):
            p(f"  {cls:<14}{n:>8}"); w.writerow([f"class_{cls}",n])
        p(f"\nPer-node:")
        for node,n,atk in cur.execute("SELECT node,COUNT(*),SUM(CASE WHEN prediction!='Normal' THEN 1 ELSE 0 END) FROM events WHERE node IS NOT NULL GROUP BY node"):
            p(f"  {node:<10} events={n}  threats={atk or 0}"); w.writerow([f"{node}_events",n]); w.writerow([f"{node}_threats",atk or 0])
        blocked=cur.execute("SELECT COUNT(*) FROM events WHERE action='blocked'").fetchone()[0]
        refined=cur.execute("SELECT COUNT(*) FROM events WHERE refined=1").fetchone()[0]
        avgc=cur.execute("SELECT AVG(confidence) FROM events WHERE prediction!='Normal'").fetchone()[0] or 0
        peak=cur.execute("SELECT MAX(pkts_per_sec) FROM events").fetchone()[0] or 0
        p(f"\nIPs blocked (new rules): {blocked}")
        p(f"Refined by rules [R]: {refined}")
        p(f"Avg attack confidence: {avgc:.1f}%")
        p(f"Peak packets/sec: {peak:.1f}")
        for k,v in [("blocked",blocked),("refined",refined),("avg_attack_confidence",round(avgc,1)),("peak_pps",round(peak,1))]:
            w.writerow([k,v])
        # --- Mitigation latency (detect -> block) ---
        rt=cur.execute("SELECT response_ms FROM events WHERE response_ms IS NOT NULL").fetchall()
        rt=[r[0] for r in rt if r[0] is not None]
        p("\n--- TABLE 4.6: Mitigation Latency (detect -> block) ---")
        if rt:
            p(f"Samples: {len(rt)}")
            p(f"Average: {sum(rt)/len(rt):.1f} ms")
            p(f"Min: {min(rt):.1f} ms   Max: {max(rt):.1f} ms")
            srt=sorted(rt); med=srt[len(srt)//2]
            p(f"Median: {med:.1f} ms")
            for k,v in [("latency_samples",len(rt)),("latency_avg_ms",round(sum(rt)/len(rt),1)),
                        ("latency_min_ms",round(min(rt),1)),("latency_max_ms",round(max(rt),1)),
                        ("latency_median_ms",round(med,1))]:
                w.writerow([k,v])
        else:
            p("No latency data yet - run an attack test first (response_ms is recorded on block).")
    con.close()
except Exception as e:
    p(f"[events.db] {e} - run from ~/fyp and make sure dashboard/events.db exists")

open(f"{OUT}/report.txt","w").write("\n".join(lines))
p("\n"+"="*64)
p(f"DONE. All tables + CSV in folder: {OUT}/")
p("Confusion matrix also saved to dashboard/confusion.json (restart app.py to show it on the dashboard)")
