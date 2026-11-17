"""
Generate the real confusion matrix from the test set for the dashboard (Intelligence page).
Run from ~/fyp :   python3 make_confusion.py
Output: dashboard/confusion.json  (app.py reads it on start -> restart app.py after running)

Uses the SAME split as train_model.py (random_state=42, stratified 80/20),
so the matrix is genuinely from the real test set, not fabricated.
"""
import json
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score

FEATURES = ['duration_sec', 'total_bytes', 'total_pkts', 'bytes_per_sec',
            'pkts_per_sec', 'avg_pkt_size']

print("Loading dataset + model...")
df = pd.read_csv('datasets/combined_dataset.csv')
X, y = df[FEATURES], df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42)

model = joblib.load('models_output/model.pkl')
scaler = joblib.load('models_output/scaler.pkl')

y_pred = model.predict(scaler.transform(X_test))
labels = sorted(y_test.unique())
cm = confusion_matrix(y_test, y_pred, labels=labels).tolist()
acc = round(accuracy_score(y_test, y_pred) * 100, 2)

out = {"labels": list(labels), "matrix": cm, "accuracy": acc,
       "test_samples": int(len(y_test))}
with open('dashboard/confusion.json', 'w') as f:
    json.dump(out, f, indent=2)

print(f"\nAccuracy on test set: {acc}%  ({len(y_test)} samples)")
print("\nConfusion matrix (rows=actual, cols=predicted):")
print(pd.DataFrame(cm, index=labels, columns=labels))
print("\nClassification report:")
print(classification_report(y_test, y_pred))
print("Saved -> dashboard/confusion.json")
print("Restart app.py to load the matrix into the dashboard.")
