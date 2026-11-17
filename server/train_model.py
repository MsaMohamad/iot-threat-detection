import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from imblearn.over_sampling import SMOTE
import joblib

print("Loading combined dataset...")
df = pd.read_csv('datasets/combined_dataset.csv')

# Feature columns (all numeric, excludes label & source)
feature_cols = ['duration_sec', 'total_bytes', 'total_pkts', 'bytes_per_sec',
                 'pkts_per_sec', 'avg_pkt_size']

X = df[feature_cols]
y = df['label']

print(f"\nTotal samples: {len(X)}")
print(f"Features: {feature_cols}")
print(f"\nLabel distribution (before split):")
print(y.value_counts())

# ========================================
# STEP 1: Split train/test FIRST (80/20)
# ========================================
print("\n" + "="*60)
print("STEP 1: Train/Test Split (80/20, stratified)")
print("="*60)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)
print(f"Training set: {len(X_train)} samples")
print(f"Testing set: {len(X_test)} samples")
print(f"\nTraining label distribution (BEFORE SMOTE):")
print(y_train.value_counts())

# ========================================
# STEP 2: Normalize (fit ONLY on train)
# ========================================
print("\n" + "="*60)
print("STEP 2: Normalization (StandardScaler)")
print("="*60)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)  # use the same scaler, do NOT refit
print("Scaler fitted pada training data sahaja ✓")

# ========================================
# STEP 3: SMOTE - ONLY on the training set!
# ========================================
print("\n" + "="*60)
print("STEP 3: SMOTE Balancing (training set sahaja)")
print("="*60)
smote = SMOTE(random_state=42)
X_train_balanced, y_train_balanced = smote.fit_resample(X_train_scaled, y_train)
print(f"Training set BEFORE SMOTE: {len(X_train_scaled)} samples")
print(f"Training set AFTER SMOTE: {len(X_train_balanced)} samples")
print(f"\nLabel distribution AFTER SMOTE:")
print(pd.Series(y_train_balanced).value_counts())

# ========================================
# STEP 4: Train Decision Tree
# ========================================
print("\n" + "="*60)
print("STEP 4: Training Decision Tree Classifier")
print("="*60)
model = DecisionTreeClassifier(max_depth=10, min_samples_split=20, random_state=42)
model.fit(X_train_balanced, y_train_balanced)
print("Model trained ✓")

# ========================================
# STEP 5: Evaluate on the REAL TEST SET (no SMOTE)
# ========================================
print("\n" + "="*60)
print("STEP 5: Evaluation (on the REAL test set, imbalanced)")
print("="*60)
y_pred = model.predict(X_test_scaled)

acc = accuracy_score(y_test, y_pred)
print(f"\nAccuracy: {acc*100:.2f}%")

print("\nClassification Report (Precision/Recall/F1 per class):")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
labels = sorted(y_test.unique())
cm = confusion_matrix(y_test, y_pred, labels=labels)
cm_df = pd.DataFrame(cm, index=labels, columns=labels)
print(cm_df)

# ========================================
# STEP 6: Save Model + Scaler
# ========================================
print("\n" + "="*60)
print("STEP 6: Saving Model & Scaler")
print("="*60)
joblib.dump(model, 'models_output/model.pkl')
joblib.dump(scaler, 'models_output/scaler.pkl')
print("Saved: models_output/model.pkl")
print("Saved: models_output/scaler.pkl")

print("\n✅ TRAINING SELESAI!")

