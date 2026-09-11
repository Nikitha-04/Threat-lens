import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib
import json
import os

def train_model(dataset_path="./data/dataset/phishing_email.csv", model_dir="./data/model"):
    print(f"Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)

    print(f"Loaded {len(df):,} rows. Columns: {df.columns.tolist()}")
    print(f"First 3 rows:\n{df.head(3).to_string()}\n")
    print(f"Label distribution:\n{df['label'].value_counts().to_string()}\n")

    df['text_combined'] = df['text_combined'].fillna('')

    X = df['text_combined']
    y = df['label']

    print("Splitting data (80/20 stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # ── Leak check: zero overlap between train and test indices ──────────────
    overlap = set(X_train.index) & set(X_test.index)
    assert len(overlap) == 0, f"DATA LEAK: {len(overlap)} rows appear in both train and test!"
    print(f"Leak check passed — 0 overlapping indices between train ({len(X_train):,}) and test ({len(X_test):,}) sets.\n")

    print("Building pipeline (TF-IDF + Logistic Regression)...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=10000, stop_words='english', sublinear_tf=True)),
        ('clf', LogisticRegression(max_iter=1000, C=1.0, solver='saga', random_state=42, n_jobs=-1))
    ])

    print("Training model...")
    pipeline.fit(X_train, y_train)

    print("Evaluating on held-out test set...")
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    metrics = {
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "accuracy":  round(float(accuracy_score(y_test, y_pred)), 6),
        "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 6),
        "recall":    round(float(recall_score(y_test, y_pred, zero_division=0)), 6),
        "f1":        round(float(f1_score(y_test, y_pred, zero_division=0)), 6),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "model_version": "baseline_v1.0"
    }

    os.makedirs(model_dir, exist_ok=True)
    metrics_path = os.path.join(model_dir, "metrics.json")
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2)

    model_path = os.path.join(model_dir, "classifier.pkl")
    joblib.dump(pipeline, model_path)

    print(f"Model saved to {model_path}. Metrics saved to {metrics_path}.")
    return metrics
