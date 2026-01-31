"""
Train a lightweight ML helper model for DLP classification.

Important:
- Cybersecurity rules remain the primary control.
- ML is used as a supporting signal to reduce false positives/negatives.
"""

from __future__ import annotations

import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer

from preprocessing.preprocess import normalize_for_ml
from feature_extraction.features import numeric_feature_frame


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = PROJECT_ROOT / "dataset" / "dlp_dataset.csv"
MODEL_PATH = PROJECT_ROOT / "model" / "dlp_model.pkl"


def main() -> None:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    df = pd.read_csv(DATASET_PATH)
    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain columns: text, label")

    df["text"] = df["text"].astype(str).map(normalize_for_ml)
    X = df[["text"]]
    y = df["label"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if len(np.unique(y)) > 1 else None
    )

    text_features = TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=1,
        max_features=4000,
    )

    pre = ColumnTransformer(
        transformers=[
            ("tfidf", text_features, "text"),
            ("num", FunctionTransformer(numeric_feature_frame, validate=False), "text"),
        ],
        remainder="drop",
    )

    clf = LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        n_jobs=None,
    )

    model = Pipeline(steps=[("pre", pre), ("clf", clf)])
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    acc = accuracy_score(y_test, preds)

    print("=== AI-DLP ML Helper Model ===")
    print(f"Dataset: {DATASET_PATH}")
    print(f"Accuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, preds, digits=4))

    os.makedirs(MODEL_PATH.parent, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\nSaved model to: {MODEL_PATH}")


if __name__ == "__main__":
    main()


