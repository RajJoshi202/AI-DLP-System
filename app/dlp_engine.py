"""
AI-Based Data Loss Prevention (DLP) Engine

Security-first design:
- Rule-based detection drives enforcement (allow/log/block).
- ML model provides a secondary signal to assist classification confidence.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Optional

import joblib

from feature_extraction.features import RuleDecision, rule_based_assessment
from preprocessing.preprocess import normalize_text, normalize_for_ml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = PROJECT_ROOT / "model" / "dlp_model.pkl"
LOG_PATH = PROJECT_ROOT / "logs" / "alerts.log"


def _get_logger() -> logging.Logger:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("dlp_alerts")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers in interactive runs
    if not logger.handlers:
        fh = logging.FileHandler(LOG_PATH, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


def load_model(path: Path = MODEL_PATH):
    if not path.exists():
        return None
    try:
        return joblib.load(path)
    except Exception:
        # If the model can't be deserialized (e.g., moved functions), continue rule-only.
        return None


def ml_assist_prediction(model, text: str) -> Optional[Dict[str, Any]]:
    """
    Returns ML prediction + confidence, if model exists.
    Labels:
      0 = SAFE
      1 = SENSITIVE
      2 = HIGHLY CONFIDENTIAL
    """
    if model is None:
        return None
    # Use a DataFrame to satisfy scikit-learn's ColumnTransformer expectations.
    import pandas as pd  # type: ignore

    X = pd.DataFrame({"text": [normalize_for_ml(text)]})
    pred = int(model.predict(X)[0])
    proba = None
    conf = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[0].tolist()
        conf = float(max(proba))
    return {"pred_label": pred, "proba": proba, "confidence": conf}


def decision_engine(text: str) -> Dict[str, Any]:
    """
    Final DLP decision:
    - Start with security rules (authoritative for blocking).
    - Use ML to adjust medium/low outcomes (assist only).
    """
    raw = text
    text = normalize_text(text)
    rules: RuleDecision = rule_based_assessment(text)

    model = load_model()
    ml = ml_assist_prediction(model, text)

    # ML assist policy:
    # - If rules already HIGH, keep block.
    # - If rules MEDIUM but ML is strongly HIGH, escalate.
    # - If rules MEDIUM and ML is strongly SAFE, keep MEDIUM (still log) but note ML disagreement.
    # - If rules LOW but ML is strongly SENSITIVE/HIGH, upgrade to SENSITIVE (log).
    final = asdict(rules)
    final["input"] = raw
    final["ml_assist"] = ml

    # Thresholds for "strong" model confidence (conservative)
    strong = 0.80

    if ml and ml.get("confidence") is not None and ml["confidence"] >= strong:
        ml_label = ml["pred_label"]
        if rules.risk_level == "HIGH":
            pass  # never downgrade a block due to ML
        elif rules.risk_level == "MEDIUM":
            if ml_label == 2:
                final["risk_level"] = "HIGH"
                final["action"] = "BLOCKED"
                final["classification"] = "HIGHLY CONFIDENTIAL"
                final["risk_score"] = max(final["risk_score"], 70)
                final["reasons"].append("ML assist: high-confidence HIGHLY CONFIDENTIAL")
            elif ml_label == 0:
                final["reasons"].append("ML assist: high-confidence SAFE (rules kept authoritative)")
        else:  # LOW
            if ml_label in (1, 2):
                final["risk_level"] = "MEDIUM"
                final["action"] = "LOGGED"
                final["classification"] = "SENSITIVE" if ml_label == 1 else "HIGHLY CONFIDENTIAL"
                final["risk_score"] = max(final["risk_score"], 35 if ml_label == 1 else 60)
                final["reasons"].append("ML assist: elevated due to high-confidence prediction")

    # Logging & alerting
    logger = _get_logger()
    if final["risk_level"] == "HIGH":
        logger.warning("ALERT | %s", json.dumps(final, ensure_ascii=False))
    elif final["risk_level"] == "MEDIUM":
        logger.info("LOG | %s", json.dumps(final, ensure_ascii=False))

    return final


def pretty_print(result: Dict[str, Any]) -> None:
    print("=== AI-DLP Decision ===")
    print(f"Classification: {result['classification']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Action: {result['action']}")
    print(f"Risk Score: {result['risk_score']}/100")
    print("Reason(s):")
    for r in result["reasons"]:
        print(f"- {r}")


def main() -> None:
    print("AI-Based DLP Engine (type 'exit' to quit)\n")
    while True:
        text = input("Enter text to analyze> ").strip()
        if text.lower() in {"exit", "quit"}:
            break
        res = decision_engine(text)
        pretty_print(res)
        print()


if __name__ == "__main__":
    main()


