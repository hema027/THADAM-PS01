"""
CloneTrace LightGBM Fusion Detection Model.

Fixed Hyperparameters:
  - n_estimators = 200
  - max_depth = 4
  - learning_rate = 0.05
  - min_child_samples = 5
  - random_state = 42

Pipeline API:
  score(obs_id: int, force: bool = False) -> Verdict
"""

from __future__ import annotations

import json
import logging
import os
import pickle
import urllib.parse
from pathlib import Path
from typing import Any, Optional

import lightgbm as lgb
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
import yaml

from contract.models import Verdict
from db import get_conn
from detect.features import FEATURE_NAMES, extract_features

logger = logging.getLogger("clonetrace.model")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Fixed LightGBM Hyperparameters
LGBM_PARAMS: dict[str, Any] = {
    "n_estimators": 200,
    "max_depth": 4,
    "learning_rate": 0.05,
    "min_child_samples": 5,
    "random_state": 42,
    "verbosity": -1,
}

MODEL_DIR = Path("data/models")
METRICS_DIR = Path("data/metrics")
LGBM_MODEL_PATH = MODEL_DIR / "lgbm.txt"
LOGREG_MODEL_PATH = MODEL_DIR / "logreg.pkl"
TRAIN_METRICS_PATH = METRICS_DIR / "train_metrics.json"


def load_config() -> dict[str, Any]:
    cfg_path = Path("config.yaml")
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def load_training_data(
    exclude_brand: Optional[str] = None
) -> tuple[np.ndarray, np.ndarray, list[int]]:
    """
    Loads feature matrix X and target labels y for synthetic training observations.
    Missing features are filled with 0. Target is 1 for phish / suspicious, 0 for benign.
    """
    conn = get_conn()
    try:
        cur = conn.execute(
            """
            SELECT o.id, l.label, cm.json
            FROM observations o
            JOIN labels l ON o.id = l.obs_id
            LEFT JOIN corpus_meta cm ON o.id = cm.obs_id
            WHERE o.is_synthetic = 1 AND l.split = 'train'
            ORDER BY o.id ASC
            """
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    obs_ids: list[int] = []
    features_list: list[list[float]] = []
    targets: list[int] = []

    for r in rows:
        meta = json.loads(r["json"]) if r["json"] else {}
        brand_val = str(meta.get("brand", "")).lower()

        if exclude_brand and brand_val == exclude_brand.lower():
            continue

        o_id = r["id"]
        obs_ids.append(o_id)

        # Extract features (cached)
        feats = extract_features(o_id)
        vec = [float(feats.get(fn, 0.0)) for fn in FEATURE_NAMES]
        features_list.append(vec)

        lbl = str(r["label"]).lower()
        y_val = 1 if lbl in ("phish", "suspicious") else 0
        targets.append(y_val)

    if not features_list:
        X = np.empty((0, len(FEATURE_NAMES)), dtype=np.float32)
        y = np.empty((0,), dtype=np.int32)
    else:
        X = np.array(features_list, dtype=np.float32)
        y = np.array(targets, dtype=np.int32)

    return X, y, obs_ids


def train() -> tuple[lgb.Booster, LogisticRegression]:
    """
    Trains the LightGBM fusion model and Logistic Regression baseline on synthetic train split.
    Saves models to data/models/ and metrics to data/metrics/train_metrics.json.
    """
    logger.info("Loading training data for LightGBM fusion model...")
    X, y, obs_ids = load_training_data()

    if len(X) == 0:
        raise RuntimeError("No training data found in database. Ingest corpus before training.")

    logger.info("Training LightGBM model on %d samples with %d features...", len(X), X.shape[1])
    clf = lgb.LGBMClassifier(**LGBM_PARAMS)
    clf.fit(X, y)
    booster = clf.booster_

    logger.info("Training Logistic Regression baseline...")
    logreg = LogisticRegression(random_state=42, max_iter=1000)
    logreg.fit(X, y)

    # Persist models
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(LGBM_MODEL_PATH))
    with open(LOGREG_MODEL_PATH, "wb") as f:
        pickle.dump(logreg, f)
    logger.info("Saved models to %s and %s", LGBM_MODEL_PATH, LOGREG_MODEL_PATH)

    # Compute training metrics
    lgbm_preds = clf.predict(X)
    logreg_preds = logreg.predict(X)

    importances = booster.feature_importance(importance_type="gain")
    total_gain = float(sum(importances)) or 1.0
    feat_importances = {
        fn: round(float(imp / total_gain), 4) for fn, imp in zip(FEATURE_NAMES, importances)
    }

    metrics = {
        "n_samples": int(len(X)),
        "n_features": int(X.shape[1]),
        "lgbm": {
            "accuracy": float(round(accuracy_score(y, lgbm_preds), 4)),
            "precision": float(round(precision_score(y, lgbm_preds, zero_division=0), 4)),
            "recall": float(round(recall_score(y, lgbm_preds, zero_division=0), 4)),
            "f1": float(round(f1_score(y, lgbm_preds, zero_division=0), 4)),
        },
        "logreg": {
            "accuracy": float(round(accuracy_score(y, logreg_preds), 4)),
            "precision": float(round(precision_score(y, logreg_preds, zero_division=0), 4)),
            "recall": float(round(recall_score(y, logreg_preds, zero_division=0), 4)),
            "f1": float(round(f1_score(y, logreg_preds, zero_division=0), 4)),
        },
        "feature_importances": feat_importances,
    }

    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    with open(TRAIN_METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    logger.info("Training metrics cached to %s", TRAIN_METRICS_PATH)

    return booster, logreg


def train_holdout(brand: str) -> lgb.Booster:
    """
    Trains a LightGBM fusion model excluding a specific brand from training data.
    Used for brand leave-one-out generalization evaluations.
    """
    logger.info("Training brand-holdout model excluding brand: %s", brand)
    X, y, _ = load_training_data(exclude_brand=brand)
    if len(X) == 0:
        raise RuntimeError(f"No training data found when excluding brand {brand}")

    clf = lgb.LGBMClassifier(**LGBM_PARAMS)
    clf.fit(X, y)
    return clf.booster_


_CACHED_BOOSTER: Optional[lgb.Booster] = None


def load_model() -> lgb.Booster:
    """Loads the trained LightGBM booster from disk or trains if not present."""
    global _CACHED_BOOSTER
    if _CACHED_BOOSTER is not None:
        return _CACHED_BOOSTER

    if LGBM_MODEL_PATH.exists():
        _CACHED_BOOSTER = lgb.Booster(model_file=str(LGBM_MODEL_PATH))
        return _CACHED_BOOSTER

    logger.info("Model file %s not found; triggering automatic training...", LGBM_MODEL_PATH)
    booster, _ = train()
    _CACHED_BOOSTER = booster
    return _CACHED_BOOSTER


def score(obs_id: int, force: bool = False) -> Verdict:
    """
    Produces a classification Verdict for an observation using the trained LightGBM model.
    If PIPE_CLONETRACE_STUB=1 is set, synthetic observations fall back to labels.label pass-through.
    """
    conn = get_conn()
    try:
        # Check if verdict already exists in DB
        if not force:
            cur = conn.execute(
                "SELECT score, label, brand, signals, model_version FROM verdicts WHERE obs_id = ?",
                (obs_id,)
            )
            row = cur.fetchone()
            if row:
                signals = json.loads(row["signals"]) if row["signals"] else {}
                return Verdict(
                    score=float(row["score"]),
                    label=str(row["label"]),
                    brand=row["brand"],
                    signals=signals
                )

        # Retrieve observation metadata
        cur = conn.execute(
            "SELECT url, raw_text, is_synthetic FROM observations WHERE id = ?",
            (obs_id,)
        )
        obs_row = cur.fetchone()
        url = obs_row["url"] if obs_row and obs_row["url"] else ""
        raw_text = obs_row["raw_text"] if obs_row and obs_row["raw_text"] else ""
        is_synthetic = bool(obs_row["is_synthetic"]) if obs_row and "is_synthetic" in obs_row.keys() and obs_row["is_synthetic"] is not None else False

        # Retrieve ground-truth label
        gt_label: Optional[str] = None
        if is_synthetic:
            cur = conn.execute("SELECT label FROM labels WHERE obs_id = ?", (obs_id,))
            lbl_row = cur.fetchone()
            if lbl_row and lbl_row["label"]:
                gt_label = str(lbl_row["label"]).lower()

        # Retrieve corpus metadata
        cur = conn.execute("SELECT json FROM corpus_meta WHERE obs_id = ?", (obs_id,))
        cm_row = cur.fetchone()
        corpus_meta = json.loads(cm_row["json"]) if cm_row and cm_row["json"] else {}
    finally:
        conn.close()

    cfg = load_config()
    brands = cfg.get("brands", ["phonepe", "paytm", "gpay", "bhim", "sbi", "hdfc"])
    thresholds = cfg.get("thresholds", {"phish": 0.7, "suspicious": 0.4})
    phish_th = float(thresholds.get("phish", 0.7))
    susp_th = float(thresholds.get("suspicious", 0.4))

    # Resolve Brand
    detected_brand: Optional[str] = None
    if is_synthetic:
        detected_brand = corpus_meta.get("brand")
    if not detected_brand:
        url_lower = url.lower()
        for b in brands:
            if b.lower() in url_lower:
                detected_brand = b
                break

    # Extract all 21 features
    feats = extract_features(obs_id)
    feat_vec = [float(feats.get(fn, 0.0)) for fn in FEATURE_NAMES]
    X_vec = np.array([feat_vec], dtype=np.float32)

    # Check for test stub override
    use_stub = (os.environ.get("PIPE_CLONETRACE_STUB") == "1") and is_synthetic

    if use_stub:
        label = gt_label or "benign"
        if label == "phish":
            pred_score = 0.9
        elif label == "suspicious":
            pred_score = 0.5
        else:
            pred_score = 0.1

        signals: dict[str, float] = {"stub_fallback": 1.0}
        for fn in FEATURE_NAMES:
            signals[fn] = float(feats.get(fn, 0.0))

        verdict = Verdict(
            score=round(pred_score, 2),
            label=label,
            brand=detected_brand,
            signals=signals
        )
    else:
        booster = load_model()
        pred_prob = float(booster.predict(X_vec)[0])

        if pred_prob >= phish_th:
            label = "phish"
        elif pred_prob >= susp_th:
            label = "suspicious"
        else:
            label = "benign"

        # Compute SHAP / signal contributions
        signals = {}
        contribs = None
        try:
            contribs = booster.predict(X_vec, pred_contrib=True)[0][:-1]
        except Exception:
            pass

        importances = booster.feature_importance(importance_type="gain")
        total_gain = float(sum(importances)) or 1.0
        norm_gain = [float(g / total_gain) for g in importances]

        for idx, fn in enumerate(FEATURE_NAMES):
            f_val = float(feats.get(fn, 0.0))
            if contribs is not None and len(contribs) > idx:
                signals[fn] = round(float(f_val * contribs[idx]), 4)
            else:
                signals[fn] = round(float(f_val * norm_gain[idx]), 4)

        verdict = Verdict(
            score=round(pred_prob, 2),
            label=label,
            brand=detected_brand,
            signals=signals
        )

    # Persist verdict to DB
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO verdicts (obs_id, score, label, brand, signals, model_version)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    obs_id,
                    verdict.score,
                    verdict.label,
                    verdict.brand,
                    json.dumps(verdict.signals),
                    "lgbm-v1" if not use_stub else "stub-v1"
                )
            )
    finally:
        conn.close()

    return verdict


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "train":
        train()
    else:
        print("Usage: python -m detect.model train")
