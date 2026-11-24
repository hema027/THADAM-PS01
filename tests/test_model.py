"""
Unit tests for detect/model.py (Step 3 Task 3).
"""
import os
import pytest
from contract.models import Verdict
from db import get_conn
from detect.model import train, score, LGBM_MODEL_PATH


def test_train_and_score_on_training_observation(corpus_env):
    # Train the model
    train()
    assert LGBM_MODEL_PATH.exists()

    conn = get_conn()
    cur = conn.execute(
        """
        SELECT o.id, l.label
        FROM observations o
        JOIN labels l ON o.id = l.obs_id
        WHERE o.is_synthetic = 1 AND l.split = 'train'
        LIMIT 1
        """
    )
    row = cur.fetchone()
    conn.close()
    assert row is not None
    obs_id = row["id"]

    verd = score(obs_id, force=True)
    assert isinstance(verd, Verdict)
    assert verd.label in ("phish", "suspicious", "benign")
    assert 0.0 <= verd.score <= 1.0


def test_signals_has_at_least_five_keys(corpus_env):
    train()
    conn = get_conn()
    cur = conn.execute("SELECT id FROM observations WHERE is_synthetic = 1 LIMIT 1")
    row = cur.fetchone()
    conn.close()
    assert row is not None
    obs_id = row["id"]

    verd = score(obs_id, force=True)
    assert isinstance(verd.signals, dict)
    assert len(verd.signals) >= 5, f"Expected at least 5 signal keys, got {len(verd.signals)}"


def test_pipe_clonetrace_stub_env_fallback(corpus_env, monkeypatch):
    conn = get_conn()
    cur = conn.execute(
        """
        SELECT o.id, l.label
        FROM observations o
        JOIN labels l ON o.id = l.obs_id
        WHERE o.is_synthetic = 1 AND l.label = 'benign'
        LIMIT 1
        """
    )
    benign_row = cur.fetchone()

    cur = conn.execute(
        """
        SELECT o.id, l.label
        FROM observations o
        JOIN labels l ON o.id = l.obs_id
        WHERE o.is_synthetic = 1 AND l.label = 'phish'
        LIMIT 1
        """
    )
    phish_row = cur.fetchone()
    conn.close()

    assert benign_row is not None
    assert phish_row is not None

    monkeypatch.setenv("PIPE_CLONETRACE_STUB", "1")

    verd_benign = score(benign_row["id"], force=True)
    assert verd_benign.label == "benign"
    assert "stub_fallback" in verd_benign.signals

    verd_phish = score(phish_row["id"], force=True)
    assert verd_phish.label == "phish"
    assert "stub_fallback" in verd_phish.signals


def test_score_idempotency(corpus_env):
    conn = get_conn()
    cur = conn.execute("SELECT id FROM observations LIMIT 1")
    row = cur.fetchone()
    conn.close()
    assert row is not None
    obs_id = row["id"]

    verd1 = score(obs_id, force=True)
    verd2 = score(obs_id, force=False)

    assert verd1.label == verd2.label
    assert verd1.score == verd2.score
    assert verd1.brand == verd2.brand
    assert verd1.signals == verd2.signals
