import os
from pathlib import Path
import pytest
from sklearn.metrics import adjusted_rand_score
from contract.models import Verdict
from db import get_conn
from detect.model import score
from pipeline import run_pipeline
from report.takedown import generate_takedown

def test_score_returns_well_formed_verdict():
    """Unit test for detect/model.py::score() per ADDENDUM E."""
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO observations (url, source, raw_text, first_seen, is_synthetic) VALUES ('https://test.xyz', 'ct', 'test', '2026-10-01', 0)"
    )
    obs_id = cur.lastrowid
    conn.commit()
    conn.close()

    verd = score(obs_id)
    assert isinstance(verd, Verdict)
    assert 0.0 <= verd.score <= 1.0
    assert verd.label in ("phish", "benign", "suspicious")
    assert isinstance(verd.signals, dict)

def test_smoke_pipeline_end_to_end():
    """
    End-to-end smoke test validating all pipeline stages on isolated temporary DB.
    """
    campaigns = run_pipeline()

    # (a) Exactly 5 campaigns found
    assert len(campaigns) == 5, f"Expected 5 campaigns, got {len(campaigns)}"

    conn = get_conn()
    try:
        # (b) Every observation has a verdict
        cur = conn.execute("""
            SELECT o.id, v.label, v.score
            FROM observations o
            LEFT JOIN verdicts v ON o.id = v.obs_id
        """)
        obs_verdicts = cur.fetchall()
        assert len(obs_verdicts) == 41
        for row in obs_verdicts:
            assert row["label"] is not None, f"Obs {row['id']} has no verdict"
            assert row["score"] is not None

        # (c) Benign observations belong to no campaign
        cur = conn.execute("""
            SELECT cm.campaign_id, o.id, l.label as gt_label, v.label as pred_label
            FROM campaign_members cm
            JOIN observations o ON cm.obs_id = o.id
            JOIN labels l ON o.id = l.obs_id
            JOIN verdicts v ON o.id = v.obs_id
            WHERE l.label = 'benign' OR v.label = 'benign'
        """)
        benign_memberships = cur.fetchall()
        assert len(benign_memberships) == 0, f"Found benign observations in campaigns: {benign_memberships}"

        # (d) Adjusted Rand Score >= 0.95 over phishing observations
        cur = conn.execute("""
            SELECT o.id, l.campaign_gt, cm.campaign_id
            FROM observations o
            JOIN labels l ON o.id = l.obs_id
            LEFT JOIN campaign_members cm ON o.id = cm.obs_id
            WHERE l.label = 'phish'
            ORDER BY o.id ASC
        """)
        phish_rows = cur.fetchall()
        gt_clusters = [r["campaign_gt"] for r in phish_rows]
        pred_clusters = [r["campaign_id"] if r["campaign_id"] is not None else -1 for r in phish_rows]

        ari = adjusted_rand_score(gt_clusters, pred_clusters)
        assert ari >= 0.95, f"Adjusted Rand Score {ari} is less than 0.95"

        # (e) ADDENDUM H: n_campaigns == 5 AND max(campaign.size) <= 9 AND no campaign contains observations from two different ground-truth campaigns
        assert len(campaigns) == 5
        assert max(c.size for c in campaigns) <= 9

        for camp in campaigns:
            placeholders = ",".join("?" for _ in camp.member_ids)
            cur = conn.execute(
                f"SELECT DISTINCT campaign_gt FROM labels WHERE obs_id IN ({placeholders})",
                camp.member_ids
            )
            gts = [r["campaign_gt"] for r in cur.fetchall()]
            assert len(gts) == 1, f"Campaign {camp.name} contains multiple ground truth campaigns: {gts}"

        # (f) generate_takedown produces a non-empty PDF file
        first_camp_id = campaigns[0].id
        pdf_path_str = generate_takedown(first_camp_id)
        pdf_path = Path(pdf_path_str)
        assert pdf_path.exists(), f"Takedown PDF {pdf_path} was not created"
        assert pdf_path.stat().st_size > 500, f"Takedown PDF {pdf_path} is unexpectedly small ({pdf_path.stat().st_size} bytes)"

    finally:
        conn.close()


def test_prototype_scorer_rules_and_signals(corpus_env):
    """Validates that detect/model.py evaluates heuristic signals on DOM."""
    conn = get_conn()
    cur = conn.execute("SELECT id FROM observations WHERE url LIKE '%phonepe%' LIMIT 1")
    row = cur.fetchone()
    conn.close()

    assert row is not None
    obs_id = row["id"]

    verd = score(obs_id, force=True)
    assert isinstance(verd, Verdict)
    assert 0.0 <= verd.score <= 1.0
    assert verd.label in ("phish", "suspicious", "benign")
    assert isinstance(verd.signals, dict)
    assert len(verd.signals) > 0, "Expected at least one rule-based signal to fire"


def test_pipeline_corpus_mode_produces_campaigns(corpus_env):
    """Validates that pipeline.py in corpus mode discovers clustered campaigns."""
    from pipeline import run_pipeline
    campaigns = run_pipeline(mode="corpus")
    assert isinstance(campaigns, list)
    assert len(campaigns) > 0, "Corpus pipeline should discover at least 1 campaign cluster"
    for camp in campaigns:
        assert camp.size >= 2
        assert len(camp.member_ids) == camp.size


def test_takedown_pdf_is_nontrivial(corpus_env):
    """Validates that the generated PDF contains structured dossier sections."""
    from pipeline import run_pipeline
    campaigns = run_pipeline(mode="corpus")
    assert len(campaigns) > 0
    pdf_path_str = generate_takedown(campaigns[0].id)
    pdf_path = Path(pdf_path_str)
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 1500, "PDF should be substantial and formatted"


def test_intake_lookup_flow():
    """Validates message text ingestion and DB correlation."""
    from detect.ingest import ingest_text
    sample_text = "Urgent: Paytm KYC suspended. Visit https://paytm-kyc-alert.xyz or call +919123456789. Send Rs 1 to paytm@upi"
    new_obs = ingest_text(sample_text, source="intake")
    assert len(new_obs) > 0

    conn = get_conn()
    try:
        cur = conn.execute("SELECT type, value FROM indicators WHERE obs_id = ?", (new_obs[0],))
        inds = {r["type"]: r["value"] for r in cur.fetchall()}
    finally:
        conn.close()

    assert "url" in inds or "vpa" in inds or "phone" in inds
