import hashlib
from pathlib import Path
import pytest
from corpus.build_corpus import build_corpus, extract_tag_skeleton
from db import get_conn

def test_corpus_counts_and_splits():
    res = build_corpus()
    assert res["total"] == 190
    assert res["train"] + res["test"] == 190
    assert res["heldout"] > 0

    conn = get_conn()
    try:
        # Check DB counts
        cur = conn.execute("SELECT COUNT(*) as cnt FROM corpus_meta")
        assert cur.fetchone()["cnt"] == 190

        # Check group split: no campaign appears in both splits
        cur = conn.execute("""
            SELECT campaign_gt, COUNT(DISTINCT split) as split_count
            FROM labels
            WHERE campaign_gt > 0
            GROUP BY campaign_gt
        """)
        for r in cur.fetchall():
            assert r["split_count"] == 1, f"Campaign {r['campaign_gt']} is split across train/test"

        # Check heldout brand is 100% in test
        cur = conn.execute("""
            SELECT l.split, COUNT(*) as cnt
            FROM labels l
            JOIN corpus_meta cm ON l.obs_id = cm.obs_id
            WHERE json_extract(cm.json, '$.brand') = 'bhim'
            GROUP BY l.split
        """)
        splits = {r["split"]: r["cnt"] for r in cur.fetchall()}
        assert "train" not in splits, "Found heldout brand BHIM in train split"
        assert splits.get("test", 0) > 0
    finally:
        conn.close()

def test_corpus_determinism(tmp_path: Path):
    build_corpus()
    sites_dir = Path("data/sites")
    site_files = sorted(list(sites_dir.glob("*/*.*")))
    assert len(site_files) > 0

    hashes_run1 = {}
    for sf in site_files:
        hashes_run1[str(sf)] = hashlib.sha256(sf.read_bytes()).hexdigest()

    # Second build
    build_corpus()
    for sf in site_files:
        hash2 = hashlib.sha256(sf.read_bytes()).hexdigest()
        assert hashes_run1[str(sf)] == hash2, f"Determinism violated for {sf}"

def test_cloaked_campaigns_have_two_distinct_variants():
    build_corpus()
    sites_dir = Path("data/sites")
    cloaked_manifests = []
    for mf_path in sites_dir.glob("*/manifest.json"):
        import json
        with open(mf_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if data.get("cloak", {}).get("rule") in ("ua", "referrer"):
                cloaked_manifests.append(mf_path.parent)

    assert len(cloaked_manifests) > 0, "No cloaked sites found"
    for site_dir in cloaked_manifests:
        index_file = site_dir / "index.html"
        decoy_file = site_dir / "decoy.html"
        assert index_file.exists()
        assert decoy_file.exists()
        index_content = index_file.read_text(encoding="utf-8")
        decoy_content = decoy_file.read_text(encoding="utf-8")
        assert index_content != decoy_content, f"Cloaked decoy is identical to phishing index in {site_dir}"

def test_skeleton_stable_within_campaign_and_different_across():
    res = build_corpus()
    skeletons_by_camp = res["campaign_skeletons"]

    # Stable within each campaign
    for c_id, skel_list in skeletons_by_camp.items():
        base_skel = skel_list[0]
        for idx, skel in enumerate(skel_list[1:], start=1):
            assert skel == base_skel, f"Skeleton mismatch within campaign {c_id} at member {idx}"

    # Different across campaigns using different templates
    c1_skel = skeletons_by_camp[1][0]  # upi_pin_entry
    c2_skel = skeletons_by_camp[2][0]  # collect_request
    assert c1_skel != c2_skel, "Skeletons of different templates should not be identical"
