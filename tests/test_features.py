"""
Unit tests for detect/features.py (Step 3 Task 1 & 2).
"""
import json
import pytest
from db import get_conn
from detect.features import extract_features

FEATURE_NAMES = [
    "visual_phash_min_distance",
    "visual_dhash_min_distance",
    "visual_clip_cosine",
    "dom_tag_tree_hash_distance",
    "html_tlsh_distance",
    "brand_in_non_brand_domain",
    "brand_name_in_title",
    "text_tfidf_cosine",
    "url_punycode_flag",
    "url_brand_in_subdomain",
    "url_entropy",
    "url_tld_risk",
    "asks_upi_pin",
    "asks_otp",
    "asks_card_cvv",
    "form_posts_to_different_origin",
    "exfil_to_telegram",
    "exfil_to_firebase",
    "js_obfuscation_score",
    "cloaking_content_diff",
    "redirect_depth",
]

def test_cloaking_content_diff_on_ua_cloaked_campaign(corpus_env):
    conn = get_conn()
    cur = conn.execute(
        """
        SELECT o.id
        FROM observations o
        JOIN corpus_meta cm ON o.id = cm.obs_id
        WHERE json_extract(cm.json, '$.cloaked') = 1
        LIMIT 1
        """
    )
    row = cur.fetchone()
    conn.close()
    assert row is not None, "No cloaked observation found in corpus"
    obs_id = row["id"]

    feats = extract_features(obs_id)
    assert feats["cloaking_content_diff"] > 0.3, f"Expected cloaking_content_diff > 0.3, got {feats['cloaking_content_diff']}"

def test_benign_observation_does_not_ask_upi_pin(corpus_env):
    conn = get_conn()
    cur = conn.execute(
        """
        SELECT o.id
        FROM observations o
        JOIN labels l ON o.id = l.obs_id
        WHERE l.label = 'benign'
        LIMIT 5
        """
    )
    rows = cur.fetchall()
    conn.close()
    assert len(rows) > 0, "No benign observations found in corpus"

    for r in rows:
        feats = extract_features(r["id"])
        assert feats["asks_upi_pin"] == 0.0, f"Obs {r['id']} asks_upi_pin expected 0, got {feats['asks_upi_pin']}"

def test_telegram_exfil_detection(corpus_env):
    conn = get_conn()
    cur = conn.execute(
        """
        SELECT o.id FROM observations o JOIN corpus_meta cm ON o.id = cm.obs_id
        WHERE json_extract(cm.json, '$.exfil_type') = 'telegram_bot'
        LIMIT 1
        """
    )
    row = cur.fetchone()
    conn.close()
    assert row is not None, "No telegram exfil observation found in corpus"
    obs_id = row["id"]

    feats = extract_features(obs_id)
    assert feats["exfil_to_telegram"] == 1.0, f"Expected exfil_to_telegram == 1.0, got {feats['exfil_to_telegram']}"

def test_sbi_phish_brand_indicators(corpus_env):
    conn = get_conn()
    cur = conn.execute(
        """
        SELECT o.id
        FROM observations o
        JOIN corpus_meta cm ON o.id = cm.obs_id
        WHERE json_extract(cm.json, '$.brand') = 'sbi'
        LIMIT 1
        """
    )
    row = cur.fetchone()
    conn.close()
    assert row is not None, "No SBI observation found in corpus"
    obs_id = row["id"]

    feats = extract_features(obs_id)
    condition = (feats["brand_name_in_title"] == 1.0) or (feats["brand_in_non_brand_domain"] == 1.0)
    assert condition, (
        f"For SBI obs {obs_id}, expected brand_name_in_title==1 or brand_in_non_brand_domain==1. "
        f"Got title={feats['brand_name_in_title']}, domain={feats['brand_in_non_brand_domain']}"
    )

def test_all_features_return_documented_types_and_ranges(corpus_env):
    conn = get_conn()
    cur = conn.execute("SELECT id FROM observations LIMIT 3")
    rows = cur.fetchall()
    conn.close()

    for r in rows:
        feats = extract_features(r["id"])
        for name in FEATURE_NAMES:
            assert name in feats, f"Missing feature {name} in obs {r['id']}"
            val = feats[name]
            assert val is not None, f"Feature {name} is None in obs {r['id']}"
            assert isinstance(val, (int, float)), f"Feature {name} is not numeric in obs {r['id']}: {type(val)}"

            if name == "visual_clip_cosine":
                assert -1.0 <= val <= 1.0, f"{name} out of range [-1, 1]: {val}"
            elif name in ("url_entropy", "redirect_depth"):
                assert val >= 0.0, f"{name} must be >= 0: {val}"
            else:
                assert 0.0 <= val <= 1.0, f"{name} out of range [0, 1]: {val}"
