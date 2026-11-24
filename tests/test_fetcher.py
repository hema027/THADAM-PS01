"""
Tests for detect/fetcher.py – pure-Python resolver + Playwright screenshots.
All resolve/fetch tests are fast (no network, no browser).
The screenshot test uses Playwright and is marked slow; skips if Chromium absent.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from db import get_conn
from detect.fetcher import fetch, resolve, capture_screenshots, _is_desktop_ua, _ua_profiles


# ---------------------------------------------------------------------------
# Helper: get UA strings from live config (via corpus_env's patched load_config)
# ---------------------------------------------------------------------------

def _get_ua(profile: str) -> str:
    return _ua_profiles().get(profile, "")


# ---------------------------------------------------------------------------
# 1. Phish page resolves under both UA profiles, status 200, html non-empty
# ---------------------------------------------------------------------------

def test_fetch_phish_page_under_both_uas(corpus_env):
    conn = get_conn()
    cur = conn.execute(
        """
        SELECT o.id, o.url
        FROM observations o
        JOIN corpus_meta cm ON o.id = cm.obs_id
        WHERE json_extract(cm.json, '$.brand') = 'phonepe'
        LIMIT 1
        """
    )
    row = cur.fetchone()
    conn.close()
    assert row is not None, "No PhonePe observation found in corpus_meta"
    obs_id = row["id"]

    fetch(obs_id, force=True)

    conn = get_conn()
    fetches = conn.execute(
        "SELECT ua_profile, status, dom_path, dead FROM fetches WHERE obs_id = ?",
        (obs_id,),
    ).fetchall()
    conn.close()

    assert len(fetches) == 2
    profiles = {f["ua_profile"] for f in fetches}
    assert profiles == {"mobile", "desktop"}
    for f in fetches:
        assert f["dead"] == 0
        assert f["status"] == 200
        dom_file = Path(f["dom_path"])
        assert dom_file.exists()
        assert len(dom_file.read_text(encoding="utf-8")) > 200


# ---------------------------------------------------------------------------
# 2. Cloaked campaign: desktop gets decoy, mobile gets phish (UA-based)
#    + referrer-based cloak: no Referer → decoy for both profiles
# ---------------------------------------------------------------------------

def test_cloaked_campaign_returns_different_dom_per_ua(corpus_env):
    # --- Part A: UA-cloaked ---
    conn = get_conn()
    cur = conn.execute(
        """
        SELECT o.id, o.url
        FROM observations o
        JOIN corpus_meta cm ON o.id = cm.obs_id
        WHERE json_extract(cm.json, '$.cloaked') = 1
          AND json_extract(cm.json, '$.cloak_rule') = 'ua'
        LIMIT 1
        """
    )
    row = cur.fetchone()
    conn.close()
    assert row is not None, "No UA-cloaked observation found in corpus_meta"
    obs_id = row["id"]

    fetch(obs_id, force=True)

    conn = get_conn()
    rows = conn.execute(
        "SELECT ua_profile, dom_path FROM fetches WHERE obs_id = ?", (obs_id,)
    ).fetchall()
    conn.close()

    doms = {r["ua_profile"]: Path(r["dom_path"]).read_text(encoding="utf-8") for r in rows}
    assert "mobile" in doms and "desktop" in doms

    desktop_lower = doms["desktop"].lower()
    mobile_lower = doms["mobile"].lower()

    # Desktop UA → decoy (cooking blog): no password input
    assert 'type="password"' not in desktop_lower, "Desktop DOM must NOT have a password input"
    assert "type='password'" not in desktop_lower

    # Mobile UA → phishing page: has password input
    has_pw = (
        'type="password"' in mobile_lower
        or "type='password'" in mobile_lower
        or "upi_pin" in mobile_lower
        or "pin" in mobile_lower
    )
    assert has_pw, "Mobile DOM must have a password / PIN input"
    assert doms["mobile"] != doms["desktop"], "Mobile and desktop DOMs must differ"

    # --- Part B: referrer-cloaked (no Referer → decoy for both) ---
    conn = get_conn()
    cur = conn.execute(
        """
        SELECT o.id, o.url
        FROM observations o
        JOIN corpus_meta cm ON o.id = cm.obs_id
        WHERE json_extract(cm.json, '$.cloaked') = 1
          AND json_extract(cm.json, '$.cloak_rule') = 'referrer'
        LIMIT 1
        """
    )
    ref_row = cur.fetchone()
    conn.close()
    assert ref_row is not None, "No referrer-cloaked observation found"
    ref_obs_id = ref_row["id"]

    fetch(ref_obs_id, force=True)

    conn = get_conn()
    ref_rows = conn.execute(
        "SELECT ua_profile, dom_path FROM fetches WHERE obs_id = ?", (ref_obs_id,)
    ).fetchall()
    conn.close()

    ref_doms = {r["ua_profile"]: Path(r["dom_path"]).read_text(encoding="utf-8") for r in ref_rows}
    for prof in ("mobile", "desktop"):
        lower = ref_doms[prof].lower()
        assert 'type="password"' not in lower, f"{prof} DOM should be decoy (no password input)"
        assert "type='password'" not in lower


# ---------------------------------------------------------------------------
# 3. Shortener URL records a redirect chain with ≥ 2 hops
# ---------------------------------------------------------------------------

def test_redirect_chain_recorded_for_shortener(corpus_env):
    conn = get_conn()
    cur = conn.execute(
        """
        SELECT o.id, o.url
        FROM observations o
        WHERE o.url LIKE '%short%'
        LIMIT 1
        """
    )
    row = cur.fetchone()
    conn.close()
    assert row is not None, "No shortener observation found"
    obs_id = row["id"]

    fetch(obs_id, force=True)

    conn = get_conn()
    f_row = conn.execute(
        "SELECT redirect_chain, final_url FROM fetches WHERE obs_id = ? AND ua_profile = 'mobile'",
        (obs_id,),
    ).fetchone()
    conn.close()

    chain = json.loads(f_row["redirect_chain"])
    assert len(chain) >= 2, f"Expected ≥2 hops, got {chain}"
    assert chain[0] != f_row["final_url"], "First hop must differ from final_url"


# ---------------------------------------------------------------------------
# 4. Unknown host is dead with a reason
# ---------------------------------------------------------------------------

def test_nonexistent_host_marked_dead(corpus_env):
    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO observations (url, source, raw_text, first_seen, is_synthetic) "
        "VALUES ('https://nonexistent-threat-domain-xyz999.xyz/index', 'feed', 'test', '2026-10-01', 1)"
    )
    dead_obs_id = cur.lastrowid
    conn.commit()
    conn.close()

    fetch(dead_obs_id, force=True)

    conn = get_conn()
    rows = conn.execute(
        "SELECT dead, dead_reason FROM fetches WHERE obs_id = ?", (dead_obs_id,)
    ).fetchall()
    conn.close()

    assert len(rows) == 2
    for r in rows:
        assert r["dead"] == 1
        assert r["dead_reason"] is not None
        # Reason must mention the unknown host or "Unknown"
        assert any(kw in (r["dead_reason"] or "") for kw in ("Unknown", "host", "not found", "404"))


# ---------------------------------------------------------------------------
# 5. Phish page's `requests` includes its exfil endpoint with blocked=True
# ---------------------------------------------------------------------------

def test_external_exfil_requests_are_blocked(corpus_env):
    conn = get_conn()
    cur = conn.execute(
        """
        SELECT o.id
        FROM observations o
        JOIN corpus_meta cm ON o.id = cm.obs_id
        WHERE json_extract(cm.json, '$.exfil_type') = 'telegram_bot'
        LIMIT 1
        """
    )
    row = cur.fetchone()
    conn.close()
    assert row is not None, "No telegram_bot exfil observation found"
    obs_id = row["id"]

    fetch(obs_id, force=True)

    conn = get_conn()
    f = conn.execute(
        "SELECT requests FROM fetches WHERE obs_id = ? AND ua_profile = 'mobile'",
        (obs_id,),
    ).fetchone()
    conn.close()

    reqs = json.loads(f["requests"])
    exfil_reqs = [r for r in reqs if "telegram.org" in r["url"] or "exfil" in r["url"]]
    assert exfil_reqs, "Expected at least one telegram/exfil URL in requests"
    for r in exfil_reqs:
        assert r["blocked"] is True, f"External request {r['url']} must be blocked"


# ---------------------------------------------------------------------------
# 6. Screenshot test (Playwright; skip if Chromium missing)
# ---------------------------------------------------------------------------

@pytest.mark.timeout(120)
def test_capture_screenshots(corpus_env, tmp_path):
    """
    Capture screenshots for 2 observations.
    Requires Playwright/Chromium; skips cleanly otherwise.
    """
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True)
                browser.close()
            except Exception:
                pytest.skip("Chromium binary not available")
    except ImportError:
        pytest.skip("playwright not installed")

    # Fetch two observations first so cached HTML exists
    conn = get_conn()
    cur = conn.execute(
        """
        SELECT o.id FROM observations o
        JOIN corpus_meta cm ON o.id = cm.obs_id
        WHERE json_extract(cm.json, '$.label') IS NOT NULL
           OR json_extract(cm.json, '$.brand') IS NOT NULL
        LIMIT 2
        """
    )
    obs_ids = [r["id"] for r in cur.fetchall()]
    if not obs_ids:
        cur = conn.execute("SELECT id FROM observations LIMIT 2")
        obs_ids = [r["id"] for r in cur.fetchall()]
    conn.close()

    assert len(obs_ids) >= 2

    for oid in obs_ids:
        fetch(oid, force=True)

    succeeded = capture_screenshots(obs_ids, profile="mobile")
    assert succeeded == len(obs_ids), f"Expected {len(obs_ids)} screenshots, got {succeeded}"

    from PIL import Image
    for oid in obs_ids:
        from detect.fetcher import _obs_cache_dir
        shot_path = _obs_cache_dir(oid) / "mobile.png"
        assert shot_path.exists(), f"mobile.png missing for obs {oid}"
        assert shot_path.stat().st_size > 5_000, "PNG too small (< 5 KB)"
        with Image.open(shot_path) as img:
            colors = img.getcolors(maxcolors=65536)
            assert colors is None or len(colors) > 1, "Screenshot appears blank (single color)"
