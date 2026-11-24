"""
Deterministic synthetic corpus generator for UPI and banking phishing simulation.
Builds site file hierarchies under data/sites/<host>/ and writes ground-truth rows to SQLite.
"""

import json
import random
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
import jinja2
import networkx as nx
import yaml
from db import get_conn, init_db

def load_config() -> dict[str, Any]:
    cfg_path = Path("config.yaml")
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}

BRAND_PALETTES = {
    "phonepe": {"primary": "#5f259f", "secondary": "#673ab7", "wordmark": "PhonePe UPI", "title": "PhonePe"},
    "paytm": {"primary": "#002970", "secondary": "#00b9f5", "wordmark": "Paytm Payments", "title": "Paytm"},
    "gpay": {"primary": "#1a73e8", "secondary": "#34a853", "wordmark": "Google Pay UPI", "title": "Google Pay"},
    "bhim": {"primary": "#005d52", "secondary": "#2e7d32", "wordmark": "BHIM Official UPI", "title": "BHIM"},
    "sbi": {"primary": "#280071", "secondary": "#00a4e4", "wordmark": "State Bank of India", "title": "SBI YONO"},
    "hdfc": {"primary": "#004c8f", "secondary": "#ed1c24", "wordmark": "HDFC Bank NetBanking", "title": "HDFC Bank"},
}

def extract_tag_skeleton(html_str: str) -> list[str]:
    """Extracts sequence of HTML tag names to test structural skeleton stability."""
    return re.findall(r'<([a-zA-Z0-9]+)[^>]*>', html_str)

def build_corpus(
    sites_dir: Optional[Path] = None,
    gallery_dir: Optional[Path] = None,
    db_path: Optional[Path] = None
) -> dict[str, Any]:
    cfg = load_config()
    c_cfg = cfg.get("corpus", {})
    seed = c_cfg.get("seed", 7)
    n_campaigns = c_cfg.get("n_campaigns", 8)
    campaign_sizes = c_cfg.get("campaign_sizes", [4, 6, 8, 10, 12, 15, 20, 25])
    n_singletons = c_cfg.get("n_singletons", 20)
    n_hard_neg = c_cfg.get("n_hard_negatives", 40)
    n_plain_benign = c_cfg.get("n_plain_benign", 30)
    heldout_brand = c_cfg.get("heldout_brand", "bhim").lower()
    train_frac = c_cfg.get("train_fraction", 0.7)
    brands = [b.lower() for b in cfg.get("brands", ["phonepe", "paytm", "gpay", "bhim", "sbi", "hdfc"])]

    # Reset random state for strict determinism
    rng = random.Random(seed)

    # Setup directories
    sites_dir = sites_dir if sites_dir is not None else Path(cfg.get("fetch", {}).get("sites_dir", "data/sites"))
    gallery_dir = gallery_dir if gallery_dir is not None else Path("data/gallery")
    sites_dir.mkdir(parents=True, exist_ok=True)
    gallery_dir.mkdir(parents=True, exist_ok=True)

    template_dir = Path(__file__).parent / "templates"
    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(template_dir)), autoescape=True)

    base_time = datetime(2026, 9, 1, 8, 0, 0, tzinfo=timezone.utc)

    # 1. Generate Gallery Stand-ins (perturbation 0)
    for brand in brands:
        b_dir = gallery_dir / brand
        b_dir.mkdir(parents=True, exist_ok=True)
        pal = BRAND_PALETTES.get(brand, BRAND_PALETTES["phonepe"])
        tmpl = jinja_env.get_template("genuine_portal.html.j2")
        rendered_gallery = tmpl.render(
            brand_wordmark=pal["wordmark"],
            brand_title=pal["title"],
            primary_color=pal["primary"],
            secondary_color=pal["secondary"],
            prefix="gal_",
            ref_code="GALLERY-REF"
        )
        (b_dir / "index.html").write_text(rendered_gallery, encoding="utf-8")

    # Campaign Kits Definition
    templates_pool = ["upi_pin_entry.html.j2", "collect_request.html.j2", "rewards_claim.html.j2", "bill_pay.html.j2", "netbanking_login.html.j2"]
    exfil_types = ["telegram_bot", "formspree_style", "own_endpoint", "none"]

    campaign_kits = []
    for c_id in range(1, n_campaigns + 1):
        target_brand = brands[(c_id - 1) % len(brands)]
        tmpl_name = templates_pool[(c_id - 1) % len(templates_pool)]
        exfil = exfil_types[(c_id - 1) % len(exfil_types)]

        # 3 of 8 cloak: 2 UA cloak, 1 Referrer cloak
        if c_id in (2, 5):
            cloak_rule = "ua"
        elif c_id == 7:
            cloak_rule = "referrer"
        else:
            cloak_rule = "none"

        campaign_kits.append({
            "campaign_id": c_id,
            "kit_id": f"kit_v{c_id:02d}",
            "brand": target_brand,
            "template": tmpl_name,
            "exfil_type": exfil,
            "cloak_rule": cloak_rule,
            "skeleton_seed": rng.randint(1000, 9999),
            "size": campaign_sizes[c_id - 1],
        })

    # Group split for campaigns: heldout_brand always test; rest 70/30 group split
    campaign_splits = {}
    for kit in campaign_kits:
        c_id = kit["campaign_id"]
        if kit["brand"] == heldout_brand:
            campaign_splits[c_id] = "test"
        else:
            # Deterministic pseudo-random partition based on c_id
            campaign_splits[c_id] = "train" if (c_id % 3 != 0) else "test"

    observations = []
    obs_id_counter = 1001  # Offset to clearly avoid overlap with seed.json IDs

    # Storage for assert invariants
    campaign_strong_graphs = {}
    campaign_indicators = {}
    campaign_skeletons = {}

    # 2. Build Phishing Campaigns
    for kit in campaign_kits:
        c_id = kit["campaign_id"]
        size = kit["size"]
        brand = kit["brand"]
        pal = BRAND_PALETTES.get(brand, BRAND_PALETTES["phonepe"])
        tmpl = jinja_env.get_template(kit["template"])
        decoy_tmpl = jinja_env.get_template("cooking_blog_decoy.html.j2")

        # Strong indicators pool for this campaign
        vpa_pool = [f"settlement.desk{c_id}_{v}@ybl" for v in range(1, 4)]
        phone_pool = [f"+919876{c_id:02d}{p:04d}" for p in range(1, 3)]
        bot_token = f"{1000000000 + c_id * 11111}:AAF-FAKE-bot_token_camp_{c_id:02d}"
        kit_hash = f"kithash_v2_{c_id:02d}_{kit['skeleton_seed']}"
        ns_pair = f"ns1.threatdns-c{c_id}.com,ns2.threatdns-c{c_id}.com"
        registrar = "NameCheap, Inc." if c_id in (1, 2) else f"ThreatRegistrar-{c_id} LLC"

        G_camp = nx.Graph()
        member_obs_ids = []
        campaign_indicators[c_id] = []
        campaign_skeletons[c_id] = []

        half = size // 2

        for i in range(size):
            obs_id = obs_id_counter
            obs_id_counter += 1
            member_obs_ids.append(obs_id)
            G_camp.add_node(obs_id)

            day_offset = (c_id * 3 + i * 2) % 30
            obs_time = base_time + timedelta(days=day_offset, hours=i)
            time_iso = obs_time.isoformat()

            # Domain variation
            dom_types = ["typo", "homoglyph", "combo", "random"]
            dtype = dom_types[i % len(dom_types)]
            tld = [".xyz", ".top", ".site", ".online", ".in", ".com"][i % 6]
            if dtype == "typo":
                host = f"{brand}-sec-update{obs_id}{tld}"
            elif dtype == "homoglyph":
                host = f"xn--{brand}pay-{obs_id}{tld}"
            elif dtype == "combo":
                host = f"verify-{brand}-auth-node{obs_id}{tld}"
            else:
                host = f"s{obs_id}fastpay{tld}"

            # Shortener redirect test for 2 specific instances
            redirect_to = None
            if c_id == 1 and i == 0:
                host = "bit.ly-shortener-demo1.xyz"
                landing_host = f"xn--{brand}pay-{obs_id+1}.top"
                redirect_to = f"https://{landing_host}/verify"
            elif c_id == 3 and i == 0:
                host = "t.co-redirect-demo2.online"
                landing_host = f"xn--{brand}pay-{obs_id+1}.top"
                redirect_to = f"https://{landing_host}/verify"

            url = f"https://{host}/" if not redirect_to else f"https://{host}/short"

            # Per-domain template perturbation (level 0 to 3)
            perturbation = i % 4
            prefix = f"p{perturbation}_c{c_id}_"
            exfil_url = f"https://api.telegram.org/bot{bot_token}/sendMessage" if kit["exfil_type"] == "telegram_bot" else f"https://exfil-node-{c_id}.xyz/submit"

            assigned_vpa = vpa_pool[0] if i <= half else vpa_pool[1 % len(vpa_pool)]
            assigned_phone = phone_pool[0] if (i in (0, 1) or i == half) else phone_pool[1 % len(phone_pool)]

            rendered_phish = tmpl.render(
                brand_wordmark=pal["wordmark"],
                brand_title=pal["title"],
                primary_color=pal["primary"],
                secondary_color=pal["secondary"],
                prefix=prefix,
                notice_text=f"Urgent: Complete your {brand.upper()} UPI profile validation within 24 hours.",
                amount=f"{rng.randint(2000, 9500)}",
                vpa=assigned_vpa,
                phone=assigned_phone,
                button_text="VERIFY & PROCEED",
                tagline="Instant Settlement Gateway",
                remarks=f"Ref #{obs_id}",
                reward_copy=f"You have been selected for a special festive cashback from {pal['wordmark']}.",
                consumer_no=f"WB{rng.randint(100000, 999999)}",
                ref_code=f"{obs_id:06d}",
                exfil_url=exfil_url
            )

            campaign_skeletons[c_id].append(extract_tag_skeleton(rendered_phish))

            # Build Site Files & Manifest
            host_dir = sites_dir / host
            host_dir.mkdir(parents=True, exist_ok=True)
            (host_dir / "index.html").write_text(rendered_phish, encoding="utf-8")

            if kit["cloak_rule"] != "none":
                rendered_decoy = decoy_tmpl.render(date_str=obs_time.strftime("%B %d, %Y"))
                (host_dir / "decoy.html").write_text(rendered_decoy, encoding="utf-8")

            manifest = {
                "routes": {"/": "index.html", "/login": "index.html", "/verify": "index.html"},
                "redirect_to": redirect_to,
                "cloak": {
                    "rule": kit["cloak_rule"],
                    "decoy_file": "decoy.html" if kit["cloak_rule"] != "none" else None
                },
                "response_headers": {
                    "content-type": "text/html; charset=utf-8",
                    "server": "cloudflare",
                    "x-frame-options": "DENY"
                },
                "tls": {
                    "issuer": "Let's Encrypt Authority X3",
                    "not_before": "2026-08-15T00:00:00Z",
                    "fingerprint": f"SHA256:{kit_hash[:16]}"
                }
            }
            (host_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            # Indicators for observation
            inds = [
                {"type": "domain", "value": host},
                {"type": "ip", "value": "104.21.55.2"},
                {"type": "asn", "value": "AS13335"},
                {"type": "nameserver", "value": ns_pair},
                {"type": "registrar", "value": registrar},
            ]

            # Strong indicator chain distribution
            if i <= half:
                inds.append({"type": "vpa", "value": vpa_pool[0]})
                inds.append({"type": "kit_hash", "value": kit_hash})
            if i >= half:
                inds.append({"type": "tg_bot", "value": bot_token})
            if i in (0, 1):
                inds.append({"type": "phone", "value": phone_pool[0]})

            campaign_indicators[c_id].append(inds)

            obs_rec = {
                "id": obs_id,
                "url": url,
                "source": "ct" if i % 2 == 0 else "sms",
                "source_ref": f"corpus-camp-{c_id}",
                "raw_text": f"Security alert on {host} for brand {brand}",
                "first_seen": time_iso,
                "is_synthetic": 1,
                "indicators": inds,
                "verdict": {
                    "score": 0.88,
                    "label": "phish",
                    "brand": brand,
                    "signals": {"brand_keyword": 0.5, "vpa_pattern": 0.4},
                    "model_version": "v2-corpus"
                },
                "labels": {
                    "label": "phish",
                    "split": campaign_splits[c_id],
                    "heldout_brand": 1 if brand == heldout_brand else 0,
                    "campaign_gt": c_id
                },
                "corpus_meta": {
                    "kit_id": kit["kit_id"],
                    "campaign_id": c_id,
                    "template": kit["template"],
                    "brand": brand,
                    "cloaked": kit["cloak_rule"] != "none",
                    "cloak_rule": kit["cloak_rule"],
                    "perturbation_level": perturbation,
                    "exfil_type": kit["exfil_type"],
                    "display_domain": host
                }
            }
            observations.append(obs_rec)

        # Build strong indicator graph within campaign
        for idx1 in range(size):
            for idx2 in range(idx1 + 1, size):
                id1 = member_obs_ids[idx1]
                id2 = member_obs_ids[idx2]
                s1 = {f"{it['type']}:{it['value']}" for it in campaign_indicators[c_id][idx1] if it["type"] in ("vpa", "tg_bot", "phone", "kit_hash")}
                s2 = {f"{it['type']}:{it['value']}" for it in campaign_indicators[c_id][idx2] if it["type"] in ("vpa", "tg_bot", "phone", "kit_hash")}
                if s1.intersection(s2):
                    G_camp.add_edge(id1, id2)

        campaign_strong_graphs[c_id] = G_camp

        # ASSERTION 1: Connected and not a clique
        assert nx.is_connected(G_camp), f"Corpus campaign {c_id} strong graph is not connected!"
        max_edges = size * (size - 1) // 2
        assert G_camp.number_of_edges() < max_edges, f"Corpus campaign {c_id} is a clique!"

    # 3. 20 Singleton Phish (campaign_gt = -1)
    for s_idx in range(1, n_singletons + 1):
        obs_id = obs_id_counter
        obs_id_counter += 1
        brand = brands[(s_idx - 1) % len(brands)]
        pal = BRAND_PALETTES.get(brand, BRAND_PALETTES["phonepe"])
        tmpl = jinja_env.get_template("upi_pin_entry.html.j2")

        day_offset = (s_idx * 3) % 30
        obs_time = base_time + timedelta(days=day_offset, hours=s_idx)
        time_iso = obs_time.isoformat()

        host = f"singleton-auth-{s_idx}-{brand}.site"
        url = f"https://{host}/login"

        rendered = tmpl.render(
            brand_wordmark=pal["wordmark"],
            brand_title=pal["title"],
            primary_color=pal["primary"],
            secondary_color=pal["secondary"],
            prefix=f"s{s_idx}_",
            notice_text=f"Urgent {brand.upper()} Verification",
            amount=f"{rng.randint(1000, 5000)}",
            vpa=f"single_{s_idx}@paytm",
            phone=f"+9198700{s_idx:05d}",
            button_text="AUTHORIZE",
            tagline="Quick Payment",
            remarks="Singleton",
            ref_code=f"{obs_id:06d}",
            exfil_url=f"https://api.telegram.org/bot999999:FAKE/sendMessage"
        )

        host_dir = sites_dir / host
        host_dir.mkdir(parents=True, exist_ok=True)
        (host_dir / "index.html").write_text(rendered, encoding="utf-8")
        manifest = {
            "routes": {"/": "index.html", "/login": "index.html"},
            "redirect_to": None,
            "cloak": {"rule": "none", "decoy_file": None},
            "response_headers": {"content-type": "text/html; charset=utf-8", "server": "apache"},
            "tls": {"issuer": "cPanel Authority", "not_before": "2026-08-01T00:00:00Z", "fingerprint": f"SHA256:single_{s_idx}"}
        }
        (host_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        inds = [
            {"type": "domain", "value": host},
            {"type": "ip", "value": "104.21.55.2"},
            {"type": "asn", "value": "AS13335"},
            {"type": "nameserver", "value": f"ns1.singleton-{s_idx}.org"},
            {"type": "registrar", "value": f"SingletonRegistrar-{s_idx} LLC"},
            {"type": "vpa", "value": f"single_{s_idx}@paytm"},
            {"type": "phone", "value": f"+9198700{s_idx:05d}"}
        ]

        split = "test" if brand == heldout_brand else ("train" if day_offset < 21 else "test")

        observations.append({
            "id": obs_id,
            "url": url,
            "source": "feed",
            "source_ref": "singleton-phish",
            "raw_text": f"Suspicious activity detected on {host}",
            "first_seen": time_iso,
            "is_synthetic": 1,
            "indicators": inds,
            "verdict": {"score": 0.85, "label": "phish", "brand": brand, "signals": {"heuristic": 0.8}, "model_version": "v2-corpus"},
            "labels": {"label": "phish", "split": split, "heldout_brand": 1 if brand == heldout_brand else 0, "campaign_gt": -1},
            "corpus_meta": {"kit_id": f"singleton_{s_idx}", "campaign_id": -1, "template": "upi_pin_entry.html.j2", "brand": brand, "cloaked": False, "cloak_rule": "none", "perturbation_level": 1, "exfil_type": "telegram_bot", "display_domain": host}
        })

    # 4. 40 Hard Negatives (campaign_gt = 0, label = benign)
    hn_templates = ["genuine_portal.html.j2", "payment_gateway_checkout.html.j2", "ecommerce_checkout.html.j2"]
    for h_idx in range(1, n_hard_neg + 1):
        obs_id = obs_id_counter
        obs_id_counter += 1
        brand = brands[(h_idx - 1) % len(brands)]
        pal = BRAND_PALETTES.get(brand, BRAND_PALETTES["phonepe"])
        tmpl_name = hn_templates[(h_idx - 1) % len(hn_templates)]
        tmpl = jinja_env.get_template(tmpl_name)

        day_offset = (h_idx * 2) % 30
        obs_time = base_time + timedelta(days=day_offset, hours=h_idx)
        time_iso = obs_time.isoformat()

        host = f"secure-{brand}-corporate-{h_idx}.com"
        url = f"https://{host}/portal"

        rendered = tmpl.render(
            brand_wordmark=pal["wordmark"],
            brand_title=pal["title"],
            primary_color=pal["primary"],
            secondary_color=pal["secondary"],
            prefix=f"hn_{h_idx}_",
            merchant_name=f"{pal['wordmark']} Authorized Direct",
            amount=f"{rng.randint(500, 3000)}",
            ref_code=f"{obs_id:06d}"
        )

        host_dir = sites_dir / host
        host_dir.mkdir(parents=True, exist_ok=True)
        (host_dir / "index.html").write_text(rendered, encoding="utf-8")
        manifest = {
            "routes": {"/": "index.html", "/portal": "index.html"},
            "redirect_to": None,
            "cloak": {"rule": "none", "decoy_file": None},
            "response_headers": {"content-type": "text/html; charset=utf-8", "server": "nginx"},
            "tls": {"issuer": "DigiCert Global Root G2", "not_before": "2026-01-01T00:00:00Z", "fingerprint": f"SHA256:digicert_{h_idx}"}
        }
        (host_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        inds = [
            {"type": "domain", "value": host},
            {"type": "ip", "value": f"198.51.100.{h_idx}"},
            {"type": "asn", "value": f"AS{30000 + h_idx}"},
            {"type": "nameserver", "value": f"ns1.corporate-{h_idx}.net"},
            {"type": "registrar", "value": f"MarkMonitor Corporate {h_idx} Inc."}
        ]

        split = "test" if brand == heldout_brand else ("train" if day_offset < 21 else "test")

        observations.append({
            "id": obs_id,
            "url": url,
            "source": "feed",
            "source_ref": "hard-negative-feed",
            "raw_text": f"Authorized banking operations on {host}",
            "first_seen": time_iso,
            "is_synthetic": 1,
            "indicators": inds,
            "verdict": {"score": 0.08, "label": "benign", "brand": brand, "signals": {"official_cert": 0.9}, "model_version": "v2-corpus"},
            "labels": {"label": "benign", "split": split, "heldout_brand": 1 if brand == heldout_brand else 0, "campaign_gt": 0},
            "corpus_meta": {"kit_id": f"hard_neg_{h_idx}", "campaign_id": 0, "template": tmpl_name, "brand": brand, "cloaked": False, "cloak_rule": "none", "perturbation_level": 0, "exfil_type": "none", "display_domain": host}
        })

    # 5. 30 Plain Benign (campaign_gt = 0, label = benign)
    benign_templates = ["news_blog.html.j2", "cooking_blog_decoy.html.j2"]
    for b_idx in range(1, n_plain_benign + 1):
        obs_id = obs_id_counter
        obs_id_counter += 1
        tmpl_name = benign_templates[(b_idx - 1) % len(benign_templates)]
        tmpl = jinja_env.get_template(tmpl_name)

        day_offset = (b_idx * 3) % 30
        obs_time = base_time + timedelta(days=day_offset, hours=b_idx)
        time_iso = obs_time.isoformat()

        host = f"independent-observer-blog{b_idx}.org"
        url = f"https://{host}/article"

        rendered = tmpl.render(date_str=obs_time.strftime("%B %d, %Y"))
        host_dir = sites_dir / host
        host_dir.mkdir(parents=True, exist_ok=True)
        (host_dir / "index.html").write_text(rendered, encoding="utf-8")
        manifest = {
            "routes": {"/": "index.html", "/article": "index.html"},
            "redirect_to": None,
            "cloak": {"rule": "none", "decoy_file": None},
            "response_headers": {"content-type": "text/html; charset=utf-8", "server": "apache"},
            "tls": {"issuer": "GlobalSign Root CA", "not_before": "2026-02-01T00:00:00Z", "fingerprint": f"SHA256:globalsign_{b_idx}"}
        }
        (host_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        inds = [
            {"type": "domain", "value": host},
            {"type": "ip", "value": f"203.0.113.{b_idx}"},
            {"type": "asn", "value": f"AS{40000 + b_idx}"},
            {"type": "nameserver", "value": f"ns1.benignpress-{b_idx}.org"},
            {"type": "registrar", "value": f"PublicDomainRegistrar-{b_idx} LLC"}
        ]

        split = "train" if day_offset < 21 else "test"

        observations.append({
            "id": obs_id,
            "url": url,
            "source": "feed",
            "source_ref": "benign-web",
            "raw_text": f"Public digital article on {host}",
            "first_seen": time_iso,
            "is_synthetic": 1,
            "indicators": inds,
            "verdict": {"score": 0.02, "label": "benign", "brand": None, "signals": {"editorial": 0.98}, "model_version": "v2-corpus"},
            "labels": {"label": "benign", "split": split, "heldout_brand": 0, "campaign_gt": 0},
            "corpus_meta": {"kit_id": f"plain_benign_{b_idx}", "campaign_id": 0, "template": tmpl_name, "brand": None, "cloaked": False, "cloak_rule": "none", "perturbation_level": 0, "exfil_type": "none", "display_domain": host}
        })

    # ASSERTIONS & INVARIANTS
    # 1. Total count check
    expected_total = sum(campaign_sizes) + n_singletons + n_hard_neg + n_plain_benign
    assert len(observations) == expected_total, f"Expected {expected_total} observations, got {len(observations)}"

    # 2. Group split integrity: no campaign appears in both splits
    for c_id in range(1, n_campaigns + 1):
        c_splits = {obs["labels"]["split"] for obs in observations if obs["labels"].get("campaign_gt") == c_id}
        assert len(c_splits) == 1, f"Campaign {c_id} spans multiple splits: {c_splits}"

    # 3. Heldout brand integrity: all heldout_brand observations must be in test
    for obs in observations:
        if obs["corpus_meta"].get("brand") == heldout_brand:
            assert obs["labels"]["split"] == "test", f"Heldout brand {heldout_brand} in train split! ID: {obs['id']}"
            assert obs["labels"]["heldout_brand"] == 1

    # 4. Every observation has site directory
    for obs in observations:
        h = obs["corpus_meta"]["display_domain"]
        assert (sites_dir / h / "manifest.json").exists(), f"Site dir or manifest missing for {h}"
        assert (sites_dir / h / "index.html").exists(), f"index.html missing for {h}"

    # Persist to SQLite
    init_db(db_path)
    conn = get_conn(db_path)
    try:
        with conn:
            # Delete previous synthetic observations with id >= 1000 (FK-safe order)
            conn.execute("DELETE FROM fetches WHERE obs_id >= 1000")
            conn.execute("DELETE FROM corpus_meta WHERE obs_id >= 1000")
            conn.execute("DELETE FROM labels WHERE obs_id >= 1000")
            conn.execute("DELETE FROM verdicts WHERE obs_id >= 1000")
            conn.execute("DELETE FROM indicators WHERE obs_id >= 1000")
            conn.execute("DELETE FROM observations WHERE id >= 1000")

            for obs in observations:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO observations (id, url, source, source_ref, raw_text, first_seen, is_synthetic)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (obs["id"], obs["url"], obs["source"], obs["source_ref"], obs["raw_text"], obs["first_seen"], obs["is_synthetic"])
                )

                for ind in obs["indicators"]:
                    conn.execute(
                        "INSERT OR IGNORE INTO indicators (obs_id, type, value) VALUES (?, ?, ?)",
                        (obs["id"], ind["type"], ind["value"])
                    )

                v = obs["verdict"]
                conn.execute(
                    """
                    INSERT OR REPLACE INTO verdicts (obs_id, score, label, brand, signals, model_version)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (obs["id"], v["score"], v["label"], v["brand"], json.dumps(v["signals"]), v["model_version"])
                )

                lbl = obs["labels"]
                conn.execute(
                    """
                    INSERT OR REPLACE INTO labels (obs_id, label, split, heldout_brand, campaign_gt)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (obs["id"], lbl["label"], lbl["split"], lbl["heldout_brand"], lbl["campaign_gt"])
                )

                conn.execute(
                    "INSERT OR REPLACE INTO corpus_meta (obs_id, json) VALUES (?, ?)",
                    (obs["id"], json.dumps(obs["corpus_meta"]))
                )
    finally:
        conn.close()

    # Split stats
    train_count = sum(1 for o in observations if o["labels"]["split"] == "train")
    test_count = sum(1 for o in observations if o["labels"]["split"] == "test")
    heldout_count = sum(1 for o in observations if o["labels"]["heldout_brand"] == 1)

    print("========================================")
    print("   CloneTrace Synthetic Corpus Stats    ")
    print("========================================")
    print(f"Total Generated Sites    : {len(observations)}")
    print(f"Phishing Campaign Sites  : {sum(campaign_sizes)} across {n_campaigns} campaigns")
    print(f"Singleton Phishing Sites : {n_singletons}")
    print(f"Hard Negative Benign     : {n_hard_neg}")
    print(f"Plain Benign Sites       : {n_plain_benign}")
    print(f"Train / Test Split       : {train_count} Train / {test_count} Test")
    print(f"Heldout Brand ({heldout_brand.upper()}) Sites : {heldout_count} (all Test)")
    print("========================================")

    return {
        "total": len(observations),
        "train": train_count,
        "test": test_count,
        "heldout": heldout_count,
        "campaign_skeletons": campaign_skeletons
    }

if __name__ == "__main__":
    build_corpus()
