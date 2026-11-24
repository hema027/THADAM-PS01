import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import networkx as nx

def generate_seed_data(seed: int = 42) -> list[dict]:
    # Campaign sizes per spec & addendum D: 4, 5, 6, 7, 9 (total 31 phish) + 10 benign = 41 total
    campaign_sizes = [4, 5, 6, 7, 9]
    brands = ["phonepe", "paytm", "gpay", "bhim", "sbi"]

    base_time = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)
    observations = []
    obs_id_counter = 1

    # Storage for assertion checks
    campaign_strong_graphs = {}
    campaign_strong_indicators = {}
    campaign_indicators = {}

    for c_idx, size in enumerate(campaign_sizes, start=1):
        brand = brands[(c_idx - 1) % len(brands)]
        c_strong_inds = {
            "vpa": f"refund.support{c_idx}@ybl",
            "tg_bot": f"bot_helpdesk_{c_idx}_bot",
            "phone": f"+9198765{c_idx:02d}100",
            "kit_hash": f"kithash_{c_idx:02d}_abcdef123456"
        }
        campaign_strong_indicators[c_idx] = c_strong_inds
        campaign_indicators[c_idx] = []

        # Graph to verify connectivity & non-clique
        G_camp = nx.Graph()
        member_obs_ids = []

        half = size // 2

        for i in range(size):
            obs_id = obs_id_counter
            obs_id_counter += 1
            member_obs_ids.append(obs_id)
            G_camp.add_node(obs_id)

            # Spread timestamps across 14 days
            day_offset = ((c_idx * 3 + i * 2) % 14)
            obs_time = base_time + timedelta(days=day_offset, hours=i * 2)
            time_iso = obs_time.isoformat()

            domain = f"{brand}-security-update-node{obs_id}.xyz"
            url = f"https://{domain}/login/verify?ref=pay{obs_id}"

            # Indicators for this observation
            inds = [
                {"type": "domain", "value": domain},
                # Shared Cloudflare decoy hub across ALL phishing observations
                {"type": "ip", "value": "104.21.55.2"},
                {"type": "asn", "value": "AS13335"},
                {"type": "nameserver", "value": f"ns1.cloudflare-decoy.com"},
            ]

            # Weak registrar: shared between Campaign 1 and 2, distinct for others
            if c_idx in (1, 2):
                inds.append({"type": "registrar", "value": "NameCheap, Inc."})
            else:
                inds.append({"type": "registrar", "value": f"Registrar-Camp-{c_idx}, LLC"})

            # Assign strong indicators to form connected non-clique structure
            # Part A (0 .. half) gets VPA & kit_hash
            # Part B (half .. size-1) gets tg_bot
            # Node 0 and 1 also get phone
            # Node half connects Part A and Part B
            if i <= half:
                inds.append({"type": "vpa", "value": c_strong_inds["vpa"]})
                inds.append({"type": "kit_hash", "value": c_strong_inds["kit_hash"]})
            if i >= half:
                inds.append({"type": "tg_bot", "value": c_strong_inds["tg_bot"]})
            if i in (0, 1):
                inds.append({"type": "phone", "value": c_strong_inds["phone"]})

            campaign_indicators[c_idx].append(inds)

            obs_record = {
                "id": obs_id,
                "url": url,
                "source": "sms" if i % 2 == 0 else "ct",
                "source_ref": f"seed-batch-c{c_idx}",
                "raw_text": f"Alert: Verify your {brand.upper()} account immediately at {url} or pay {c_strong_inds['vpa']}",
                "first_seen": time_iso,
                "is_synthetic": 1,
                "indicators": inds,
                "verdict": {
                    "score": round(0.82 + (i % 5) * 0.03, 2),
                    "label": "phish",
                    "brand": brand,
                    "signals": {"brand_keyword": 0.45, "vpa_pattern": 0.40, "heuristic": 0.10},
                    "model_version": "v0-seed"
                },
                "labels": {
                    "label": "phish",
                    "split": "train" if i % 3 != 0 else "test",
                    "heldout_brand": 0,
                    "campaign_gt": c_idx
                }
            }
            observations.append(obs_record)

        # Build strong indicator graph for this campaign
        for idx1 in range(size):
            for idx2 in range(idx1 + 1, size):
                id1 = member_obs_ids[idx1]
                id2 = member_obs_ids[idx2]
                inds1 = {f"{it['type']}:{it['value']}" for it in campaign_indicators[c_idx][idx1] if it['type'] in ('vpa', 'tg_bot', 'phone', 'kit_hash')}
                inds2 = {f"{it['type']}:{it['value']}" for it in campaign_indicators[c_idx][idx2] if it['type'] in ('vpa', 'tg_bot', 'phone', 'kit_hash')}
                if inds1.intersection(inds2):
                    G_camp.add_edge(id1, id2)

        campaign_strong_graphs[c_idx] = G_camp

        # ASSERTION 1: Strong indicator graph within campaign MUST be connected
        assert nx.is_connected(G_camp), f"Campaign {c_idx} strong graph is not connected!"

        # ASSERTION 2: Strong indicator graph within campaign MUST NOT be a clique
        max_possible_edges = size * (size - 1) // 2
        actual_edges = G_camp.number_of_edges()
        assert actual_edges < max_possible_edges, f"Campaign {c_idx} strong graph is a clique ({actual_edges}/{max_possible_edges})!"

    # ASSERTION 3: Campaigns 1 and 2 are linked only by the weak shared registrar (no shared strong indicators)
    c1_strong = {f"{it['type']}:{it['value']}" for obs_inds in campaign_indicators[1] for it in obs_inds if it['type'] in ('vpa', 'tg_bot', 'phone', 'kit_hash')}
    c2_strong = {f"{it['type']}:{it['value']}" for obs_inds in campaign_indicators[2] for it in obs_inds if it['type'] in ('vpa', 'tg_bot', 'phone', 'kit_hash')}
    assert len(c1_strong.intersection(c2_strong)) == 0, "Campaigns 1 and 2 share strong indicators!"

    # 10 Benign Observations
    for b_idx in range(1, 11):
        obs_id = obs_id_counter
        obs_id_counter += 1

        day_offset = (b_idx * 2) % 14
        obs_time = base_time + timedelta(days=day_offset, hours=b_idx)
        time_iso = obs_time.isoformat()

        domain = f"benign-service-{b_idx}.org"
        url = f"https://{domain}/info"

        inds = [
            {"type": "domain", "value": domain},
            {"type": "ip", "value": f"192.0.2.{10 + b_idx}"},
            {"type": "asn", "value": f"AS{20000 + b_idx}"},
            {"type": "nameserver", "value": f"ns1.benigndns-{b_idx}.org"},
            {"type": "registrar", "value": f"BenignRegistrar-{b_idx} LLC"}
        ]

        obs_record = {
            "id": obs_id,
            "url": url,
            "source": "feed",
            "source_ref": "benign-feed",
            "raw_text": f"Welcome to benign information portal {url}. No phishing here.",
            "first_seen": time_iso,
            "is_synthetic": 1,
            "indicators": inds,
            "verdict": {
                "score": 0.05,
                "label": "benign",
                "brand": None,
                "signals": {"benign_heuristics": 0.95},
                "model_version": "v0-seed"
            },
            "labels": {
                "label": "benign",
                "split": "test" if b_idx % 2 == 0 else "train",
                "heldout_brand": 0,
                "campaign_gt": 0
            }
        }
        observations.append(obs_record)

    assert len(observations) == 41, f"Expected 41 observations, got {len(observations)}"
    return observations

def make_seed(output_path: Path = Path("data/seed.json")) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = generate_seed_data(seed=42)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {len(data)} seed observations at {output_path}")

if __name__ == "__main__":
    make_seed()
