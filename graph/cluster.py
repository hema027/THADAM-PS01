import json
from pathlib import Path
from typing import Any
import networkx as nx
import yaml
from contract.models import Campaign, Indicator
from db import get_conn

def load_config() -> dict[str, Any]:
    config_path = Path(__file__).resolve().parent.parent / "config.yaml"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {
        "louvain_resolution": 1.0,
        "louvain_split": True,
        "random_seed": 42,
    }

def cluster(G: nx.Graph, obs_ids: list[int] | None = None) -> list[Campaign]:
    """
    Clusters observation nodes into phishing campaigns using a 2-stage algorithm:
    1. Strong edge connected components
    2. Split-only Louvain modularity decomposition for components with >= 8 members
    Persists results to campaigns and campaign_members tables (idempotent).
    """
    cfg = load_config()
    louvain_split = cfg.get("louvain_split", True)
    louvain_res = cfg.get("louvain_resolution", 1.0)
    seed = cfg.get("random_seed", 42)

    # 1. Connected components over STRONG edges only
    G_strong = nx.Graph()
    G_strong.add_nodes_from(G.nodes(data=True))

    for u, v, data in G.edges(data=True):
        if data.get("is_strong", False):
            G_strong.add_edge(u, v, **data)

    initial_components = list(nx.connected_components(G_strong))

    # 2. Split-only stage (ADDENDUM C)
    final_components: list[set[int]] = []
    for comp in initial_components:
        if louvain_split and len(comp) >= 8:
            subgraph = G.subgraph(comp)
            # Only run Louvain if subgraph has edges
            if subgraph.number_of_edges() > 0:
                try:
                    communities = nx.community.louvain_communities(
                        subgraph,
                        weight="weight",
                        resolution=louvain_res,
                        seed=seed
                    )
                    if len(communities) > 1 and all(len(c) >= 3 for c in communities):
                        mod = nx.community.modularity(subgraph, communities, weight="weight")
                        if mod >= 0.4:
                            final_components.extend(communities)
                            continue
                except Exception:
                    pass
        final_components.append(comp)

    # Filter campaigns with size >= 2
    valid_components = [c for c in final_components if len(c) >= 2]

    # Sort campaigns by size descending
    valid_components.sort(key=lambda c: len(c), reverse=True)

    conn = get_conn()
    campaign_objects: list[Campaign] = []

    try:
        with conn:
            if obs_ids is None:
                # Clear all old rows (idempotent full run)
                conn.execute("DELETE FROM campaign_members")
                conn.execute("DELETE FROM campaigns")
                start_idx = 1
            else:
                # Clear only memberships for the given obs_ids
                if obs_ids:
                    del_placeholders = ",".join("?" for _ in obs_ids)
                    conn.execute(f"DELETE FROM campaign_members WHERE obs_id IN ({del_placeholders})", obs_ids)
                    conn.execute("DELETE FROM campaigns WHERE id NOT IN (SELECT DISTINCT campaign_id FROM campaign_members)")
                cur_max = conn.execute("SELECT COALESCE(MAX(id), 0) as max_id FROM campaigns").fetchone()["max_id"]
                start_idx = cur_max + 1

            for idx, comp in enumerate(valid_components, start=start_idx):
                member_ids = sorted(list(comp))
                placeholders = ",".join("?" for _ in member_ids)

                # Fetch member details
                cur = conn.execute(
                    f"""
                    SELECT o.id, o.first_seen, v.brand
                    FROM observations o
                    LEFT JOIN verdicts v ON o.id = v.obs_id
                    WHERE o.id IN ({placeholders})
                    """,
                    member_ids
                )
                rows = cur.fetchall()

                first_seen_list = [r["first_seen"] for r in rows if r["first_seen"]]
                first_seen = min(first_seen_list) if first_seen_list else ""
                last_seen = max(first_seen_list) if first_seen_list else ""

                brands_set = {r["brand"] for r in rows if r["brand"]}
                brands = sorted(list(brands_set))

                # Compute top shared indicators within campaign by edge weight sum
                cur = conn.execute(
                    f"SELECT obs_id, type, value FROM indicators WHERE obs_id IN ({placeholders})",
                    member_ids
                )
                ind_rows = cur.fetchall()

                # Tally indicator presence among members
                ind_members: dict[tuple[str, str], set[int]] = {}
                for r in ind_rows:
                    ind_members.setdefault((r["type"], r["value"]), set()).add(r["obs_id"])

                # Weight sum across member pairs in G
                ind_weight_sums: dict[tuple[str, str], float] = {}
                sub_G = G.subgraph(comp)
                for u, v, data in sub_G.edges(data=True):
                    for ind in data.get("indicators", []):
                        k = (ind["type"], ind["value"])
                        ind_weight_sums[k] = ind_weight_sums.get(k, 0.0) + ind["weight"]

                # If no edges, fallback to frequency
                if not ind_weight_sums:
                    for k, m_set in ind_members.items():
                        if len(m_set) >= 2:
                            ind_weight_sums[k] = float(len(m_set))

                sorted_inds = sorted(ind_weight_sums.items(), key=lambda x: x[1], reverse=True)
                top_indicators = [
                    Indicator(type=k[0], value=k[1])
                    for k, _ in sorted_inds[:5]
                ]

                # Sum edge weights per indicator type
                type_weights: dict[str, float] = {}
                for (itype, _), w in ind_weight_sums.items():
                    type_weights[itype] = type_weights.get(itype, 0.0) + w

                if type_weights:
                    top_type = max(type_weights.items(), key=lambda x: x[1])[0]
                elif sorted_inds:
                    top_type = sorted_inds[0][0][0]
                else:
                    top_type = "indicator"

                valid_brands = [b for b in brands if str(b).lower() != "unknown"]
                brand_str = str(valid_brands[0]).lower() if valid_brands else (str(brands[0]).lower() if brands else "unknown")
                camp_name = f"{brand_str} - {len(member_ids)} domains - shared {top_type}"
                top_indicators_json = json.dumps([ind.model_dump() for ind in top_indicators])
                brands_json = json.dumps(brands)

                cur = conn.execute(
                    """
                    INSERT INTO campaigns (id, name, first_seen, last_seen, size, brands, top_indicators)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (idx, camp_name, first_seen, last_seen, len(member_ids), brands_json, top_indicators_json)
                )

                for m_id in member_ids:
                    conn.execute(
                        "INSERT INTO campaign_members (campaign_id, obs_id) VALUES (?, ?)",
                        (idx, m_id)
                    )

                campaign_objects.append(
                    Campaign(
                        id=idx,
                        name=camp_name,
                        size=len(member_ids),
                        brands=brands,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        top_indicators=top_indicators,
                        member_ids=member_ids
                    )
                )

        return campaign_objects
    finally:
        conn.close()
