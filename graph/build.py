"""
RAKSHA-HACK // Forensic Syndicate Correlation Graph Builder.
Renders a clean, non-jittery, hierarchical intelligence graph linking
Case Artifacts (SMS/Web/APK) to Shared Financial & Telecom Anchors (UPI, Phone, Domain).
"""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Any

from pyvis.network import Network

from db import get_conn


def build_viz_graph(campaign_id: int) -> Network | None:
    """Builds a clean, dark-slate forensic correlation graph for a campaign cluster."""
    conn = get_conn()
    try:
        camp = conn.execute(
            "SELECT id, name, brands, top_indicators FROM campaigns WHERE id = ?",
            (campaign_id,),
        ).fetchone()
        if not camp:
            return None

        members = conn.execute(
            """
            SELECT o.id, o.url, o.source, COALESCE(v.label, 'unknown') as label, COALESCE(v.score, 0.0) as score
            FROM campaign_members cm
            JOIN observations o ON cm.obs_id = o.id
            LEFT JOIN verdicts v ON o.id = v.obs_id
            WHERE cm.campaign_id = ?
            ORDER BY o.id ASC
            """,
            (campaign_id,),
        ).fetchall()

        if not members:
            return None

        member_ids = [m["id"] for m in members]
        placeholders = ",".join("?" for _ in member_ids)
        indicators = conn.execute(
            f"""
            SELECT obs_id, type, value
            FROM indicators
            WHERE obs_id IN ({placeholders})
            ORDER BY type, value
            """,
            member_ids,
        ).fetchall()
    finally:
        conn.close()

    # Initialize clean dark-slate canvas matching the RAKSHA-HACK UI
    net = Network(
        height="480px",
        width="100%",
        bgcolor="#0b0f17",
        font_color="#e2e8f0",
        directed=False,
    )

    # Central Syndicate Hub Node
    hub_id = f"camp_{campaign_id}"
    net.add_node(
        hub_id,
        label=f"{camp['name']}",
        title=f"Syndicate Cluster: {camp['name']} ({len(members)} linked cases)",
        shape="diamond",
        size=26,
        color={
            "background": "#1e293b",
            "border": "#f59e0b",
            "highlight": {"background": "#334155", "border": "#fbbf24"},
        },
        borderWidth=2.5,
        font={"size": 14, "face": "Inter, sans-serif", "color": "#fbbf24", "bold": True},
        level=0,
    )

    # Track unique indicator nodes to prevent duplicates and highlight shared pivots
    ind_usage: dict[tuple[str, str], list[int]] = {}
    for ind in indicators:
        key = (str(ind["type"]).lower(), str(ind["value"]))
        ind_usage.setdefault(key, []).append(int(ind["obs_id"]))

    # Add Case Artifact Nodes (SMS / WEB / APK)
    for m in members:
        obs_id = int(m["id"])
        src = str(m["source"]).upper()
        host = urllib.parse.urlparse(str(m["url"])).netloc or str(m["url"])
        if len(host) > 28:
            host = host[:25] + "..."

        score = float(m["score"])
        is_high = str(m["label"]).lower() == "phish" or score >= 0.65
        border_col = "#ef4444" if is_high else "#f59e0b"

        obs_node_id = f"obs_{obs_id}"
        net.add_node(
            obs_node_id,
            label=f"Case #{obs_id} [{src}]\n{host}",
            title=f"Case #{obs_id} ({src}) | Risk Score: {score:.2f} | Artifact: {m['url']}",
            shape="box",
            margin=10,
            color={
                "background": "#111827",
                "border": border_col,
                "highlight": {"background": "#1f2937", "border": "#f87171"},
            },
            borderWidth=1.8,
            font={"size": 12, "face": "JetBrains Mono, monospace", "color": "#f1f5f9"},
            level=1,
        )

        # Link Artifact to Syndicate Hub
        net.add_edge(
            hub_id,
            obs_node_id,
            color={"color": "#334155", "highlight": "#f59e0b"},
            width=1.5,
            dashes=True,
        )

    # Indicator palette by forensic type
    type_styles: dict[str, dict[str, str]] = {
        "vpa": {"border": "#38bdf8", "tag": "UPI VPA"},
        "phone": {"border": "#a78bfa", "tag": "PHONE"},
        "domain": {"border": "#34d399", "tag": "DOMAIN"},
        "crypto_wallet": {"border": "#f472b6", "tag": "CRYPTO"},
    }

    # Add Shared & Individual Identifier Nodes
    for (i_type, i_val), linked_obs in ind_usage.items():
        unique_obs = sorted(set(linked_obs))
        is_pivot = len(unique_obs) > 1
        style = type_styles.get(i_type, {"border": "#94a3b8", "tag": i_type.upper()})

        disp_val = i_val if len(i_val) <= 26 else i_val[:23] + "..."
        pivot_badge = " [SHARED PIVOT]" if is_pivot else ""

        ind_node_id = f"ind_{i_type}_{i_val}"
        net.add_node(
            ind_node_id,
            label=f"{style['tag']}{pivot_badge}\n{disp_val}",
            title=f"{style['tag']}: {i_val} (Referenced in {len(unique_obs)} case(s))",
            shape="dot" if not is_pivot else "hexagon",
            size=18 if is_pivot else 12,
            color={
                "background": "#1e1b4b" if is_pivot else "#0f172a",
                "border": "#ef4444" if is_pivot else style["border"],
                "highlight": {"background": "#312e81", "border": "#fbbf24"},
            },
            borderWidth=2.5 if is_pivot else 1.5,
            font={
                "size": 11,
                "face": "JetBrains Mono, monospace",
                "color": "#fca5a5" if is_pivot else "#cbd5e1",
            },
            level=2,
        )

        for obs_id in unique_obs:
            net.add_edge(
                f"obs_{obs_id}",
                ind_node_id,
                color={
                    "color": "#ef4444" if is_pivot else "#475569",
                    "highlight": "#38bdf8",
                },
                width=2.4 if is_pivot else 1.2,
            )

    # Clean, stable layout options (eliminates chaotic spinning & overlapping)
    options = {
        "layout": {
            "hierarchical": {
                "enabled": True,
                "direction": "UD",
                "sortMethod": "directed",
                "levelSeparation": 135,
                "nodeSpacing": 210,
                "treeSpacing": 240,
            }
        },
        "physics": {
            "enabled": False
        },
        "edges": {
            "smooth": {
                "enabled": True,
                "type": "cubicBezier",
                "forceDirection": "vertical",
                "roundness": 0.45,
            }
        },
        "interaction": {
            "hover": True,
            "tooltipDelay": 120,
            "zoomView": True,
            "dragView": True,
            "dragNodes": True,
        },
    }
    net.set_options(json.dumps(options))
    return net