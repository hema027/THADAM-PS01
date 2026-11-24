"""
RAKSHA-HACK // R4C Rajasthan Police Cyber Fraud & Scam Attribution Web Application (PS01).
True Modern Web-App Experience (Zero Left Sidebar, Direct Access without Login):
1. Full-Width Top Navigation Bar + Collapsible Filter Drawer (no cramped left sidebar!)
2. Interactive Blue & White Glassmorphic Command UI:
   - Colorful Multi-Metric Bar Diagram + Channel Donut Breakdown
   - Live Radial Threat Gauge Meter & One-Click Demo Scenario Chips
   - Dedicated URL, Message, Website & APK Scanner, Case Queue, Syndicate Graph, PDF Dossier & Heat-List
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import sys
import urllib.parse
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import streamlit.components.v1 as components
import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from app.theme import get_indicator_color
except ImportError:
    from theme import get_indicator_color

from db import get_conn, init_db
from detect.ingest import ingest_text
from graph.build import build_viz_graph
from report.takedown import generate_takedown

# 1. Page Configuration — Collapsed Sidebar so it behaves like a true full-screen Web App!
st.set_page_config(
    page_title="RAKSHA-HACK | R4C Cyber Command Portal",
    layout="wide",
    initial_sidebar_state="collapsed",
)

init_db()

# 2. Modern Full-Screen Blue & White Web App Stylesheet (Completely hides left sidebar!)
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header[data-testid="stHeader"] {display: none !important;}
    section[data-testid="stSidebar"] {display: none !important;}
    button[data-testid="collapsedControl"] {display: none !important;}

    @keyframes pulseGlow {
        0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.55); }
        70% { box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    @keyframes floatIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .stApp {
        background: radial-gradient(circle at 15% 10%, #dbeafe 0%, #eff6ff 35%, #f8fafc 75%, #eef2f6 100%) !important;
        color: #0f172a !important;
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }

    .block-container {
        padding-top: 1.4rem !important;
        padding-bottom: 2rem !important;
        max-width: 1380px !important;
    }

    code, pre, .mono {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Top Web-App Navbar */
    .webapp-navbar {
        background: linear-gradient(120deg, #071936 0%, #0d2b5c 55%, #1d4ed8 100%);
        border: 1px solid rgba(147, 197, 253, 0.35);
        border-radius: 16px;
        padding: 16px 26px;
        margin-bottom: 18px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 10px 30px rgba(7, 25, 54, 0.18);
        animation: floatIn 0.35s ease-out;
    }
    .nav-brand {
        display: flex;
        align-items: center;
        gap: 14px;
    }
    .nav-logo-box {
        width: 42px;
        height: 42px;
        border-radius: 11px;
        background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%);
        border: 1px solid rgba(255, 255, 255, 0.35);
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 800;
        font-size: 15px;
        color: #ffffff;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.45);
    }
    .nav-title {
        font-size: 20px;
        font-weight: 800;
        color: #ffffff;
        letter-spacing: 0.03em;
        line-height: 1.1;
    }
    .nav-subtitle {
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        color: #93c5fd;
        margin-top: 3px;
    }
    .nav-right {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .officer-chip {
        background: rgba(255, 255, 255, 0.12);
        border: 1px solid rgba(147, 197, 253, 0.3);
        border-radius: 10px;
        padding: 6px 14px;
        color: #f8fafc;
        font-size: 12px;
        font-weight: 600;
    }
    .live-pill {
        background: rgba(16, 185, 129, 0.16);
        border: 1px solid rgba(52, 211, 153, 0.45);
        color: #6ee7b7;
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        font-weight: 700;
        padding: 6px 12px;
        border-radius: 10px;
        display: flex;
        align-items: center;
        gap: 7px;
    }
    .live-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #10b981;
        animation: pulseGlow 2s infinite;
    }

    /* Horizontal Top Navigation Bar (Replaces Left Sidebar Radio!) */
    div[data-testid="stHorizontalBlock"] div[role="radiogroup"] {
        background: #ffffff;
        border: 1px solid #bfdbfe;
        border-radius: 14px;
        padding: 6px;
        display: flex;
        justify-content: space-between;
        gap: 6px;
        box-shadow: 0 4px 16px rgba(29, 78, 216, 0.06);
        margin-bottom: 14px;
    }
    div[data-testid="stHorizontalBlock"] div[role="radiogroup"] label {
        flex: 1;
        justify-content: center;
        background: transparent;
        border-radius: 10px;
        padding: 9px 14px;
        font-weight: 700;
        font-size: 13.5px;
        color: #334155 !important;
        transition: all 0.2s ease;
        border: 1px solid transparent;
    }
    div[data-testid="stHorizontalBlock"] div[role="radiogroup"] label:hover {
        background: #eff6ff;
        color: #1d4ed8 !important;
    }
    div[data-testid="stHorizontalBlock"] div[role="radiogroup"] label[data-checked="true"],
    div[data-testid="stHorizontalBlock"] div[role="radiogroup"] label:has(input:checked) {
        background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%) !important;
        color: #ffffff !important;
        box-shadow: 0 4px 12px rgba(29, 78, 216, 0.28);
    }
    div[data-testid="stHorizontalBlock"] div[role="radiogroup"] label:has(input:checked) * {
        color: #ffffff !important;
    }
    /* Hide default radio circles in top nav bar */
    div[data-testid="stHorizontalBlock"] div[role="radiogroup"] label > div:first-child {
        display: none !important;
    }

    /* Elevated White Cards */
    .ui-card {
        background: rgba(255, 255, 255, 0.97);
        border: 1px solid #dbeafe;
        border-radius: 16px;
        padding: 20px 24px;
        box-shadow: 0 6px 24px rgba(15, 23, 42, 0.05);
        transition: all 0.25s ease;
        animation: floatIn 0.4s ease-out;
    }
    .ui-card:hover {
        border-color: #93c5fd;
        box-shadow: 0 10px 30px rgba(29, 78, 216, 0.09);
    }
    .card-kicker {
        font-size: 11.5px;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.07em;
        color: #1d4ed8;
        margin-bottom: 8px;
    }

    /* Mission Callout Strip */
    .mission-strip {
        background: linear-gradient(90deg, #eff6ff 0%, #ffffff 100%);
        border: 1px solid #bfdbfe;
        border-left: 5px solid #2563eb;
        border-radius: 12px;
        padding: 14px 20px;
        margin-bottom: 18px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    /* Interactive Tabs */
    button[data-baseweb="tab"] {
        background-color: #ffffff !important;
        border: 1px solid #dbeafe !important;
        border-radius: 12px 12px 0 0 !important;
        color: #475569 !important;
        font-size: 13.5px !important;
        font-weight: 700 !important;
        padding: 11px 22px !important;
        margin-right: 8px !important;
        transition: all 0.2s ease;
    }
    button[data-baseweb="tab"]:hover {
        color: #1d4ed8 !important;
        background-color: #eff6ff !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%) !important;
        border-color: #1d4ed8 !important;
        color: #ffffff !important;
        box-shadow: 0 6px 16px rgba(29, 78, 216, 0.28) !important;
    }

    /* Primary & Action Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%) !important;
        color: #ffffff !important;
        font-size: 13.5px !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 0.55rem 1.25rem !important;
        box-shadow: 0 4px 14px rgba(37, 99, 235, 0.26) !important;
        transition: all 0.2s ease;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #1d4ed8 0%, #1e3a8a 100%) !important;
        transform: translateY(-2px);
        box-shadow: 0 8px 20px rgba(29, 78, 216, 0.36) !important;
    }

    /* Inputs */
    .stTextInput input, .stTextArea textarea, div[data-baseweb="select"] > div {
        background-color: #ffffff !important;
        border: 1.5px solid #cbd5e1 !important;
        border-radius: 10px !important;
        color: #0f172a !important;
        font-size: 13.5px !important;
    }
    .stTextInput input:focus, .stTextArea textarea:focus {
        border-color: #2563eb !important;
        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.16) !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_brands() -> list[str]:
    cfg_path = Path("config.yaml")
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
            return cfg.get("brands", ["phonepe", "paytm", "gpay", "bhim", "sbi", "hdfc"])
    return ["phonepe", "paytm", "gpay", "bhim", "sbi", "hdfc"]


def map_ps01_risk_tier(label: str, score: float) -> tuple[str, str, str]:
    lbl = str(label).lower()
    if lbl == "phish" or score >= 0.65:
        return "High Risk", "#dc2626", "#fef2f2"
    if lbl == "suspicious" or score >= 0.30:
        return "Medium Risk", "#d97706", "#fffbeb"
    return "Low Risk", "#059669", "#ecfdf5"


def render_risk_gauge(score: float, risk_tier: str, badge_col: str) -> go.Figure:
    pct = round(score * 100, 1)
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=pct,
            number={"suffix": "%", "font": {"size": 28, "family": "JetBrains Mono", "color": badge_col}},
            title={"text": f"<b>{risk_tier.upper()}</b>", "font": {"size": 13, "family": "Plus Jakarta Sans", "color": "#071936"}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#94a3b8"},
                "bar": {"color": badge_col, "thickness": 0.28},
                "bgcolor": "#f1f5f9",
                "borderwidth": 1,
                "bordercolor": "#cbd5e1",
                "steps": [
                    {"range": [0, 30], "color": "#d1fae5"},
                    {"range": [30, 65], "color": "#fef3c7"},
                    {"range": [65, 100], "color": "#fee2e2"},
                ],
                "threshold": {
                    "line": {"color": "#071936", "width": 3},
                    "thickness": 0.75,
                    "value": pct,
                },
            },
        )
    )
    fig.update_layout(height=185, margin=dict(l=18, r=18, t=34, b=10), paper_bgcolor="rgba(0,0,0,0)")
    return fig


def render_interactive_telemetry_charts(
    total_c: int,
    flagged_c: int,
    camps_c: int,
    dossiers_c: int,
    df_records: pd.DataFrame,
) -> None:
    col_bar, col_donut = st.columns([7, 5])

    with col_bar:
        st.markdown('<div class="ui-card" style="padding-bottom:8px;">', unsafe_allow_html=True)
        st.markdown('<div class="card-kicker">Investigation Telemetry — Colorful Multi-Metric Bar Diagram</div>', unsafe_allow_html=True)

        bar_df = pd.DataFrame(
            {
                "Metric": [
                    "Artifacts Analyzed",
                    "High / Medium Risk",
                    "Linked Campaigns",
                    "Dossiers Ready",
                ],
                "Count": [total_c, flagged_c, camps_c, dossiers_c],
                "Description": [
                    "Total SMS, Web & APK inputs",
                    "Flagged suspicious or phishing",
                    "Correlated UPI / phone clusters",
                    "Actionable police reports",
                ],
            }
        )

        fig_bar = go.Figure(
            data=[
                go.Bar(
                    x=bar_df["Metric"],
                    y=bar_df["Count"],
                    text=bar_df["Count"],
                    textposition="outside",
                    textfont=dict(size=14, family="JetBrains Mono", color="#071936"),
                    hovertext=bar_df["Description"],
                    hovertemplate="<b>%{x}</b><br>Count: %{y}<br>%{hovertext}<extra></extra>",
                    marker=dict(
                        color=["#2563eb", "#e11d48", "#f59e0b", "#10b981"],
                        line=dict(color=["#1d4ed8", "#be123c", "#d97706", "#059669"], width=1.5),
                    ),
                    width=0.46,
                )
            ]
        )
        max_y = max(bar_df["Count"].max() + 2, 5)
        fig_bar.update_layout(
            height=245,
            margin=dict(l=12, r=12, t=22, b=12),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#f8fafc",
            xaxis=dict(showgrid=False, tickfont=dict(size=12, family="Plus Jakarta Sans", color="#1e293b")),
            yaxis=dict(range=[0, max_y], gridcolor="#e2e8f0", zeroline=False, tickfont=dict(size=11, family="JetBrains Mono", color="#64748b")),
            showlegend=False,
        )
        st.plotly_chart(fig_bar, use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)

    with col_donut:
        st.markdown('<div class="ui-card" style="padding-bottom:8px;">', unsafe_allow_html=True)
        st.markdown('<div class="card-kicker">Intake Channel Distribution</div>', unsafe_allow_html=True)

        if not df_records.empty and "source" in df_records.columns:
            src_counts = df_records["source"].str.upper().value_counts().reset_index()
            src_counts.columns = ["Channel", "Cases"]
        else:
            src_counts = pd.DataFrame({"Channel": ["SMS", "WEB", "APK"], "Cases": [1, 1, 1]})

        fig_donut = px.pie(
            src_counts,
            names="Channel",
            values="Cases",
            hole=0.60,
            color_discrete_sequence=["#1d4ed8", "#0ea5e9", "#6366f1", "#10b981", "#f59e0b"],
        )
        fig_donut.update_traces(
            textposition="inside",
            textinfo="label+percent",
            textfont=dict(size=11.5, family="JetBrains Mono", color="#ffffff"),
            hovertemplate="<b>%{label} Channel</b><br>Artifacts: %{value} (%{percent})<extra></extra>",
        )
        fig_donut.update_layout(
            height=245,
            margin=dict(l=10, r=10, t=18, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=-0.12, xanchor="center", x=0.5, font=dict(size=11, color="#334155")),
            annotations=[
                dict(
                    text=f"<b>{total_c}</b><br>Total",
                    x=0.5,
                    y=0.5,
                    font=dict(size=15, family="Plus Jakarta Sans", color="#071936"),
                    showarrow=False,
                )
            ],
        )
        st.plotly_chart(fig_donut, use_container_width=True, config={"displayModeBar": False})
        st.markdown("</div>", unsafe_allow_html=True)


# ===========================================================================
# FULL-SCREEN WEB APPLICATION (DIRECT ACCESS — NO LOGIN PAGE)
# ===========================================================================
st.markdown(
    """
    <div class="webapp-navbar">
        <div class="nav-brand">
            <div class="nav-logo-box">RH</div>
            <div>
                <div class="nav-title">RAKSHA-HACK // Cyber Fraud Attribution Web Console</div>
                <div class="nav-subtitle">R4C Rajasthan Police • Dedicated URL, Message, Website &amp; APK Scanner</div>
            </div>
        </div>
        <div class="nav-right">
            <span class="officer-chip">PS01 Forensics Unit</span>
            <span class="live-pill"><span class="live-dot"></span>STATIC ENGINE ONLINE</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Creative Horizontal Top Menu Bar + Collapsible Triage Filter Drawer (Replaces Left Sidebar!)
top_menu_col, filter_btn_col = st.columns([9.5, 2.5])
with top_menu_col:
    nav = st.radio(
        "Primary Navigation",
        [
            "Intake & Scanner",
            "Case History",
            "Campaign Links",
            "Evidence Report",
            "Threat Heat-List",
        ],
        horizontal=True,
        label_visibility="collapsed",
    )

with filter_btn_col:
    with st.popover("Repository & Triage Filters", use_container_width=True):
        st.markdown('<div class="card-kicker">Evidence Store</div>', unsafe_allow_html=True)
        dataset = st.radio("Dataset", ["seed", "corpus"], horizontal=True, label_visibility="collapsed")
        st.markdown('<div class="card-kicker" style="margin-top:10px;">Filter Records</div>', unsafe_allow_html=True)
        label_filter = st.multiselect("Risk Level", ["phish", "suspicious", "benign"], default=[])
        brand_filter = st.multiselect("Impersonated Entity", load_brands(), default=[])
        source_filter = st.multiselect("Intake Channel", ["sms", "web", "apk", "feed", "ct"], default=[])


# Data Query
def get_observations_data(dataset_mode: str) -> pd.DataFrame:
    conn = get_conn()
    try:
        where_clauses = ["o.id IN (SELECT obs_id FROM corpus_meta)" if dataset_mode == "corpus" else "o.id NOT IN (SELECT obs_id FROM corpus_meta)"]
        params: list[Any] = []

        if label_filter:
            where_clauses.append(f"v.label IN ({','.join('?' for _ in label_filter)})")
            params.extend(label_filter)
        if brand_filter:
            where_clauses.append(f"v.brand IN ({','.join('?' for _ in brand_filter)})")
            params.extend(brand_filter)
        if source_filter:
            where_clauses.append(f"o.source IN ({','.join('?' for _ in source_filter)})")
            params.extend(source_filter)

        query = f"""
            SELECT
                o.id, o.first_seen, o.url, o.source,
                COALESCE(v.label, 'unknown') as label,
                COALESCE(v.score, 0.0) as score,
                COALESCE(v.brand, 'unknown') as brand,
                v.signals,
                (SELECT COUNT(*) FROM indicators i WHERE i.obs_id = o.id) as indicator_count,
                (SELECT c.name FROM campaign_members cm JOIN campaigns c ON cm.campaign_id = c.id WHERE cm.obs_id = o.id LIMIT 1) as campaign
            FROM observations o
            LEFT JOIN verdicts v ON o.id = v.obs_id
            WHERE {' AND '.join(where_clauses)}
            ORDER BY o.id DESC
        """
        rows = conn.execute(query, params).fetchall()
        return pd.DataFrame([dict(r) for r in rows])
    finally:
        conn.close()


df_obs = get_observations_data(dataset)

total_count = len(df_obs)
flagged_count = int((df_obs["label"].isin(["phish", "suspicious"])).sum()) if not df_obs.empty else 0
camps_count = int(df_obs["campaign"].dropna().nunique()) if not df_obs.empty else 0
takedown_count = int(((df_obs["label"] == "phish") & (df_obs["score"] >= 0.65)).sum()) if not df_obs.empty else 0


# ===========================================================================
# MODULE 1: INTAKE & SCANNER
# ===========================================================================
if nav == "Intake & Scanner":
    render_interactive_telemetry_charts(total_count, flagged_count, camps_count, takedown_count, df_obs)

    st.markdown(
        """
        <div class="mission-strip">
            <div>
                <div style="font-size:14px; font-weight:800; color:#071936;">Dedicated URL &amp; Artifact Upload Scanner</div>
                <div style="font-size:12.5px; color:#334155; margin-top:2px;">
                    Upload or paste suspicious URLs, scam messages, fraudulent websites, or Android APKs below to extract UPI/phone pivots and correlate fraud syndicates.
                </div>
            </div>
            <span class="mono" style="font-size:11px; font-weight:700; color:#1d4ed8; background:#dbeafe; padding:6px 12px; border-radius:7px;">LIVE SCANNER</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    def classify_and_link_observation(obs_id: Any, raw_text: str, source_type: str = "sms"):
        if isinstance(obs_id, list):
            first = obs_id[0] if obs_id else None
            obs_id = first["id"] if isinstance(first, dict) else (int(first) if isinstance(first, int) else 0)
        elif isinstance(obs_id, dict):
            obs_id = int(obs_id.get("id", 0))

        conn_check = get_conn()
        try:
            exists = conn_check.execute("SELECT id FROM observations WHERE id = ?", (obs_id,)).fetchone()
            if not exists:
                latest = conn_check.execute("SELECT MAX(id) as max_id FROM observations").fetchone()
                obs_id = int(latest["max_id"]) if latest and latest["max_id"] else 0
        finally:
            conn_check.close()

        text_lower = raw_text.lower()
        signals: dict[str, float] = {}
        reasons: list[str] = []

        if any(w in text_lower for w in ["urgent", "blocked", "suspended", "immediately", "disconnected", "overdue", "kyc", "electricity", "parcel"]):
            signals["lure_keywords"] = 0.35
            reasons.append("Urgency / fake KYC / utility disconnection lure")
        if any(w in text_lower for w in ["guaranteed", "daily return", "200%", "double", "profit", "betting", "referral", "vip pool", "mlm"]):
            signals["heuristic"] = 0.40
            reasons.append("Unrealistic guaranteed ROI / Ponzi-MLM or betting language")
        if any(tld in text_lower for tld in [".xyz", ".top", ".invalid", ".apk", ".tk", ".ml"]):
            signals["risky_tld"] = 0.30
            reasons.append("High-risk or unverified top-level domain extension")
        if any(w in text_lower for w in ["instant loan", "zero cibil", "processing fee", "loan approved", "stock tip", "trading app", "apk download"]):
            signals["loan_invest_lure"] = 0.35
            reasons.append("Fake instant-loan or fraudulent investment app lure")
        if "http://" in text_lower:
            signals["insecure_http"] = 0.20
            reasons.append("Unencrypted HTTP link (missing HTTPS)")

        crypto_matches = re.findall(r"\b(?:0x[a-fA-F0-9]{40}|T[A-Za-z1-9]{33}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", raw_text)
        if crypto_matches:
            signals["crypto_wallet"] = 0.35
            reasons.append(f"Contains cryptocurrency collection wallet ({crypto_matches[0][:12]}...)")

        matched_brand = "unknown"
        for b in load_brands():
            if b.lower() in text_lower:
                matched_brand = b.lower()
                signals["brand_keyword"] = 0.25
                reasons.append(f"Impersonates target entity: {b.upper()}")
                break

        vpa_matches = re.findall(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}", raw_text)
        phone_matches = re.findall(r"(?:\+91[\-\s]?)?[6-9]\d{9}", raw_text)
        url_matches = re.findall(r"https?://[^\s'\"<>]+", raw_text)

        if vpa_matches:
            signals["vpa_pattern"] = 0.30
            reasons.append("Contains UPI VPA payment identifier")
        if phone_matches:
            signals["phone_pattern"] = 0.20
            reasons.append("Contains unverified helpline / WhatsApp number")

        score = min(0.99, sum(signals.values()))
        label = "phish" if score >= 0.65 else ("suspicious" if score >= 0.30 else "benign")
        if not reasons:
            reasons.append("No high-risk fraud indicators detected")

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        conn = get_conn()
        linked_matches: list[dict[str, Any]] = []
        extracted: list[tuple[str, str]] = []

        try:
            conn.execute(
                """
                INSERT INTO verdicts (obs_id, label, score, brand, signals)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(obs_id) DO UPDATE SET
                    label = excluded.label, score = excluded.score,
                    brand = excluded.brand, signals = excluded.signals
                """,
                (obs_id, label, round(score, 2), matched_brand, json.dumps(signals)),
            )

            for vpa in set(vpa_matches):
                extracted.append(("vpa", vpa.lower()))
            for ph in set(phone_matches):
                extracted.append(("phone", re.sub(r"[\s\-]", "", ph)))
            for u in set(url_matches):
                host = urllib.parse.urlparse(u).netloc.lower()
                if host:
                    extracted.append(("domain", host))
            for cw in set(crypto_matches):
                extracted.append(("crypto_wallet", cw))

            for i_type, i_val in extracted:
                conn.execute("INSERT OR IGNORE INTO indicators (obs_id, type, value) VALUES (?, ?, ?)", (obs_id, i_type, i_val))

            all_inds = conn.execute("SELECT type, value FROM indicators WHERE obs_id = ?", (obs_id,)).fetchall()
            matched_obs_ids: set[int] = set()

            for ind in all_inds:
                i_type, i_val = ind["type"], ind["value"]
                prior = conn.execute(
                    "SELECT DISTINCT obs_id FROM indicators WHERE type = ? AND value = ? AND obs_id != ?",
                    (i_type, i_val, obs_id),
                ).fetchall()
                prior_ids = [r["obs_id"] for r in prior]
                if prior_ids:
                    matched_obs_ids.update(prior_ids)
                    linked_matches.append({"type": i_type, "value": i_val, "prior_obs": prior_ids})

            if matched_obs_ids and obs_id > 0:
                placeholders = ",".join("?" for _ in matched_obs_ids)
                existing_camp = conn.execute(
                    f"SELECT campaign_id FROM campaign_members WHERE obs_id IN ({placeholders}) LIMIT 1",
                    list(matched_obs_ids),
                ).fetchone()

                if existing_camp:
                    camp_id = existing_camp["campaign_id"]
                else:
                    camp_name = f"CAMP-{matched_brand.upper()}-{obs_id:03d}"
                    cur_c = conn.execute(
                        "INSERT INTO campaigns (name, size, brands, first_seen, last_seen, top_indicators) VALUES (?, ?, ?, ?, ?, ?)",
                        (camp_name, len(matched_obs_ids) + 1, json.dumps([matched_brand]), now_iso, now_iso, json.dumps([m["value"] for m in linked_matches[:3]])),
                    )
                    camp_id = cur_c.lastrowid

                for member_id in list(matched_obs_ids) + [obs_id]:
                    conn.execute("INSERT OR IGNORE INTO campaign_members (campaign_id, obs_id) VALUES (?, ?)", (camp_id, member_id))

                new_size = conn.execute("SELECT COUNT(DISTINCT obs_id) as cnt FROM campaign_members WHERE campaign_id = ?", (camp_id,)).fetchone()["cnt"]
                conn.execute("UPDATE campaigns SET size = ?, last_seen = ? WHERE id = ?", (new_size, now_iso, camp_id))

            conn.commit()
        finally:
            conn.close()

        return obs_id, label, score, matched_brand, reasons, extracted, linked_matches

    tab_url_sms, tab_web, tab_apk = st.tabs([
        "URL & Message Scanner",
        "Website & Ponzi Analyzer",
        "Android APK Uploader",
    ])

    with tab_url_sms:
        st.markdown('<div class="ui-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-kicker">Interactive Demo Presets — Click to Auto-Fill &amp; Test</div>', unsafe_allow_html=True)
        p1, p2, p3 = st.columns(3)
        with p1:
            if st.button("Preset 1: UPI KYC Phishing", key="p_upi", use_container_width=True):
                st.session_state["sms_input_box"] = (
                    "Dear Customer, your PhonePe UPI access has been blocked due to pending KYC update. "
                    "Complete verification immediately at https://phonepe-kyc-verify.xyz/login. "
                    "Helpline: +919876543210 or UPI pay refund@upi"
                )
        with p2:
            if st.button("Preset 2: Electricity Bill Scam", key="p_elec", use_container_width=True):
                st.session_state["sms_input_box"] = (
                    "URGENT: Your electricity connection will be disconnected tonight at 9:30 PM due to overdue bill. "
                    "Update immediately at http://jvvnl-bill-pay.top or call officer +919876543210"
                )
        with p3:
            if st.button("Preset 3: Safe Bank Alert", key="p_safe", use_container_width=True):
                st.session_state["sms_input_box"] = (
                    "Your SBI statement for October is ready. View securely on the official SBI YONO app."
                )

        sms_text = st.text_area(
            "Suspect URL or Message",
            key="sms_input_box",
            height=115,
            placeholder="Paste suspicious URL (https://...) or SMS / WhatsApp message to scan...",
            label_visibility="collapsed",
        )

        if st.button("Run Forensic URL / Message Scan", use_container_width=True, key="btn_sms"):
            if not sms_text.strip():
                st.warning("Enter a URL or message to scan.")
            else:
                raw_id = ingest_text(sms_text.strip(), source="sms")
                obs_id, label, score, brand, reasons, extracted, linked = classify_and_link_observation(raw_id, sms_text.strip(), "sms")
                risk_tier, badge_col, tint_bg = map_ps01_risk_tier(label, score)

                g_col, d_col = st.columns([4, 8])
                with g_col:
                    st.plotly_chart(render_risk_gauge(score, risk_tier, badge_col), use_container_width=True, config={"displayModeBar": False})
                with d_col:
                    st.markdown(
                        f'<div style="background:{tint_bg}; border:1px solid {badge_col}44; border-left:5px solid {badge_col}; border-radius:12px; padding:16px; margin-top:8px;">'
                        f'<div style="display:flex; justify-content:space-between; align-items:center;">'
                        f'<span style="color:{badge_col}; font-weight:800; font-size:16px;">{risk_tier} Verdict</span>'
                        f'<span class="mono" style="color:#334155; font-size:12px; font-weight:700;">Case #{obs_id} • Target: {brand.upper()}</span>'
                        f'</div>'
                        f'<div style="font-size:12.5px; font-weight:700; color:#0f172a; margin-top:10px;">Triggered Forensic Signals</div>'
                        f'<ul style="font-size:12.5px; color:#334155; margin-top:4px; padding-left:18px;">{"".join(f"<li>{r}</li>" for r in reasons)}</ul>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown('<div class="card-kicker" style="margin-top: 14px;">Extracted Identifiers</div>', unsafe_allow_html=True)
                    if extracted:
                        for i_t, i_v in extracted:
                            st.markdown(
                                f'<div style="background:#f8fafc; border:1px solid #dbeafe; border-radius:9px; padding:10px 14px; margin-bottom:6px;">'
                                f'<span style="color:#1d4ed8; font-size:11px; font-weight:800;">{i_t.upper()}</span> '
                                f'<span class="mono" style="font-size:12.5px; color:#0f172a; margin-left:8px;">{i_v}</span></div>',
                                unsafe_allow_html=True,
                            )
                    else:
                        st.markdown('<div style="color:#64748b; font-size:12.5px;">No identifiers extracted.</div>', unsafe_allow_html=True)

                with col_b:
                    st.markdown('<div class="card-kicker" style="margin-top: 14px;">Cross-Channel Syndicate Links</div>', unsafe_allow_html=True)
                    if linked:
                        for m in linked:
                            p_str = ", ".join(f"Case #{pid}" for pid in m["prior_obs"])
                            st.markdown(
                                f'<div style="background:#fef2f2; border:1px solid #fecaca; border-left:5px solid #dc2626; border-radius:9px; padding:10px 14px; margin-bottom:6px;">'
                                f'<div class="mono" style="font-weight:700; font-size:12.5px; color:#0f172a;">{m["type"].upper()}: {m["value"]}</div>'
                                f'<div style="color:#dc2626; font-size:11.5px; font-weight:700; margin-top:2px;">Correlated with {p_str}</div>'
                                f'</div>',
                                unsafe_allow_html=True,
                            )
                    else:
                        st.markdown('<div style="background:#eff6ff; border:1px solid #bfdbfe; border-radius:9px; padding:12px; color:#1e40af; font-size:12.5px;">Identifiers indexed. Future website or APK submissions sharing these values will link automatically.</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with tab_web:
        st.markdown('<div class="ui-card">', unsafe_allow_html=True)
        w_title, w_btn = st.columns([9, 3])
        with w_title:
            st.markdown('<div class="card-kicker">Upload / Scan Fraudulent Website URL &amp; Content</div>', unsafe_allow_html=True)
        with w_btn:
            if st.button("Load Ponzi Scam Website", key="preset_web", use_container_width=True):
                st.session_state["web_url_box"] = "https://fast-profit-club.top/join"
                st.session_state["web_body_box"] = (
                    "Guaranteed 200% daily return! Join our VIP pool and refer 3 friends for instant bonus. "
                    "Deposit via UPI: winbig@okicici, USDT TRC20: T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb, or WhatsApp +919876543210"
                )

        web_url = st.text_input("Website URL", key="web_url_box", placeholder="https://fast-profit-club.top/join")
        web_body = st.text_area("Page Text / Promotional Copy", key="web_body_box", height=105, placeholder="Paste website promotional text or payment handles...")

        if st.button("Run Website Forensic Scan", use_container_width=True, key="btn_web"):
            combined = f"{web_url.strip()} {web_body.strip()}".strip()
            if not combined:
                st.warning("Enter a website URL or text content.")
            else:
                raw_id = ingest_text(combined, source="web")
                obs_id, label, score, brand, reasons, extracted, linked = classify_and_link_observation(raw_id, combined, "web")
                risk_tier, badge_col, tint_bg = map_ps01_risk_tier(label, score)

                g_col, d_col = st.columns([4, 8])
                with g_col:
                    st.plotly_chart(render_risk_gauge(score, risk_tier, badge_col), use_container_width=True, config={"displayModeBar": False})
                with d_col:
                    st.markdown(
                        f'<div style="background:{tint_bg}; border:1px solid {badge_col}44; border-left:5px solid {badge_col}; border-radius:12px; padding:16px; margin-top:8px;">'
                        f'<div style="display:flex; justify-content:space-between; align-items:center;">'
                        f'<span style="color:{badge_col}; font-weight:800; font-size:16px;">{risk_tier} Verdict</span>'
                        f'<span class="mono" style="color:#334155; font-size:12px; font-weight:700;">Case #{obs_id}</span>'
                        f'</div>'
                        f'<ul style="font-size:12.5px; color:#334155; margin-top:8px; padding-left:18px;">{"".join(f"<li>{r}</li>" for r in reasons)}</ul>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
                if linked:
                    for m in linked:
                        p_str = ", ".join(f"Case #{pid}" for pid in m["prior_obs"])
                        st.markdown(
                            f'<div style="background:#fef2f2; border:1px solid #fecaca; border-left:5px solid #dc2626; border-radius:9px; padding:10px 14px; margin-top:8px;">'
                            f'<div class="mono" style="font-weight:700; font-size:12.5px;">{m["type"].upper()}: {m["value"]}</div>'
                            f'<div style="color:#dc2626; font-size:11.5px; font-weight:700;">Cross-Channel Match — Linked to {p_str}</div>'
                            f'</div>',
                            unsafe_allow_html=True,
                        )
        st.markdown("</div>", unsafe_allow_html=True)

    with tab_apk:
        st.markdown('<div class="ui-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-kicker">Upload Android APK Package for Static Scanning</div>', unsafe_allow_html=True)
        uploaded_apk = st.file_uploader("Upload Android Package (.apk)", type=["apk", "zip"])
        if uploaded_apk is not None:
            apk_bytes = uploaded_apk.read()
            sha256_hash = hashlib.sha256(apk_bytes).hexdigest()
            extracted_urls: set[str] = set()
            extracted_perms: set[str] = set()
            dex_count = 0

            try:
                with zipfile.ZipFile(io.BytesIO(apk_bytes), "r") as zf:
                    for name in zf.namelist():
                        if name.endswith(".dex"):
                            dex_count += 1
                        if name == "AndroidManifest.xml" or name.endswith(".dex"):
                            data_str = zf.read(name).decode("latin-1", errors="ignore")
                            for u in re.findall(r"https?://[a-zA-Z0-9.\-_/:?=&%]+", data_str):
                                if not any(ok_d in u for ok_d in ["schemas.android.com", "googleapis.com", "w3.org"]):
                                    extracted_urls.add(u[:120])
                            for perm in re.findall(r"android\.permission\.[A-Z_]+", data_str):
                                extracted_perms.add(perm)
            except Exception as exc:
                st.error(f"Could not read APK archive: {exc}")

            dangerous_set = {
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.SEND_SMS",
                "android.permission.READ_CONTACTS",
                "android.permission.CAMERA",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_INSTALL_PACKAGES",
            }
            flagged_perms = sorted(extracted_perms.intersection(dangerous_set))
            apk_score = min(0.99, 0.25 + 0.18 * len(flagged_perms) + (0.25 if extracted_urls else 0.0))
            apk_label = "phish" if apk_score >= 0.65 else ("suspicious" if apk_score >= 0.30 else "benign")
            risk_tier, badge_col, tint_bg = map_ps01_risk_tier(apk_label, apk_score)

            g_col, d_col = st.columns([4, 8])
            with g_col:
                st.plotly_chart(render_risk_gauge(apk_score, risk_tier, badge_col), use_container_width=True, config={"displayModeBar": False})
            with d_col:
                st.markdown(
                    f'<div style="background:{tint_bg}; border:1px solid {badge_col}44; border-left:5px solid {badge_col}; border-radius:12px; padding:16px; margin-top:8px;">'
                    f'<div style="display:flex; justify-content:space-between;">'
                    f'<span style="color:{badge_col}; font-weight:800; font-size:16px;">{risk_tier} APK Verdict</span>'
                    f'<span class="mono" style="color:#475569; font-size:11.5px; font-weight:700;">DEX Bytecode Files: {dex_count}</span>'
                    f'</div>'
                    f'<div class="mono" style="font-size:11.5px; color:#334155; margin-top:10px; word-break:break-all;">SHA-256: {sha256_hash}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

            p_col, u_col = st.columns(2)
            with p_col:
                st.markdown('<div class="card-kicker" style="margin-top: 14px;">Sensitive Permissions</div>', unsafe_allow_html=True)
                for fp in flagged_perms:
                    st.markdown(f'<div class="mono" style="color:#dc2626; font-size:12px; margin-bottom:4px;">{fp}</div>', unsafe_allow_html=True)
            with u_col:
                st.markdown('<div class="card-kicker" style="margin-top: 14px;">Embedded Endpoints</div>', unsafe_allow_html=True)
                for eu in sorted(extracted_urls)[:15]:
                    st.markdown(f'<div class="mono" style="color:#0f172a; font-size:11.5px; word-break:break-all; margin-bottom:4px;">{eu}</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)


# ===========================================================================
# MODULE 2: CASE HISTORY
# ===========================================================================
elif nav == "Case History":
    render_interactive_telemetry_charts(total_count, flagged_count, camps_count, takedown_count, df_obs)
    if df_obs.empty:
        st.info("No case records found matching active filters.")
    else:
        left_col, right_col = st.columns([7, 5])
        with left_col:
            st.markdown('<div class="ui-card">', unsafe_allow_html=True)
            st.markdown('<div class="card-kicker">Interactive Case Queue</div>', unsafe_allow_html=True)
            search_q = st.text_input("Search", placeholder="Filter by domain, brand, campaign ID, or case number...", label_visibility="collapsed")
            if search_q.strip():
                q_low = search_q.strip().lower()
                df_obs = df_obs[
                    df_obs["url"].astype(str).str.lower().str.contains(q_low, na=False)
                    | df_obs["campaign"].astype(str).str.lower().str.contains(q_low, na=False)
                    | df_obs["brand"].astype(str).str.lower().str.contains(q_low, na=False)
                    | df_obs["id"].astype(str).str.contains(q_low, na=False)
                ]

            display_df = df_obs[["id", "first_seen", "source", "url", "label", "score", "campaign", "brand"]].copy()
            display_df["label"] = display_df.apply(lambda r: map_ps01_risk_tier(r["label"], float(r["score"]))[0], axis=1)
            display_df.rename(
                columns={"id": "Case", "first_seen": "Timestamp", "source": "Channel", "url": "Host / Artifact", "label": "Risk Tier", "score": "Score", "campaign": "Campaign", "brand": "Target"},
                inplace=True,
            )
            display_df["Score"] = display_df["Score"].apply(lambda s: f"{float(s):.2f}")
            display_df["Channel"] = display_df["Channel"].apply(lambda c: str(c).upper())
            display_df["Campaign"] = display_df["Campaign"].fillna("—")
            display_df["Host / Artifact"] = display_df["Host / Artifact"].apply(lambda u: urllib.parse.urlparse(str(u)).netloc or str(u))

            event = st.dataframe(display_df, use_container_width=True, height=490, hide_index=True, on_select="rerun", selection_mode="single-row", key="rh_case_table")
            selected_rows = getattr(event.selection, "rows", []) if event and hasattr(event, "selection") else []
            selected_id = int(display_df.iloc[selected_rows[0]]["Case"]) if selected_rows else (int(display_df.iloc[0]["Case"]) if not display_df.empty else None)
            st.markdown("</div>", unsafe_allow_html=True)

        with right_col:
            st.markdown('<div class="ui-card">', unsafe_allow_html=True)
            st.markdown('<div class="card-kicker">Forensic Case Inspector</div>', unsafe_allow_html=True)
            if selected_id is not None:
                sel_row = df_obs[df_obs["id"] == selected_id].iloc[0]
                score_val = float(sel_row["score"])
                url_val = str(sel_row["url"])
                risk_tier, lbl_color, tint_bg = map_ps01_risk_tier(str(sel_row["label"]), score_val)

                st.plotly_chart(render_risk_gauge(score_val, risk_tier, lbl_color), use_container_width=True, config={"displayModeBar": False})
                st.markdown(
                    f'<div style="background:{tint_bg}; border:1px solid {lbl_color}44; border-radius:10px; padding:12px;">'
                    f'<div style="display:flex; justify-content:space-between; align-items:center;">'
                    f'<span style="font-weight:800; font-size:14.5px; color:#0f172a;">Case #{selected_id}</span>'
                    f'<span style="color:{lbl_color}; font-weight:700; font-size:12px;">{risk_tier}</span>'
                    f'</div>'
                    f'<div class="mono" style="color:#334155; font-size:12px; margin-top:6px; word-break:break-all;">{url_val}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

                st.markdown('<div class="card-kicker" style="margin-top:16px;">Associated Indicators</div>', unsafe_allow_html=True)
                conn = get_conn()
                try:
                    ind_rows = conn.execute("SELECT type, value FROM indicators WHERE obs_id = ?", (selected_id,)).fetchall()
                finally:
                    conn.close()

                if ind_rows:
                    ind_html = "".join(
                        f'<div style="padding:7px 11px; background:#f8fafc; border:1px solid #dbeafe; border-radius:7px; margin-bottom:6px;">'
                        f'<span style="color:#1d4ed8; font-size:11px; font-weight:800;">{r["type"].upper()}</span> '
                        f'<span class="mono" style="font-size:12px; color:#0f172a; margin-left:6px;">{r["value"]}</span></div>'
                        for r in ind_rows
                    )
                    st.markdown(ind_html, unsafe_allow_html=True)
                else:
                    st.markdown('<div style="color:#64748b; font-size:12.5px;">No extracted identifiers for this record.</div>', unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)


# ===========================================================================
# MODULE 3: CAMPAIGN LINKS
# ===========================================================================
elif nav == "Campaign Links":
    conn = get_conn()
    try:
        camps = [dict(r) for r in conn.execute("SELECT id, name, size, brands, first_seen, last_seen FROM campaigns ORDER BY size DESC").fetchall()]
    finally:
        conn.close()

    if not camps:
        st.info("No linked campaigns yet. Analyze related artifacts in Intake & Scanner to generate cluster links.")
    else:
        left_c, right_c = st.columns([4, 8])
        with left_c:
            st.markdown('<div class="ui-card">', unsafe_allow_html=True)
            st.markdown('<div class="card-kicker">Linked Syndicate Clusters</div>', unsafe_allow_html=True)
            selected_camp_name = st.radio("Select Cluster", [c["name"] for c in camps], label_visibility="collapsed")
            selected_camp = next(c for c in camps if c["name"] == selected_camp_name)
            st.markdown(
                f'<div style="background:#eff6ff; border:1px solid #bfdbfe; border-radius:10px; padding:14px; margin-top:12px;">'
                f'<div style="font-size:15px; font-weight:800; color:#071936;">{selected_camp["name"]}</div>'
                f'<div style="font-size:12.5px; color:#334155; margin-top:6px;">Linked Records: <b style="color:#1d4ed8;">{selected_camp["size"]}</b></div>'
                f'<div style="font-size:12.5px; color:#334155; margin-top:2px;">Window: <span class="mono">{str(selected_camp["first_seen"])[:10]}</span> to <span class="mono">{str(selected_camp["last_seen"])[:10]}</span></div>'
                f'</div>',
                unsafe_allow_html=True,
            )
            st.markdown("</div>", unsafe_allow_html=True)
        with right_c:
            st.markdown('<div class="ui-card">', unsafe_allow_html=True)
            st.markdown('<div class="card-kicker">Interactive Infrastructure Attribution Graph</div>', unsafe_allow_html=True)
            net = build_viz_graph(selected_camp["id"])
            if net:
                components.html(net.generate_html(), height=480)
            st.markdown("</div>", unsafe_allow_html=True)


# ===========================================================================
# MODULE 4: EVIDENCE REPORT
# ===========================================================================
elif nav == "Evidence Report":
    st.markdown('<div class="ui-card">', unsafe_allow_html=True)
    st.markdown('<div class="card-kicker">R4C Investigation Dossier Export</div>', unsafe_allow_html=True)
    conn = get_conn()
    try:
        camps = [dict(r) for r in conn.execute("SELECT id, name, size, brands, first_seen, last_seen, top_indicators FROM campaigns ORDER BY size DESC").fetchall()]
    finally:
        conn.close()

    if camps:
        c_choice = st.selectbox("Select Campaign Cluster", [f"{c['name']} ({c['size']} linked cases)" for c in camps])
        sel_c = camps[[f"{c['name']} ({c['size']} linked cases)" for c in camps].index(c_choice)]
        pdf_path: Path | None = None
        try:
            res = str(generate_takedown(campaign_id=sel_c["id"]))
            if res.lower().endswith(".pdf") and Path(res).exists():
                pdf_path = Path(res)
        except Exception:
            pass

        report_md = (
            f"# R4C Rajasthan Police — Cyber Fraud Investigation Dossier\n\n"
            f"- **Campaign Reference:** `{sel_c['name']}` (Cluster ID: `{sel_c['id']}`)\n"
            f"- **Linked Observations:** `{sel_c['size']}`\n"
            f"- **Targeted Entities:** `{sel_c['brands']}`\n"
            f"- **Shared Anchors:** `{sel_c['top_indicators']}`\n"
            f"- **Active Window (UTC):** `{sel_c['first_seen']}` to `{sel_c['last_seen']}`\n"
            f"- **Recommended Action:** Issue Section 91 notice to freeze linked UPI VPAs, block mobile numbers, and suspend registrar domains.\n"
        )

        col_dl1, col_dl2 = st.columns(2)
        with col_dl1:
            if pdf_path and pdf_path.exists():
                st.download_button("Download PDF Dossier", data=pdf_path.read_bytes(), file_name=pdf_path.name, mime="application/pdf", use_container_width=True)
        with col_dl2:
            st.download_button("Download Markdown Dossier (.md)", data=report_md, file_name=f"R4C_{sel_c['name']}.md", mime="text/markdown", use_container_width=True)

        st.markdown(f'<div style="background:#f8fafc; border:1px solid #dbeafe; border-radius:10px; padding:16px; margin-top:14px;">{report_md}</div>', unsafe_allow_html=True)
    else:
        st.info("No correlated campaigns available yet.")
    st.markdown("</div>", unsafe_allow_html=True)


# ===========================================================================
# MODULE 5: THREAT HEAT-LIST
# ===========================================================================
elif nav == "Threat Heat-List":
    st.markdown('<div class="card-kicker">Frequently Reported Scam Identifiers &amp; Impersonated Brands</div>', unsafe_allow_html=True)
    conn = get_conn()
    try:
        top_inds = [dict(r) for r in conn.execute("SELECT UPPER(type) as Type, value as Identifier, COUNT(DISTINCT obs_id) as Cases FROM indicators GROUP BY type, value ORDER BY Cases DESC LIMIT 25").fetchall()]
        brand_counts = [dict(r) for r in conn.execute("SELECT UPPER(brand) as Brand, COUNT(*) as Detections FROM verdicts WHERE label IN ('phish', 'suspicious') AND brand != 'unknown' GROUP BY brand ORDER BY Detections DESC").fetchall()]
    finally:
        conn.close()

    m1, m2 = st.columns([7, 5])
    with m1:
        st.markdown('<div class="ui-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-kicker">Top Reused Fraud Indicators</div>', unsafe_allow_html=True)
        if top_inds:
            st.dataframe(pd.DataFrame(top_inds), use_container_width=True, height=420, hide_index=True)
        st.markdown("</div>", unsafe_allow_html=True)
    with m2:
        st.markdown('<div class="ui-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-kicker">Targeted Entity Breakdown</div>', unsafe_allow_html=True)
        if brand_counts:
            st.dataframe(pd.DataFrame(brand_counts), use_container_width=True, height=420, hide_index=True)
        st.markdown("</div>", unsafe_allow_html=True)