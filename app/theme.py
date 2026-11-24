"""
CloneTrace Central Design System & Theme Tokens.
Reused across Streamlit UI, PyVis graph visualizations, and Takedown PDF reports.
"""

from __future__ import annotations

# Core Palette (Linear / SOC Work Surface)
BG = "#0F1115"
SURFACE = "#171A21"
BORDER = "#262B35"
TEXT = "#E6E8EC"
MUTED = "#8A91A0"
ACCENT = "#4C8DFF"     # Selection / Primary
DANGER = "#E5484D"     # Phish / High Risk
WARNING = "#F5A524"    # Suspicious / Medium Risk
OK = "#30A46C"         # Benign / Verified Clean

# Semantic Label Colors
LABEL_COLORS = {
    "phish": DANGER,
    "suspicious": WARNING,
    "benign": OK,
    "unknown": MUTED,
}

# Indicator Colors by Type (for PyVis & Dossier)
INDICATOR_TYPE_COLORS = {
    "vpa": "#9D5BD2",          # Purple
    "phone": "#2ECC71",        # Emerald
    "tg_bot": "#2AABEE",       # Telegram Blue
    "tg_handle": "#0088CC",    # Telegram Handle
    "apk_cert": "#F39C12",     # Amber/Orange
    "apk_hash": "#E67E22",     # Dark Orange
    "kit_hash": "#E74C3C",     # Crimson
    "favicon_hash": "#FF7675",  # Coral
    "cert_fp": "#6C5CE7",      # Violet
    "nameserver": "#74B9FF",   # Light Blue
    "ip": "#8A91A0",           # Infrastructure Gray
    "asn": "#636E72",          # Charcoal Gray
    "registrar": "#B2BEC3",    # Silver Gray
}

def get_indicator_color(ind_type: str) -> str:
    return INDICATOR_TYPE_COLORS.get(ind_type, MUTED)

def get_label_color(label: str) -> str:
    return LABEL_COLORS.get(str(label).lower(), MUTED)

# Global Streamlit CSS Injection
CUSTOM_CSS = f"""
<style>
/* Hide default Streamlit chrome */
#MainMenu {{visibility: hidden !important;}}
header {{visibility: hidden !important;}}
footer {{visibility: hidden !important;}}

/* Root container styling */
.stApp {{
    background-color: {BG} !important;
    color: {TEXT} !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}}

/* Sidebar tightening */
section[data-testid="stSidebar"] {{
    background-color: {SURFACE} !important;
    border-right: 1px solid {BORDER} !important;
    padding-top: 1rem !important;
}}

/* Dense header adjustments */
.block-container {{
    padding-top: 1.5rem !important;
    padding-bottom: 2rem !important;
    padding-left: 2rem !important;
    padding-right: 2rem !important;
    max-width: 100% !important;
}}

/* Metrics styling */
div[data-testid="stMetric"] {{
    background-color: {SURFACE} !important;
    border: 1px solid {BORDER} !important;
    border-radius: 2px !important;
    padding: 0.5rem 1rem !important;
}}

div[data-testid="stMetricLabel"] {{
    color: {MUTED} !important;
    font-size: 12px !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em !important;
}}

div[data-testid="stMetricValue"] {{
    color: {TEXT} !important;
    font-size: 20px !important;
    font-weight: 600 !important;
}}

/* Monospace tokens */
.mono {{
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace !important;
    font-size: 13px !important;
}}

/* Detail panel card */
.panel-box {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 2px;
    padding: 12px 16px;
    margin-bottom: 12px;
}}

.panel-title {{
    color: {MUTED};
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 8px;
}}

/* Table overrides */
.stDataFrame {{
    border: 1px solid {BORDER} !important;
}}
</style>
"""
