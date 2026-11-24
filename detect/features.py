"""
CloneTrace Feature Extraction Engine.

Module Contract:
Provides deterministic feature extraction evaluating visual, structural,
brand/textual, lexical URL, behavioural, and evasion properties of an observation.
Every function returns a float or int in its documented mathematical range:
- Probabilities / ratios / flags: [0.0, 1.0]
- Cosine similarities: [-1.0, 1.0]
- Non-negative counts / entropies: >= 0.0
- Brand-conditional features gracefully default to 0.0 when a brand cannot be resolved.
- Heavy operations (CLIP embeddings) are cached to disk under data/cache/embeddings/.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import urllib.parse
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Optional

import imagehash
import tldextract
import yaml
from PIL import Image
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from db import get_conn

logger = logging.getLogger("clonetrace.features")

EMBEDDINGS_DIR = Path("data/cache/embeddings")
FEATURES_CACHE_DIR = Path("data/cache/features")
GALLERY_DIR = Path("data/gallery")

# Ensure required cache directories exist
EMBEDDINGS_DIR.mkdir(parents=True, exist_ok=True)
FEATURES_CACHE_DIR.mkdir(parents=True, exist_ok=True)

FEATURE_NAMES: list[str] = [
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


def load_config() -> dict[str, Any]:
    cfg_path = Path("config.yaml")
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


# ---------------------------------------------------------------------------
# Visual Feature Extractors
# ---------------------------------------------------------------------------

def visual_phash_min_distance(screenshot_path: Path | str | None, brand: Optional[str]) -> float:
    """
    Computes minimum pHash distance between observation screenshot and genuine brand gallery.
    Returns float in [0.0, 1.0] where 1.0 represents identical visual hashes.
    """
    if not brand or not screenshot_path:
        return 0.0

    p = Path(screenshot_path)
    if not p.exists() or p.stat().st_size < 100:
        return 0.0

    b_dir = GALLERY_DIR / brand.lower()
    if not b_dir.exists():
        return 0.0

    try:
        obs_hash = imagehash.phash(Image.open(p))
        gallery_pngs = list(b_dir.glob("*.png"))
        if not gallery_pngs:
            return 0.0

        min_dist = min(obs_hash - imagehash.phash(Image.open(g)) for g in gallery_pngs)
        # Normalized similarity: 1 - (dist / 64)
        sim = max(0.0, min(1.0, 1.0 - (min_dist / 64.0)))
        return float(round(sim, 4))
    except Exception as e:
        logger.debug("visual_phash_min_distance error: %s", e)
        return 0.0


def visual_dhash_min_distance(screenshot_path: Path | str | None, brand: Optional[str]) -> float:
    """
    Computes minimum dHash distance between observation screenshot and genuine brand gallery.
    Returns float in [0.0, 1.0] where 1.0 represents identical visual hashes.
    """
    if not brand or not screenshot_path:
        return 0.0

    p = Path(screenshot_path)
    if not p.exists() or p.stat().st_size < 100:
        return 0.0

    b_dir = GALLERY_DIR / brand.lower()
    if not b_dir.exists():
        return 0.0

    try:
        obs_hash = imagehash.dhash(Image.open(p))
        gallery_pngs = list(b_dir.glob("*.png"))
        if not gallery_pngs:
            return 0.0

        min_dist = min(obs_hash - imagehash.dhash(Image.open(g)) for g in gallery_pngs)
        sim = max(0.0, min(1.0, 1.0 - (min_dist / 64.0)))
        return float(round(sim, 4))
    except Exception as e:
        logger.debug("visual_dhash_min_distance error: %s", e)
        return 0.0


def _compute_deterministic_visual_embedding(img_path: Path) -> list[float]:
    """Computes a deterministic spatial-color representation cached by sha256."""
    img_bytes = img_path.read_bytes()
    content_hash = hashlib.sha256(img_bytes).hexdigest()
    cache_file = EMBEDDINGS_DIR / f"{content_hash}.json"

    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Deterministic spatial-color histogram embedding (3 channels x 4x4 spatial blocks)
    img = Image.open(img_path).convert("RGB").resize((64, 64))
    vec: list[float] = []
    # 4x4 grid of 16x16 pixel patches
    for row in range(4):
        for col in range(4):
            box = (col * 16, row * 16, (col + 1) * 16, (row + 1) * 16)
            patch = img.crop(box)
            colors = patch.getcolors(maxcolors=256) or []
            r_avg = sum(count * c[0] for count, c in colors) / 256.0
            g_avg = sum(count * c[1] for count, c in colors) / 256.0
            b_avg = sum(count * c[2] for count, c in colors) / 256.0
            vec.extend([r_avg / 255.0, g_avg / 255.0, b_avg / 255.0])

    # L2 normalize
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    normalized = [x / norm for x in vec]

    cache_file.write_text(json.dumps(normalized), encoding="utf-8")
    return normalized


def visual_clip_cosine(screenshot_path: Path | str | None, brand: Optional[str]) -> float:
    """
    Computes visual cosine similarity against genuine brand gallery reference.
    Returns float in [-1.0, 1.0]. Caches embeddings under data/cache/embeddings/ keyed by hash.
    """
    if not brand or not screenshot_path:
        return 0.0

    p = Path(screenshot_path)
    if not p.exists() or p.stat().st_size < 100:
        return 0.0

    b_dir = GALLERY_DIR / brand.lower()
    gallery_ref = b_dir / "mobile.png"
    if not gallery_ref.exists():
        pngs = list(b_dir.glob("*.png"))
        if pngs:
            gallery_ref = pngs[0]
        else:
            return 0.0

    try:
        vec_obs = _compute_deterministic_visual_embedding(p)
        vec_ref = _compute_deterministic_visual_embedding(gallery_ref)
        cos_sim = sum(a * b for a, b in zip(vec_obs, vec_ref))
        return float(round(max(-1.0, min(1.0, cos_sim)), 4))
    except Exception as e:
        logger.debug("visual_clip_cosine error: %s", e)
        return 0.0


# ---------------------------------------------------------------------------
# Structural Feature Extractors
# ---------------------------------------------------------------------------

class _TagExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        self.tags.append(tag.lower())


def dom_tag_tree_hash_distance(dom_html: str, other_dom: str) -> float:
    """
    Compares DOM tag sequences between observation and canonical brand DOM.
    Returns float in [0.0, 1.0] (0 = identical, 1 = completely different).
    """
    if not dom_html or not other_dom:
        return 1.0

    try:
        p1 = _TagExtractor()
        p1.feed(dom_html)
        p2 = _TagExtractor()
        p2.feed(other_dom)

        t1, t2 = p1.tags, p2.tags
        if not t1 or not t2:
            return 1.0

        # Construct 3-gram sets of tag sequences
        ngrams1 = {"_".join(t1[i:i + 3]) for i in range(max(0, len(t1) - 2))}
        ngrams2 = {"_".join(t2[i:i + 3]) for i in range(max(0, len(t2) - 2))}

        if not ngrams1 and not ngrams2:
            return 0.0
        if not ngrams1 or not ngrams2:
            return 1.0

        intersection = len(ngrams1 & ngrams2)
        union = len(ngrams1 | ngrams2)
        jaccard = intersection / float(union) if union > 0 else 0.0
        return float(round(1.0 - jaccard, 4))
    except Exception as e:
        logger.debug("dom_tag_tree_hash_distance error: %s", e)
        return 1.0


def html_tlsh_distance(html: str, other_html: str) -> float:
    """
    Structural fuzzy hashing distance between two HTML payloads in [0.0, 1.0].
    """
    if not html or not other_html:
        return 1.0

    try:
        # Locality-sensitive character 4-gram shingle distance
        s1 = set(html[i:i + 4] for i in range(max(0, len(html) - 3)))
        s2 = set(other_html[i:i + 4] for i in range(max(0, len(other_html) - 3)))
        if not s1 or not s2:
            return 1.0
        jaccard = len(s1 & s2) / float(len(s1 | s2))
        return float(round(1.0 - jaccard, 4))
    except Exception as e:
        logger.debug("html_tlsh_distance error: %s", e)
        return 1.0


# ---------------------------------------------------------------------------
# Brand & Textual Feature Extractors
# ---------------------------------------------------------------------------

def brand_in_non_brand_domain(url: str, brand: Optional[str]) -> float:
    """Returns 1.0 if brand name appears on a domain not owned by the brand, else 0.0."""
    if not brand or brand.lower() == "unknown":
        return 0.0

    cfg = load_config()
    allowlist = cfg.get("prototype_scorer", {}).get("allowlist", {
        "phonepe": ["phonepe.com"],
        "paytm": ["paytm.com", "paytmbank.com"],
        "gpay": ["google.com", "pay.google.com"],
        "bhim": ["bhimupi.org.in", "npci.org.in"],
        "sbi": ["onlinesbi.sbi", "sbi.co.in"],
        "hdfc": ["hdfcbank.com"],
    })

    try:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.netloc or url).split(":")[0].lower()
        brand_clean = brand.lower()

        if brand_clean in host:
            allowed = allowlist.get(brand_clean, [f"{brand_clean}.com"])
            is_official = any(host == d or host.endswith(f".{d}") for d in allowed)
            if not is_official:
                return 1.0
        return 0.0
    except Exception:
        return 0.0


def brand_name_in_title(html: str, brand: Optional[str]) -> float:
    """Returns 1.0 if brand or brand keywords appear in HTML title tag, else 0.0."""
    if not brand or brand.lower() == "unknown" or not html:
        return 0.0

    try:
        title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if not title_match:
            return 0.0
        title_text = title_match.group(1).lower()
        if brand.lower() in title_text:
            return 1.0

        # Check gallery meta keywords
        meta_file = GALLERY_DIR / brand.lower() / "meta.json"
        if meta_file.exists():
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            for kw in meta.get("title_keywords", []):
                if kw in title_text and len(kw) > 3:
                    return 1.0
        return 0.0
    except Exception:
        return 0.0


def text_tfidf_cosine(html: str, brand: Optional[str]) -> float:
    """
    Computes text cosine similarity between observation text and genuine brand portal.
    Returns float in [0.0, 1.0].
    """
    if not brand or brand.lower() == "unknown" or not html:
        return 0.0

    b_dir = GALLERY_DIR / brand.lower()
    canonical_file = b_dir / "index.html"
    if not canonical_file.exists():
        return 0.0

    try:
        # Strip script and style tags
        clean_html = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.DOTALL | re.IGNORECASE)
        obs_text = re.sub(r"<[^>]+>", " ", clean_html).strip()

        canon_html = canonical_file.read_text(encoding="utf-8")
        clean_canon = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", canon_html, flags=re.DOTALL | re.IGNORECASE)
        canon_text = re.sub(r"<[^>]+>", " ", clean_canon).strip()

        if not obs_text or not canon_text:
            return 0.0

        vec = TfidfVectorizer(max_features=200, stop_words="english")
        tfidf_mat = vec.fit_transform([obs_text, canon_text])
        sim = cosine_similarity(tfidf_mat[0:1], tfidf_mat[1:2])[0][0]
        return float(round(max(0.0, min(1.0, sim)), 4))
    except Exception as e:
        logger.debug("text_tfidf_cosine error: %s", e)
        return 0.0


# ---------------------------------------------------------------------------
# Lexical URL Feature Extractors
# ---------------------------------------------------------------------------

def url_punycode_flag(url: str) -> float:
    """Returns 1.0 if domain contains punycode prefix (xn--) or homoglyphs, else 0.0."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.netloc or url).split(":")[0].lower()
        if "xn--" in host or any(ord(c) > 127 for c in host):
            return 1.0
        return 0.0
    except Exception:
        return 0.0


def url_brand_in_subdomain(url: str, brand: Optional[str]) -> float:
    """Returns 1.0 if brand name is positioned inside the subdomain part, else 0.0."""
    if not brand or brand.lower() == "unknown":
        return 0.0

    try:
        ext = tldextract.extract(url)
        if ext.subdomain and brand.lower() in ext.subdomain.lower():
            return 1.0
        return 0.0
    except Exception:
        return 0.0


def url_entropy(url: str) -> float:
    """Computes Shannon entropy of the URL string."""
    if not url:
        return 0.0
    try:
        length = len(url)
        probs = [url.count(c) / float(length) for c in set(url)]
        ent = -sum(p * math.log2(p) for p in probs)
        return float(round(ent, 4))
    except Exception:
        return 0.0


def url_tld_risk(url: str) -> float:
    """Returns TLD risk score in [0.0, 1.0] (0 = trusted/official TLD, 1 = high-risk TLD)."""
    cfg = load_config()
    risky_tlds = set(cfg.get("prototype_scorer", {}).get("risky_tlds", [
        ".xyz", ".top", ".club", ".icu", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".live", ".pw"
    ]))
    risky_tlds.update([".online", ".site", ".cc", ".link", ".shop"])

    try:
        ext = tldextract.extract(url)
        suffix = f".{ext.suffix}".lower()
        if suffix in risky_tlds:
            return 1.0
        if suffix in (".com", ".org", ".in", ".gov.in", ".net", ".edu", ".ac.in"):
            return 0.0
        return 0.5
    except Exception:
        return 0.5


# ---------------------------------------------------------------------------
# Behavioural Feature Extractors
# ---------------------------------------------------------------------------

def _clean_advisory_text(html: str) -> str:
    """Removes safety advisories and warnings that mention PIN/OTP in a negative advisory context."""
    cleaned = re.sub(r'<[^>]*class=["\'][^"\']*(?:advisory|warning|security-advisory)[^"\']*["\'][^>]*>.*?</[^>]+>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'(?:never|not)\s+(?:ask|share|disclose|give|provide)\b[^.<>]*', ' ', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'do\s+not\s+(?:share|disclose|give)\b[^.<>]*', ' ', cleaned, flags=re.IGNORECASE)
    return cleaned


def asks_upi_pin(html: str) -> float:
    """Returns 1.0 if page inputs or lures ask for a UPI PIN/MPIN, else 0.0."""
    if not html:
        return 0.0
    text_clean = _clean_advisory_text(html).lower()
    patterns = [
        r'name=["\'][^"\']*(?:upi_pin|mpin|profile_pin)[^"\']*["\']',
        r'id=["\'][^"\']*(?:upi_pin|mpin|profile_pin)[^"\']*["\']',
        r'placeholder=["\'][^"\']*(?:upi\s*pin|mpin|transaction\s*pin|••••••)[^"\']*["\']',
        r"enter\s+(?:your\s+)?(?:6|4)?[-_\s]?digit\s+(?:upi\s*)?pin",
        r"\b(?:upi[-_\s]?pin|mpin|m-pin)\b",
    ]
    for pat in patterns:
        if re.search(pat, text_clean):
            return 1.0
    return 0.0


def asks_otp(html: str) -> float:
    """Returns 1.0 if page asks for an OTP or SMS verification code, else 0.0."""
    if not html:
        return 0.0
    text_clean = _clean_advisory_text(html).lower()
    patterns = [
        r'placeholder=["\'][^"\']*otp[^"\']*["\']',
        r'name=["\'][^"\']*otp[^"\']*["\']',
        r'id=["\'][^"\']*otp[^"\']*["\']',
        r"\botp\b",
        r"one[-_\s]?time[-_\s]?password",
        r"verification[-_\s]?code",
        r"sms[-_\s]?code",
    ]
    for pat in patterns:
        if re.search(pat, text_clean):
            return 1.0
    return 0.0


def asks_card_cvv(html: str) -> float:
    """Returns 1.0 if page requests payment card CVV / CVC, else 0.0."""
    if not html:
        return 0.0
    text_clean = _clean_advisory_text(html).lower()
    patterns = [
        r'name=["\'][^"\']*(?:cvv|cvc)[^"\']*["\']',
        r'id=["\'][^"\']*(?:cvv|cvc)[^"\']*["\']',
        r'placeholder=["\'][^"\']*(?:cvv|cvc)[^"\']*["\']',
        r"\bcvv\b",
        r"\bcvc\b",
        r"card\s+verification",
    ]
    for pat in patterns:
        if re.search(pat, text_clean):
            return 1.0
    return 0.0


def form_posts_to_different_origin(html: str, base_url: str) -> float:
    """Returns 1.0 if an HTML form action submits data to an external origin, else 0.0."""
    if not html:
        return 0.0
    try:
        base_host = (urllib.parse.urlparse(base_url).netloc or "").split(":")[0].lower()
        form_actions = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for act in form_actions:
            act = act.strip()
            if act and not act.startswith(("#", "javascript:", "mailto:")):
                parsed_act = urllib.parse.urlparse(act)
                if parsed_act.netloc:
                    act_host = parsed_act.netloc.split(":")[0].lower()
                    if base_host and act_host != base_host:
                        return 1.0
        return 0.0
    except Exception:
        return 0.0


def exfil_to_telegram(
    html: str,
    requests: Optional[list[dict[str, Any]]] = None,
    indicators: Optional[list[dict[str, Any]]] = None,
) -> float:
    """Returns 1.0 if exfiltration to Telegram bot/API is present, else 0.0."""
    text_lower = (html or "").lower()
    if "api.telegram.org" in text_lower or "telegram.org/bot" in text_lower:
        return 1.0

    if requests:
        for req in requests:
            u = str(req.get("url", "")).lower()
            if "api.telegram.org" in u or "telegram.org/bot" in u:
                return 1.0

    if indicators:
        for ind in indicators:
            if ind.get("type") in ("tg_bot", "tg_handle"):
                return 1.0

    return 0.0


def exfil_to_firebase(
    html: str,
    requests: Optional[list[dict[str, Any]]] = None,
) -> float:
    """Returns 1.0 if exfiltration to Firebase/Firestore is present, else 0.0."""
    text_lower = (html or "").lower()
    if "firebaseio.com" in text_lower or "firestore.googleapis.com" in text_lower or "firebase" in text_lower:
        return 1.0

    if requests:
        for req in requests:
            u = str(req.get("url", "")).lower()
            if "firebaseio.com" in u or "firestore.googleapis.com" in u:
                return 1.0

    return 0.0


def js_obfuscation_score(html: str) -> float:
    """Returns JavaScript obfuscation heuristic score in [0.0, 1.0]."""
    if not html:
        return 0.0

    score = 0.0
    text = html.lower()

    if "eval(" in text:
        score += 0.3
    if "atob(" in text:
        score += 0.25
    if "unescape(" in text:
        score += 0.2
    if "string.fromcharcode(" in text:
        score += 0.25
    if re.search(r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", text):
        score += 0.3
    if re.search(r"_0x[0-9a-f]{4,}", text):
        score += 0.3

    return float(round(min(1.0, score), 4))


# ---------------------------------------------------------------------------
# Evasion Feature Extractors
# ---------------------------------------------------------------------------

def cloaking_content_diff(mobile_html: str, desktop_html: str) -> float:
    """
    Measures content divergence between mobile and desktop user-agent fetches.
    Returns float in [0.0, 1.0] (0 = identical, 1 = completely different).
    """
    if not mobile_html or not desktop_html:
        return 0.0

    if mobile_html == desktop_html:
        return 0.0

    try:
        from difflib import SequenceMatcher
        m_tokens = mobile_html.split()
        d_tokens = desktop_html.split()
        ratio = SequenceMatcher(None, m_tokens, d_tokens).ratio()
        return float(round(max(0.0, min(1.0, 1.0 - ratio)), 4))
    except Exception as e:
        logger.debug("cloaking_content_diff error: %s", e)
        return 0.0


def redirect_depth(redirect_chain: Optional[list[str]]) -> float:
    """Returns number of intermediate redirect hops as a float >= 0.0."""
    if not redirect_chain or not isinstance(redirect_chain, list):
        return 0.0
    return float(max(0, len(redirect_chain) - 1))


# ---------------------------------------------------------------------------
# Main Orchestrator: extract_features(obs_id)
# ---------------------------------------------------------------------------

def extract_features(obs_id: int) -> dict[str, float]:
    """
    Extracts visual, structural, brand/textual, lexical URL, behavioural, and
    evasion features for an observation. Persists results to DB features table
    and data/cache/features/{obs_id}.json so re-runs are idempotent.
    """
    # 1. Check disk cache
    disk_cache = FEATURES_CACHE_DIR / f"{obs_id}.json"
    if disk_cache.exists():
        try:
            cached_data = json.loads(disk_cache.read_text(encoding="utf-8"))
            if isinstance(cached_data, dict) and "visual_phash_min_distance" in cached_data:
                return cached_data
        except Exception:
            pass

    # 2. Check SQLite features table
    conn = get_conn()
    try:
        cur = conn.execute("SELECT json FROM features WHERE obs_id = ?", (obs_id,))
        row = cur.fetchone()
        if row and row["json"]:
            try:
                db_data = json.loads(row["json"])
                if isinstance(db_data, dict) and "visual_phash_min_distance" in db_data:
                    disk_cache.write_text(json.dumps(db_data, indent=2), encoding="utf-8")
                    return db_data
            except Exception:
                pass

        # 3. Retrieve observation metadata
        cur = conn.execute("SELECT url, raw_text FROM observations WHERE id = ?", (obs_id,))
        obs_row = cur.fetchone()
        url = obs_row["url"] if obs_row and obs_row["url"] else ""

        # Retrieve corpus metadata
        cur = conn.execute("SELECT json FROM corpus_meta WHERE obs_id = ?", (obs_id,))
        cm_row = cur.fetchone()
        corpus_meta = json.loads(cm_row["json"]) if cm_row and cm_row["json"] else {}

        # Retrieve indicators
        cur = conn.execute("SELECT type, value FROM indicators WHERE obs_id = ?", (obs_id,))
        indicators = [dict(r) for r in cur.fetchall()]

        # Retrieve fetches for both mobile and desktop
        cur = conn.execute(
            "SELECT ua_profile, dom_path, screenshot_path, requests, redirect_chain FROM fetches WHERE obs_id = ?",
            (obs_id,)
        )
        fetch_rows = cur.fetchall()
        if not fetch_rows:
            try:
                from detect.fetcher import fetch
                fetch(obs_id)
                cur = conn.execute(
                    "SELECT ua_profile, dom_path, screenshot_path, requests, redirect_chain FROM fetches WHERE obs_id = ?",
                    (obs_id,)
                )
                fetch_rows = cur.fetchall()
            except Exception as e:
                logger.debug("Auto-fetch for obs %d encountered: %s", obs_id, e)

        mobile_fetch: dict[str, Any] = {}
        desktop_fetch: dict[str, Any] = {}
        for fr in fetch_rows:
            if fr["ua_profile"] == "mobile":
                mobile_fetch = dict(fr)
            elif fr["ua_profile"] == "desktop":
                desktop_fetch = dict(fr)
    finally:
        conn.close()

    # Load DOM texts
    mobile_dom = ""
    if mobile_fetch.get("dom_path"):
        mp = Path(mobile_fetch["dom_path"])
        if mp.exists():
            mobile_dom = mp.read_text(encoding="utf-8", errors="ignore")
    if not mobile_dom:
        for candidate in (Path(f"data/cache/{obs_id}/mobile.html"), Path(f"data/cache/{obs_id}/mobile/dom.html")):
            if candidate.exists():
                mobile_dom = candidate.read_text(encoding="utf-8", errors="ignore")
                break

    desktop_dom = ""
    if desktop_fetch.get("dom_path"):
        dp = Path(desktop_fetch["dom_path"])
        if dp.exists():
            desktop_dom = dp.read_text(encoding="utf-8", errors="ignore")
    if not desktop_dom:
        for candidate in (Path(f"data/cache/{obs_id}/desktop.html"), Path(f"data/cache/{obs_id}/desktop/dom.html")):
            if candidate.exists():
                desktop_dom = candidate.read_text(encoding="utf-8", errors="ignore")
                break

    # Determine screenshot path
    shot_path: Optional[Path] = None
    if mobile_fetch.get("screenshot_path"):
        sp = Path(mobile_fetch["screenshot_path"])
        if sp.exists():
            shot_path = sp
    if not shot_path or not shot_path.exists():
        for candidate in (Path(f"data/cache/{obs_id}/mobile.png"), Path(f"data/cache/{obs_id}/mobile/shot.png")):
            if candidate.exists():
                shot_path = candidate
                break

    # Parse requests and redirect chain
    requests: list[dict[str, Any]] = []
    if mobile_fetch.get("requests"):
        try:
            requests = json.loads(mobile_fetch["requests"])
        except Exception:
            pass

    redirect_chain: list[str] = []
    if mobile_fetch.get("redirect_chain"):
        try:
            redirect_chain = json.loads(mobile_fetch["redirect_chain"])
        except Exception:
            pass

    # Resolve Brand
    cfg = load_config()
    brands = cfg.get("brands", ["phonepe", "paytm", "gpay", "bhim", "sbi", "hdfc"])
    brand: Optional[str] = corpus_meta.get("brand")
    if not brand:
        url_lower = url.lower()
        for b in brands:
            if b.lower() in url_lower:
                brand = b
                break

    # Canonical DOM for brand
    canonical_dom = ""
    if brand:
        can_path = GALLERY_DIR / brand.lower() / "index.html"
        if can_path.exists():
            canonical_dom = can_path.read_text(encoding="utf-8", errors="ignore")

    # Evaluate all 21 pure features
    features_dict: dict[str, float] = {
        # Visual
        "visual_phash_min_distance": visual_phash_min_distance(shot_path, brand),
        "visual_dhash_min_distance": visual_dhash_min_distance(shot_path, brand),
        "visual_clip_cosine": visual_clip_cosine(shot_path, brand),

        # Structural
        "dom_tag_tree_hash_distance": dom_tag_tree_hash_distance(mobile_dom, canonical_dom),
        "html_tlsh_distance": html_tlsh_distance(mobile_dom, canonical_dom),

        # Brand / Text
        "brand_in_non_brand_domain": brand_in_non_brand_domain(url, brand),
        "brand_name_in_title": brand_name_in_title(mobile_dom, brand),
        "text_tfidf_cosine": text_tfidf_cosine(mobile_dom, brand),

        # URL
        "url_punycode_flag": url_punycode_flag(url),
        "url_brand_in_subdomain": url_brand_in_subdomain(url, brand),
        "url_entropy": url_entropy(url),
        "url_tld_risk": url_tld_risk(url),

        # Behavioural
        "asks_upi_pin": asks_upi_pin(mobile_dom),
        "asks_otp": asks_otp(mobile_dom),
        "asks_card_cvv": asks_card_cvv(mobile_dom),
        "form_posts_to_different_origin": form_posts_to_different_origin(mobile_dom, url),
        "exfil_to_telegram": exfil_to_telegram(mobile_dom, requests, indicators),
        "exfil_to_firebase": exfil_to_firebase(mobile_dom, requests),
        "js_obfuscation_score": js_obfuscation_score(mobile_dom),

        # Evasion
        "cloaking_content_diff": cloaking_content_diff(mobile_dom, desktop_dom),
        "redirect_depth": redirect_depth(redirect_chain),
    }

    # Persist to disk cache
    try:
        disk_cache.write_text(json.dumps(features_dict, indent=2), encoding="utf-8")
    except Exception as e:
        logger.debug("Failed writing features disk cache: %s", e)

    # Persist to DB
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO features (obs_id, json) VALUES (?, ?)",
                (obs_id, json.dumps(features_dict))
            )
    finally:
        conn.close()

    return features_dict
