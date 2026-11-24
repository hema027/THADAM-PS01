import re
import urllib.parse
from datetime import datetime, timezone
from typing import Optional
from db import get_conn

URL_PATTERN = re.compile(r'https?://[^\s<>"\'{}|\\^`]+', re.IGNORECASE)
VPA_PATTERN = re.compile(r'[\w.\-]{2,}@[a-zA-Z]{2,}')
PHONE_PATTERN = re.compile(r'(?:\+91[\s-]?)?[6-9]\d{9}')

def clean_url(url: str) -> str:
    # Strip trailing punctuation that might be attached from sentence text
    return re.sub(r'[.,;!?\)\>\]]+$', '', url)

def extract_urls(text: str) -> list[str]:
    raw_urls = URL_PATTERN.findall(text)
    urls = []
    seen = set()
    for raw in raw_urls:
        u = clean_url(raw)
        if u and u not in seen:
            seen.add(u)
            urls.append(u)
    return urls

def extract_vpas(text: str) -> list[str]:
    matches = VPA_PATTERN.findall(text)
    vpas = []
    seen = set()
    for m in matches:
        _, _, provider = m.partition('@')
        # Rule I: Discard any match whose part after '@' contains a '.' (email, not VPA)
        if '.' in provider:
            continue
        val = m.lower()
        if val not in seen:
            seen.add(val)
            vpas.append(val)
    return vpas

def extract_phones(text: str) -> list[str]:
    matches = PHONE_PATTERN.findall(text)
    phones = []
    seen = set()
    for m in matches:
        normalized = re.sub(r'[\s-]', '', m)
        if normalized not in seen:
            seen.add(normalized)
            phones.append(normalized)
    return phones

def extract_domain(url: str) -> Optional[str]:
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.split(':')[0].lower()
        return netloc if netloc else None
    except Exception:
        return None

def ingest_text(text: str, source: str) -> list[int]:
    """
    Extracts URLs, UPI VPAs, and Indian phone numbers from text.
    Inserts observations and associated indicators into SQLite database.
    Returns list of newly created observation IDs.
    """
    urls = extract_urls(text)
    vpas = extract_vpas(text)
    phones = extract_phones(text)

    # If no URL, no VPA, no phone -> return empty list
    if not urls and not vpas and not phones:
        return []

    conn = get_conn()
    now_iso = datetime.now(timezone.utc).isoformat()
    inserted_ids = []

    try:
        with conn:
            if urls:
                for url in urls:
                    # Check if URL is already inserted in observations table
                    cur = conn.execute("SELECT id FROM observations WHERE url = ?", (url,))
                    row = cur.fetchone()
                    if row is not None:
                        # Duplicate URL not inserted twice
                        continue

                    cur = conn.execute(
                        """
                        INSERT INTO observations (url, source, raw_text, first_seen, is_synthetic)
                        VALUES (?, ?, ?, ?, 0)
                        """,
                        (url, source, text, now_iso)
                    )
                    obs_id = cur.lastrowid
                    inserted_ids.append(obs_id)

                    # Indicators for this URL observation
                    domain = extract_domain(url)
                    if domain:
                        conn.execute(
                            "INSERT OR IGNORE INTO indicators (obs_id, type, value) VALUES (?, 'domain', ?)",
                            (obs_id, domain)
                        )
                    for vpa in vpas:
                        conn.execute(
                            "INSERT OR IGNORE INTO indicators (obs_id, type, value) VALUES (?, 'vpa', ?)",
                            (obs_id, vpa)
                        )
                    for phone in phones:
                        conn.execute(
                            "INSERT OR IGNORE INTO indicators (obs_id, type, value) VALUES (?, 'phone', ?)",
                            (obs_id, phone)
                        )
            else:
                # No URL, but VPA or Phone exists -> insert one observation with url NULL
                cur = conn.execute(
                    """
                    INSERT INTO observations (url, source, raw_text, first_seen, is_synthetic)
                    VALUES (NULL, ?, ?, ?, 0)
                    """,
                    (source, text, now_iso)
                )
                obs_id = cur.lastrowid
                inserted_ids.append(obs_id)

                for vpa in vpas:
                    conn.execute(
                        "INSERT OR IGNORE INTO indicators (obs_id, type, value) VALUES (?, 'vpa', ?)",
                        (obs_id, vpa)
                    )
                for phone in phones:
                    conn.execute(
                        "INSERT OR IGNORE INTO indicators (obs_id, type, value) VALUES (?, 'phone', ?)",
                        (obs_id, phone)
                    )
    finally:
        conn.close()

    return inserted_ids
