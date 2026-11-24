"""
CloneTrace fetcher – pure-Python resolver + Playwright screenshots.

resolve()      – applies manifest cloaking / redirects, returns HTML from disk.
fetch()        – resolve both UA profiles, write cache, persist fetches rows.
fetch_many()   – simple sequential loop.
capture_screenshots() – one Chromium session, loads cached HTML via file://.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import statistics
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Optional

import yaml

from db import get_conn

logger = logging.getLogger("clonetrace.fetcher")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def load_config() -> dict[str, Any]:
    cfg_path = Path("config.yaml")
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def _fetch_cfg() -> dict[str, Any]:
    return load_config().get("fetch", {})


def _ua_profiles() -> dict[str, str]:
    return _fetch_cfg().get("ua_profiles", {
        "mobile": (
            "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36"
        ),
        "desktop": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
        ),
    })


def _sites_dir() -> Path:
    return Path(_fetch_cfg().get("sites_dir", "data/sites"))


def _cache_dir() -> Path:
    return Path(_fetch_cfg().get("cache_dir", "data/cache"))


# ---------------------------------------------------------------------------
# Resolution data class
# ---------------------------------------------------------------------------

@dataclass
class Resolution:
    status: int = 0
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    tls: dict[str, Any] = field(default_factory=dict)
    html: str = ""
    requests: list[dict[str, Any]] = field(default_factory=list)
    dead: int = 0
    dead_reason: Optional[str] = None
    fetched_at: str = ""


# ---------------------------------------------------------------------------
# UA discrimination helper (single source of truth, mirrors build_corpus.py)
# ---------------------------------------------------------------------------

def _is_desktop_ua(ua: str) -> bool:
    """Return True iff the UA string looks like a desktop browser."""
    desktop_signals = ("Windows", "Macintosh", "X11", "Headless")
    mobile_signals = ("Android", "Mobile")
    has_desktop = any(s in ua for s in desktop_signals)
    has_mobile = any(s in ua for s in mobile_signals)
    return has_desktop and not has_mobile


# ---------------------------------------------------------------------------
# External-URL extractor  (html.parser, not regex over the whole doc)
# ---------------------------------------------------------------------------

_EXTERNAL_ATTR_MAP: dict[str, list[str]] = {
    "script": ["src"],
    "img": ["src"],
    "link": ["href"],
    "iframe": ["src"],
    "form": ["action"],
    "a": ["href"],
    "audio": ["src"],
    "video": ["src"],
    "source": ["src"],
    "track": ["src"],
    "embed": ["src"],
    "object": ["data"],
}

# URLs embedded in inline JS (fetch/XHR/WebSocket patterns)
_JS_URL_RE = re.compile(
    r"""(?:fetch|XMLHttpRequest|WebSocket|open)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []
        self._in_script = False
        self._script_buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag == "script":
            self._in_script = True
        attr_dict = dict(attrs)
        for attr in _EXTERNAL_ATTR_MAP.get(tag, []):
            val = attr_dict.get(attr)
            if val:
                self.urls.append(val)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            snippet = "".join(self._script_buf)
            self.urls.extend(_JS_URL_RE.findall(snippet))
            self._in_script = False
            self._script_buf = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_buf.append(data)


def _extract_external_urls(html: str, sites_dir: Path) -> list[dict[str, Any]]:
    """Parse HTML and return all referenced URLs with blocked=True for non-local ones."""
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass

    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_url in parser.urls:
        raw_url = raw_url.strip()
        if not raw_url or raw_url.startswith("data:") or raw_url.startswith("#"):
            continue
        if raw_url in seen:
            continue
        seen.add(raw_url)
        parsed = urllib.parse.urlparse(raw_url)
        host = parsed.netloc.split(":")[0].lower()
        # Relative URLs have no host → count as local (not blocked)
        if host:
            blocked = not (sites_dir / host).exists()
        else:
            blocked = False
        result.append({
            "url": raw_url,
            "method": "GET",
            "resource_type": "unknown",
            "blocked": blocked,
        })
    return result


# ---------------------------------------------------------------------------
# Pure-Python resolver
# ---------------------------------------------------------------------------

_PARKED_KEYWORDS = [
    "domain is for sale",
    "buy this domain",
    "account suspended",
    "this domain has expired",
    "website is under construction",
    "domain parked",
]


def resolve(
    host: str,
    ua_profile: str,
    referer: Optional[str] = None,
    *,
    sites_dir: Optional[Path] = None,
) -> Resolution:
    """
    Pure-Python resolver over data/sites/<host>/manifest.json.
    Applies cloaking and follows redirects (max 5 hops). Never touches the network.
    """
    if sites_dir is None:
        sites_dir = _sites_dir()

    ua_string = _ua_profiles().get(ua_profile, "")
    is_desktop = _is_desktop_ua(ua_string)

    visited: set[str] = set()
    chain: list[str] = []
    current_host = host
    current_url = f"https://{host}/"
    hops = 0
    MAX_HOPS = 5

    res = Resolution(fetched_at=datetime.now(timezone.utc).isoformat())

    while hops < MAX_HOPS:
        if current_host in visited:
            res.dead = 1
            res.dead_reason = "Redirect loop detected"
            break
        visited.add(current_host)
        chain.append(current_url)
        hops += 1

        site_dir = sites_dir / current_host
        if not site_dir.exists():
            res.dead = 1
            res.dead_reason = f"Unknown host: {current_host}"
            break

        manifest_path = site_dir / "manifest.json"
        manifest: dict[str, Any] = {}
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception:
                pass

        # Collect TLS from first hop
        if hops == 1:
            res.tls = manifest.get("tls", {})
            res.headers = manifest.get("response_headers", {})

        # Follow redirect?
        redirect_to = manifest.get("redirect_to")
        if redirect_to:
            parsed = urllib.parse.urlparse(redirect_to)
            current_host = parsed.netloc.split(":")[0].lower()
            current_url = redirect_to
            continue

        # Apply cloak rule
        cloak = manifest.get("cloak", {})
        rule = cloak.get("rule", "none")

        if rule == "ua" and is_desktop and cloak.get("decoy_file"):
            target_file = cloak["decoy_file"]
        elif rule == "referrer" and not referer and cloak.get("decoy_file"):
            target_file = cloak["decoy_file"]
        else:
            parsed_path = urllib.parse.urlparse(current_url).path
            target_file = manifest.get("routes", {}).get(parsed_path, "index.html")

        file_path = site_dir / target_file
        if not file_path.exists():
            file_path = site_dir / "index.html"

        if not file_path.exists():
            res.dead = 1
            res.dead_reason = f"File not found: {target_file}"
            break

        html = file_path.read_text(encoding="utf-8")
        res.status = 200
        res.final_url = current_url
        res.redirect_chain = chain
        res.html = html

        # Parked-domain check
        html_lower = html.lower()
        for kw in _PARKED_KEYWORDS:
            if kw in html_lower:
                res.dead = 1
                res.dead_reason = "Parked or Suspended Domain"
                break

        if not res.dead and len(html.encode("utf-8")) < 200:
            res.dead = 1
            res.dead_reason = "HTML under 200 bytes"

        res.requests = _extract_external_urls(html, sites_dir)
        return res

    # Exhausted hops or broke early
    res.final_url = current_url
    res.redirect_chain = chain
    return res


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _obs_cache_dir(obs_id: int) -> Path:
    return _cache_dir() / str(obs_id)


def _persist_fetch_row(
    obs_id: int,
    ua_profile: str,
    res: Resolution,
    dom_path: str,
    screenshot_path: str,
) -> None:
    conn = get_conn()
    try:
        with conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO fetches (
                    obs_id, ua_profile, status, final_url, redirect_chain,
                    screenshot_path, dom_path, headers, tls, requests,
                    dead, dead_reason, fetched_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    obs_id,
                    ua_profile,
                    res.status,
                    res.final_url,
                    json.dumps(res.redirect_chain),
                    screenshot_path,
                    dom_path,
                    json.dumps(res.headers),
                    json.dumps(res.tls),
                    json.dumps(res.requests),
                    res.dead,
                    res.dead_reason,
                    res.fetched_at,
                ),
            )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Public fetch() – resolve both profiles, write cache, persist rows
# ---------------------------------------------------------------------------

def fetch(obs_id: int, force: bool = False) -> None:
    """
    Resolve a single observation under both UA profiles.
    Writes HTML cache files and one fetches row per profile.
    Never contacts the network.
    """
    conn = get_conn()
    try:
        cur = conn.execute(
            "SELECT url FROM observations WHERE id = ? AND url IS NOT NULL", (obs_id,)
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if row is None:
        logger.warning("Observation %d not found or has no URL", obs_id)
        return

    url = row["url"]
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.split(":")[0].lower()

    item_dir = _obs_cache_dir(obs_id)
    item_dir.mkdir(parents=True, exist_ok=True)

    for ua_profile in ("mobile", "desktop"):
        dom_path = item_dir / f"{ua_profile}.html"
        shot_path = item_dir / f"{ua_profile}.png"
        meta_path = item_dir / f"{ua_profile}_meta.json"

        if not force and dom_path.exists():
            # Cache hit: re-read and re-persist the DB row
            try:
                if meta_path.exists():
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    res = Resolution(**{k: meta[k] for k in Resolution.__dataclass_fields__ if k in meta})
                    _persist_fetch_row(obs_id, ua_profile, res, str(dom_path), str(shot_path))
                    continue
            except Exception:
                pass  # fall through to re-fetch

        t0 = time.perf_counter()
        res = resolve(host, ua_profile, sites_dir=_sites_dir())
        elapsed = time.perf_counter() - t0
        print(
            f"[RESOLVE] obs={obs_id} profile={ua_profile} | "
            f"status={res.status} dead={res.dead} elapsed={elapsed:.3f}s",
            flush=True,
        )

        dom_path.write_text(res.html, encoding="utf-8")

        meta = {
            "status": res.status,
            "final_url": res.final_url,
            "redirect_chain": res.redirect_chain,
            "headers": res.headers,
            "tls": res.tls,
            "requests": res.requests,
            "dead": res.dead,
            "dead_reason": res.dead_reason,
            "fetched_at": res.fetched_at,
        }
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

        _persist_fetch_row(obs_id, ua_profile, res, str(dom_path), str(shot_path))


# ---------------------------------------------------------------------------
# fetch_many / fetch_all
# ---------------------------------------------------------------------------

def fetch_many(obs_ids: list[int], force: bool = False) -> None:
    """Sequential loop over obs_ids."""
    for obs_id in obs_ids:
        fetch(obs_id, force=force)


def fetch_all(force: bool = False) -> None:
    conn = get_conn()
    try:
        cur = conn.execute(
            "SELECT id FROM observations WHERE url IS NOT NULL ORDER BY id ASC"
        )
        ids = [r["id"] for r in cur.fetchall()]
    finally:
        conn.close()

    logger.info("Starting fetch for %d observations...", len(ids))
    t0 = time.time()
    fetch_many(ids, force=force)
    elapsed = time.time() - t0
    logger.info(
        "Completed %d observations in %.2fs (%.1f obs/min)",
        len(ids),
        elapsed,
        len(ids) / (elapsed / 60) if elapsed > 0 else 0,
    )


# ---------------------------------------------------------------------------
# Screenshot capture (Playwright, file:// only, one Chromium session)
# ---------------------------------------------------------------------------

def capture_screenshots(
    obs_ids: list[int],
    profile: str = "mobile",
    wall_cap_s: Optional[float] = None,
) -> int:
    """
    Load each observation's cached HTML via file://, take a screenshot.
    Returns the count of successfully written PNGs.
    Skips pages whose PNG already exists.
    Playwright errors are caught per-page and logged; the browser closes in finally.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        logger.error("playwright not installed – cannot capture screenshots")
        return 0

    cfg = load_config().get("fetch", {})
    settle_ms = int(cfg.get("settle_ms", 800))
    if wall_cap_s is None:
        wall_cap_s = float(cfg.get("screenshot_wall_cap_s", 300))

    ua_string = _ua_profiles().get(profile, _ua_profiles()["mobile"])
    is_mobile = profile == "mobile"
    viewport = {"width": 390, "height": 844} if is_mobile else {"width": 1366, "height": 768}

    succeeded = 0
    wall_start = time.time()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, args=["--disable-gpu"])
        try:
            context = browser.new_context(
                user_agent=ua_string,
                viewport=viewport,
                is_mobile=is_mobile,
                has_touch=is_mobile,
            )
            for obs_id in obs_ids:
                if time.time() - wall_start > wall_cap_s:
                    logger.warning(
                        "screenshot wall-clock cap %.0fs reached after %d pages",
                        wall_cap_s,
                        succeeded,
                    )
                    break

                item_dir = _obs_cache_dir(obs_id)
                dom_path = item_dir / f"{profile}.html"
                shot_path = item_dir / f"{profile}.png"

                if shot_path.exists():
                    succeeded += 1
                    continue

                if not dom_path.exists():
                    logger.warning("obs %d: no cached HTML for profile %s, skipping", obs_id, profile)
                    continue

                page = context.new_page()
                try:
                    # Abort every non-file request immediately
                    page.route("**/*", lambda route: (
                        route.abort() if not route.request.url.startswith("file://") else route.continue_()
                    ))
                    page.goto(
                        dom_path.absolute().as_uri(),
                        wait_until="domcontentloaded",
                        timeout=10_000,
                    )
                    if settle_ms > 0:
                        page.wait_for_timeout(settle_ms)
                    shot_bytes = page.screenshot(type="png", full_page=False)
                    shot_path.write_bytes(shot_bytes)

                    # Update screenshot_path in DB
                    conn = get_conn()
                    try:
                        with conn:
                            conn.execute(
                                "UPDATE fetches SET screenshot_path = ? WHERE obs_id = ? AND ua_profile = ?",
                                (str(shot_path), obs_id, profile),
                            )
                    finally:
                        conn.close()

                    succeeded += 1
                except PWTimeout:
                    logger.warning("obs %d screenshot timeout", obs_id)
                except Exception as exc:
                    logger.warning("obs %d screenshot error: %s", obs_id, exc)
                finally:
                    page.close()

            context.close()
        finally:
            browser.close()

    logger.info("Screenshots: %d/%d succeeded", succeeded, len(obs_ids))
    return succeeded


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def run_bench() -> dict[str, Any]:
    """
    Measure resolve() latency over a 40-obs sample.
    Writes data/metrics/fetch_stats.json.
    """
    conn = get_conn()
    try:
        cur = conn.execute(
            "SELECT id, url FROM observations WHERE url IS NOT NULL LIMIT 40"
        )
        sample = [(r["id"], r["url"]) for r in cur.fetchall()]
    finally:
        conn.close()

    if not sample:
        logger.warning("No observations to benchmark")
        return {}

    latencies_ms: list[float] = []
    dead_count = 0

    ua_profiles = _ua_profiles()
    m_ua = ua_profiles["mobile"]
    sites = _sites_dir()

    t_all_start = time.time()
    for obs_id, url in sample:
        host = urllib.parse.urlparse(url).netloc.split(":")[0].lower()
        t0 = time.perf_counter()
        res = resolve(host, "mobile", sites_dir=sites)
        latencies_ms.append((time.perf_counter() - t0) * 1000)
        if res.dead:
            dead_count += 1
    elapsed = time.time() - t_all_start

    n = len(latencies_ms)
    latencies_ms.sort()
    p50 = statistics.median(latencies_ms) if latencies_ms else 0.0
    p95 = latencies_ms[int(n * 0.95)] if n else 0.0
    urls_per_min = round(n / (elapsed / 60), 2) if elapsed > 0 else 0.0

    metrics_dir = Path("data/metrics")
    metrics_dir.mkdir(parents=True, exist_ok=True)
    bench_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sample_size": n,
        "elapsed_s": round(elapsed, 3),
        "urls_per_min": urls_per_min,
        "p50_latency_ms": round(p50, 3),
        "p95_latency_ms": round(p95, 3),
        "dead_count": dead_count,
    }
    stats_file = metrics_dir / "fetch_stats.json"
    stats_file.write_text(json.dumps(bench_data, indent=2), encoding="utf-8")

    print("========================================")
    print("   CloneTrace Fetch Throughput Bench    ")
    print("========================================")
    print(f"Sample : {n} URLs | Elapsed: {elapsed:.2f}s")
    print(f"Speed  : {urls_per_min:.1f} URLs/min")
    print(f"p50    : {p50:.3f}ms  |  p95: {p95:.3f}ms")
    print(f"Dead   : {dead_count}")
    print(f"\nWrote metrics to {stats_file}")
    print("========================================")
    return bench_data


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloneTrace Pure-Python Resolver + Playwright Screenshots")
    parser.add_argument("--all", action="store_true", help="Fetch all observations")
    parser.add_argument("--bench", action="store_true", help="Run benchmark and write fetch_stats.json")
    parser.add_argument("--obs", type=int, help="Fetch single observation ID")
    parser.add_argument("--shots", action="store_true", help="Capture screenshots for all observations")
    parser.add_argument("--shots-profile", default="mobile", help="UA profile for screenshots (default: mobile)")
    parser.add_argument("--force", action="store_true", help="Bypass cache")
    args = parser.parse_args()

    if args.bench:
        run_bench()
    elif args.shots:
        conn = get_conn()
        try:
            ids = [r["id"] for r in conn.execute("SELECT id FROM observations WHERE url IS NOT NULL ORDER BY id").fetchall()]
        finally:
            conn.close()
        n = capture_screenshots(ids, profile=args.shots_profile)
        print(f"Screenshots: {n}/{len(ids)} succeeded")
    elif args.obs:
        fetch(args.obs, force=args.force)
    elif args.all:
        fetch_all(force=args.force)
    else:
        parser.print_help()
