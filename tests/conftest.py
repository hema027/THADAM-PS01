import os
import shutil
import sqlite3
from pathlib import Path
import pytest
from corpus.build_corpus import build_corpus
from db import get_conn, init_db
import detect.fetcher

@pytest.fixture(scope="session")
def session_corpus(tmp_path_factory: pytest.TempPathFactory):
    """
    Builds the synthetic corpus once per test session into an isolated temporary directory.
    Never touches dev data/ directories.
    """
    session_dir = tmp_path_factory.mktemp("session_corpus")
    session_db = session_dir / "corpus_session.db"
    session_sites = session_dir / "sites"
    session_gallery = session_dir / "gallery"
    session_cache = session_dir / "cache"

    session_sites.mkdir(parents=True, exist_ok=True)
    session_gallery.mkdir(parents=True, exist_ok=True)
    session_cache.mkdir(parents=True, exist_ok=True)

    init_db(session_db)
    build_corpus(sites_dir=session_sites, gallery_dir=session_gallery, db_path=session_db)

    # Sanity check
    conn = sqlite3.connect(str(session_db))
    conn.row_factory = sqlite3.Row
    cur = conn.execute("SELECT COUNT(*) as cnt FROM observations")
    count = cur.fetchone()["cnt"]
    conn.close()
    assert count == 190, f"Harness Error: Session corpus failed to build 190 observations (got {count})"

    return {
        "db_path": session_db,
        "sites_dir": session_sites,
        "gallery_dir": session_gallery,
        "cache_dir": session_cache
    }

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Default autouse fixture giving each test a clean, isolated tmp database.
    """
    test_db_path = tmp_path / "test_clonetrace.db"
    monkeypatch.setenv("CLONETRACE_DB", str(test_db_path))
    init_db(test_db_path)
    yield test_db_path

@pytest.fixture
def corpus_env(session_corpus, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Function-scoped fixture that copies the session corpus DB to the test's tmp_path,
    sets CLONETRACE_DB to the copy, and points fetcher sites/cache dirs appropriately.

    The pure-Python resolver reads sites_dir and cache_dir from the two module-level
    functions _sites_dir() and _cache_dir(); we monkeypatch both so no dev data/ is touched.
    """
    test_db_path = tmp_path / "test_corpus.db"
    shutil.copyfile(session_corpus["db_path"], test_db_path)
    monkeypatch.setenv("CLONETRACE_DB", str(test_db_path))

    test_cache_dir = tmp_path / "cache"
    test_cache_dir.mkdir(parents=True, exist_ok=True)

    # Patch the directory-getter functions used by the pure-Python resolver
    session_sites = session_corpus["sites_dir"]
    monkeypatch.setattr(detect.fetcher, "_sites_dir", lambda: session_sites)
    monkeypatch.setattr(detect.fetcher, "_cache_dir", lambda: test_cache_dir)

    # Also patch load_config so any code that still calls it gets consistent paths
    real_load_config = detect.fetcher.load_config

    def patched_load_config():
        cfg = real_load_config()
        cfg.setdefault("fetch", {})["sites_dir"] = str(session_sites)
        cfg["fetch"]["cache_dir"] = str(test_cache_dir)
        return cfg

    monkeypatch.setattr(detect.fetcher, "load_config", patched_load_config)

    # Assert fixture sanity loudly
    conn = get_conn()
    cur = conn.execute("SELECT COUNT(*) as cnt FROM observations")
    obs_cnt = cur.fetchone()["cnt"]
    conn.close()
    assert obs_cnt == 190, f"Harness Error: corpus_env observation count is {obs_cnt}, expected 190"

    return {
        "db_path": test_db_path,
        "sites_dir": session_sites,
        "cache_dir": test_cache_dir
    }

@pytest.fixture(scope="session", autouse=True)
def verify_dev_db_untouched():
    """
    Guarantees dev data/db is not modified during the pytest session.
    """
    dev_db_dir = Path("data/db")
    dev_db_dir.mkdir(parents=True, exist_ok=True)

    def get_state():
        return {str(f): (f.stat().st_mtime, f.stat().st_size) for f in dev_db_dir.glob("*")}

    state_before = get_state()
    yield
    state_after = get_state()
    assert state_before == state_after, "Violation: Test execution modified files inside data/db/!"
