-- CloneTrace SQLite Schema
-- SCHEMA_VERSION = 2.0.0

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    source TEXT,
    source_ref TEXT,
    raw_text TEXT,
    first_seen TEXT,
    is_synthetic INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fetches (
    obs_id INTEGER,
    ua_profile TEXT,
    status INTEGER,
    final_url TEXT,
    redirect_chain TEXT,
    screenshot_path TEXT,
    dom_path TEXT,
    headers TEXT,
    tls TEXT,
    requests TEXT,
    dead INTEGER DEFAULT 0,
    dead_reason TEXT,
    fetched_at TEXT,
    FOREIGN KEY(obs_id) REFERENCES observations(id)
);

CREATE TABLE IF NOT EXISTS features (
    obs_id INTEGER PRIMARY KEY,
    json TEXT,
    FOREIGN KEY(obs_id) REFERENCES observations(id)
);

CREATE TABLE IF NOT EXISTS verdicts (
    obs_id INTEGER PRIMARY KEY,
    score REAL,
    label TEXT,
    brand TEXT,
    signals TEXT,
    model_version TEXT,
    FOREIGN KEY(obs_id) REFERENCES observations(id)
);

CREATE TABLE IF NOT EXISTS indicators (
    obs_id INTEGER,
    type TEXT,
    value TEXT,
    UNIQUE(obs_id, type, value),
    FOREIGN KEY(obs_id) REFERENCES observations(id)
);

CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY,
    name TEXT,
    first_seen TEXT,
    last_seen TEXT,
    size INTEGER,
    brands TEXT,
    top_indicators TEXT
);

CREATE TABLE IF NOT EXISTS campaign_members (
    campaign_id INTEGER,
    obs_id INTEGER,
    FOREIGN KEY(campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY(obs_id) REFERENCES observations(id)
);

CREATE TABLE IF NOT EXISTS labels (
    obs_id INTEGER PRIMARY KEY,
    label TEXT,
    split TEXT,
    heldout_brand INTEGER DEFAULT 0,
    campaign_gt INTEGER,
    FOREIGN KEY(obs_id) REFERENCES observations(id)
);

CREATE TABLE IF NOT EXISTS corpus_meta (
    obs_id INTEGER PRIMARY KEY,
    json TEXT,
    FOREIGN KEY(obs_id) REFERENCES observations(id)
);

CREATE INDEX IF NOT EXISTS idx_indicators_type_val ON indicators(type, value);
CREATE INDEX IF NOT EXISTS idx_indicators_obs_id ON indicators(obs_id);
