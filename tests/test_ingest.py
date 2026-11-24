from db import get_conn
from detect.ingest import ingest_text

def test_ingest_url_vpa_phone_sms():
    text = "Dear user, urgently send Rs 5000 to fraud@ybl or contact helpline +919876543210 at https://paytm-security-kyc.com/login"
    obs_ids = ingest_text(text, source="sms")

    assert len(obs_ids) == 1
    obs_id = obs_ids[0]

    conn = get_conn()
    cur = conn.execute("SELECT url, source, raw_text FROM observations WHERE id = ?", (obs_id,))
    row = cur.fetchone()
    assert row["url"] == "https://paytm-security-kyc.com/login"
    assert row["source"] == "sms"
    assert "fraud@ybl" in row["raw_text"]

    cur = conn.execute("SELECT type, value FROM indicators WHERE obs_id = ? ORDER BY type", (obs_id,))
    indicators = cur.fetchall()
    ind_map = {r["type"]: r["value"] for r in indicators}

    assert ind_map["domain"] == "paytm-security-kyc.com"
    assert ind_map["vpa"] == "fraud@ybl"
    assert ind_map["phone"] == "+919876543210"
    conn.close()

def test_ingest_shortener_url():
    text = "Click https://bit.ly/claim-gpay-reward to claim your cashback immediately."
    obs_ids = ingest_text(text, source="feed")

    assert len(obs_ids) == 1
    obs_id = obs_ids[0]

    conn = get_conn()
    cur = conn.execute("SELECT url, source FROM observations WHERE id = ?", (obs_id,))
    row = cur.fetchone()
    assert row["url"] == "https://bit.ly/claim-gpay-reward"
    assert row["source"] == "feed"

    cur = conn.execute("SELECT type, value FROM indicators WHERE obs_id = ?", (obs_id,))
    indicators = cur.fetchall()
    assert any(r["type"] == "domain" and r["value"] == "bit.ly" for r in indicators)
    conn.close()

def test_ingest_no_indicators():
    text = "Hello team, please find the meeting notes attached for tomorrow morning."
    obs_ids = ingest_text(text, source="report")

    assert obs_ids == []
    conn = get_conn()
    cur = conn.execute("SELECT COUNT(*) as cnt FROM observations")
    assert cur.fetchone()["cnt"] == 0
    conn.close()

def test_ingest_duplicate_url_not_inserted_twice():
    text1 = "Visit https://sbi-secure-update.xyz/verify for account unlock."
    text2 = "URGENT: Visit https://sbi-secure-update.xyz/verify now!"

    obs_ids1 = ingest_text(text1, source="ct")
    assert len(obs_ids1) == 1

    obs_ids2 = ingest_text(text2, source="ct")
    assert len(obs_ids2) == 0

    conn = get_conn()
    cur = conn.execute("SELECT COUNT(*) as cnt FROM observations WHERE url = 'https://sbi-secure-update.xyz/verify'")
    assert cur.fetchone()["cnt"] == 1
    conn.close()

def test_ingest_email_not_treated_as_vpa():
    text = "Contact support at customer.care@google.com or send upi to care@okhdfcbank"
    obs_ids = ingest_text(text, source="report")

    assert len(obs_ids) == 1
    obs_id = obs_ids[0]

    conn = get_conn()
    cur = conn.execute("SELECT type, value FROM indicators WHERE obs_id = ?", (obs_id,))
    inds = cur.fetchall()
    vpa_values = [r["value"] for r in inds if r["type"] == "vpa"]

    # care@okhdfcbank should be present, customer.care@google.com should NOT
    assert "care@okhdfcbank" in vpa_values
    assert "customer.care@google.com" not in vpa_values
    conn.close()
