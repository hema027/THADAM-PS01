from contract.models import Indicator
from db import get_conn

def enrich(obs_id: int) -> list[Indicator]:
    """
    Enriches an observation with external threat intelligence and DNS/WHOIS indicators.
    Stub: returns indicators already in DB for that observation.
    # TODO(step 2): real implementation (live WHOIS, passive DNS, IP ASN lookup, certificate transparency)
    """
    conn = get_conn()
    try:
        cur = conn.execute("SELECT type, value FROM indicators WHERE obs_id = ?", (obs_id,))
        rows = cur.fetchall()
        return [Indicator(type=r["type"], value=r["value"]) for r in rows]
    finally:
        conn.close()
