"""
CloneTrace Contract Models and System Function Signatures.

System Module Function Signatures:
-----------------------------------
- detect/ingest.py:
    ingest_text(text: str, source: str) -> list[int]
- detect/fetcher.py:
    fetch(obs_id: int) -> None
- detect/features.py:
    extract_features(obs_id: int) -> dict
- detect/model.py:
    score(obs_id: int) -> Verdict
- detect/apk.py:
    analyze_apk(path: str) -> int
- detect/eval.py:
    run_eval() -> dict
- graph/enrich.py:
    enrich(obs_id: int) -> list[Indicator]
- graph/build.py:
    build_graph() -> networkx.Graph
    build_viz_graph(campaign_id: int) -> tuple[pyvis.network.Network, dict] or networkx.Graph
- graph/cluster.py:
    cluster(G: networkx.Graph) -> list[Campaign]
- graph/synth.py:
    generate_synthetic(n_campaigns: int, seed: int) -> None
- report/takedown.py:
    generate_takedown(campaign_id: int) -> str
"""

from typing import Optional
from pydantic import BaseModel, Field

class Indicator(BaseModel):
    type: str
    value: str

class Verdict(BaseModel):
    score: float
    label: str
    brand: Optional[str] = None
    signals: dict[str, float] = Field(default_factory=dict)

class Campaign(BaseModel):
    id: int
    name: str
    size: int
    brands: list[str] = Field(default_factory=list)
    first_seen: str
    last_seen: str
    top_indicators: list[Indicator] = Field(default_factory=list)
    member_ids: list[int] = Field(default_factory=list)
