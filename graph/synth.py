from pathlib import Path
from scripts.make_seed import make_seed

def generate_synthetic(n_campaigns: int = 5, seed: int = 42) -> None:
    """
    Generates synthetic phishing and benign observation datasets for testing and benchmarks.
    Wraps make_seed logic.
    """
    _ = (n_campaigns, seed)
    seed_path = Path(__file__).resolve().parent.parent / "data" / "seed.json"
    make_seed(seed_path)
