from typing import Any
from db import get_conn

def run_eval() -> dict[str, Any]:
    """
    Evaluates detection verdicts against ground-truth labels in the database.
    Distinguishes between synthetic and real observations.
    """
    conn = get_conn()
    try:
        cur = conn.execute("""
            SELECT o.id, o.is_synthetic, v.label as pred_label, v.score, l.label as gt_label, l.split
            FROM observations o
            LEFT JOIN verdicts v ON o.id = v.obs_id
            LEFT JOIN labels l ON o.id = l.obs_id
        """)
        rows = cur.fetchall()

        total = len(rows)
        if total == 0:
            return {"status": "no_data", "total": 0}

        def compute_metrics(subset):
            if not subset:
                return {"count": 0, "accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1": 0.0}
            tp = fp = tn = fn = 0
            for r in subset:
                pred_pos = r["pred_label"] in ("phish", "suspicious")
                gt_pos = r["gt_label"] in ("phish", "suspicious")
                if pred_pos and gt_pos:
                    tp += 1
                elif pred_pos and not gt_pos:
                    fp += 1
                elif not pred_pos and not gt_pos:
                    tn += 1
                else:
                    fn += 1
            n = len(subset)
            acc = (tp + tn) / n if n > 0 else 0.0
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            return {
                "count": n,
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
            }

        synth_rows = [r for r in rows if r["is_synthetic"] == 1]
        real_rows = [r for r in rows if r["is_synthetic"] == 0]

        eval_results = {
            "total_observations": total,
            "overall": compute_metrics(rows),
            "synthetic": compute_metrics(synth_rows),
            "real": compute_metrics(real_rows),
        }
        return eval_results
    finally:
        conn.close()

if __name__ == "__main__":
    results = run_eval()
    print("=== CloneTrace Detection Evaluation ===")
    print(f"Total Observations: {results.get('total_observations', 0)}")
    for subset_name in ("overall", "synthetic", "real"):
        sub = results.get(subset_name, {})
        print(f"\n[{subset_name.upper()}] (N={sub.get('count', 0)})")
        print(f"  Accuracy : {sub.get('accuracy', 0.0)}")
        print(f"  Precision: {sub.get('precision', 0.0)}")
        print(f"  Recall   : {sub.get('recall', 0.0)}")
        print(f"  F1-Score : {sub.get('f1', 0.0)}")
