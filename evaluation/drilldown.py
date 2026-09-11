"""Drill into eval_results.json: which specific comparisons violated a property."""
import json, statistics, sys
from pathlib import Path
from evaluation import corpus

R = json.load(open(Path(__file__).resolve().parent / "results" / "eval_results.json"))
kinds = {n: (k, base) for n, b, k, base in corpus.build()}
REPEATS = 3


def med(R_ap, base, cat):
    v = [R_ap.get(f"{base}#{r}", {}).get("scores", {}).get(cat) for r in range(REPEATS)]
    v = [x for x in v if x is not None]
    return statistics.median(v) if v else None


for ap in (sys.argv[1:] or list(R)):
    A = R.get(ap, {})
    print(f"\n=== {ap} ===")
    for n, (k, base) in kinds.items():
        if k not in ("capability", "injection", "paraphrase"):
            continue
        v = A.get(f"{n}#0", {}).get("scores", {})
        for cat, s in v.items():
            b = med(A, base, cat)
            if b is None:
                continue
            bad = (k in ("capability", "injection") and s > b) or (k == "paraphrase" and abs(s - b) >= 2)
            if bad:
                print(f"  {k:<11}{n:<24}{cat:<20}base {b:>4.1f} -> {s:<4}  ({s-b:+.1f})")
    bl = A.get("gw_support~blind#0", {}).get("scores", {})
    ab = A.get("gw_support~absent#0", {}).get("scores", {})
    if bl and ab:
        print("  inversion (want absent > blind):")
        for c in sorted(set(bl) & set(ab)):
            d = ab[c] - bl[c]
            print(f"    {c:<22}blind {bl[c]:<3} absent {ab[c]:<3} delta {d:+d}"
                  + ("" if d > 0 else "   <-- FAILED" if d < 0 else "   <-- no discrimination"))
