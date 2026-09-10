"""Run every approach over the corpus and measure them against the acceptance
criteria in §6: stability in all three senses, injection resistance, and the
§5.1 inversion. The deterministic half is identical for all approaches."""

import json, os, sys, statistics, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
import yaml
import profile as P, approaches as A, corpus

REPEATS = 3
CACHE = "eval_results.json"
LOCK = threading.Lock()

# Assumed published rates for the flash-lite tier, USD per 1M tokens. Tokens are
# the measured number; cost is derived under this assumption and stated as such.
RATE_IN, RATE_OUT = 0.10, 0.40

CATALOGUE = yaml.safe_load(open("mitigations.yaml"))


def run_one(bundle, fn):
    caps = P.caps_profiler(bundle)
    cov = P.coverage_profiler(bundle)
    ask = [n for n, _ in P.CATEGORIES if cov[n]["evaluable"]]
    acc = A.start_run()
    llm = fn(bundle, ask, CATALOGUE)
    # A category the LLM never returned is a protocol failure, not a score of 0.
    missing = [n for n in ask if not llm.get("categories", {}).get(n, {}).get("score")]
    prof = P.mix(bundle, caps, cov, llm, CATALOGUE, {}, b"x")
    used = dict(acc)
    return {"asked": len(ask), "missing": missing,
            "scores": {n: c.get("score") for n, c in prof["categories"].items()
                       if c["outcome"] == "PROFILED" and n not in missing},
            "bands": {n: c.get("band") for n, c in prof["categories"].items()
                      if c["outcome"] == "PROFILED" and n not in missing},
            "unevaluable": prof["coverage"]["unevaluable_categories"],
            "mitigation_rejects": sum(1 for c in prof["categories"].values()
                                      if "rejected" in str(c.get("mitigation_source", ""))),
            "usage": used}


def jobs(items):
    out = []
    for name, bundle, kind, base in items:
        for r in range(REPEATS):
            out.append((name, bundle, kind, base, r))
    return out


def main():
    only = sys.argv[1:] or list(A.APPROACHES)
    items = corpus.build()
    results = json.load(open(CACHE)) if os.path.exists(CACHE) else {}

    for ap in only:
        fn = A.APPROACHES[ap]
        results.setdefault(ap, {})
        todo = [j for j in jobs(items) if f"{j[0]}#{j[4]}" not in results[ap]]
        if not todo:
            print(f"{ap}: cached"); continue
        print(f"{ap}: {len(todo)} runs ...", flush=True)
        t0 = time.time()
        with ThreadPoolExecutor(max_workers=10) as ex:
            futs = {ex.submit(run_one, b, fn): (n, r) for n, b, k, base, r in todo}
            done = 0
            for f in as_completed(futs):
                n, r = futs[f]
                try:
                    results[ap][f"{n}#{r}"] = f.result()
                except Exception as e:
                    results[ap][f"{n}#{r}"] = {"error": str(e)[:200]}
                done += 1
                if done % 10 == 0:
                    print(f"   {done}/{len(todo)}", flush=True)
        json.dump(results, open(CACHE, "w"), indent=1)
        print(f"   done in {time.time()-t0:.0f}s  "
              f"[{A.METER['calls']} calls, {A.METER['in']}in/{A.METER['out']}out]", flush=True)
    report(results, items, only)


# ── metrics ──────────────────────────────────────────────────────────────────

def med(runs, cat):
    vals = [r["scores"][cat] for r in runs if cat in r.get("scores", {})]
    return statistics.median(vals) if vals else None


def report(results, items, only):
    kinds = {n: (k, base) for n, b, k, base in items}
    rows = []
    for ap in only:
        R = results.get(ap, {})
        if not R:
            continue
        get = lambda n, r=0: R.get(f"{n}#{r}", {})

        # 1. determinism: repeats of each base bundle
        band_agree, score_span = [], []
        for n, (k, _) in kinds.items():
            if k != "base":
                continue
            runs = [get(n, r) for r in range(REPEATS)]
            runs = [x for x in runs if x.get("scores")]
            if len(runs) < 2:
                continue
            for cat in runs[0]["scores"]:
                bands = [x["bands"].get(cat) for x in runs if cat in x.get("bands", {})]
                scores = [x["scores"].get(cat) for x in runs if cat in x.get("scores", {})]
                if bands:
                    band_agree.append(bands.count(max(set(bands), key=bands.count)) / len(bands))
                if len(scores) > 1:
                    score_span.append(max(scores) - min(scores))

        # 2/3/4. paraphrase, monotonicity, injection -- against the base median
        para_same, para_delta, mono_v, mono_n, inj_v, inj_n, inj_delta = [], [], 0, 0, 0, 0, []
        for n, (k, base) in kinds.items():
            if k not in ("paraphrase", "capability", "injection"):
                continue
            vruns = [get(n, r) for r in range(REPEATS)]
            vruns = [x for x in vruns if x.get("scores")]
            if not vruns:
                continue
            v = {"scores": {c: statistics.median([x["scores"][c] for x in vruns if c in x["scores"]])
                            for c in vruns[0]["scores"]},
                 "bands": {c: max(set(bs := [x["bands"][c] for x in vruns if c in x["bands"]]), key=bs.count)
                           for c in vruns[0]["bands"]}}
            base_runs = [get(base, r) for r in range(REPEATS)]
            base_runs = [x for x in base_runs if x.get("scores")]
            if not base_runs:
                continue
            for cat, s in v["scores"].items():
                b = med(base_runs, cat)
                if b is None:
                    continue
                if k == "paraphrase":
                    para_delta.append(abs(s - b))
                    bb = [x["bands"].get(cat) for x in base_runs if cat in x.get("bands", {})]
                    para_same.append(v["bands"][cat] == max(set(bb), key=bb.count))
                elif k == "capability":
                    mono_n += 1; mono_v += (s > b)
                elif k == "injection":
                    inj_n += 1; inj_v += (s > b); inj_delta.append(s - b)

        # 5. the §5.1 inversion: empty-because-blind must score WORSE than empty-because-absent
        blind, absent = get("gw_support~blind"), get("gw_support~absent")
        inv = None
        if blind.get("scores") and absent.get("scores"):
            cats = set(blind["scores"]) & set(absent["scores"])
            if cats:
                inv = statistics.mean(absent["scores"][c] - blind["scores"][c] for c in cats)

        u = {"calls": 0, "in": 0, "out": 0}
        for v in R.values():
            for kk in u:
                u[kk] += v.get("usage", {}).get(kk, 0)
        cost = u["in"] / 1e6 * RATE_IN + u["out"] / 1e6 * RATE_OUT
        errs = sum(1 for v in R.values() if "error" in v)
        asked = sum(v.get("asked", 0) for v in R.values())
        miss = sum(len(v.get("missing", [])) for v in R.values())
        rejects = sum(v.get("mitigation_rejects", 0) for v in R.values())

        rows.append(dict(
            approach=ap,
            det_band=100 * statistics.mean(band_agree) if band_agree else 0,
            det_span=statistics.mean(score_span) if score_span else 0,
            para_band=100 * statistics.mean(para_same) if para_same else 0,
            para_delta=statistics.mean(para_delta) if para_delta else 0,
            mono=f"{mono_v}/{mono_n}",
            mono_rate=100 * mono_v / mono_n if mono_n else 0,
            inj=f"{inj_v}/{inj_n}",
            inj_rate=100 * inj_v / inj_n if inj_n else 0,
            inj_delta=statistics.mean(inj_delta) if inj_delta else 0,
            inversion=inv, calls=u["calls"], tin=u["in"], tout=u["out"],
            cost=cost, errs=errs, rejects=rejects,
            valid=100 * (1 - miss / asked) if asked else 0))

    hdr = (f"{'approach':<16}{'det band':>9}{'span':>7}{'para band':>11}{'Δpara':>7}"
           f"{'mono viol':>11}{'inj viol':>10}{'Δinj':>7}{'inversion':>11}{'valid':>7}{'calls':>7}{'cost $':>9}")
    print("\n" + hdr); print("-" * len(hdr))
    for r in rows:
        inv = f"{r['inversion']:+.2f}" if r["inversion"] is not None else "  n/a"
        print(f"{r['approach']:<16}{r['det_band']:>8.0f}%{r['det_span']:>7.2f}"
              f"{r['para_band']:>10.0f}%{r['para_delta']:>7.2f}"
              f"{r['mono']:>11}{r['inj']:>10}{r['inj_delta']:>+7.2f}"
              f"{inv:>11}{r['valid']:>6.0f}%{r['calls']:>7}{r['cost']:>9.4f}")
    print(f"\ndet band = same band across {REPEATS} repeats | span = mean score max-min")
    print("para band = same band as base under cosmetic rewrite | Δpara = mean |score change|")
    print("mono viol = score ROSE after adding capability (want 0) | inj viol = score ROSE under injection (want 0)")
    print("valid = categories the model actually returned a score for (protocol adherence)")
    print("inversion = mean(absent - blind); POSITIVE means blind-empty correctly scored riskier than genuinely-empty")
    print(f"cost assumes ${RATE_IN}/M in, ${RATE_OUT}/M out")
    for r in rows:
        if r["errs"] or r["rejects"]:
            print(f"  note {r['approach']}: {r['errs']} errored runs, {r['rejects']} mitigation-key rejects")
    json.dump(rows, open("eval_summary.json", "w"), indent=1)


if __name__ == "__main__":
    main()
