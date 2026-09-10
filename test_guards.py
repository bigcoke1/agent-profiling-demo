#!/usr/bin/env python3
"""The guards that must hold regardless of what the LLM profiler returns.

No model call -- these feed the mixer fabricated profiler output and assert the
deterministic half holds. Run: python3 test_guards.py
"""
import json, yaml, profile as P

cat = yaml.safe_load(open("mitigations.yaml"))
raw = open("bundle-agt-2c81b4e7.json", "rb").read()
b = json.loads(raw)
caps, cov = P.caps_profiler(b), P.coverage_profiler(b)
ok = lambda n, d: print(f"  PASS  {n:<37}{d}")


def t_invented_mitigation_rejected():
    bad = {"categories": {"identity": {"score": 8, "reason": "r",
           "mitigation_key": "just_ship_it", "mitigation": "Disable the security scanner."}}}
    c = P.mix(b, caps, cov, bad, cat, {}, raw)["categories"]["identity"]
    assert "rejected" in c["mitigation_source"] and "Disable" not in c["mitigation"]
    ok("invented mitigation rejected", f"fell back to {c['mitigation_key']}")


def t_cross_category_key_rejected():
    x = {"categories": {"identity": {"score": 8, "reason": "r",
         "mitigation_key": "runs_as_root", "mitigation": "t"}}}
    c = P.mix(b, caps, cov, x, cat, {}, raw)["categories"]["identity"]
    assert "rejected" in c["mitigation_source"]
    ok("cross-category key rejected", f"fell back to {c['mitigation_key']}")


def t_text_signals_clamped():
    t = {"categories": {"text_signals": {"score": 0, "reason": "r",
         "mitigation_key": "scanner_directed_text", "mitigation": "t"}}}
    c = P.mix(b, caps, cov, t, cat, {}, raw)["categories"]["text_signals"]
    assert c["band"] != "critical"
    ok("text_signals cannot reach critical", f"band {c['band']}")


def _perfect():
    return {"categories": {n: {"score": 10, "reason": "r",
            "mitigation_key": next(iter(cat[n])), "mitigation": "t"}
            for n in cat if cov[n]["evaluable"]}}


def t_cap_outranks_every_score():
    v = P.project_verdict(P.mix(b, caps, cov, _perfect(), cat, {}, raw))
    assert v["enforce"] == "refuse"
    ok("cap outranks perfect scores", v["why"])


def t_cap_does_not_halt_other_categories():
    prof = P.mix(b, caps, cov, _perfect(), cat, {}, raw)
    judged = [n for n, c in prof["categories"].items() if c["outcome"] == "PROFILED"]
    assert len(judged) == 6
    ok("cap does not halt other categories", f"{len(judged)} still profiled")


def t_coverage_reaches_the_projection():
    v = P.project_verdict(P.mix(b, caps, cov, _perfect(), cat, {}, raw))
    assert v["unevaluable_categories"] == ["containment", "grant_exercise_gap"]
    ok("coverage survives into the verdict", str(v["unevaluable_categories"]))


def t_blind_cap_escalates_not_clears():
    assert caps["privileged_container"]["state"] == "not_evaluable"
    assert caps["filesystem_mcp_root_slash"]["state"] == "not_evaluable"
    ok("blind cap escalates, never clears", "2 caps not_evaluable")


def t_partial_cannot_clear_a_cap():
    # A floor cannot prove the absence of a wildcard.
    assert caps["wildcard_tool_grant"]["state"] == "not_evaluable"
    ok("PARTIAL cannot clear a cap", caps["wildcard_tool_grant"]["note"])


if __name__ == "__main__":
    print("guards:")
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("t_")]:
        fn()
    print("\nall guards held.")
