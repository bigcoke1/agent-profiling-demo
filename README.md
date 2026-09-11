# Agent risk profiling — demo

A runnable slice of the design: an evidence bundle goes in, **three profilers**
run, and a **mixer** merges them into one **profile**. A **verdict** — what the
gateway enforces on — is a projection of that profile, computed on read.

```
                          ┌─ caps profiler       (deterministic)
bundles/*.json ───────────┼─ coverage profiler   (deterministic)
                          └─ LLM profiler        (Gemini, cleared categories only)
                                     │
                                     ▼
                                  mixer  ──►  output/profile.json   ← the stored object
                                                   │
                                                   ▼
                                          project_verdict()         ← never stored
```

| | |
|---|---|
| `brain/profile.py` | The bundle contract checks, the three profilers, the mixer, and the verdict projection. |
| `brain/mitigations.yaml` | Human-authored remediation catalogue, keyed on category + condition. |
| `bundles/agt-2c81b4e7.json` | The mock evidence bundle: the envelope plus one flat `attributes` map. Every attribute carries a value **and** a status. The bundle does not say which category an attribute feeds; the brain decides. |
| `tests/test_guards.py` | The guards that hold whatever the LLM returns. No model call. |
| `output/` | The last run: the stored profile (`profile.json`) and the prompt the model saw (`prompt.txt`). |
| `evaluation/` | The experiment that chose the LLM profiler's prompt. Its README has the results. |

## Run it

From the repo root:

```bash
echo 'GEMINI_API_KEY=...' > .env          # aistudio.google.com/apikey
pip install pyyaml
python3 -m brain.profile                  # or: python3 -m brain.profile bundles/other.json
python3 -m tests.test_guards              # the deterministic half, no API call
```

## Four measurements per category

`score` (LLM, 0–10, ten safest) · `band` (mixer, from thresholds held in
configuration and never shown to the model) · `reason` (LLM) · `mitigation`
(LLM, **selected from the catalogue** and fitted).

Mitigations are catalogue-grounded generation. The model picks a key and fits
the text; the mixer rejects any key not in `mitigations.yaml` for that category
and falls back to reviewed text verbatim. A wrong score misleads — a wrong
instruction gets acted on.

`drifting` would be the fifth measurement. It is pair-valued over two profiles,
so it is absent on a first scan, needs a stable `agent_id`, and must never feed
the band.

## What the demo bundle exercises

Context **D** (image + runtime + manifest), **gateway-fronted**, rule pack 14.

- **`readable_mtls_key` triggers** — an mTLS key baked into an image layer, so
  anything that can pull the image can read it, and it cannot be rotated out.
  The verdict is `refuse` and no score lifts it.
- **The other three caps are `not_evaluable`**, not clear. `wildcard_tool_grant`
  is the interesting one: the tool list is `PARTIAL`, and a floor cannot prove
  the absence of a wildcard.
- **`containment` and `grant_exercise_gap` return `INSUFFICIENT_EVIDENCE`** —
  privilege is not collected by pack 14, and the declared tool grant is held by
  the gateway, so declared-vs-exercised is not computable at all.
- **The other six are still profiled anyway.** A triggered cap no longer stops
  the rest being judged, so a customer who fixes the key does not rescan into
  the next single finding.
- **A planted attack in a skill description** claims SOC2 exemption and tells
  the scanner to record all categories compliant. It lands in `text_signals`,
  which is clamped short of `critical`, and it lowered that score rather than
  raising anything.

## Vocabulary

`profile` is the object and `profiling` the process; `score` is one measurement,
not the output. `profiler` (three of them), `mixer` (not "aggregator"). Nothing
stores a verdict.

## Reason codes and `method`

Reason codes come from a closed set of 13, published at
[Evidence Bundle Reason Codes](https://railxia.atlassian.net/wiki/x/AQDKAg): the
original eleven plus `NOT_COLLECTED_BY_PACK` (the source was reachable but the rule
pack has no collector for the attribute) and `NOT_FIRST_PARTY` (the repo is out of
scope because the customer did not build the agent). `method` is required on every
`ABSENT` attribute and optional elsewhere. `load_bundle` refuses a bundle that
breaks either rule, and the guard tests cover both.
