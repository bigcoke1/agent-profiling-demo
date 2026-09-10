# Agent risk profiling — demo

A runnable slice of the design: an evidence bundle goes in, **three profilers**
run, and a **mixer** merges them into one **profile**. A **verdict** — what the
gateway enforces on — is a projection of that profile, computed on read.

```
                          ┌─ caps profiler       (deterministic)
bundle.yaml ──────────────┼─ coverage profiler   (deterministic)
                          └─ LLM profiler        (Gemini, cleared categories only)
                                     │
                                     ▼
                                  mixer  ──►  profile.json   ← the stored object
                                                   │
                                                   ▼
                                          project_verdict()  ← never stored
```

| | |
|---|---|
| `bundle-agt-2c81b4e7.yaml` | Evidence bundle. Every field carries a value **and** a status. |
| `mitigations.yaml` | Human-authored remediation catalogue, keyed on category + condition. |
| `profile.py` | The three profilers, the mixer, and the verdict projection. |
| `test_guards.py` | The guards that hold whatever the LLM returns. No model call. |
| `profile.json` | Sample output — the profile, not a verdict. |

## Run it

```bash
echo 'GEMINI_API_KEY=...' > .env      # aistudio.google.com/apikey
pip install pyyaml
python3 profile.py                    # or: python3 profile.py other-bundle.yaml
python3 test_guards.py                # deterministic half, no API call
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

Context **C** (image + runtime), **gateway-fronted**, rule pack 14.

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

## The twelfth reason code

The bundle uses `NOT_COLLECTED_BY_PACK`, which is **proposed, not in the enum**:
the source was reachable and the attribute is in the spec, but pack 14 ships no
collector for it. Distinct from `NO_SOURCE_ACCESS` (source unreachable) and from
`SOURCE_OK_NOT_PRESENT` (the one code that is an answer). It is the only absence
that legitimately becomes an answer with no change to the agent, which is what
`drifting` will need in order not to report a collector upgrade as agent drift.
