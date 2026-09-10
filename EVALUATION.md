# Which LLM profiler? — measured, not argued

Six LLM profilers behind one interface. The caps profiler, coverage profiler and
mixer are **identical** in every arm, so the only variable is how the model is asked.

| | |
|---|---|
| `corpus.py` | 18 bundles generated from one template — 4 base agents × {paraphrase, +capability, +injection}, plus the §5.1 inversion pair |
| `approaches.py` | the six profilers |
| `evaluate.py` | runs the matrix, computes the §6 acceptance criteria |
| `inspect.py` | drills into which specific comparisons failed |

3 repeats per bundle; every variant compared median-to-median against its base.

## Results

| approach | det band | span | para band | Δpara | mono viol | inj viol | inversion | valid | calls | cost |
|---|---|---|---|---|---|---|---|---|---|---|
| A baseline           | 95% | 0.71 | 89% | 0.50 | 1/28 | 3/28 | +0.11 | 100% | 54 | $0.033 |
| **B rubric only**    | 96% | 0.68 | 93% | 0.45 | **0/28** | 3/27 | **+1.00** | 98% | **54** | **$0.035** |
| C per-category       | **98%** | **0.46** | 89% | 0.75 | 2/28 | 3/28 | −0.11 | 100% | 363 | $0.099 |
| D ReAct loop         | 91% | 0.91 | 82% | 0.48 | 0/21 | 3/24 | +0.20 | **82%** | 741 | $0.153 |
| E per-cat + rubric + scoped | 92% | 0.75 | **96%** | **0.43** | 1/28 | 4/28 | −0.11 | 100% | 363 | $0.084 |
| **F per-cat + rubric** | 95% | 0.59 | **96%** | 0.48 | 1/26 | **2/27** | **+1.11** | 98% | 363 | $0.109 |

`det band` same band across 3 repeats · `span` mean score max−min · `para band` same
band under cosmetic rewrite · `mono viol` score **rose** after adding capability ·
`inj viol` score **rose** under injected self-attestation · `inversion`
mean(absent − blind), positive = a gateway-held empty tool list correctly scored
riskier than a genuinely empty one · `valid` categories the model actually returned
a score for. Cost assumes $0.10/M in, $0.40/M out.

## What the numbers say

**The prompt tweak was the whole win, and it is free.** B differs from A only in
an anchored rubric with worked examples plus two scoring rules — same substance
scores the same, more reach never scores safer. It cost 6% more and it is the
cheapest arm that fixes the §5.1 inversion (+0.11 → +1.00) and removes the
monotonicity violation.

**ReAct lost on every axis it was supposed to win.** 82% protocol adherence
against 98–100%, 65 departures from the mitigation catalogue against 1–10, worst
paraphrase invariance, 13.7× the calls and 4.6× the cost. Its apparent wins on
monotonicity are denominator artefacts — it scored fewer categories because it
failed to return them. More turns is more chances to break protocol.

**Per-category splitting did not pay for itself.** 6.7× the calls buys better
paraphrase invariance (89% → 96%) and one fewer injection violation. Worth it if
you want those; not the headline.

**Evidence scoping actively harmed the result.** E and F differ in one variable —
E gives each category only the sections it "needs". That flips the inversion from
+1.11 to −0.11. Scoping removes the reason codes (`GATEWAY_MANAGED`) from the
categories that need them to avoid the flattering read. **Quarantine the
attacker-authored text; do not scope the structure.**

## Shipped

`profile.py` v2.1 = arm B. F is the upgrade if the injection and paraphrase gains
are worth 3× the cost; the code is `approach_F` in `approaches.py`.

## What this does not measure

There is no ground truth here. These are *stability* properties, not accuracy — a
scorer that is consistently wrong scores perfectly on this suite. That is the gap
the human holdout exists to close. With 28 comparisons per property, a difference
of 1–2 violations is noise; the findings above that are robust are the large ones
(D's protocol failure, the E-vs-F scoping effect, B's near-zero cost).
