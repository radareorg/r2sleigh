---
name: feedback-user-facing-impact-table
description: "Every loop update ends with a table of user-facing impact (speed, complexity, correctness, CI time), measured not guessed"
metadata:
  node_type: memory
  type: feedback
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-04T17:36:35.254Z
---

Each status update in the roadmap loop must include a table of the user-facing improvement the turn delivered: asymptotic complexity before/after, measured wall time (census, equivalence, CI), correctness counts (equivalence equal/differs, tests), memory where relevant.

**Why:** the user asked (2026-10-04) to see what each refactor buys them — "how much faster and correct result and ci runs will be faster" — not only internal structure notes.

**How to apply:** report measured numbers from the census A/B, contabo equivalence and test runs; state "no user-visible change" plainly when a stage is structure-only (byte-identical output, timing within noise), and give the complexity change it enables. Never present an unmeasured speedup as measured. Related: [[census-and-equivalence-gates]].
