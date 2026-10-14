---
name: ci-ratchet-check
description: "Check the PR's CI run after each push; the equivalence ratchet compares failure reasons, not only statuses"
metadata:
  node_type: memory
  type: feedback
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-05T00:32:40.346Z
---

CI on engine/roadmap (PR #67) was red for ~20 pushes (94bc999f..928f0526, 2026-10-04/05) on one ratchet line nobody read: a residual's spelled type changed (`r2sleigh_residual_i64` -> `u64`, caused by f9111a28). Contabo equivalence comparisons only diffed `status`, so they missed it.

**Why:** a red gate hides the next real regression; the ratchet also fails when a non-equal record fails "for another reason".

**How to apply:** after pushing, `gh run list --branch engine/roadmap` and read failed jobs (`gh run view <id> --log-failed | grep 'ratchet: '`). When comparing contabo records to `tests/equiv/baseline.json`, compare `gate.reason(status, evidence)` against the baseline `reason` too (import `tests/equiv/gate.py`). Bisect a changed reason before blessing it. Related: [[feedback-user-facing-impact-table]].
