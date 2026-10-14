---
name: advisor-for-design
description: technical design questions go to the advisor for the best long-term solution after research; no patchy fixes; radare2 defects go upstream as PRs
metadata:
  node_type: memory
  type: feedback
  originSessionId: f617cb1c-6459-42bc-b410-ade5debf9280
  modified: 2026-10-13T07:17:21.299Z
---

On 2026-10-13 the user said: "for radare2 fixes yes, raise upstream PRs. for technical questions ask advisor for best long term solution not patchy solution do research before implementing".

**Why:** the user wants each technical decision settled the way it should be settled long term, with no quick patch that a later rewrite must undo. They also approved upstream radare2 PRs for the defects the differential finds.

**How to apply:**
- Before implementing a design choice, research the code, the specs and prior art: an open question (a premise to accept, a contract shape such as a two-register result, where a fact's owner lives) goes to the advisor along with that research.
- Choose the long-term owner and contract, not the smallest diff.
- A radare2 defect the differential judges `r2s-right` becomes an upstream PR in `../radare2`, one idea per PR, with a one-line commit message and no assistant attribution (AGENTS.md, radare2 section). Validate it with `make -C ../radare2` and `r2r`.
- Related: [[rate-every-fix]].
