---
name: loop-never-idles-on-merge-questions
description: pending merge or D27 answers block only the merge; stacked roadmap work continues; the loop stops only when no item can proceed
metadata:
  node_type: memory
  type: feedback
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-11T09:59:25.595Z
---

On 2026-10-11 the roadmap /loop held four hourly ticks and then stopped, waiting on two answers (who merges stack 128 into `rebuild`; D27 now or after SM). The user asked "why did we stopped the loop ? is whole roadmap complete ?". The roadmap still had LX2, SM, T, the D27 merge, and step 6 left.

**Why:** an open merge question blocks only that merge; the next roadmap item stacks on the top PR (`gh stack link --base rebuild`) and needs no answer.

**How to apply:** leave merge questions open as a one-line note and keep working the next item in ROADMAP.md's Order section. Stop the loop only when every remaining item needs the user. Related: [[stacked-prs]], [[rate-every-fix]].
