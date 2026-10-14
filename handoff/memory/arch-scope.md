---
name: arch-scope
description: x86-64 and aarch64 are the graded targets; other arches only need to plug in without hardcoding
metadata:
  node_type: memory
  type: feedback
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-07T08:01:22.306Z
---

Do not spend effort taking riscv, mips or other arches end to end (lift to decompiler). Adding an arch must be effortless and free of hardcoding, but supporting it out of the box is not a goal now.

**Why:** the user said (2026-10-07) "we do not have to support all arches out of the box, pluggin in new arch should be effortless, not end to end right now".

**How to apply:** fix work targets x86-64 and aarch64 (the equivalence gates). A riscv/mips census move is fine as a side effect of an arch-neutral fix; never chase one. Keep arch facts in data (Sleigh bundle, r2abi rows, conventions) instead of per-arch code paths.
