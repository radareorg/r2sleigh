---
name: cache-last-resort
description: "caching is a last resort after the algorithm cannot be made fast; hold only program-wide facts computed once, never per-function artifacts across requests"
metadata:
  node_type: memory
  type: feedback
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-12T09:43:47.611Z
---

The user (2026-10-12): "even when we're doing cache we should only and only do it where we absolutely cannot optimize the algorithm", after calling 500+ MB of session cache bad design and asking that it be rethought "mathematically" and rewritten.

**Why:** retention hid slow algorithms behind memory; a 50-function session held 935 MB of per-function artifacts that nothing read again.

**How to apply:**
- The query database has two retention classes (#169): `Retention::Held` only for program-wide facts computed once (callee summaries, names, returns, the survey), `Retention::Newest` for a function's walk, analysis, sealing and rendering. Never add a capacity, an LRU or a byte budget to make a slow path look fast.
- Justify any held query by recompute cost per byte held; a whole analysis is about 8 ns/byte, so it is never worth holding.
- When a revisit is slow, speed up the algorithm (F2, LX, SM), not the cache.

Related: [[memory-footprint-priority]], [[rate-every-fix]].
