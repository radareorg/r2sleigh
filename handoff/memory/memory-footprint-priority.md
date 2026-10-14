---
name: memory-footprint-priority
description: "user runs out of RAM and swap on a 16 GB Mac; engine peak RSS is a first-class metric, measured with dhat"
metadata:
  node_type: memory
  type: feedback
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-08T13:26:27.175Z
---

On 2026-10-08 the user said: "i am not happy with the space optimization we're doing ... we keep running out of memory + swap ... with this performance we can never scale". The machine has 16 GB RAM and 3 GB swap.

**Why:** a 9 MB binary took 900 MB for one `pdd` and 351 MB for `afl`; the user wants the engine to scale to large binaries, and the dev loop (builds, test suite, census) to fit in RAM.

**How to apply:**
- Report peak RSS beside time in every impact table ([[feedback-user-facing-impact-table]]), on the census TIMED cases (0pack/pumasim pdd and afl, see [[large-function-perf-check]]).
- Find the peak with dhat: a scratch worktree with `dhat = "0.3"`, `dhat::Alloc` as global allocator, `Profiler::new_heap()` in main, dropped before every `process::exit`; build with `CARGO_PROFILE_RELEASE_DEBUG=line-tables-only CARGO_PROFILE_RELEASE_STRIP=false`; rank `pps` by `gb` (bytes at the global peak) by first engine frame. Never commit the dhat change.
- Run one heavy job at a time (cargo build/test, census, sweep, dhat); never two cargo builds in different target dirs at once.
- CI's timing gate holds RSS within 1.1x of the base (MF, branch mem-footprint).
