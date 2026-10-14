---
name: large-function-perf-check
description: "The pdd census (small fixtures, debug, one process per function) cannot see large-function regressions; time release pdd on big ELF functions too"
metadata:
  node_type: memory
  type: project
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-04T19:10:23.995Z
---

The census (665 functions, debug build, a process per function) is dominated by process startup; engine work there is ~2.5 ms/function in release. A quadratic regression (named-block clones per query, stage 3b, 2026-10-04) took 0pack's `get_authenticated_attributes` from 8.4 s to 23.8 s while the census looked faster.

**Why:** user-facing time is release `pdd` on large real functions; the census measures something else.

**How to apply:** after any change to r2ssa/r2dec hot paths, build `--release` and time `r2s -q -c "pdd @ <addr>" ../radare2/test/bins/elf/<bin>` for 0pack 0x0062ecf0, 0pack 0x0058e3d0, pumasim 0x0023fdf0 (largest by `afl` size), comparing output hashes and seconds against the previous commit's release binary. Profile with `CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=line-tables-only CARGO_TARGET_DIR=target/prof` and macOS `sample <pid> 5`. Report in the impact table ([[feedback-user-facing-impact-table]]).
