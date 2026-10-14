---
name: profile-not-print
description: "Diagnose perf with samply/flamegraphs and logic with lldb or refusal evidence, not ad-hoc eprintln"
metadata:
  node_type: memory
  type: feedback
  originSessionId: cf9e98c3-7781-4316-8fad-7694098f271e
  modified: 2026-10-07T10:30:46.377Z
---

Use real tools before print statements: `samply` (installed in ~/.cargo/bin) on a `--profile profiling` build (release + line tables, unstripped, in Cargo.toml) folded by `scripts/samply_collapse.py` into a report and an `inferno-flamegraph` SVG; jeprof (homebrew) for heap; lldb on `--profile debugger` for logic; `R2DEC_TRACE_REFUSAL=1` evidence lines before adding any `eprintln!`.

**Why:** the user asked (2026-10-07) why flamegraphs, jemalloc, heap tools and debuggers were not used instead of print statements; one samply run found a 2.3x pdd regression (per-gap recomputation of certificate_elided_cells) that print bisection had missed.

**How to apply:** for any timing regression, profile first and read inclusive/self tables; for wrong output, read existing refusal evidence, then break in lldb. Only add a temporary print when neither answers, and remove it before commit. Related: [[large-function-perf-check]].
