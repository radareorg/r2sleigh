Measuring r2s
=============

This file used to describe `scripts/reversing_benchmark.py`, a harness that
drove radare2 with the r2sleigh plugin (`a:sla`, `pd:s`) over tiered corpora.
The plugin is deleted, so that harness, `scripts/kernel_smoke.py` and
`scripts/bench_semantic_metadata.py` could not run a single cell and are
removed. Each question they asked has a live owner that asks it of `r2s`:

| Question | Owner | Run |
|---|---|---|
| Does the rendered C compute what the binary computes? | `tests/equiv` | `tests/equiv/run_equiv.py --r2s target/debug/r2s` |
| Does any rendering read a value nothing wrote? | `scripts/certify_render.py` | `python3 scripts/certify_render.py --bins <dir> --r2s target/release/r2s` |
| How much of a whole binary renders at all? | `tests/coverage` | `./tests/coverage/run_coverage.sh` |
| Where do discovery, naming and decoding disagree with radare2? | `scripts/diff_r2.py` | `python3 scripts/diff_r2.py --bins <dir> --limit 30` |
| What does DecBench say, on its own protocol? | `tests/decbench` | `tests/decbench/run_decbench.sh` |
| How does a stage's cost grow with the body? | `tests/corpus/growth_fit.py`, `work_fit.py` | `R2SLEIGH_TIMING=1 tests/coverage/sweep_binary.sh <bin> > log` |

A large binary (a coreutils build, a kernelcache) is measured for robustness
by `tests/coverage/sweep_binary.sh <binary>`, which renders every function
`afl` finds in one streaming `r2s` process and records each refusal's cause.
`scripts/setup_corpus.py` still builds local corpora (coreutils, CGC, Juliet)
under `/tmp/r2sleigh-corpora` for feeding those sweeps.

Principles that carry over:

- Keep binaries local. Do not commit corpus builds, kernelcaches or reports.
- Keep reports deterministic and sorted, so two revisions diff.
- A failure is a work item at its canonical owner, never snapshot churn.
- A score is never semantic proof: read representative output before claiming
  a gain (AGENTS.md, Manual Verification).
