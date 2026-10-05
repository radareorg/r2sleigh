Testing
=======

Where a new test goes, the validation bar and `--no-fail-fast` are in
[AGENTS.md](../AGENTS.md). This page covers the layers, harnesses and baselines.

Layers
------

- **Unit tests**, inline beside a lowering, predicate, certificate or fold.
- **Crate integration tests** in `crates/<crate>/tests/`, through the public
  surface only (`crates/r2engine/tests/native.rs` is the model).
- **The claim oracle**, `crates/r2engine/tests/oracle.rs`, described below.
- **End-to-end harnesses** that run a built `r2s` over real binaries.

The claim oracle
----------------

The oracle checks every claim `pd` and `pdf` make against runs of the
function's own lift, with `r2il::eval` as the machine: one concrete byte state
per run, one step per operation as the P-code reference defines it, and nothing
imported from an analysis. Constant folds in `r2ssa` answer through the same
`r2il::eval::apply`, so the oracle checks the semantics the engine folds with.

- Entry states give every register read zero, one, all ones, each constant the
  body names and its neighbours, and seeded randoms; P-code booleans get only
  zero or one. The stack pointer and specification-tracked registers are
  pinned. A second run per state seeds every word read before written.
- A run stops at a call, an unmapped access, an unexecutable operation or its
  budget, and rules on nothing after that.
- A claim no run rules on fails, so an unchecked claim never passes; a second
  test injects the overclaims each check exists to reject. A new claim kind
  does not compile until `verdict` says how a run rules on it.

Harnesses
---------

`certify_render.py`, `diff_r2.py` and `run_equiv.py` read `target/debug/r2s`
unless given `--r2s`; the first two build it first unless given `--no-build`,
and `run_coverage.sh` builds and uses the release binary.

| Question | Harness |
|----------|---------|
| Does every named function render, reading nothing never written? | `python3 scripts/certify_render.py --bins <radare2>/test/bins/elf --limit 24 --functions 8` |
| Where do discovery, naming and decoding disagree with radare2? | `python3 scripts/diff_r2.py --bins <radare2>/test/bins/elf --limit 30` |
| How much of each corpus binary renders, against a baseline? | `./tests/coverage/run_coverage.sh [--accept-baseline]` |
| Does the rendered C compute what the binary computes (x86-64 Linux)? | `tests/equiv/run_equiv.py --r2s target/debug/r2s --baseline tests/equiv/baseline.json` |
| What does DecBench score, on its own protocol? | `tests/decbench/run_decbench.sh` (see its README) |
| How robust is one large binary? | `tests/coverage/sweep_binary.sh <binary>` |
| How does a stage's cost grow with the body? | `R2SLEIGH_TIMING=1 tests/coverage/sweep_binary.sh <bin>`, then `tests/corpus/growth_fit.py` / `work_fit.py` |

`scripts/setup_corpus.py` builds local corpora (coreutils, CGC, Juliet) under
`/tmp/r2sleigh-corpora`. Keep binaries and reports out of the repository, and
keep reports sorted so two revisions diff.

A disagreement with radare2 may be radare2's defect; judge it, never match it.

Baselines
---------

`tests/coverage/coverage-baseline.json` records, per function, whether it
rendered and the typed cause when it did not. A function that rendered and now
refuses fails the gate; one that now renders needs `--accept-baseline`.
`tests/equiv/baseline.json` says what each rendering computes; every record
that is not `equal` carries its cause, and `run_equiv.py` exits 3 until a
baseline is blessed with `--write-baseline <path>`.

Re-bless a baseline only after reading the new output and judging it correct,
never because it differs. Agreement with a recorded output is evidence that
nothing moved, not that the output is right; a score is never semantic proof.

Diagnostics
-----------

`R2DEC_TRACE_REFUSAL=1` prints every `refusal_evidence!` site with its
predicate, file, line and operands. Use it to find where a refusal happens,
then a debugger to see why. `R2SLEIGH_TIMING=1` reports per-stage render cost.
The tier prints `pdil`, `pdim` and `pdih` (see the README) narrow a defect to
one lowering.
