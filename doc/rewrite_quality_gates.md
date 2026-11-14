Quality gate
============

`scripts/quality-gate.sh` is the local gate for rewrite and
architecture-sensitive work. It changes no tracked source, and a missing tool
fails the gate with an install hint rather than skipping a check. It
complements the validation bar in [AGENTS.md](../AGENTS.md); it does not
replace it.

```bash
scripts/quality-gate.sh                  # run it
scripts/quality-gate.sh --dry-run        # print the commands only
scripts/quality-gate.sh --strict-dylint  # deny Dylint warnings (or R2SLEIGH_STRICT_DYLINT=1)
```

Phases
------

| # | Phase | Runs |
|---|-------|------|
| 1 | Tools | checks every tool below is installed |
| 2 | Dependencies | `cargo machete --with-metadata --skip-target-dir`; `cargo +nightly udeps --workspace --all-targets --all-features` |
| 3 | Format and lint | `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test -p r2rewrite` |
| 4 | Dylint | `tools/dylints/r2sleigh_lints` over the workspace |
| 5 | Kani | every crate whose `src` contains a `kani::proof` harness |
| 6 | Mutants | `cargo mutants` on `crates/r2ssa/src/var.rs`, output in `target/quality-gate/mutants-r2ssa-var` |
| 7 | Harness contracts | the Python unit tests of `tests/equiv` and `tests/decbench`, and `tests/test_no_plugin.py` |
| 8 | Certification contracts | `scripts/test_certify_render.py` |
| 9 | Equivalence | builds `r2s`, then `tests/equiv/run_equiv.py` against `tests/equiv/baseline.json` |

Equivalence runs last because it exits 3 until a baseline is blessed
([testing.md](testing.md)). `R2SLEIGH_MUTANTS_JOBS` (default 2) and
`R2SLEIGH_MUTANTS_TIMEOUT` (default 300 s) tune local resource use only.

Tools
-----

```bash
cargo install cargo-machete
cargo install cargo-udeps --locked
cargo install cargo-dylint dylint-link
cargo install --locked kani-verifier
cargo install --locked cargo-mutants
rustup toolchain install nightly
rustup component add rustfmt clippy
rustup toolchain install nightly-2026-10-01 --component rustc-dev --component llvm-tools-preview
```

The Dylint toolchain is pinned in `tools/dylints/r2sleigh_lints/rust-toolchain`.

Reading failures
----------------

- **machete / udeps**: check whether the dependency is really unused.
- **Dylint**: warnings are reported by default because known debt remains;
  CI fails when their count rises above
  `tools/dylints/r2sleigh_lints/warning-baseline.txt` (lower it when it falls);
  use `--strict-dylint` on a cleaned slice. A strict failure usually means
  semantic storage or address facts are classified by string prefix instead of
  a typed contract.
- **Kani**: fix the invariant or tighten the proof; never delete a harness.
- **Mutants**: a survivor means the tests do not pin the behaviour.

## Round 5 lints (D289, D411, D416)

- `SCAN_IN_LOOP` (warn, `function_scale.rs`): a whole pass over a
  function-scale set inside a loop body or an iterator closure. That is an
  iteration, `clone` or `len()`-sized allocation of a dense table, a graph
  table or a collection of a function's entities or registry rows, or a call
  to a same-crate function that makes one over a function-owned table. A
  receiver that depends on the loop's own binding passes
  (`for b in blocks { for i in &b.insts }` is `O(I)`). One pass per item over
  a function-sized set is `O(|X| x |Y|)`; five of the engine's quadratics had
  this shape (1cd65fdcc, c67924d1a, adee2bc73, 6e3250060, 8e9b6edc1). The lint
  is blind to cross-crate callees, rebuilds per call and fixpoint height. A
  bounded scan states its bound in `allow(scan_in_loop, reason = ...)`, and the
  scaling bench (D404, D417) proves it. `STANDING_SCANS` lists the scans
  standing when D416 landed, by item, scan and count, unaudited. Each goes when
  its item is rewritten or its bound is stated beside it. A new scan, or one
  more of a listed one, fires; a count that falls fails until it is lowered.
- `UNPROVEN_NEGATIVE` (deny): a `bool` field of a public struct whose name
  ends in `stated`, `assumed`, `cited`, `proven` or `kept`. Such a field
  states that something does not happen (a call reads no more, a register is
  kept), and any code that builds the struct sets it with no evidence. Five
  built fixes had that cause (f6943caa5, D382, D393, D395, D379). The fact is a
  type whose owner mints it from its evidence: `ReadBound`, `Cancelled`,
  `StackWrites`, `Citation`.
- `BUILD_FACTS_READS_A_CALLEE_FACT` (deny): `r2ssa::semantic::BuildFacts` is
  what a static phase reads of a build. A read of the function or its context
  outside the allowed shape and source call-site accessors, or a method handing
  either out, lets a callee's statement reach a phase a kept build does not run
  again (doc/adr-callee-builds.md, D289).
