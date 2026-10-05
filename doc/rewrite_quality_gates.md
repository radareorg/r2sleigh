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
rustup toolchain install nightly-2026-04-16 --component rustc-dev --component llvm-tools-preview
```

The Dylint toolchain is pinned in `tools/dylints/r2sleigh_lints/rust-toolchain`.

Reading failures
----------------

- **machete / udeps**: check whether the dependency is really unused.
- **Dylint**: warnings are reported by default because known debt remains;
  use `--strict-dylint` on a cleaned slice. A strict failure usually means
  semantic storage or address facts are classified by string prefix instead of
  a typed contract.
- **Kani**: fix the invariant or tighten the proof; never delete a harness.
- **Mutants**: a survivor means the tests do not pin the behaviour.
