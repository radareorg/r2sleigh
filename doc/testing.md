Testing Strategy
================

Overview
--------

Tests live beside the code they test, as inline `#[cfg(test)]` modules, plus
per-crate integration tests and a set of end-to-end harnesses that run the
built `r2s`. All new features require tests, and a fix requires the test that
reproduces what it fixed.

The whole suite runs with:

```bash
cargo test --workspace --all-features --no-fail-fast
```

**`--no-fail-fast` is not optional.** Without it `cargo test` stops at the first
failing target, so one crate's known failure hides every failure in every target
that would have run after it. A whole session once reported the suite green
apart from two known fixtures while two more were red behind them. When a suite
is reported, report the count it printed rather than the class that was
expected, and give every standing failure a recorded cause — a failure count
with no cause becomes a lens that filters out everything not already in it.

Test levels
-----------

### Unit tests

Each crate has inline test modules. This is where a lowering, a predicate or a
certificate is pinned.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_narrow_return_certifies_the_full_carrier() {
        // ...
    }
}
```

### Crate integration tests

`crates/<crate>/tests/` holds tests that drive a crate's public surface without
reaching inside it. `crates/r2engine/tests/native.rs` is the model: it builds an
in-memory program out of byte literals, implements the six-method `Program`
trait over it, and asserts on what the engine renders. No binary on disk, no
external tool, no fixture to regenerate.

### End-to-end gates

These run the built `r2s` over real binaries. **Build before measuring**: the
harnesses default to `target/debug/r2s`, which `cargo build --release` does not
touch, and a measurement taken after one describes a tree several changes old.

```bash
# Certification: every named function renders, and reads nothing
# that was never written. radare2 is not run.
python3 scripts/certify_render.py --bins <radare2>/test/bins/elf \
  --limit 24 --functions 8

# Differential: the same commands through radare2 and through r2s.
python3 scripts/diff_r2.py --bins <radare2>/test/bins/elf --limit 30

# Coverage: how much of a whole binary renders at all, against a
# blessed baseline.
./tests/coverage/run_coverage.sh
```

A disagreement with radare2 is not automatically a defect in `r2s`. It may be
radare2's, in which case the fix goes upstream as its own pull request and the
expectation is corrected rather than matched.

What each kind of change needs
------------------------------

| Change | Test |
|---|---|
| New opcode | Unit test in the crate that lowers it |
| New lowering or fold | Unit test, plus a tier print that shows it |
| New `r2s` command | Integration test in `crates/r2s/tests/` |
| Optimization pass | Unit test in `r2ssa` with before and after SSA |
| Decompiler change | The certification gate, plus a unit test for the rule |
| Bug fix | A regression test reproducing the original bug |
| Discovery or naming change | The differential gate, with the disagreement judged |

Baselines and blessing
----------------------

The coverage baseline (`tests/coverage/coverage-baseline.json`) records, per
function, whether it rendered and the typed cause when it did not. A function
that rendered and now refuses fails the gate. A function that now renders is
reported and needs `--accept-baseline` to be recorded.

**A baseline is re-blessed only after the new output has been read and judged
correct**, never because it merely differs. The corpus is a canary, not a
specification: the verifier rewrites the C it checks, so agreement with a
recorded output is evidence that nothing moved, not evidence that the output is
right.

Diagnostics
-----------

`R2DEC_TRACE_REFUSAL=1` turns on the evidence channel: every `refusal_evidence!`
site prints its predicate, its file and line, and its operands. It gates the
body walk, the dispatch-table resolution, the value-range solve, the per-phase
cost line and the obligation shape.

Use it to find *where*, then attach a debugger to see *what*. Re-running under
the evidence channel and grepping a different tag each time is print debugging
with extra steps; one stop on the refusing predicate shows the whole frame at
once.

The three tier prints narrow a defect to exactly one lowering:

```bash
r2s -q -c 's main; pdil' BINARY   # r2il, as lifted
r2s -q -c 's main; pdim' BINARY   # r2ssa, with each value's binding disposition
r2s -q -c 's main; pdih' BINARY   # the r2dec tree, before rendering
```

Before committing
-----------------

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-features -- -D warnings`
3. `cargo test --workspace --all-features --no-fail-fast`
4. `bash scripts/structure-report.sh` — the structural debt may fall, never rise
5. The gate that covers what changed, from the table above
6. New behaviour has at least one test, and edge cases are covered
