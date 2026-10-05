Contributing to r2sleigh
========================

The working rules — ownership, the anti-hack standard, testing policy and the
validation bar — are in [AGENTS.md](AGENTS.md) and apply to every change.

Reporting issues
----------------

Include the architecture and binary, the exact `r2s` command, expected and
actual output, the commit and `cargo --version`. For a refusal, add
`R2DEC_TRACE_REFUSAL=1` output; for a crash, `RUST_BACKTRACE=1`.

Commits
-------

Prefix the component, imperative mood, first line at most 72 characters; the
body says why, not what:

```
r2ssa: fix phi placement for switch blocks
r2s: add the ax cross-reference command
```

Code style
----------

- `cargo fmt --all`; `cargo clippy --workspace --all-features -- -D warnings`.
- `thiserror` for error types; `Result` rather than `panic!`; `anyhow` only in
  tests and binaries.
- Exhaustive `match` over a `_ =>` catch-all where feasible; small functions;
  `scripts/structure-report.sh` must not rise.
- Edition 2024: `#[unsafe(no_mangle)]`, explicit `unsafe {}` inside
  `unsafe fn`.

Pull requests
-------------

- [ ] the validation bar in [AGENTS.md](AGENTS.md) passes
- [ ] new behavior has a test at the layer users exercise ([doc/testing.md](doc/testing.md))
- [ ] rendered-output changes are explained line by line, and read by hand
- [ ] docs updated where a decision or status changed (ROADMAP, the ADR)

By contributing you agree your contributions are licensed under
LGPL-3.0-only.
