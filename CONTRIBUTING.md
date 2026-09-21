Contributing to r2sleigh
========================

Thank you for your interest in contributing. This document covers the workflow,
code style, and testing requirements for all contributions.

Reporting Issues
----------------

When reporting a bug, include:

1. **Architecture and binary**: what you were analyzing (e.g., x86-64 ELF)
2. **Command**: the exact `r2s` command that failed
3. **Expected vs actual output**: what you expected and what you got
4. **Version info**: the commit and `cargo --version`

For a refusal, include what the evidence channel says; for a crash, a
backtrace:

```bash
R2DEC_TRACE_REFUSAL=1 r2s -q -c 's main; pdd' /path/to/binary
RUST_BACKTRACE=1 r2s -q -c 's main; pdd' /path/to/binary
```

Getting Started
---------------

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-change`
3. Make your changes
4. Add tests (see Testing Requirements below)
5. Run the full test suite:
   ```bash
   cargo test --workspace --all-features --no-fail-fast
   ```
6. Open a pull request

Commit Messages
---------------

Use short, descriptive commit messages. Prefix with the affected component:

```
r2il: add FloatCompare opcode
r2ssa: fix phi placement for switch blocks
r2dec: improve for-loop detection heuristic
r2s: add the ax cross-reference command
tests: cover the narrow-return certificate
docs: update the testing guide
```

- First line: imperative mood, max 72 characters
- Body (optional): explain *why*, not *what*

Rust Code Style
---------------

The project uses Rust edition 2024.

### Error handling

- Use `thiserror` for error types
- Return `Result<T, E>` from fallible functions, not `panic!`
- Use `anyhow` only in tests and CLI, not in library crates

### Naming

- Types: `PascalCase`
- Functions/methods: `snake_case`
- Constants: `SCREAMING_SNAKE_CASE`
- Feature flags: lowercase with hyphens (`all-archs`)

### Formatting and lints

```bash
cargo fmt --all
cargo clippy --all-features -- -D warnings
```

### Edition 2024 notes

- Use `#[unsafe(no_mangle)]` instead of `#[no_mangle]`
- Use `unsafe { ... }` blocks inside `unsafe fn` bodies

### Prefer

- `format!()` over string concatenation
- `matches!()` over verbose `match` with `true`/`false` arms
- Exhaustive `match` over `_ =>` catch-all when feasible
- Small, focused functions over large monoliths

Testing Requirements
--------------------

**All new features must have tests.** This is enforced during review.

### What to test

| Change type | Required test |
|-------------|---------------|
| New opcode | Unit test in the crate that lowers it |
| New `r2s` command | Integration test in `crates/r2s/tests/` |
| New optimization pass | Unit test in `r2ssa` with before and after SSA |
| Bug fix | Regression test reproducing the bug |
| Decompiler change | The certification gate, plus a unit test for the rule |

### Running tests

```bash
# --no-fail-fast, always: without it one crate's failure hides the rest
cargo test --workspace --all-features --no-fail-fast

# One crate
cargo test -p r2ssa --all-features

# The certification gate, which runs the built shell
python3 scripts/certify_render.py --bins <radare2>/test/bins/elf \
  --limit 24 --functions 8
```

See [doc/testing.md](doc/testing.md) for the full guide.

Pull Request Checklist
----------------------

Before submitting a PR, confirm:

- [ ] `cargo build --workspace --all-features` succeeds
- [ ] `cargo test --workspace --all-features --no-fail-fast` passes
- [ ] `cargo clippy --workspace --all-features -- -D warnings` is clean
- [ ] `bash scripts/structure-report.sh` does not raise the structural debt
- [ ] New features have tests
- [ ] Commit messages follow the style above
- [ ] Documentation updated if needed (doc/, AGENTS.md)

Code Review
-----------

All PRs are reviewed before merging. Reviewers will check:

- Correctness (does it do what it claims?)
- Test coverage (are edge cases handled?)
- Style consistency (does it match the codebase?)
- Performance (does it avoid unnecessary allocations or O(n^2) patterns?)

License
-------

By contributing, you agree that your contributions are licensed under the
LGPL-3.0-only license, matching the project.
