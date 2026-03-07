# Agent Guidelines for r2sleigh

> LLM-focused working notes for contributors and coding agents.

## Project Summary

`r2sleigh` is a Sleigh-to-r2il pipeline for radare2.

```text
.sla (Ghidra) --> libsla --> P-code --> r2il --> ESIL
                                          |
                                          +--> SSA (r2ssa)
                                          +--> Type inference (r2types)
                                          +--> Symbolic / taint (r2sym)
                                          +--> Decompiler (r2dec)
                                          +--> Plugin / CLI export surfaces
```

The repository is no longer just "P-code to ESIL". A lot of current work lands in SSA, decompilation, symbolic execution, type inference, and radare2 integration layers.

## Read This First

1. Default to `tests/r2r` for new plugin regressions and command-output checks.
2. Do not add new snapshot-style plugin tests to `tests/e2e/integration_tests.rs` unless the case genuinely cannot be expressed in `r2r`.
3. Build and run commands in this repo have drifted over time. Prefer the commands in this file over older examples.
4. File paths below use the current `src/` layout. Older references like `r2plugin/lib.rs` are stale.
5. Architecture feature support differs by crate. Check the relevant `Cargo.toml` before documenting or wiring a new arch.

## Workspace Layout

```text
crates/
├── r2il/             # Core IL types and serialization
├── r2sleigh-lift/    # Sleigh/P-code lifting, disassembly, ESIL formatting
├── r2sleigh-export/  # Unified export pipeline for lift/ssa/defuse/dec
├── r2sleigh-cli/     # Standalone CLI
├── r2ssa/            # SSA form, dominators, def-use, optimization
├── r2sym/            # Symbolic execution, taint, summaries, solving
├── r2types/          # Type inference and signatures
└── r2dec/            # Decompiler AST, folding, lowering, codegen
r2plugin/             # Rust cdylib + C radare2 wrapper
tests/
├── r2r/              # Preferred snapshot and command regression suite
└── e2e/              # Rust semantic/FFI/benchmark suite and fixture binaries
```

## Core Types and Entry Points

| Type / Function | Location | Purpose |
|-----------------|----------|---------|
| `Varnode` | `crates/r2il/src/varnode.rs` | Sized data location: reg/mem/const/unique |
| `SpaceId` | `crates/r2il/src/space.rs` | Address-space enum |
| `R2ILOp` | `crates/r2il/src/opcode.rs` | Semantic IL op enum |
| `R2ILBlock` | `crates/r2il/src/opcode.rs` | One-instruction IL block |
| `ArchSpec` | `crates/r2il/src/serialize.rs` | Architecture metadata |
| `Disassembler` | `crates/r2sleigh-lift/src/disasm.rs` | libsla wrapper and P-code lifting |
| `format_op()` / `op_to_esil()` | `crates/r2sleigh-lift/src/esil.rs` | Text and ESIL formatting |
| `run_action_output()` | `crates/r2sleigh-cli/src/main.rs` | CLI action/format dispatcher |
| export helpers | `crates/r2sleigh-export/src/lib.rs` | Shared export pipeline used by CLI/plugin |
| `SSAVar` | `crates/r2ssa/src/var.rs` | Versioned SSA variable |
| `SSAOp` | `crates/r2ssa/src/op.rs` | SSA operation enum |
| `to_ssa()` | `crates/r2ssa/src/block.rs` | R2IL block -> SSA block |
| `DefUseInfo` | `crates/r2ssa/src/defuse.rs` | Def-use analysis result |
| `FunctionSSABlock` / `SSAFunction` | `crates/r2ssa/src/function.rs` | Function-level SSA with phi nodes |
| `AnalysisResult` and type passes | `crates/r2types/src/` | Type inference payloads |
| `CExpr` / `CStmt` | `crates/r2dec/src/ast.rs` | Decompiler AST |
| `FoldingContext` | `crates/r2dec/src/fold/` | Expression folding and simplification |
| `LowerCtx` | `crates/r2dec/src/analysis/lower.rs` | SSA-to-expression lowering |
| plugin Rust surface | `r2plugin/src/lib.rs` | JSON commands, analysis helpers, FFI |
| plugin C wrapper | `r2plugin/r_anal_sleigh.c` | radare2 callbacks and command dispatch |

## Build and Run

Use these commands from the workspace root unless noted otherwise.

```bash
# Build the workspace with x86 support
cargo build --workspace --features x86

# Run the Rust test suite
cargo test --workspace --features x86

# Run the CLI explicitly
cargo run -p r2sleigh-cli --bin r2sleigh --features x86 -- \
  disasm --arch x86-64 --bytes "31c00000000000000000000000000000" --format json

# Install the plugin via the workspace alias
cargo install-plugin -- --features x86

# Or install all plugin architectures through the Makefile helper
make -C r2plugin RUST_FEATURES=all-archs install

# Run the preferred plugin regression suite
make -C tests/r2r run

# Run the Rust e2e suite when needed
cargo e2e-test
```

Notes:

- `cargo run --features x86 -- ...` is stale at the workspace root; use `-p r2sleigh-cli --bin r2sleigh`.
- `cargo install-plugin` is defined in `.cargo/config.toml` and wraps `r2plugin/src/bin/r2sleigh-plugin-install.rs`.
- x86/x86-64 disassembly still needs at least 16 bytes of input; pad with zeros.

## Architecture Support

Feature matrices are not identical across crates.

- `r2plugin` currently exposes `x86`, `arm`, `riscv`, and `all-archs`.
- `r2sleigh-cli` currently exposes `x86`, `arm`, `mips`, `riscv`, and `all-archs`.
- There is still some compatibility code for `mips` in shared/plugin code, but the plugin crate itself is currently feature-gated around `x86`, `arm`, and `riscv`.
- If you change architecture wiring, inspect both `r2plugin/Cargo.toml` and `crates/r2sleigh-cli/Cargo.toml`.

For radare2 auto-selection, the plugin currently maps common values like:

- `anal.arch=x86`, `anal.bits=64` -> `x86-64`
- `anal.arch=x86`, `anal.bits=32` -> `x86`
- `anal.arch=arm`, `anal.bits=32` -> `arm`
- `anal.arch=arm`, `anal.bits=64` or `anal.arch=arm64` / `aarch64` -> `aarch64`
- `anal.arch=riscv`, `anal.bits=32` -> `riscv32`
- `anal.arch=riscv`, `anal.bits=64` -> `riscv64`

Manual override stays:

```bash
r2 -qc 'a:sla.arch x86-64; a:sla.arch' /bin/ls
```

## Testing Policy

### Default: `tests/r2r`

Use `tests/r2r` for new regressions involving:

- plugin commands such as `a:sla.*`, `a:sym.*`, `pdd`, `pdD`
- JSON/text/ESIL/CFG/SSA/def-use/type payload shape
- command UX, help text, error text, and normalized decompiler output
- radare2 integration behavior that is best expressed as command snapshots

Why:

- faster feedback
- better snapshot-style diffs
- already normalized around radare2 command execution
- consistent with how users exercise the plugin

### Use `tests/e2e` only when `r2r` is the wrong tool

Keep Rust E2E tests for:

- FFI / ABI checks
- CLI `run` export semantics
- analysis-quality thresholds or benchmark-style assertions
- cases that need direct Rust-side orchestration rather than command snapshots

`tests/e2e/integration_tests.rs` still exists, but it is not the default place for new plugin regression coverage.

## Adding New Tests

### Preferred workflow for new features

1. Implement the feature.
2. If the user-facing behavior is visible through radare2 commands, add or update an `r2r` case.
3. If the feature needs a specific binary pattern, add or update a fixture source under `tests/e2e/`.
4. Run `make -C tests/r2r run`.
5. If the change also affects CLI semantics, FFI, or benchmark-style behavior, run `cargo e2e-test` or a focused `tests/e2e` module.

### Where to put new `r2r` cases

`tests/r2r/db/extras/r2sleigh_core`
- very small, deterministic instruction-level checks
- good for `a:sla.json`, `a:sla.regs`, `a:sla.mem`, `a:sla.vars`

`tests/r2r/db/extras/r2sleigh_integration_fast`
- function-level plugin behavior that should stay quick
- good for `a:sla.ssa.func`, `a:sla.cfg.json`, `a:sla.dom`, `a:sla.types`, `a:sla.opvals`

`tests/r2r/db/extras/r2sleigh_integration_extended`
- slower or heavier coverage
- symbolic execution, taint, complex decompilation, larger binaries

### `r2r` test authoring tips

- Normalize output with `jq -c`, `grep`, `head`, `tail`, or boolean expressions.
- Prefer structural assertions over brittle full-output matches when formatting is likely to evolve.
- Keep these args unless you have a reason not to:

```text
-e scr.color=false -e log.level=0 -e bin.relocs.apply=true
```

- `tests/r2r/Makefile` builds the fixture binaries from `tests/e2e/` and symlinks them into `tests/r2r/bins/`.
- If you add a brand-new fixture binary, update `tests/r2r/Makefile` so the harness links it.

Minimal `r2r` example:

```text
NAME=instruction_json_nonempty
FILE=bins/vuln_test
ARGS=-e scr.color=false -e bin.relocs.apply=true
EXPECT=<<EOF_EXPECT
true
EOF_EXPECT
CMDS=<<EOF_CMDS
s 0x401281
a:sla.json | jq -c 'length>0'
EOF_CMDS
RUN
```

### Fixture guidance

Use the smallest fixture that exercises the behavior:

- `tests/e2e/vuln_test.c` for focused plugin features and common analysis cases
- `tests/e2e/stress_test.c` for larger decompiler/symbolic/type cases
- `tests/e2e/test_func.c` for small structured helper functions
- `tests/e2e/sym_test.c` for symbolic-execution-specific patterns

When you add a fixture function:

1. Add the function with a short comment explaining what it exercises.
2. Wire it into the fixture's `main()` or other entry path if the tests need runtime access.
3. Add or update the corresponding `r2r` snapshot.

## Common Change Workflows

### Add a new R2IL opcode

1. Add the variant to `crates/r2il/src/opcode.rs`.
2. Teach the lifter to emit it in `crates/r2sleigh-lift/src/disasm.rs`.
3. Add text and ESIL formatting in `crates/r2sleigh-lift/src/esil.rs`.
4. Check any export path that formats or serializes the new op through `crates/r2sleigh-export/src/lib.rs` or CLI output.
5. Add tests. Prefer an `r2r` snapshot when the opcode is visible through plugin output.

### Add SSA support for a new op

1. Add the SSA variant to `crates/r2ssa/src/op.rs`.
2. Convert it in `crates/r2ssa/src/block.rs`.
3. Update `dst()` and `sources()` in `crates/r2ssa/src/op.rs`.
4. Add function-level or instruction-level coverage, usually via `a:sla.ssa`, `a:sla.ssa.func`, or `a:sla.defuse`.

### Add decompiler support for a new SSA op

1. Add lowering in `crates/r2dec/src/analysis/lower.rs` if needed.
2. Add fold/codegen support under `crates/r2dec/src/fold/`.
3. Test through `a:sla.dec` snapshots and add direct Rust tests when local folding behavior is easier to assert there.

### Add or change a plugin command

1. Rust-side command data shaping usually lives in `r2plugin/src/lib.rs`.
2. radare2 command dispatch and help text live in `r2plugin/r_anal_sleigh.c`.
3. Add or update `r2r` coverage for help text, happy path, and error path.

### Add a new architecture

1. Update the relevant crate feature flags.
2. Wire spec/disassembler creation in the CLI, plugin, and export surfaces that need it.
3. Add at least one focused test path for the new arch.
4. Prefer documenting only architectures that are actually wired and tested in the crate you changed.

## Plugin Command Surface

Common instruction-level commands:

| Command | Purpose |
|---------|---------|
| `a:sla` | status / help |
| `a:sla.info` | current architecture info |
| `a:sla.arch [name]` | get or set Sleigh arch override |
| `a:sla.json` | raw r2il for current instruction |
| `a:sla.regs` | read/write registers |
| `a:sla.opvals` | analysis src/dst register view |
| `a:sla.mem` | memory accesses |
| `a:sla.vars` | varnodes |
| `a:sla.ssa` | instruction SSA |
| `a:sla.defuse` | instruction def-use |

Function-level commands:

| Command | Purpose |
|---------|---------|
| `a:sla.ssa.func` | function SSA with phi nodes |
| `a:sla.ssa.func.opt` | optimized function SSA |
| `a:sla.defuse.func` | function-wide def-use |
| `a:sla.dom` | dominator tree |
| `a:sla.slice <var>` | backward slice |
| `a:sla.types` | type-inference payload |
| `a:sla.taint` | taint analysis |
| `a:sla.sym` | symbolic summary |
| `a:sla.sym.paths` | explored symbolic paths |
| `a:sla.sym.merge [on|off]` | symbolic merge toggle |
| `a:sla.dec [name|addr]` | decompile |
| `pdd`, `pdD` | aliases for `a:sla.dec` |
| `a:sla.cfg` | ASCII CFG |
| `a:sla.cfg.json` | CFG JSON |

Targeted symbolic commands:

| Command | Purpose |
|---------|---------|
| `a:sym.explore <target>` | explore paths reaching target |
| `a:sym.solve <target>` | solve concrete input for target |
| `a:sym.state` | show cached symbolic state |

Important:

- Use `a:sym.solve`, not the old `a:sla.sym.solve` spelling.
- Use `a:sla.cfg.json` when you want stable structured assertions.

## Two SSA Block Types

There are two different block types in `r2ssa`:

| Type | Location | Purpose |
|------|----------|---------|
| `SSABlock` | `crates/r2ssa/src/block.rs` | single-instruction SSA block |
| `FunctionSSABlock` | `crates/r2ssa/src/function.rs` | function block with phi nodes |

`r2dec` works with `FunctionSSABlock`.

When writing direct decompiler tests, build `FunctionSSABlock` values directly rather than assuming a convenience constructor exists.

## File Quick Reference

| File | Edit this when... |
|------|--------------------|
| `crates/r2il/src/opcode.rs` | adding or changing IL ops |
| `crates/r2sleigh-lift/src/disasm.rs` | changing P-code lifting or register naming |
| `crates/r2sleigh-lift/src/esil.rs` | changing text or ESIL rendering |
| `crates/r2sleigh-export/src/lib.rs` | changing shared export formatting or action plumbing |
| `crates/r2sleigh-cli/src/main.rs` | changing CLI commands or action/format routing |
| `crates/r2ssa/src/op.rs` | changing SSA operations |
| `crates/r2ssa/src/block.rs` | changing SSA conversion |
| `crates/r2ssa/src/function.rs` | function SSA / phi handling |
| `crates/r2ssa/src/defuse.rs` | changing def-use analysis |
| `crates/r2sym/src/` | changing symbolic execution or taint internals |
| `crates/r2types/src/` | changing type inference |
| `crates/r2dec/src/fold/` | changing decompiler folding and lowering |
| `crates/r2dec/src/codegen.rs` | changing C output formatting |
| `r2plugin/src/lib.rs` | changing plugin-side Rust logic and JSON payloads |
| `r2plugin/r_anal_sleigh.c` | changing radare2 callbacks, command help, dispatch |
| `tests/r2r/Makefile` | changing r2r harness setup or fixture linking |
| `tests/r2r/db/extras/` | adding or updating snapshot regressions |
| `tests/e2e/README.md` | checking when to use Rust E2E vs `r2r` |
| `tests/e2e/integration_tests.rs` | legacy semantic/FFI coverage, not the default for new snapshots |

## Gotchas

1. x86/x86-64 lifting still expects 16 bytes minimum.
2. ESIL subtraction must use ASCII `-`, not Unicode minus.
3. `Const` means literal; `Unique` means temporary SSA-like storage, not memory.
4. Width mismatches usually need explicit sign/zero extension.
5. Register aliasing needs deterministic policy in output and recovery.
6. `#[no_mangle]` is now `#[unsafe(no_mangle)]` under Rust 2024.
7. Plugin, CLI, and export crate feature matrices are not identical.
8. Prefer `a:sla.cfg.json`, `a:sla.types`, and `jq`-normalized checks over raw pretty-printed output in snapshots.
9. Use `r2dec/address.rs::parse_address_from_var_name()` for consistent `const:` / `ram:` parsing.
10. Taint summaries intentionally filter noisy stack/frame-pointer labels.
11. If you add a new fixture binary, remember both the build step and the `tests/r2r/bins/` symlink step.

## Useful References

- `README.md` for current build and testing quick-start
- `tests/e2e/README.md` for the split between `r2r` and Rust E2E
- `doc/` for IL, SSA, ESIL, decompiler, taint, symex, and type-system notes
- radare2 ESIL docs: <https://book.rada.re/disassembling/esil.html>
- Ghidra P-code reference: <https://ghidra.re/courses/languages/html/pcoderef.html>
