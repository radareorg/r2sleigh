Developer Guide
===============

This document describes the internal architecture of r2sleigh, how the crates
fit together, and how to extend the project with new opcodes, architectures,
commands, and optimization passes.

For build instructions see [BUILDING.md](BUILDING.md). For contribution
workflow see [CONTRIBUTING.md](CONTRIBUTING.md).

Module Map
----------

```
crates/
├── r2il/             Core IL types (Varnode, SpaceId, R2ILOp, R2ILBlock)
├── r2sleigh-lift/    Sleigh/P-code → r2il translation, ESIL formatting
├── r2sleigh-cli/     CLI tool (compile, disasm, info)
├── r2ssa/            SSA: CFG, domtree, phi, optimization, taint, defuse
├── r2sym/            Symbolic execution: Z3, paths, solver, call hooks
├── r2types/          Type inference: constraint solver, arena, signatures
└── r2dec/            Decompiler: folding, structuring, codegen, symbols
r2plugin/             radare2 plugin: Rust cdylib + C wrapper
tests/e2e/            Integration tests against radare2
```

### Crate Dependency Graph

```
r2il  ←──  r2sleigh-lift  ←──  r2sleigh-cli
  ↑              ↑
  |              |
r2ssa ←────────┘
  ↑
  ├──── r2sym (symbolic execution)
  ├──── r2types (type inference)
  ├──── r2dec (decompiler)
  └──── r2plugin (radare2 FFI)
```

All crates depend on `r2il` for the core types. `r2ssa` depends on both `r2il`
and `r2sleigh-lift` (for register name resolution). The analysis crates
(`r2sym`, `r2types`, `r2dec`) depend on `r2ssa` for the SSA representation.

Data Flow: Bytes to C Code
---------------------------

```
Machine code bytes
        │
        ▼
   [r2sleigh-lift]  Disassembler::lift()
        │           Uses libsla to get P-code, translates to R2ILOp
        ▼
   R2ILBlock { addr, size, ops: Vec<R2ILOp> }
        │
        ├──────────────────────────────────────┐
        │                                      │
        ▼                                      ▼
   [r2sleigh-lift]                        [r2ssa]
   op_to_esil()                           SSAFunction::from_blocks()
        │                                      │
        ▼                                      ▼
   ESIL string                            SSAFunction { cfg, blocks, phis }
   (radare2 compat)                            │
                                               ├───── optimize_function()
                                               ├───── TaintAnalysis::analyze()
                                               ├───── backward_slice_from_var()
                                               │
                                               ▼
                                          [r2dec]
                                          FoldingContext → RegionAnalyzer →
                                          ControlFlowStructurer → CodeGenerator
                                               │
                                               ▼
                                          C code string
```

Key Types
---------

| Type | Crate | File | Purpose |
|------|-------|------|---------|
| `Varnode` | r2il | `varnode.rs` | Sized data location (space + offset + size) |
| `SpaceId` | r2il | `space.rs` | Address space (Ram, Register, Unique, Const) |
| `R2ILOp` | r2il | `opcode.rs` | 60+ typed semantic operations |
| `R2ILBlock` | r2il | `opcode.rs` | Operations for one machine instruction |
| `SSAVar` | r2ssa | `var.rs` | Versioned variable (name + version + size) |
| `SSAOp` | r2ssa | `op.rs` | R2ILOp with SSAVar inputs/outputs + Phi |
| `SSAFunction` | r2ssa | `function.rs` | Complete function: CFG + SSA blocks |
| `FunctionSSABlock` | r2ssa | `function.rs` | Block with phi nodes (used by r2dec) |
| `BasicBlock` | r2ssa | `cfg.rs` | CFG node with terminator |
| `TaintPolicy` | r2ssa | `taint.rs` | Trait for taint source/sink/sanitizer rules |
| `SymValue` | r2sym | `value.rs` | Concrete, symbolic (Z3 BV), or unknown |
| `SymState` | r2sym | `state.rs` | Registers, memory, constraints, taint masks |
| `SymExecutor` | r2sym | `executor.rs` | Steps through SSA ops, manages call hooks |
| `PathExplorer` | r2sym | `path.rs` | DFS/BFS/random path exploration with limits |
| `TypeArena` | r2types | `model.rs` | Interned type storage |
| `Constraint` | r2types | `constraint.rs` | Type constraint (SetType, Equal, Subtype, ...) |
| `TypeSolver` | r2types | `solver.rs` | Fixed-point constraint solver |
| `CExpr` | r2dec | `ast.rs` | C expression AST |
| `CStmt` | r2dec | `ast.rs` | C statement AST (If, While, For, Switch, ...) |
| `FoldingContext` | r2dec | `fold.rs` | Expression folding, dead code elimination |
| `CodeGenerator` | r2dec | `codegen.rs` | AST to C string pretty-printer |

How to Add a New Opcode
------------------------

1. **Add variant to `R2ILOp`** in `crates/r2il/src/opcode.rs`:

   ```rust
   IntFoo { dst: Varnode, a: Varnode, b: Varnode },
   ```

2. **Add P-code translation** in `crates/r2sleigh-lift/src/pcode.rs`:

   ```rust
   OpCode::Int(IntOp::Foo) => R2ILOp::IntFoo { dst, a, b },
   ```

3. **Add ESIL output** in `crates/r2sleigh-lift/src/esil.rs`:

   ```rust
   IntFoo { dst, a, b } => format!("{},{},FOO,{},=", vn(a), vn(b), vn(dst)),
   ```

4. **Add format_op arm** in `crates/r2sleigh-lift/src/esil.rs`:

   ```rust
   IntFoo { dst, a, b } => format!("IntFoo {{ dst: {}, a: {}, b: {} }}", vn(dst), vn(a), vn(b)),
   ```

5. **Add SSAOp variant** in `crates/r2ssa/src/op.rs` and update `dst()`,
   `sources()`, and `convert_op()`.

6. **Add decompiler support** in `crates/r2dec/src/fold.rs`:

   ```rust
   // In op_to_expr():
   SSAOp::IntFoo { a, b, .. } => self.binary_expr(BinaryOp::Foo, a, b),
   ```

7. **Add integration test** in `tests/e2e/integration_tests.rs`.

How to Add a New Architecture
-----------------------------

1. Enable the feature flag in `sleigh-config` (in `Cargo.toml` dependency).
2. Add the architecture name to the match arm in
   `crates/r2sleigh-cli/src/main.rs` (`get_disassembler()`).
3. Add the arch-to-bits mapping in `r2plugin/src/lib.rs` (architecture
   detection).
4. Add the arch to the supported list in error messages.
5. Add integration tests in `tests/e2e/integration_tests.rs`.

How to Add a New Plugin Command
-------------------------------

1. Add the command string to the dispatch table in
   `r2plugin/r_anal_sleigh.c` (`sleigh_cmd()`).
2. Implement the Rust function in `r2plugin/src/lib.rs`, exported with
   `#[unsafe(no_mangle)] pub extern "C" fn`.
3. Add the command to the help output.
4. Add an integration test.
5. Update [doc/plugin.md](doc/plugin.md) with the new command.

How to Add an Optimization Pass
-------------------------------

1. Implement the pass as a function in `crates/r2ssa/src/optimize.rs`:

   ```rust
   fn my_pass(func: &mut SSAFunction, stats: &mut OptimizationStats) -> bool {
       // Return true if anything changed
   }
   ```

2. Add a config flag to `OptimizationConfig`:

   ```rust
   pub enable_my_pass: bool,
   ```

3. Wire it into the iteration loop in `optimize_function()`.
4. Add a stat counter to `OptimizationStats`.
5. Add unit tests.

Key Design Decisions
--------------------

### Two SSABlock Types

There are two `SSABlock` types in `r2ssa`:

- `SSABlock` (`block.rs`) -- single instruction, no phi nodes, produced by
  `to_ssa()`.
- `FunctionSSABlock` (`function.rs`) -- function-level block with
  `phis: Vec<PhiNode>`, produced by `SSAFunction::from_blocks()`.

The decompiler uses `FunctionSSABlock`. When writing tests, create blocks
directly as structs, not via `SSABlock::new()`.

### String-Based SSAVar Names

`SSAVar` uses `String` names (e.g., `"rax"`, `"tmp:1000"`, `"const:42"`)
rather than integer IDs. This simplifies debugging and display, but means
lookups are string comparisons. A future refactor may introduce interned IDs.

### Flag Handling in Decompilation

x86 instructions produce many CPU flag updates (CF, ZF, SF, OF, etc.) that are
rarely consumed. The decompiler:

1. Counts uses of each flag variable
2. Eliminates flag computations that are never read
3. Reconstructs high-level comparisons from flag patterns
   (e.g., `!ZF && OF==SF` becomes `a > b`)

### Three-Tier Decompiler Fallback

For robustness, the decompiler has three tiers:

1. **Folded structuring**: full expression folding + control flow structuring
2. **Unfolded structuring**: minimal folding, conservative
3. **Linear emission**: per-block statement output as last resort

When fallback triggers, the output includes
`/* r2dec fallback: <reason> */`.

### Architecture Assumptions

Some code paths have hardcoded x86-64 assumptions (e.g., stack/frame pointer
names in `fold.rs`, argument registers in `taint.rs`). These should be
abstracted behind an ABI/calling-convention model in the future.

### Post-Analysis Signature/CC Write-Back

The plugin's `post_analysis` callback (`aaaa`) includes a write-back stage for
x86/x86-64 functions:

1. Rust FFI `r2sleigh_infer_signature_cc_json()` builds SSA and infers
   signature + calling convention.
2. C wrapper applies results with:
   - `afs <signature> @ <addr>`
   - `afc <cc> @ <addr>`
3. Existing function names are preserved by using the current function name in
   the generated signature.
4. Large functions are skipped via `SLEIGH_SIG_WRITEBACK_MAX_BLOCKS` to bound
   post-analysis cost.

Per-Topic Documentation
-----------------------

| Topic | Document |
|-------|----------|
| Intermediate language | [doc/r2il.md](doc/r2il.md) |
| SSA and optimization | [doc/ssa.md](doc/ssa.md) |
| Decompiler pipeline | [doc/decompiler.md](doc/decompiler.md) |
| ESIL generation | [doc/esil.md](doc/esil.md) |
| Taint analysis | [doc/taint.md](doc/taint.md) |
| Symbolic execution | [doc/symex.md](doc/symex.md) |
| radare2 plugin | [doc/plugin.md](doc/plugin.md) |
| Type inference | [doc/types.md](doc/types.md) |
| Testing | [doc/testing.md](doc/testing.md) |
