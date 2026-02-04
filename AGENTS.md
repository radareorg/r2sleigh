# Agent Guidelines for r2sleigh

> LLM-optimized context for AI coding assistants working on this codebase.

## Project Summary

**r2sleigh** = Sleigh-to-r2il compiler for radare2. Converts Ghidra P-code to ESIL.

```
Input:  Ghidra .sla files (via libsla)
Output: r2il binary format + ESIL text
```

## Architecture (READ THIS FIRST)

```
crates/
├── r2il/           # Core IL types (Varnode, R2ILOp, ArchSpec)
├── r2sleigh-lift/  # P-code → r2il translation
├── r2sleigh-cli/   # CLI tool (compile, disasm, info)
├── r2ssa/          # SSA transformation and analysis
├── r2sym/          # Symbolic execution + taint analysis
└── r2dec/          # Decompiler (scaffolding)
r2plugin/           # C-ABI for radare2 integration
```

### Data Flow

```
.sla (Ghidra) → libsla → P-code ops → PcodeTranslator → R2ILOp → ESIL string
                                                              ↓
                                                          to_ssa()
                                                              ↓
                                                         SSABlock → def_use()
```

### Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `Varnode` | `r2il/varnode.rs` | Sized data location (reg/mem/const/temp) |
| `SpaceId` | `r2il/space.rs` | Address space enum (Ram, Register, Unique, Const) |
| `R2ILOp` | `r2il/opcode.rs` | 60+ semantic operations (Copy, IntAdd, Load, Branch...) |
| `R2ILBlock` | `r2il/opcode.rs` | Sequence of ops for one instruction |
| `Disassembler` | `r2sleigh-lift/disasm.rs` | Wraps libsla for P-code generation |
| `op_to_esil()` | `r2sleigh-lift/esil.rs` | Converts R2ILOp → ESIL string |
| `SSAVar` | `r2ssa/var.rs` | Versioned variable (name_version) |
| `SSAOp` | `r2ssa/op.rs` | SSA operation with versioned vars |
| `SSABlock` | `r2ssa/block.rs` | SSA form of an instruction |
| `FunctionSSABlock` | `r2ssa/function.rs` | SSA block with phi nodes (used by r2dec) |
| `SSAFunction` | `r2ssa/function.rs` | Complete function in SSA form |
| `DefUseInfo` | `r2ssa/defuse.rs` | Def-use chain analysis results |
| `CExpr` | `r2dec/ast.rs` | C expression AST |
| `CStmt` | `r2dec/ast.rs` | C statement AST |
| `FoldingContext` | `r2dec/fold.rs` | Expression folding/dead code elimination |

## Build Commands

```bash
# Standard build
cargo build --features x86

# Run CLI
cargo run --features x86 -- disasm --arch x86-64 --bytes "31c0000000000000000000000000000000"

# Test
cargo test --all-features
```

**IMPORTANT**: Disassembly requires 16+ bytes of input (pad with zeros).

## Local Plugin Setup (radare2 in sibling dir)

- Build + install: `make -C r2plugin RUST_FEATURES=x86 install`
- Verify load: `r2 -qc 'L' /bin/ls` (check for sleigh in the plugin list)
- Plugin dir comes from `r2 -H R2_USER_PLUGINS` (see `r2plugin/Makefile`)
- `pkg-config r_anal` is used for headers/libs; set `PKG_CONFIG_PATH` if needed

### Using Plugin Automatically with `aaa`

**Important**: The plugin implements the `op` callback, which radare2 calls automatically during analysis. However, radare2 selects analysis plugins based on architecture matching, not via a config variable.

The plugin will be used automatically when:
1. **Architecture matches**: The plugin supports `x86`, `arm`, and `mips` architectures
2. **Plugin is loaded**: Ensure it's installed in `~/.local/share/radare2/plugins/`
3. **Architecture is set correctly**: radare2 auto-detects from the binary, or set explicitly:

```bash
# The plugin works automatically if architecture matches
r2 -qc 'e bin.relocs.apply=true; aaa' /bin/ls

# Verify plugin is working:
r2 -qc 'e bin.relocs.apply=true; aaa; s entry0+4; a:sla.info' /bin/ls

# If architecture doesn't match, set it explicitly:
r2 -qc 'e anal.arch=x86; e anal.bits=64; aaa' /bin/ls
```

The plugin auto-detects architecture from `anal.arch` and `anal.bits`:
- `anal.arch=x86` + `anal.bits=64` → uses `x86-64`
- `anal.arch=x86` + `anal.bits=32` → uses `x86`
- `anal.arch=arm` → uses `arm`
- `anal.arch=mips` → uses `mips`

You can override with: `a:sla.arch x86-64`

**Note**: The plugin's `op` callback is called automatically by radare2 during analysis (`aaa`, `aa`, etc.) when the architecture matches. There's no need to "select" it explicitly - it works transparently.

## Code Style

### Rust Conventions

- Edition 2024 (requires `#[unsafe(no_mangle)]` syntax)
- Use `thiserror` for error types
- Prefer `format!()` over string concatenation
- Feature flags: `x86`, `arm` (via `sleigh-config`)

### ESIL Syntax (Critical)

ESIL = Reverse Polish Notation for radare2's VM.

```
a,b,+     → a + b
a,b,=     → b = a (assignment)
a,[N]     → read N bytes from addr a
a,b,=[N]  → write N bytes of b to addr a
a,?{,x,}  → if a then x
```

**Operators**:
| Op | ESIL | Notes |
|----|------|-------|
| add | `+` | |
| sub | `-` | ASCII 0x2D only! |
| bitwise NOT | `~` | NOT `!` (boolean) |
| signed shift right | `>>>` | NOT `>>>>` |
| sign extend | `val,bits,~~` | |
| compare | `==`, `<`, `<$` (signed) | |

### Adding New Opcodes

1. Add variant to `R2ILOp` enum in `r2il/opcode.rs`
2. Add translation in `translate_pcode()` in `r2sleigh-lift/pcode.rs`
3. Add ESIL output in `op_to_esil()` in `r2sleigh-cli/main.rs`
4. Add formatting in `format_op()` in same file
5. **Add integration test** in `tests/e2e/integration_tests.rs` to prevent regression
6. **Add test case** to `tests/e2e/vuln_test.c` if the feature needs a specific binary pattern to test

## Integration Testing Requirements

**MANDATORY**: When adding any new feature, you MUST add an integration test.

### Workflow for New Features

1. **Implement the feature** (opcode, analysis, plugin command, etc.)
2. **Check if test binary is needed**:
   - If the feature needs a specific binary pattern, add a test function to `tests/e2e/vuln_test.c`
   - Compile: `gcc -O0 -g -fno-stack-protector -no-pie -o vuln_test vuln_test.c`
3. **Add integration test** in `tests/e2e/integration_tests.rs`:
   - Use the `e2e` test harness (`r2_at_func`, `r2_at_addr`, etc.)
   - Add to appropriate module or create new module
   - Use `rstest` for parameterized tests when testing multiple cases
4. **Run tests**: `cd tests/e2e && cargo test`
5. **Verify**: All tests pass before committing

### Test Coverage Checklist

When adding a feature, ensure tests cover:
- ✅ Basic functionality (command executes without crash)
- ✅ Expected output format (JSON structure, text patterns)
- ✅ Error cases (invalid input, missing data)
- ✅ Edge cases (empty results, boundary conditions)

### Adding Test Cases to vuln_test.c

If your new feature requires a specific binary pattern to test (e.g., a particular instruction sequence, control flow pattern, or data dependency), add a test function to `tests/e2e/vuln_test.c`:

1. **Add the test function** with a descriptive name and comment
2. **Add it to the `main()` switch statement** so it can be invoked
3. **Update the integration test** to use the new function

Example: Adding a test for a new floating-point operation:

```c
// In vuln_test.c
// Test N: Floating point comparison
int test_fp_compare(double x) {
    if (x > 3.14) {
        return 1;
    }
    return 0;
}

// In main() switch:
case N:
    if (argc > 2) {
        double x = atof(argv[2]);
        printf("test_fp_compare(%f) = %d\n", x, test_fp_compare(x));
    }
    break;
```

Then add an integration test:

```rust
// In integration_tests.rs
#[test]
fn test_fp_operation() {
    setup();
    let result = r2_at_func(vuln_test_binary(), "test_fp_compare", "a:sla.json");
    result.assert_ok();
    assert!(result.contains("FloatCompare"), "Should show float comparison op");
}
```

## Common Tasks

### Add ESIL for new opcode

```rust
// In op_to_esil() in r2sleigh-lift/esil.rs:
IntFoo { dst, a, b } => format!("{},{},FOO,{},=", vn(a), vn(b), vn(dst)),
```

### Add new architecture

1. Enable feature in `sleigh-config`
2. Add match arm in `get_disassembler()` in `main.rs`
3. Add to supported list in error message
4. **Add integration test** in `tests/e2e/integration_tests.rs` for the new architecture

### Add SSA support for new opcode

1. Add variant to `SSAOp` in `r2ssa/op.rs`
2. Add conversion in `convert_op()` in `r2ssa/block.rs`
3. Update `dst()` and `sources()` methods in `SSAOp`
4. **Add integration test** in `tests/e2e/integration_tests.rs` to verify SSA conversion works

### Debug P-code output

```bash
# JSON shows raw R2ILOp structure
cargo run --features x86 -- disasm --arch x86-64 --bytes "..." --format json
```

### Debug SSA output

```bash
# In radare2
r2 -qc 's entry0+4; a:sleigh.ssa' /bin/ls
r2 -qc 's entry0+4; a:sleigh.defuse' /bin/ls
```

## File Quick Reference

| File | Lines | What to edit for... |
|------|-------|---------------------|
| `r2il/opcode.rs` | ~650 | New IL opcodes |
| `r2sleigh-lift/pcode.rs` | ~300 | P-code → R2ILOp translation |
| `r2sleigh-lift/disasm.rs` | ~700 | Disassembler wrapper, register names |
| `r2sleigh-lift/esil.rs` | ~200 | ESIL output formatting |
| `r2sleigh-cli/main.rs` | ~400 | CLI commands |
| `r2ssa/var.rs` | ~100 | SSA variable type |
| `r2ssa/op.rs` | ~600 | SSA operations |
| `r2ssa/block.rs` | ~500 | SSA conversion |
| `r2ssa/defuse.rs` | ~200 | Def-use analysis |
| `r2sym/executor.rs` | ~400 | R2IL interpreter for symbolic execution |
| `r2sym/state.rs` | ~300 | Symbolic state (regs, mem, constraints) |
| `r2sym/solver.rs` | ~200 | Z3 integration and model extraction |
| `r2sym/path.rs` | ~200 | Path exploration and results |
| `r2dec/structure.rs` | ~275 | Control-flow structuring |
| `r2dec/fold.rs` | ~500 | Expression folding and dead code elimination |
| `r2dec/expr.rs` | ~500 | Expression builder (legacy, use fold.rs) |
| `r2dec/codegen.rs` | ~680 | C code generation |
| `r2dec/ast.rs` | ~690 | C AST types (CExpr, CStmt, CType) |
| `r2dec/region.rs` | ~200 | Region analysis for control flow |
| `r2dec/types.rs` | ~200 | Type inference |
| `r2dec/variable.rs` | ~200 | Variable recovery |
| `r2plugin/lib.rs` | ~1200 | C-ABI exports for radare2 |
| `r2plugin/r_anal_sleigh.c` | ~400 | radare2 RAnalPlugin wrapper |
| `tests/e2e/integration_tests.rs` | ~500 | Integration tests (REQUIRED for new features) |
| `tests/e2e/lib.rs` | ~150 | Test harness utilities |
| `tests/e2e/vuln_test.c` | ~220 | Test binary source (add functions for new features) |

## Testing Checklist

Before committing changes:

```bash
# 1. Build succeeds
cargo build --features x86

# 2. Run unit tests
cargo test --features x86

# 3. Run integration tests (REQUIRED for new features)
cd tests/e2e
cargo test

# 4. Test CLI
cargo run --features x86 -- disasm --arch x86-64 --bytes "31c0000000000000000000000000000000" --format esil

# 5. Test plugin (after make install in r2plugin/)
r2 -qc 'a:sleigh.info' /bin/ls
r2 -qc 's entry0+4; a:sleigh.ssa' /bin/ls
```

### Adding Integration Tests for New Features

**CRITICAL**: When adding any new feature, you MUST add an integration test to prevent regression.

1. **For new plugin commands**: Add test in `tests/e2e/integration_tests.rs` in the appropriate module
2. **For new opcodes/operations**: Add test that exercises the opcode via `a:sla.json` or `a:sla.ssa`
3. **For new analysis features**: Add test that validates the analysis output
4. **If test binary is needed**: Add a test function to `tests/e2e/vuln_test.c` that exercises the feature

Example: Adding a new plugin command `a:sla.newfeature`:

```rust
// In tests/e2e/integration_tests.rs
mod new_feature {
    use super::*;
    
    #[test]
    fn new_feature_works() {
        setup();
        let result = r2_at_func(vuln_test_binary(), "main", "a:sla.newfeature");
        result.assert_ok();
        assert!(result.contains("expected_output"), "Should show expected output");
    }
}
```

If the feature needs a specific binary pattern, add to `vuln_test.c`:

```c
// In tests/e2e/vuln_test.c
int test_new_feature(int x) {
    // Pattern that exercises the new feature
    return x * 2;
}
```

## Gotchas

1. **16-byte minimum**: libsla reads 16 bytes for x86-64. Always pad input.
2. **Unicode minus**: Use ASCII `-` (0x2D), not `−` (U+2212) in ESIL.
3. **Feature flags**: `sleigh-config` features must match CLI features.
4. **Rust 2024**: `#[no_mangle]` → `#[unsafe(no_mangle)]`
5. **Width mismatches**: normalize widths and use explicit sign/zero-extend ops.
6. **Const vs Unique**: Const is literal, Unique is temp SSA space (not memory).
7. **Register aliasing**: overlapping regs need a deterministic policy in output.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `libsla` | Ghidra Sleigh bindings (P-code generation) |
| `sleigh-config` | Pre-compiled .sla files |
| `bincode` | Binary serialization |
| `clap` | CLI argument parsing |
| `thiserror` | Error derive macros |
| `serde` | Serialization traits |
| `serde_json` | JSON output |

## Plugin Commands

| Command | Output | Purpose |
|---------|--------|---------|
| `a:sla` | text | Status and help |
| `a:sla.info` | text | Architecture info |
| `a:sla.arch [name]` | text | Get/set architecture override |
| `a:sla.json` | JSON | Raw r2il ops for current instruction |
| `a:sla.regs` | JSON | Registers read/written |
| `a:sla.mem` | JSON | Memory accesses |
| `a:sla.vars` | JSON | All varnodes |
| `a:sla.ssa` | JSON | SSA form for current function |
| `a:sla.defuse` | JSON | Def-use analysis |
| `a:sla.taint` | JSON | Taint analysis |
| `a:sla.slice [var]` | JSON | Backward slice from variable |
| `a:sla.dec` | text | Decompile function to C |
| `a:sla.cfg` | JSON | Control flow graph |
| `a:sla.sym.paths` | JSON | Symbolic execution paths |
| `a:sla.sym.solve` | JSON | Solve for target address |

**Note**: Commands use `a:sla` prefix (short for `a:sleigh`). Both work.

## r2dec Decompiler Architecture

The decompiler (`r2dec`) converts SSA form to readable C code.

### Decompilation Pipeline

```
SSAFunction → RegionAnalyzer → ControlFlowStructurer → FoldingContext → CodeGenerator → C code
     ↓              ↓                    ↓                   ↓               ↓
  SSA ops     Region tree         CStmt/CExpr        Optimized AST     String output
```

### Key Types in r2dec

| Type | Location | Purpose |
|------|----------|---------|
| `CExpr` | `r2dec/ast.rs` | C expression AST (Binary, Unary, Var, Call, etc.) |
| `CStmt` | `r2dec/ast.rs` | C statement AST (If, While, Return, Block, etc.) |
| `CType` | `r2dec/ast.rs` | C type representation (Int, Ptr, Struct, etc.) |
| `CFunction` | `r2dec/ast.rs` | Complete function with params, locals, body |
| `FoldingContext` | `r2dec/fold.rs` | Expression folding and dead code elimination |
| `Region` | `r2dec/region.rs` | Control flow region (Block, IfThenElse, While, etc.) |
| `CodeGenerator` | `r2dec/codegen.rs` | Converts AST to C string with pretty printing |

### Two SSABlock Types (Important!)

There are **two different `SSABlock` types** in r2ssa:

| Type | Location | Purpose |
|------|----------|---------|
| `SSABlock` | `r2ssa/block.rs` | Single instruction block (addr, size, ops) |
| `FunctionSSABlock` | `r2ssa/function.rs` | Function block with phi nodes (addr, size, ops, phis) |

**r2dec uses `FunctionSSABlock`** (re-exported as `r2ssa::FunctionSSABlock`).

When writing tests for r2dec:
```rust
// DON'T use SSABlock::new() - it doesn't exist for FunctionSSABlock
// DO create blocks directly:
let block = FunctionSSABlock {
    addr: 0x1000,
    size: 4,
    ops: vec![...],
    phis: Vec::new(),
};
```

### Expression Folding (fold.rs)

The `FoldingContext` performs three key optimizations:

1. **Use-counting**: Tracks how many times each SSA variable is used
2. **Single-use inlining**: Variables used only once get inlined at use site
3. **Dead code elimination**: Unused CPU flags (CF, ZF, SF, etc.) are removed

**CPU flags that are auto-eliminated when unused**:
- `cf`, `pf`, `af`, `zf`, `sf`, `of`, `df`, `tf`
- Also versioned variants: `cf_1`, `zf_2`, etc.

**Constant handling**: `const:xxx` → actual numeric values
- `const:0x42` → `0x42`
- `const:fffffffc` → `0xfffffffcU`

### Adding Decompiler Support for New SSA Operations

1. Add case to `FoldingContext::op_to_expr()` in `r2dec/fold.rs`
2. Add case to `FoldingContext::op_to_stmt()` in `r2dec/fold.rs`
3. Test with `r2 -qc 'aaa; s func; a:sla.dec' /path/to/binary`

Example for a new binary op:
```rust
// In op_to_expr():
SSAOp::IntFoo { a, b, .. } => self.binary_expr(BinaryOp::Foo, a, b),

// In op_to_stmt():
SSAOp::IntFoo { dst, a, b } => self.binary_stmt(dst, a, b, BinaryOp::Foo),
```

### Control Flow Structuring

The `ControlFlowStructurer` converts region trees to C statements:

| Region Type | C Output |
|-------------|----------|
| `Region::Block` | Statement sequence |
| `Region::IfThenElse` | `if (cond) { ... } else { ... }` |
| `Region::WhileLoop` | `while (cond) { ... }` |
| `Region::DoWhileLoop` | `do { ... } while (cond);` |
| `Region::Irreducible` | Labels + gotos |

### Debugging Decompiler Output

```bash
# View decompiled C code
r2 -qc 'aaa; s main; a:sla.dec' /path/to/binary

# View SSA form (input to decompiler)
r2 -qc 'aaa; s main; a:sla.ssa' /path/to/binary

# View raw IL (before SSA)
r2 -qc 'aaa; s main; a:sla.json' /path/to/binary
```

## Deep radare2 Integration

The plugin provides callbacks that radare2 calls automatically during analysis.

### Plugin Callbacks (in r_anal_sleigh.c)

| Callback | When Called | Purpose |
|----------|-------------|---------|
| `sleigh_op` | `aaa`/analysis | Lift instructions to ESIL |
| `sleigh_recover_vars` | `afva` | Provide SSA-derived variables |
| `sleigh_analyze_fcn` | After `af` | Per-function SSA/analysis |
| `sleigh_get_data_refs` | After `aar` | Provide def-use xrefs |
| `sleigh_post_analysis` | End of `aaaa` | Cross-function analysis |

### Variable Recovery (recover_vars)

The plugin provides stack variables and register arguments to radare2's `afv` system.

**Stack variable detection** (in `lib.rs`):
1. Track `IntAdd`/`IntSub` with RBP/RSP as base
2. Store address temps in `stack_addr_temps` map
3. When `Store`/`Load` uses a tracked temp, emit stack variable

**Register argument detection**:
- Check sources with version 0 against arg register list
- x86-64 arg regs: `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` (+ 32-bit aliases)
- Set `RAnalVarProt.kind = R_ANAL_VAR_KIND_REG` and `delta = reg_index`

**Important**: `RAnalVarProt.delta` means different things:
- For `R_ANAL_VAR_KIND_REG`: register index from `r_reg_get()`
- For `R_ANAL_VAR_KIND_SPV`/`BPV`: stack offset

### Register Name Lookup

When mapping register names to indices:
```c
// In r_anal_sleigh.c
// radare2's anal->reg uses UPPERCASE names (e.g., "RDI" not "rdi")
char *upper_reg = strdup(reg_name);
for (char *p = upper_reg; *p; p++) *p = toupper(*p);
RRegItem *ri = r_reg_get(anal->reg, upper_reg, R_REG_TYPE_GPR);
prot->delta = ri->index;  // Use index, not offset
```

## Links

- [radare2 ESIL docs](https://book.rada.re/disassembling/esil.html)
- [Ghidra P-code reference](https://ghidra.re/courses/languages/html/pcoderef.html)
- [libsla crate](https://crates.io/crates/libsla)
