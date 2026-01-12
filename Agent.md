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
└── r2ssa/          # SSA transformation and analysis
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
| `DefUseInfo` | `r2ssa/defuse.rs` | Def-use chain analysis results |

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

### Add SSA support for new opcode

1. Add variant to `SSAOp` in `r2ssa/op.rs`
2. Add conversion in `convert_op()` in `r2ssa/block.rs`
3. Update `dst()` and `sources()` methods in `SSAOp`

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
| `r2plugin/lib.rs` | ~1200 | C-ABI exports for radare2 |
| `r2plugin/r_anal_sleigh.c` | ~400 | radare2 RAnalPlugin wrapper |

## Testing Checklist

Before committing changes:

```bash
# 1. Build succeeds
cargo build --features x86

# 2. Run tests
cargo test --features x86

# 3. Test CLI
cargo run --features x86 -- disasm --arch x86-64 --bytes "31c0000000000000000000000000000000" --format esil

# 4. Test plugin (after make install in r2plugin/)
r2 -qc 'a:sleigh.info' /bin/ls
r2 -qc 's entry0+4; a:sleigh.ssa' /bin/ls
```

## Gotchas

1. **16-byte minimum**: libsla reads 16 bytes for x86-64. Always pad input.
2. **Unicode minus**: Use ASCII `-` (0x2D), not `−` (U+2212) in ESIL.
3. **Feature flags**: `sleigh-config` features must match CLI features.
4. **Rust 2024**: `#[no_mangle]` → `#[unsafe(no_mangle)]`

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
| `a:sleigh` | text | Status |
| `a:sleigh.info` | text | Architecture info |
| `a:sleigh.json` | JSON | Raw r2il ops |
| `a:sleigh.regs` | JSON | Registers read/written |
| `a:sleigh.mem` | JSON | Memory accesses |
| `a:sleigh.vars` | JSON | All varnodes |
| `a:sleigh.ssa` | JSON | SSA form |
| `a:sleigh.defuse` | JSON | Def-use analysis |

## Links

- [radare2 ESIL docs](https://book.rada.re/disassembling/esil.html)
- [Ghidra P-code reference](https://ghidra.re/courses/languages/html/pcoderef.html)
- [libsla crate](https://crates.io/crates/libsla)
