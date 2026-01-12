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
└── r2sleigh-cli/   # CLI tool (compile, disasm, info)
r2plugin/           # C-ABI for radare2 integration
```

### Data Flow

```
.sla (Ghidra) → libsla → P-code ops → PcodeTranslator → R2ILOp → ESIL string
```

### Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `Varnode` | `r2il/varnode.rs` | Sized data location (reg/mem/const/temp) |
| `SpaceId` | `r2il/space.rs` | Address space enum (Ram, Register, Unique, Const) |
| `R2ILOp` | `r2il/opcode.rs` | 60+ semantic operations (Copy, IntAdd, Load, Branch...) |
| `Disassembler` | `r2sleigh-lift/disasm.rs` | Wraps libsla for P-code generation |
| `op_to_esil()` | `r2sleigh-cli/main.rs:451` | Converts R2ILOp → ESIL string |

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
// In op_to_esil() match arm:
IntFoo { dst, a, b } => format!("{},{},FOO,{},=", vn(a), vn(b), vn(dst)),
```

### Add new architecture

1. Enable feature in `sleigh-config`
2. Add match arm in `get_disassembler()` in `main.rs`
3. Add to supported list in error message

### Debug P-code output

```bash
# JSON shows raw R2ILOp structure
cargo run --features x86 -- disasm --arch x86-64 --bytes "..." --format json
```

## File Quick Reference

| File | Lines | What to edit for... |
|------|-------|---------------------|
| `r2il/opcode.rs` | ~650 | New IL opcodes |
| `r2sleigh-lift/pcode.rs` | ~300 | P-code → R2ILOp translation |
| `r2sleigh-lift/disasm.rs` | ~200 | Disassembler wrapper, register names |
| `r2sleigh-cli/main.rs` | ~700 | CLI commands, ESIL output |
| `r2plugin/lib.rs` | ~150 | C-ABI exports for radare2 |

## Testing Checklist

Before committing changes:

```bash
# 1. Build succeeds
cargo build --features x86

# 2. No warnings
cargo build --features x86 2>&1 | grep -i warning

# 3. Test common instructions
cargo run --features x86 -- disasm --arch x86-64 --bytes "31c0000000000000000000000000000000" --format esil
cargo run --features x86 -- disasm --arch x86-64 --bytes "55000000000000000000000000000000" --format esil
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

## Links

- [radare2 ESIL docs](https://book.rada.re/disassembling/esil.html)
- [Ghidra P-code reference](https://ghidra.re/courses/languages/html/pcoderef.html)
- [libsla crate](https://crates.io/crates/libsla)
