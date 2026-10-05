Building r2sleigh
=================

| Dependency | Version | Notes |
|------------|---------|-------|
| Rust | 1.85+ | edition 2024, via [rustup](https://rustup.rs/) |
| radare2 | 5.9+ | optional; only the differential harnesses run it |
| Z3 | 4.8+ | optional |

Nothing links against `libr`: no radare2 headers or C compiler are needed.

```bash
cargo build --release -p r2s --features sleigh       # the shell
cargo build --release -p r2sleigh-cli --features x86 # the Sleigh toolchain
```

Without `--features sleigh` the shell builds but refuses to lift.

| Feature | Architectures |
|---------|---------------|
| `x86` | x86, x86-64 (16/32/64-bit modes) |
| `arm` | ARM 32-bit, Thumb, aarch64 |
| `mips` | MIPS, both endiannesses |
| `riscv` | RV32GC, RV64GC |
| `all-archs` | all of the above |

Profiles: `release` (optimized, parallel codegen, abort on panic, stripped)
for everyday work and CI; `dist` (LTO, one codegen unit) for distributables;
`probe` when a profiler must name a line; `ci` for the equivalence runs.

Tests and gates are in [doc/testing.md](doc/testing.md). Build before
measuring: the harnesses default to `target/debug/r2s`, which a release build
does not touch.

Troubleshooting
---------------

- **`r2s: built without the sleigh feature`**: rebuild with `--features sleigh`.
- **A function refuses where another renders**: that is the decompiler printing
  only what it can prove. `R2DEC_TRACE_REFUSAL=1` names the refusing
  predicate; `pdil`/`pdim`/`pdih` narrow a defect to one tier.
- **Linker errors**: only Z3 needs a system library, and only with its
  feature on (`apt install libz3-dev`, `dnf install z3-devel`).
