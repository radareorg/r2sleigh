Building r2sleigh
=================

Prerequisites
-------------

| Dependency | Version | Notes |
|------------|---------|-------|
| Rust | 1.85+ | Edition 2024; install via [rustup](https://rustup.rs/) |
| radare2 | 5.9+ | Optional; only the differential harnesses run it |
| Z3 | 4.8+ | Optional |

Nothing links against `libr`, so no radare2 headers, `pkg-config` entry or C
compiler is needed to build or test the engine.

Building the shell
------------------

`r2s` is the tool: it opens a binary, walks and lifts it, and decompiles.

```bash
cargo build --release -p r2s --features sleigh
```

`--features sleigh` is what brings the Sleigh decoder in; without it the shell
builds but refuses to lift. It carries x86 and ARM, which is the whole of what
`pdd` is admitted for today.

Building the Sleigh toolchain
-----------------------------

`r2sleigh-cli` compiles and inspects Sleigh specifications, standalone.

```bash
cargo build --release -p r2sleigh-cli --features x86

cargo run --release -p r2sleigh-cli --features x86 -- \
  disasm --arch x86-64 --bytes "31c0000000000000000000000000000000"
```

### Feature flags

| Flag | Architectures | Notes |
|------|--------------|-------|
| `x86` | x86, x86-64 | Includes 16/32/64-bit modes |
| `arm` | ARM 32-bit, Thumb, aarch64 | |
| `mips` | MIPS | Big and little endian |
| `riscv` | RISC-V (RV32GC, RV64GC) | Little-endian baseline |
| `all-archs` | All of the above | Larger binary, longer compile |

Running tests
-------------

```bash
# --no-fail-fast, always: without it cargo stops at the first failing target,
# so one crate's known failure hides every failure after it.
cargo test --workspace --all-features --no-fail-fast
```

The end-to-end gates run the built shell. Build before measuring: the default
binary is the debug one, which `cargo build --release` does not touch, and a
measurement taken after one describes a tree several changes old.

```bash
# Every named function renders, and reads nothing that was never written
python3 scripts/certify_render.py --bins <radare2>/test/bins/elf \
  --limit 24 --functions 8

# The same commands through radare2 and through r2s, diffed
python3 scripts/diff_r2.py --bins <radare2>/test/bins/elf --limit 30

# How much of a whole binary renders at all
./tests/coverage/run_coverage.sh
```

Advisory, non-blocking:

```bash
python3 scripts/bench_semantic_metadata.py --runs 7 --max-overhead-pct 5
```

See [doc/testing.md](doc/testing.md) for the full guide.

R2IL format compatibility
-------------------------

- The sole format identity is `R2PSTC07`; there is no separate format-version
  authority.
- The loader accepts exactly
  `R2PSTC07 || payload_length_u64_le || postcard(ArchSpec)` and rejects
  truncation or trailing bytes.
- Older encodings are rejected rather than migrated through a second semantic
  path.

Troubleshooting
---------------

### `r2s: built without the sleigh feature`

The shell was built without a decoder. Rebuild with `--features sleigh`.

### A function refuses where another renders

That is the decompiler working: it prints what it can prove and says what it
could not. `R2DEC_TRACE_REFUSAL=1` names the predicate and the site that
refused. `pdil`, `pdim` and `pdih` print the low, medium and high tiers, which
is how a defect is narrowed to one lowering.

### Build fails with linker errors

Only Z3 needs a system library, and only when its feature is on. Build without
it, or install it:

```bash
sudo apt install libz3-dev     # Debian/Ubuntu
sudo dnf install z3-devel      # Fedora
```

Release and dist builds
-----------------------

The workspace `release` profile is tuned for normal local and CI iteration:
optimized code, parallel codegen, abort-on-panic, stripped artifacts. Use
`dist` only when a maximum-optimized distributable is worth the link time, and
`probe` when a profiler has to name a line.

```toml
[profile.release]
lto = false
codegen-units = 16
panic = "abort"
strip = true

[profile.dist]
inherits = "release"
lto = true
codegen-units = 1
```

```bash
cargo build --release -p r2s --features sleigh
cargo build --profile dist -p r2s --features sleigh
cargo build --profile probe -p r2s --features sleigh
```
