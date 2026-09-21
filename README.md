r2sleigh
========

A binary analysis engine and certifying decompiler, in Rust, with `r2s` as its
shell. Semantics come from Ghidra's Sleigh specifications rather than from
hand-written per-architecture models, and the decompiler refuses rather than
guessing when it cannot prove what it would print.

```
bytes --> Sleigh --> r2il (low) --> r2ssa (medium) --> r2dec (high) --> C
              |                          |                  |
          r2image                    r2types            r2rewrite
        ELF/Mach-O/DWARF          type inference       term rewriting
```

`r2s` opens a binary, walks and lifts it, and answers with no radare2 in the
process. radare2 remains the differential target this engine is graded against,
and general fixes found while grading it go upstream as their own pull requests.

Quick start
-----------

```bash
cargo build --release -p r2s --features sleigh
```

```bash
# Every function the engine finds, with why each one is believed
target/release/r2s -q -c 'afl' /bin/ls

# Decompile one
target/release/r2s -q -c 's main; pdd' /bin/ls

# Disassemble, radare2's spelling
target/release/r2s -q -c 's main; pd 16' /bin/ls
```

Each tier of the IL prints on its own, so a defect belongs to exactly one
lowering:

```bash
target/release/r2s -q -c 's main; pdil' /bin/ls   # r2il, as lifted
target/release/r2s -q -c 's main; pdim' /bin/ls   # r2ssa, with binding plan
target/release/r2s -q -c 's main; pdih' /bin/ls   # the r2dec tree
```

The Sleigh toolchain has its own binary:

```bash
cargo build --release -p r2sleigh-cli --features x86
r2sleigh disasm --arch x86-64 --bytes "4889e500000000000000000000000000"
```

Architectures
-------------

| Architecture | Feature | Status |
|--------------|---------|--------|
| x86-64       | `x86`   | Decompiles |
| x86 (32-bit) | `x86`   | Decompiles |
| aarch64      | `arm`   | Decompiles |
| ARM 32-bit   | `arm`   | Disassembles; `pdd` not yet admitted |
| RISC-V 32/64 | `riscv` | Lifts |
| MIPS         | `mips`  | Lifts |

Depth before breadth: x86 and ARM come first and stay first.

Crates
------

| Crate | Purpose |
|-------|---------|
| `r2s` | The shell: a radare2-compatible command surface |
| `r2image` | ELF and Mach-O parsing, and DWARF through `gimli` |
| `r2abi` | Calling conventions and library prototypes |
| `r2il` | Core IL: `Varnode`, `SpaceId`, `R2ILOp`, `R2ILBlock` |
| `r2sleigh-lift` | Sleigh and P-code to r2il |
| `r2sleigh-export` | Instruction exporter (lift/ssa/defuse/dec) |
| `r2sleigh-cli` | Sleigh toolchain: compile, disasm, info |
| `r2ssa` | SSA: control flow, dominators, liveness, taint, value ranges |
| `r2source` | The facts a capture owns, and their contracts |
| `r2types` | Type inference: constraint solver, signatures, shapes |
| `r2rewrite` | Term rewriting over the medium tier |
| `r2dec` | Structuring, binding, certification and C rendering |
| `r2engine` | Request orchestration, discovery, the native route |

Documentation
-------------

| Document | Description |
|----------|-------------|
| [doc/engine-vision.md](doc/engine-vision.md) | What this is becoming, and why |
| [BUILDING.md](BUILDING.md) | Build instructions and troubleshooting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Code style and pull requests |
| [DEVELOPERS.md](DEVELOPERS.md) | Architecture overview and module map |
| [ROADMAP.md](ROADMAP.md) | Ordered execution list |
| [doc/certifying_decompiler.md](doc/certifying_decompiler.md) | Obligations, certificates, refusal |
| [doc/r2il.md](doc/r2il.md) | Intermediate language design |
| [doc/ssa.md](doc/ssa.md) | SSA construction and optimization |
| [doc/decompiler.md](doc/decompiler.md) | Decompiler pipeline |
| [doc/types.md](doc/types.md) | Type inference |
| [doc/testing.md](doc/testing.md) | Testing strategy |

Testing
-------

```bash
# --no-fail-fast, always: without it one crate's failure hides the rest
cargo test --workspace --all-features --no-fail-fast

# Every named function renders, and reads nothing that was never written
python3 scripts/certify_render.py --bins <radare2>/test/bins/elf --limit 24 --functions 8

# The same commands through radare2 and through r2s, diffed
python3 scripts/diff_r2.py --bins <radare2>/test/bins/elf --limit 30
```

R2IL format
-----------

- `R2PSTC07` is the sole format identity; there is no version field and no
  compatibility branch.
- Saving emits `R2PSTC07 || payload_length_u64_le || postcard(ArchSpec)`, and
  the reader requires exact payload consumption.
- `ArchSpec::register_projections` is the source-owned, name-free register
  geometry table. Empty means unavailable; otherwise it is sorted, complete for
  unique declared storages, and validated as coherent overlap components.
- Endianness has exactly two architecture-level authorities,
  `instruction_endianness` and `memory_endianness`.
- Memory semantics carry explicit ordering: `Fence`, `LoadLinked` /
  `StoreConditional`, `AtomicCAS`, `LoadGuarded` / `StoreGuarded`.

Export action and format pairs are strict and fail explicitly rather than
falling back: `lift` takes `json`, `text`, `esil`, `r2cmd`; `ssa` and `defuse`
take `json` and `text`; `dec` takes `c_like`, `json` and `text`.

Requirements
------------

- Rust 1.85+ (edition 2024)
- radare2, only to run the differential harnesses
- Z3, optional

License
-------

LGPL-3.0-only
