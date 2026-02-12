r2sleigh
========

Sleigh-to-r2il compiler and radare2 analysis plugin. Converts Ghidra P-code
processor specifications into a typed intermediate language suitable for binary
analysis, SSA transformation, decompilation, symbolic execution, and taint
analysis.

```
.sla (Ghidra) --> libsla --> P-code --> r2il --> ESIL (radare2)
                                          |
                                          +--> SSA (r2ssa) --> Taint / Symbolic (r2sym)
                                          |
                                          +--> Decompiler (r2dec) --> C code
                                          |
                                          +--> Type Inference (r2types)
```

Features
--------

- Pure Rust (edition 2024) using `libsla` (Ghidra native bindings)
- Strongly-typed intermediate language (r2il) with 60+ opcodes
- SSA transformation with dominator tree, phi nodes, and optimization pipeline
- Constraint-based type inference with struct/signature support
- Decompiler producing C code with expression folding, control flow structuring,
  for-loop/switch detection, string literals, and symbol resolution
- Z3-backed symbolic execution with path exploration
- SSA-based taint analysis with automatic radare2 integration
- radare2 plugin with 20+ commands, automatic analysis hooks, and ESIL output
- CLI tool for standalone Sleigh compilation and disassembly

Quick Start
-----------

### Build the CLI

```bash
cargo build --release -p r2sleigh-cli --features x86
```

### Build and install the radare2 plugin

```bash
cd r2plugin
make RUST_FEATURES=x86
make install
```

### First commands

```bash
# CLI: disassemble bytes
r2sleigh disasm --arch x86-64 --bytes "4889e500000000000000000000000000"

# Plugin: decompile a function
r2 -qc 'aaa; s main; a:sla.dec' /bin/ls

# Plugin: SSA form
r2 -qc 'aaa; s main; a:sla.ssa' /bin/ls

# Plugin: taint analysis
r2 -qc 'aaa; s main; a:sla.taint' /bin/ls
```

Supported Architectures
-----------------------

| Architecture | Feature Flag | Status |
|--------------|-------------|--------|
| x86-64       | `x86`       | Working |
| x86 (32-bit) | `x86`      | Working |
| ARM          | `arm`       | Available |
| MIPS         | `mips`      | Available |

Project Structure
-----------------

| Crate | Purpose |
|-------|---------|
| `r2il` | Core IL types: `Varnode`, `SpaceId`, `R2ILOp`, `R2ILBlock` |
| `r2sleigh-lift` | Sleigh/P-code to r2il translation, ESIL formatting |
| `r2sleigh-cli` | CLI: compile, disasm, info commands |
| `r2ssa` | SSA: CFG, dominator tree, phi nodes, optimization, taint |
| `r2sym` | Symbolic execution: Z3 solver, path exploration |
| `r2types` | Type inference: constraint solver, signatures, struct shapes |
| `r2dec` | Decompiler: expression folding, structuring, codegen |
| `r2plugin` | radare2 plugin: Rust cdylib + C wrapper |

Documentation
-------------

| Document | Description |
|----------|-------------|
| [BUILDING.md](BUILDING.md) | Build instructions, installation, troubleshooting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute, code style, PR guidelines |
| [DEVELOPERS.md](DEVELOPERS.md) | Architecture overview, module map, how to extend |
| [ROADMAP.md](ROADMAP.md) | Planned features and priorities |
| [doc/r2il.md](doc/r2il.md) | Intermediate language design |
| [doc/ssa.md](doc/ssa.md) | SSA construction and optimization |
| [doc/decompiler.md](doc/decompiler.md) | Decompiler pipeline |
| [doc/esil.md](doc/esil.md) | ESIL generation |
| [doc/taint.md](doc/taint.md) | Taint analysis |
| [doc/symex.md](doc/symex.md) | Symbolic execution |
| [doc/plugin.md](doc/plugin.md) | radare2 plugin and commands |
| [doc/types.md](doc/types.md) | Type inference |
| [doc/testing.md](doc/testing.md) | Testing strategy |

Requirements
------------

- Rust 1.85+ (edition 2024)
- radare2 (for plugin)
- pkg-config (for plugin build)
- Z3 (for symbolic execution, optional)

License
-------

LGPL-3.0-only
