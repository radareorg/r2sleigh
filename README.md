r2sleigh
========

A binary analysis engine and certifying decompiler in Rust, with `r2s` as its
shell. Semantics come from Ghidra's Sleigh specifications rather than
hand-written per-architecture models, and the decompiler refuses rather than
guesses when it cannot prove what it would print. `r2s` speaks radare2's
command language with no radare2 in the process; radare2 is the differential
target the engine is graded against.

```
bytes --> Sleigh --> r2il (low) --> r2ssa (medium) --> r2dec (high) --> C
              |                          |                  |
          r2image                    r2types            r2rewrite
        ELF/Mach-O/DWARF          type inference       term rewriting
```

Quick start
-----------

```bash
cargo build --release -p r2s --features sleigh

target/release/r2s -q -c 'afl' /bin/ls                    # functions, and why each is believed
target/release/r2s -q -c 'iz' /bin/ls                     # strings
target/release/r2s -q -c 'axt 0x100003f10' /bin/ls        # references to an address
target/release/r2s -q -c 's main; pdd' /bin/ls            # decompile
target/release/r2s -q -c 's main; wx 9090; pdd' /bin/ls   # patch in memory, then decompile
target/release/r2s -q -c 's main; pd 16' /bin/ls          # disassemble
target/release/r2s /bin/ls                                # interactive; V for the visual mode
```

Each IL tier prints on its own, so a defect belongs to one lowering: `pdil`
(r2il as lifted), `pdim` (r2ssa with its binding plan), `pdih` (the r2dec
tree). `R2DEC_TRACE_REFUSAL=1` names the predicate and site behind a refusal.

Architectures
-------------

| Architecture | Feature | Status |
|--------------|---------|--------|
| x86-64, x86 | `x86` | decompiles |
| aarch64 | `arm` | decompiles |
| ARM 32-bit | `arm` | disassembles; `pdd` not yet admitted |
| RISC-V, MIPS | `riscv`, `mips` | lift |

Crates
------

| Crate | Purpose |
|-------|---------|
| `r2s` | The shell: radare2's command language over the engine |
| `r2s-tui` | The visual mode |
| `r2engine` | Query orchestration, discovery, routes, summaries |
| `r2image` | ELF and Mach-O parsing, DWARF through `gimli` |
| `r2abi` | Library prototypes, syscalls, cited ABI rows |
| `r2sleigh-lift` | Sleigh decoding to r2il; the machine profile from the `.cspec` |
| `r2il` | The low IL (`Varnode`, `R2ILOp`, `R2ILBlock`) and its semantics |
| `r2ssa` | The IR: SSA, indexes, liveness, values, memory, certificates |
| `r2source` | Contracts between the layers |
| `r2types` | Type inference, layouts, signatures |
| `r2rewrite` | Term rewriting with proved rules |
| `r2dec` | Structuring, binding and C rendering |
| `r2sleigh-cli`, `r2sleigh-export` | The Sleigh toolchain and the instruction exporter |

Extending
---------

- **An opcode**: `R2ILOp` in `crates/r2il/src/opcode.rs`, its P-code
  translation in `crates/r2sleigh-lift/src/translate.rs`, text in `text.rs`,
  `SSAOp` in `crates/r2ssa/src/op.rs`, lowering in
  `crates/r2dec/src/fold/op_lower/`.
- **An architecture**: a trusted language in `crates/r2sleigh-lift`
  (`TrustedSleighProfile`, `embedded_machine`) whose compiler specification
  the `LanguageProfile` parses; nothing below the lifter matches its name
  ([doc/adr-machine-profile.md](doc/adr-machine-profile.md)).
- **A command**: one entry in `VERBS` in `crates/r2s/src/commands.rs`, spelled
  as radare2 spells it.

Documentation
-------------

| Document | What |
|----------|------|
| [ROADMAP.md](ROADMAP.md) | What is done, what is left, in order |
| [AGENTS.md](AGENTS.md) | Working rules: ownership, anti-hack standard, validation bar |
| [BUILDING.md](BUILDING.md) | Build, features, profiles, troubleshooting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Issues, commits, pull requests |
| [doc/engine-vision.md](doc/engine-vision.md) | What this is becoming, and why |
| [doc/testing.md](doc/testing.md) | Gates and where a test goes |
| `doc/r2il.md`, `doc/ssa.md`, `doc/decompiler.md`, `doc/types.md` | The tiers |
| `doc/adr-*.md` | One design decision each, linked from the roadmap |

Requirements
------------

Rust 1.85+ (edition 2024). radare2 only for the differential harnesses. Z3
optional. License: LGPL-3.0-only.
