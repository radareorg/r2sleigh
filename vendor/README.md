# Vendored crates

The Sleigh crates this engine is built on, owned and built from this tree.
Each was copied from the commit below with only the files its own `include`
list packages; local changes are listed, and a refresh re-applies them.

| Crate | Upstream | Taken from | Local changes |
|---|---|---|---|
| `libsla` 1.2.0 | github.com/mnemonikr/libsla, via the 0verflowme fork | `ebf92321` | user-operation names and the parser-cache reset (libsla#18, #19) |
| `libsla-sys` 0.1.5 | github.com/mnemonikr/libsla-sys, via the 0verflowme fork | `2ddd71ac` (Ghidra `aed1cf1c`) | the same two passthroughs (libsla-sys#8, #9); Ghidra's decompiler C++ only |
| `sleigh-config` 1.0.1 | github.com/mnemonikr/sleigh-config, via the 0verflowme fork | `71551911` | only the processors the workspace enables (x86, ARM, AARCH64, MIPS, RISCV) and their features |

Licences: Apache-2.0 (each crate's `LICENSE`), with Ghidra's `NOTICE`,
`DISCLAIMER.md` and `licenses/` kept beside its sources.
