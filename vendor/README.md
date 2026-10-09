# Vendored crates

The Sleigh crates this engine is built on, owned and built from this tree.
Each was copied from the commit below with only the files its own `include`
list packages; local changes are listed, and a refresh re-applies them.

| Crate | Upstream | Taken from | Local changes |
|---|---|---|---|
| `libsla` 1.2.0 | github.com/mnemonikr/libsla, via the 0verflowme fork | `ebf92321` | user-operation names and the parser-cache reset (libsla#18, #19); `GhidraSleigh` reads its address spaces once, a space's name is interned, and the p-code emit reads each varnode in place and its space from that list (ROADMAP PF1) |
| `libsla-sys` 0.1.5 | github.com/mnemonikr/libsla-sys, via the 0verflowme fork | `2ddd71ac` (Ghidra `aed1cf1c`) | the same two passthroughs (libsla-sys#8, #9); `getVarnodeSpace` and `getVarnodeOffset`, which read a varnode where `getAddress` allocated an `Address`; Ghidra's decompiler C++ only; Ghidra: `SleighBase` keeps the context fields `buildXrefs` found, so `reregisterContext` walks no symbol table, `Sleigh` records whether a decode committed context and can mark its cached parses stale, and the bridge's `clearCache` rebuilds the context only after a commit (ROADMAP PF0) |
| `sleigh-compiler` 2.0.2 | github.com/mnemonikr/sleigh-compiler | crates.io 2.0.2 | builds against `libsla-sys`'s Ghidra sources instead of its own copy, since it links that `libsla` and must see the same class layouts |
| `sleigh-config` 1.0.1 | github.com/mnemonikr/sleigh-config, via the 0verflowme fork | `71551911` | only the processors the workspace enables (x86, ARM, AARCH64, MIPS, RISCV) and their features; Ghidra's Go compiler specifications corrected to Go's `abi-internal.md`: on x86-64, RDX (the closure context, scratch at return) is no longer unaffected and X8 to X14 carry float arguments; on AArch64, the return address is x30, a call shifts the stack by nothing, x16 and x17 (scratch, used by linker trampolines) are no longer unaffected, and x18 (reserved), x28 (the goroutine) and x29 (the frame pointer) are (ROADMAP LP1); AArch64 `addv` to a B register zeroes the 31 bytes above it (`zext_zb`), where Ghidra 11.4 zeroed only those above the Q register and left the source lanes in bytes 1 to 15 |

Licences: Apache-2.0 (each crate's `LICENSE`), with Ghidra's `NOTICE`,
`DISCLAIMER.md` and `licenses/` kept beside its sources.
