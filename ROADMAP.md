# r2sleigh Roadmap (Concise)

> Goal: bring Sleigh-powered, typed lifting to radare2 with backward-compatible ESIL and a path to richer analysis.

## Snapshot (Jan 2025)

- Core crates compile and lift via libsla; x86/x86-64/ARM available through `sleigh-config`.
- CLI emits JSON/ESIL; P-code → r2il translation tested.
- **radare2 plugin complete**: FFI exports, C wrapper, Makefile, basic commands.
- Plugin tested: `e anal.arch=sleigh` works with disassembly and ESIL output.

## Phase Overview

- Phase 1: Foundation — **done** (types, translator, CLI, ESIL).
- Phase 2: radare2 integration — **done** (FFI + plugin + commands).
- Phase 3: Advanced analysis — **next** (SSA, symbolic, memory model, dataflow).
- Phase 4: Native decompiler — **long-term** (AST, structuring, codegen).

---

## Architecture Summary

```
.sla → libsla (P-code) → r2sleigh-lift (r2il) → ESIL | future SSA/symbolic/decomp
```

Crates:
- `crates/r2il`: core types (`Varnode`, `SpaceId`, `R2ILOp`, `ArchSpec`, serialization).
- `crates/r2sleigh-lift`: P-code translation + disasm wrapper + ESIL formatting.
- `crates/r2sleigh-cli`: CLI (compile/disasm/info).
- `r2plugin`: Rust cdylib + C wrapper for radare2 (`RAnalPlugin`).

---

## Phase 1 (Complete)

- r2il opcodes (60+), spaces, varnodes, serialization with version/magic.
- P-code translator + libsla disassembler wrapper.
- ESIL output path in CLI.
- x86/x86-64 and ARM feature-gated via `sleigh-config`.
- Tests: serializer round-trip, translator sanity (Copy/Add), CLI smoke commands.

---

## Phase 2: radare2 Integration (Complete)

### Deliverables (Done)

- **FFI surface** (Rust cdylib `r2plugin/src/lib.rs`):
  - `r2il_arch_init(arch)` — load arch spec from sleigh-config ✓
  - `r2il_lift(ctx, bytes, len, addr)` — lift to `R2ILBlock` ✓
  - `r2il_block_free`, `r2il_block_op_count`, `r2il_block_op_json` ✓
  - `r2il_block_size`, `r2il_block_addr` ✓
  - `r2il_block_type`, `r2il_block_jump`, `r2il_block_fail` ✓
  - `r2il_block_to_esil(ctx, block)` — ESIL string ✓
  - `r2il_block_mnemonic(ctx, bytes, len, addr)` — disassembly ✓
  - `r2il_string_free` ✓

- **C wrapper** (`r2plugin/r_anal_sleigh.c`):
  - `RAnalPlugin` with `sleigh_op()` callback ✓
  - Maps `R2ILBlock` → `RAnalOp` (type, size, jump/fail, ESIL) ✓
  - Handles 16-byte minimum padding for libsla ✓
  - Lazy architecture initialization with caching ✓

- **Build integration** (`r2plugin/Makefile`):
  - Builds Rust cdylib + C wrapper → `anal_sleigh.so` ✓
  - `make install` / `make uninstall` targets ✓
  - Feature flags for x86/arm/all-archs ✓

- **User commands**:
  - `a:sleigh` — status ✓
  - `a:sleigh.info` — architecture info ✓
  - `a:sleigh.json` — r2il ops as JSON ✓

- **Documentation**:
  - README with plugin installation and usage ✓

### Verified Working

```bash
$ r2 -qc 'e anal.arch=sleigh; pd 3' /tmp/test.bin
            0x00000000      55             push rbp
            0x00000001      4889e5         mov rbp, rsp
            0x00000004      c3             ret

$ r2 -qc 'e anal.arch=sleigh; e asm.esil=true; pd 3' /tmp/test.bin
            0x00000000      55             rbp,8,rsp,-,=[8],8,rsp,-=
            0x00000001      4889e5         rsp,rbp,=
            0x00000004      c3             rsp,[8],rip,=,8,rsp,+=
```

---

## Phase 3: Advanced Analysis (Next)

Goal: typed analysis on top of r2il.

- SSA: insert phi, rename, expose SSA blocks; conversions to/from r2il.
- Dataflow: def-use, reaching defs, taint scaffolding on SSA.
- Memory model: regions + permission checks; hook loads/stores.
- Symbolic execution: expression domain + optional solver bridge; branch forking.
- IR hygiene: normalize flag semantics, consistent bit-width ops.
- Integration points: r2 commands to show SSA/taint summaries; JSON outputs for scripting.

Prereqs: stable r2il schema, consistent varnode naming, cross-arch register metadata.

---

## Phase 4: Native Decompiler (Long-term)

Goal: structure SSA to AST and emit C-like code without external tools.

- Control-flow structuring (dom tree, loops, switches).
- Type recovery (propagation + call signatures + struct inference).
- Pattern library for idioms (memcpy, strlen, prolog/epilog).
- Pretty-printer configurable for styles.

Prereqs: mature SSA + dataflow + type info; extensive tests per-arch.

---

## Technical Notes

- `.r2il` today: `bincode` serialization with magic/version and `HashMap` for registers; not a stable C ABI. Either freeze a deterministic binary layout or add a JSON/CBOR export for C consumers.
- libsla quirk: x86-64 needs 16 bytes minimum; plugin pads input automatically.
- Spaces: `SpaceId` maps `Const`, `Register`, `Ram`, `Unique`, `Custom(n)`; loads/stores carry a space constant operand.
- ESIL syntax: ASCII minus (`-`), signed shift `>>>`, sign-extend `val,bits,~~`, boolean vs bitwise correctness.

---

## Testing Strategy

- Rust: `cargo test --all-features`; add translator/ESIL golden tests per opcode.
- Plugin: radare2 oneliners for load/lift/ESIL; compare against native plugins where applicable.
- Integration: sample bytes for x86-64 and ARM (padded) through CLI and plugin; ensure consistent sizes and branch targets.
- Fuzzing (optional): feed random bytes through `lift` to guard translator panics.

---

## Risks / Mitigations

- **Format churn**: lock a stable `.r2il` spec before publishing plugin; add version gating.
- **ESIL mismatch**: cross-check with radare2 native outputs; add regression tests.
- **Performance**: cache lifts; avoid repeated libsla init; limit allocations in FFI paths.
- **Maintenance**: upstream sleigh-config changes; keep feature flags aligned between CLI/plugin.

---

## References

- Agent guidelines: `Agent.md`
- radare2 coding notes: `../radare2/AGENTS.md`
- ESIL reference: https://book.rada.re/disassembling/esil.html
- Sleigh docs: https://ghidra.re/courses/languages/html/sleigh.html
- P-code reference: https://ghidra.re/courses/languages/html/pcoderef.html
