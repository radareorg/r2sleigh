# r2sleigh Roadmap (Concise)

> Goal: bring Sleigh-powered, typed lifting to radare2 with backward-compatible ESIL and a path to richer analysis.

## Snapshot (Jan 2025)
- Core crates compile and lift via libsla; x86/x86-64/ARM available through `sleigh-config`.
- CLI emits JSON/ESIL; P-code → r2il translation tested.
- C-ABI exists only for loading `.r2il` (no per-instruction lifting exported yet).
- No radare2 plugin or r2 commands are implemented; Makefiles in roadmap only.

## Phase Overview
- Phase 1: Foundation — **done** (types, translator, CLI, ESIL).
- Phase 2: radare2 integration — **active** (FFI + plugin + commands).
- Phase 3: Advanced analysis — **backlog** (SSA, symbolic, memory model, dataflow).
- Phase 4: Native decompiler — **long-term** (AST, structuring, codegen).

---

## Architecture Summary

```
.sla → libsla (P-code) → r2sleigh-lift (r2il) → ESIL | future SSA/symbolic/decomp
```

Crates:
- `crates/r2il`: core types (`Varnode`, `SpaceId`, `R2ILOp`, `ArchSpec`, serialization).
- `crates/r2sleigh-lift`: P-code translation + disasm wrapper around libsla.
- `crates/r2sleigh-cli`: CLI (compile/disasm/info) + ESIL formatting.
- `r2plugin`: Rust cdylib surface for radare2 (currently only arch load helpers).

---

## Phase 1 (Complete)
- r2il opcodes (60+), spaces, varnodes, serialization with version/magic.
- P-code translator + libsla disassembler wrapper.
- ESIL output path in CLI.
- x86/x86-64 and ARM feature-gated via `sleigh-config`.
- Tests: serializer round-trip, translator sanity (Copy/Add), CLI smoke commands.

---

## Phase 2: radare2 Integration (Current Focus)

Objective: ship a loadable radare2 plugin that uses r2sleigh for lifting and ESIL generation.

### Deliverables
- **FFI surface** (Rust cdylib):
  - `r2il_arch_init(arch)` → load arch spec (from embedded sleigh-config or `.r2il` file).
  - `r2il_lift(ctx, bytes, len, addr)` → `R2ILBlock`.
  - `r2il_block_free`, `r2il_block_op_json`, `r2il_block_size`.
  - `r2il_block_to_esil(block)` → ESIL string for radare2.
  - Architecture introspection: register list, spaces, bits, endianness.
- **C wrapper (radare2 plugin)**:
  - `r_anal` plugin that maps `R2ILBlock` → `RAnalOp` (type, size, jump/fail, stack hints, ESIL).
  - Handles libsla minimum-bytes requirement (pad/peek 16 bytes for x86-64).
  - Caching lifted blocks keyed by `(pc, bytes)` to avoid relifting.
- **Build integration**:
  - `r2plugin/Makefile` to build `anal_sleigh` against produced cdylib.
  - CI job or script to run `cargo build -p r2sleigh-plugin --features x86,arm` and compile plugin.
- **User commands**:
  - `asl` family (`asl`, `aslj`, `asle`, `asli`, `asls`) for dumping r2il/ESIL/register info.
- **Tests**:
  - Plugin loads: `r2 -qc "e anal.arch=sleigh; asl?" --`.
  - Lift sanity: compare ESIL vs native `x86` for a few opcodes.
  - Error paths: unsupported arch, short input (<16 bytes), bad sleigh data.

### Open Questions / Decisions
- Where to source `.r2il` specs at runtime: embed sleigh-config vs load from disk.
- Mapping multi-op blocks to single `RAnalOp`: choose representative op type and set jump/fail/cond fields; expose full r2il via JSON command.
- ESIL fidelity: prefer deterministic ASCII `-` and radare2 operators; ensure sign/zero-extend syntax matches `Agent.md`.
- Versioning: stabilize `.r2il` format for C consumers (consider replacing `bincode + HashMap` with a deterministic layout).

### Immediate Task List
1) Expand `r2plugin/src/lib.rs` to export lifting APIs and block inspection (ESIL + JSON).
2) Add thin C shim `r2plugin/r_anal_sleigh.c` that calls FFI and fills `RAnalOp`.
3) Wire Makefile to build `anal_sleigh.so` against the Rust cdylib.
4) Implement `asl` commands in radare2 (or a minimal `asl` proof via `cmd_help`).
5) Add integration tests and docs (`README` snippet + plugin usage).

---

## Phase 3: Advanced Analysis (Backlog)

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
- libsla quirk: x86-64 needs 16 bytes minimum; plugin must pad/peek safely.
- Spaces: `SpaceId` maps `Const`, `Register`, `Ram`, `Unique`, `Custom(n)`; loads/stores carry a space constant operand.
- ESIL syntax: stick to ASCII minus (`-`), signed shift `>>>`, sign-extend `val,bits,~~`, boolean vs bitwise correctness.

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
