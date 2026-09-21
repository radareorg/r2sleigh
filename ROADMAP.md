r2sleigh Roadmap
================

> The ordered execution list. For what this is becoming and why, read
> [doc/engine-vision.md](doc/engine-vision.md); for the working rules, read
> [AGENTS.md](AGENTS.md).

North Star
----------

`r2s` is the tool: a binary analysis engine and certifying decompiler that owns
its facts. The properties being aimed at:

- one canonical IL substrate, printable at every tier
- one canonical SSA and dataflow layer
- one canonical semantic artifact with explicit evidence
- one canonical request orchestrator
- one certifying render contract: C only when checked facts justify it,
  otherwise a marked gap or a refusal that says why
- confidence on every engine-tier fact, and it cannot be stripped

The metric is not command count. It is whether the output is right, and whether
the engine can say why it believes what it prints.

Where this stands
-----------------

Done, and gated:

- **Native body lift** at a given address, refusing at indirect transfers.
- **The sdb type and convention import**: `r2abi` reads the conventions and
  about five hundred library prototypes natively.
- **Native request construction** and `pdd` end to end in `r2s`, on x86-64,
  aarch64 and ARM 32-bit disassembly.
- **DWARF through `gimli`**: source parameter and local names, frame bases and
  declared prototypes, which radare2's C path did not give.
- **Printable IL tiers**: `pdil`, `pdim` and `pdih` print the low, medium and
  high tiers, so a defect belongs to exactly one lowering.
- **Discovery** as a fixed point over direct transfers, with `Stated`, `Called`
  and `Reached` on every address.
- **The plugin and the snapshot bridge are deleted**, and the gate is rebuilt on
  `r2s` itself.

Next, in order
--------------

1. **Collapse the switch import.** The native route derives its own jump tables
   through `values.rs` and `indirect.rs`; what remains is one `SwitchInfo`
   rather than two, an unresolved record for a switch with no dispatch, and the
   redundant half of `dispatch_table_read`.
2. **The name database, cross-references and strings.** One address-to-name
   table with a kind, a size and a confidence, and a reverse index, replacing
   every rival naming rule in the tree. Queries over the IL, not separate
   scanners. New commands: `f`, `ax`/`axt`, `iz`/`izz`.
3. **Discovery across a typed handoff.** A constant argument counts as a
   function only where the callee's declared prototype says that parameter is
   one, which is how a stripped binary reaches `main` through
   `__libc_start_main`.
4. **Write and patch mode**, with incremental invalidation. The first thing
   that actually exercises demand-driven analysis, so it decides the shape.
5. **The memory model**, finishing the value-set keystone: abstract locations
   in the CodeSurfer sense, a region and an offset, where the region is a
   global, a named stack frame or an allocation site.
6. **Interprocedural control-flow graph to fixpoint.** Callees are walked one
   level deep today, which is the largest single improvement available to
   output quality.
7. **Exception-handler recovery**, and structure and array recovery over the
   memory model.
8. **Binary diffing.** Independent of the above and high value.
9. **Solver escalation**, with verification and value-set analysis as its
   consumers, so it does not repeat the deleted symbolic crate's fate.
10. **Equivalence checking**, which makes every later claim mechanical rather
    than hand-checked.
11. **The rest of the command language and r2pipe compatibility.**
12. **The agent surface**: the stateless typed query API, confidence carried
    through the contracts, explain over the existing ledger, and budget-aware
    rendering with elision reported and fetchable.
13. **Trace recording and query.**

Standing debt
-------------

Carried with a cause, not as a baseline:

- Nine refusals over the `cmp`/`sdiff`/`diff3`/`diff` corpus, and four
  `ConflictingValue` cases traced to marker placement.
- Nine `libarm.so` functions behind a barrier the lift emits as `CALLOTHER`.
- `pdd` on ARM 32-bit is not admitted: `TrustedSleighProfile::from_tuple` takes
  a tuple only once it has been verified against the active analyzer.
- Entry condition flags cannot be booleans until the architecture
  specification carries a flag fact; nothing available today tells `CF` from
  `AL`.
- The measurement harnesses under `scripts/` and `tests/decbench/` still drive
  radare2, and need repointing at `r2s`.
- The Dylint rules under `tools/dylints/` include lints written for plugin-side
  policy that can no longer fire.

Ownership
---------

| Crate | Owns |
|-------|------|
| `r2image` | What the container states: bytes, sections, symbols, relocations, entries, DWARF |
| `r2abi` | Calling conventions, library prototypes, compiler specifications |
| `r2il` | The low tier: `Varnode`, `SpaceId`, `R2ILOp`, `R2ILBlock` |
| `r2sleigh-lift` | Decoding and lifting through Sleigh |
| `r2ssa` | The medium tier: SSA, dataflow, prepared facts, certificates, refusal evidence |
| `r2source` | The facts a capture owns, and their contracts |
| `r2types` | Type inference, layouts, signatures |
| `r2rewrite` | Term rewriting, and reporting where each read moved |
| `r2dec` | The high tier: structuring, binding, certification, rendering |
| `r2engine` | Request orchestration, discovery, the native route |
| `r2s` | Command dispatch, and the only implementor of `Program` |

One fact, one owner. When two places answer the same question, one of them is
deleted.
