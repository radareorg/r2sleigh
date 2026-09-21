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
- **One switch owner**: jump tables are derived from our own value ranges and
  imported from nothing.
- **One name database**, with a kind, a size and a confidence per address, plus
  cross-references and strings: `f`, `iz`, `ax`, `axt`.
- **Discovery crosses a typed handoff**: a stripped binary goes from 5 functions
  to 20, because a declaration says `__libc_start_main` takes a function.
- **Write and patch mode**: `w`, `wx`, `wc`, `wcr`. The patch is a layer, the
  file is untouched, and the analysis follows the patched bytes because a
  prepared function is keyed by the bytes it was captured from.

Next, in order
--------------

1. **Finish the name collapse.** `r2source::DisplayNames` is a second naming
   table, `r2dec` has two callee resolvers that disagree on how a call is
   spelled, and three spellings of an unnamed function survive (`fcn.{x}`,
   `fcn_{x}`, `sub_{x}`). One table already exists; these have to move into it.
2. **The memory model**, finishing the value-set keystone: abstract locations
   in the CodeSurfer sense, a region and an offset, where the region is a
   global, a named stack frame or an allocation site.
3. **Interprocedural control-flow graph to fixpoint.** Callees are walked one
   level deep today, which is the largest single improvement available to
   output quality.
4. **Exception-handler recovery**, and structure and array recovery over the
   memory model.
5. **Binary diffing.** Independent of the above and high value.
6. **Solver escalation**, with verification and value-set analysis as its
   consumers, so it does not repeat the deleted symbolic crate's fate.
7. **Equivalence checking**, which makes every later claim mechanical rather
   than hand-checked.
8. **The rest of the command language and r2pipe compatibility.**
9. **The agent surface**: the stateless typed query API, confidence carried
   through the contracts, explain over the existing ledger, and budget-aware
   rendering with elision reported and fetchable.
10. **Trace recording and query.**

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
- `scripts/kernel_smoke.py`, `scripts/bench_semantic_metadata.py`,
  `scripts/reversing_benchmark.py` and `tests/decbench/` still drive radare2
  with the deleted plugin. Source-gold is restored natively; the
  fixed-performance gate is not.
- With no debug information nothing proves the signedness of a 32-bit return,
  so `main` renders `uint32_t` where the source says `int`. Recorded in
  `tests/gold/source_gold_baseline.json` with its cause.
- `tools/dylints/r2sleigh_lints` has 32 file-scanning tests asserting on
  functions that were renamed or deleted in August and September; nothing runs
  them in continuous integration, which is why they rotted.
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
