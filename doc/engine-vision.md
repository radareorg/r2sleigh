Engine vision
=============

What r2sleigh is becoming, and why. Order and status: [ROADMAP.md](../ROADMAP.md);
working rules: [AGENTS.md](../AGENTS.md).

Thesis
------

r2sleigh is a binary analysis engine that ships a decompiler, built
agent-first. Two consequences shape everything else.

**The engine owns its facts.** Whoever discovers the work owns the program,
and whoever owns the program decides what is analysed and what a changed byte
invalidates. The radare2 plugin is deleted; `r2s` opens the binary and every
fact arrives through `r2engine::program::Source`. radare2 remains the
differential target for discovery, naming, decoding and cross-references.

**The primary consumer is an agent.** Agents fail on analysis tools for
structural reasons (a hidden cursor, a turn per hop, text to parse, empty
results that look like errors, unbounded output, guesses that look proven),
and no renderer fixes those. Success is an agent answering a real question in
one or two calls, with confidence on every field and the ability to ask why.
The agent surface itself (ROADMAP A) is built last, on purpose: it is a thin
layer over the query database (Q) and provenance (C), and built before them it
would be a second API to delete.

Non-goals
---------

- **No port of radare2** (`libr` is about 1.1 million lines): parity through
  depth, and the long tail of formats and architectures is not matched.
- **No new architectures** until x86 and ARM depth is done.
- **No parallel pipelines**: when a newer approach wins, the older is deleted.
- **No per-architecture semantics**: Sleigh only, never ESIL-style
  hand-written approximations.

Topology
--------

- **The engine**: IL, analyses, fact database and decompiler in one process,
  with no serialization boundary inside it.
- **The debugger**, if built, is a separate process: it needs privileges and
  the debuggee can crash it ([drafts/debugger.md](drafts/debugger.md), not adopted).
- **Frontends** (`r2s`, its visual mode, an agent surface) are clients of a
  typed engine API; the engine never formats output for any of them, the
  discipline radare2's `libr/core` lost.

Refusal and confidence
----------------------

A decompiler may refuse; a function listing or a cross-reference query cannot.
So the fact lattice has two consumption policies, not two pipelines: the engine
tier answers best-effort with confidence attached, and the decompiler tier
keeps the right to refuse on top. Every engine-tier fact carries a confidence
(`r2source::confidence`) from the first one written.

The IL in tiers
---------------

Three tiers, each one crate and each printable, so a defect is localised to
one lowering:

| Tier | Crate | Shape | Print |
|------|-------|-------|-------|
| Low | `r2il` | machine-faithful, flags explicit, no variables ([r2il.md](r2il.md)) | `pdil` |
| Medium | `r2ssa` | SSA with stack variables, resolved calls, dead flags removed ([ssa.md](ssa.md)) | `pdim` |
| High | `r2dec` | structured, typed, C-shaped ([decompiler.md](decompiler.md)) | `pdih` |

Analysis capability
-------------------

radare2 does FLIRT, RTTI, DWARF, PDB and search adequately, and jump tables,
variable recovery and type inference weakly, by heuristics. What this engine
adds, in order:

1. **Values and memory, one fixpoint.** Value-set analysis (strided intervals,
   `r2ssa/src/values.rs`) replaces jump-table heuristics; a region-and-offset
   memory model is what structure recovery needs. A solver returns only as an
   escalation behind the facts API once something consumes it: the deleted
   symbolic crate showed a solver with no consumers does not pay for itself.
2. **What that unlocks.** An interprocedural CFG to fixpoint with indirect
   calls resolved; array and structure recovery from access patterns;
   exception handlers from `.eh_frame` and LSDA. Loop and induction analysis
   is largely built (`InductionFact`, `ForLoopCertificate`, `LoopTrips`).
3. **Absent from both.** Binary diffing over callee summaries, library
   identification that survives optimisation, reassembleable rewriting, and
   deobfuscation (MBA simplification belongs in `r2rewrite`).
4. **Language runtimes**: Go metadata, Rust panic locations, C++ RTTI carried
   to `this` typing.
5. **Research-grade**, judged separately: superset disassembly, learned
   function boundaries.
6. **Checking the decompiler's output.** `tests/equiv` runs each rendering
   beside its original; next is a solver comparison of re-lifted C against
   the original IL.

The agent interface
-------------------

The evidence system exists (`obligation.rs`, the obligation ledger,
`r2types::evidence`, `r2source::contracts`); the surface over it does not yet.
Its principles: stateless addressed queries with no cursor; compound questions
in one call; confidence (proven, inferred, guessed, unknown) on every field; a
token budget per call with elisions reported; summaries and stable handles by
default; decompiled C as the default rendering; errors that return the schema
and the nearest valid form; **explain** (a fact's evidence chain) and
**verify** (a hypothesis proved, disproved with a counterexample, or unknown).
Around a dozen tools; command strings are an escape hatch, never the
interface.

Invariants
----------

Beyond the ownership rules in AGENTS.md: the engine never formats output;
there is no implicit cursor; confidence travels with every fact; there is no
serialization boundary inside the engine process; analysis is demand-driven
and invalidated incrementally ([adr-query-database.md](adr-query-database.md));
and every IL tier is printable.

Open questions: the extension interface (a C ABI, WebAssembly, or r2pipe
compatibility), and shipping an `r2s` whose `Cargo.toml` patches `libsla`,
`libsla-sys` and `sleigh-config` to three git forks.
