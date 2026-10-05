r2sleigh Roadmap
================

> The one ordered execution list. Why the project exists and what it is
> becoming is in [doc/engine-vision.md](doc/engine-vision.md); the working
> rules are in [AGENTS.md](AGENTS.md). Each structural item has an ADR, linked
> from its row; this file owns the order, the status and the decisions, and
> the ADRs own the design. Where they disagree, this file wins and the
> disagreement is a defect.

What r2s is
-----------

The radare2 plugin is deleted. `r2s` is the tool, with three surfaces over one
engine that owns its facts:

1. **The engine**: discovery, lifting, SSA, memory, types and a certifying
   decompiler, answering typed queries. It prints C only where checked facts
   justify it; otherwise a counted residual, or a refusal that says why.
2. **The shell and the visual mode**: radare2's command language and keys, so a
   radare2 user moves without relearning. It adds what radare2 never had:
   completion, discoverability, linked views, a graph you can read, and a UI
   that never blocks.
3. **The agent surface**: stateless addressed queries, confidence on every
   field, explain and verify.

How we measure, in order of authority:

| Gate | Question it answers |
|------|---------------------|
| Equivalence (`tests/equiv`) | Does the rendered C compute what the machine code computes? The north-star number. |
| Census (`pdd` of every function of the coverage, pinned and stripped corpora) | Did a change move any rendering? A structural change must leave it byte-identical, or say which lines moved and why. |
| Certification (`scripts/certify_render.py`) | Does every rendering read only what it assigns, and never panic? |
| Source-gold (`scripts/differential_truth.py`) | Are recovered signatures what the source declared, or marked when not? |
| Coverage (`tests/coverage`) | How much of a whole binary renders, and does any of it regress? |
| Differential (`scripts/diff_r2.py`) | Where discovery, naming and decoding disagree with radare2, and who is right. |
| Structure report (`scripts/structure-report.sh`) | Did nesting, function length, argument counts or redundant clones rise? |

A benchmark score is never proof of quality. Output is read by hand before a
quality claim (AGENTS.md, Manual Verification).

Where this stands
-----------------

Measured on `engine/roadmap` (PR #67) on 2026-10-04.

| Measure | Value |
|---------|-------|
| Equivalence | 599 of 756 `equal` (x86-64, gcc 13 and clang 18, -O0 to -O2), from 582. The rest: residual-trap 85, ub 22, unsupported 20, refused 17, differs 11, compile-error 1, slow 1. Blessed from CI's run |
| Census | 665 functions; 8 refused |
| Certification | 113 rendered, 17 refused, 0 undefined reads, 0 panics |
| Coverage | 554 of 562 rendered (98%); baseline blessed from CI's run |
| Workspace tests | 2110 passed; 2 fail only under Apple clang 21, as on master |

Landed on the program so far:

- **G**:
  - CI under ten minutes;
  - baselines blessed from CI;
  - SSA validation checks dominance, and the sealed function validates.
- **F1** (doc/adr-stable-identity.md):
  - stable `OpId`s;
  - the stage types `Lifted → Prepared → Sealed`;
  - every fact keyed by id, never by position;
  - nothing written into an artifact once it is built.
- **PE** (doc/adr-written-lanes.md):
  - result widths from the bytes the instructions wrote;
  - a stated extension writes its destination;
  - a sign extension is signed.
- **P1.7**: a narrow formal is the caller's lane, and the whole register
  keeps the caller's bytes.
- **C0–C1** (doc/adr-provenance.md):
  - one provenance vocabulary;
  - interface types and the format parameter carry it.
- **K in r2ssa** (doc/adr-fixpoint.md):
  - one fixpoint driver (block, edge and sparse);
  - memory SSA, stack roots, call results, control domains, call arguments
    and address provenance rewritten onto it, or as worklists;
  - the optimiser run to its fixpoint;
  - no silent caps.
- **V1, S1, V2, V3** in part:
  - a visual mode that never blocks;
  - the verb table, `e` and `-e`;
  - colour from roles the lifter and the C emitter record;
  - tab completion.

What the review found
---------------------

On 2026-10-04, with F1, K and PE done, the code was rated **4 out of 10**:

- about 7 for its ideas and its safety discipline, which are good: it is
  deterministic, it refuses rather than fakes, its gates are strong, and its
  core semantics are mostly right;
- about 3 for its algorithms and its structure.

The output can be trusted; the machinery that produces it is the weak part.
The evidence:

1. **Iteration done by hand.**
   - About 45 computations repeated "until nothing changes".
   - About 25 rescanned the whole function each round with no stated
     lattice.
   - Six stopped at a hard-coded round count and kept a partial result
     without saying so.
   - About ten were not monotone. They overwrote instead of joining,
     speculated and rolled back, or minted facts and never retracted them.
   - K fixed r2ssa's. r2types' and r2dec's remain.
2. **Recomputation instead of ownership.**
   - Preparation builds the graph twice and liveness twice; the second
     liveness pass resolves a dependency cycle (liveness, spans, facts,
     liveness) by running it again.
   - Interface recovery prepares a whole provisional fact set first.
   - r2dec computes dominators of its own.
   - Discovery re-walked the whole program on every `afl` (42 s on libc)
     until it got one more cache.
3. **Side tables instead of indexes.**
   - 684 maps and sets in production code are keyed by a function's own
     entities (`SSAVar`, `ValueId`, `InstId`, the optimiser's `VarKey`
     strings): 373 in r2ssa, 240 in r2dec and 71 in r2types, counted by the
     `ENTITY_KEYED_MAP` Dylint.
   - Every lookup is a tree walk or a hash of a name, and every pass builds
     the relation it needs again.
4. **Caches instead of a database.** Eight caches each decide for themselves
   whether a write touched them:
   - the analysis memo;
   - `PerRevision`;
   - two mutexed tables;
   - the reference index;
   - the survey;
   - the entry modes;
   - the names table.

   `Revision` has four axes because no single one says what an answer
   depended on.
5. **Twelve owners of the stack frame.**
   - Three rules decide an object's extent, four analyses its escape and
     three its containment.
   - A proof is fed back as a declaration.
   - `afv` and `pdd` name and list different locals.
6. **A renderer that proves again.**
   - Of r2dec's 78k lines, the journal (9k), the binding plan (13k) and
     placement (6k) check again what r2ssa proved, and retry when the check
     fails.
   - A printer identity was refused because the journal wanted a literal
     rendered.
   - A more precise fact made the text worse.

Decision: **algorithms and structure before more features.** The next items
re-found the engine on one indexed IR, one query database, one frame model
and a printer. Feature tracks resume on that base, so that each is written
once.

Decisions
---------

Taken 2026-10-03:

- **D1. Restructure, not rewrite.** The lifter, r2image, r2abi, the
  certificates' decisions, r2rewrite's proved rules, Kani and the gates are
  kept. Each replaced part runs beside the old path until the gates agree,
  then the old path is deleted in the same change.
- **D2. Stable identity before more facts.** Done (F1).
- **D3. Stages are types.** Done (F1).
- **D4. Provenance is part of every fact**, as `Fact<T>`. C0–C1 done.
- **D5. Gates are blessed in CI, never on a laptop.**
- **D6. Equivalence runs on arm64 too**, under qemu-user.
- **D7. The visual mode never calls the engine while drawing.** Done (V1).

Confirmed 2026-10-04:

- **D8.** The observation journal is replaced, not kept; R replaces it
  (doc/adr-renderer-printer.md).
- **D9.** `doc/adr-location-ssa.md` is superseded. Its remainder (one
  liveness model over locations, pruned flag and temporary phis) is F2.2.
- **D10.** DecBench is measured again only once it runs where PyPI is
  reachable.

Taken 2026-10-04, after the review:

- **D11. Algorithms before features.** No new code may add:
  - an iteration that is not on the fixpoint driver or a stated worklist;
  - a cap that keeps a partial result silently;
  - a map keyed by a function's own entities;
  - a cache outside the query database.

  Dylints enforce each one as its owner lands (F2.0, Q4).
- **D12. One IR, indexed once** (doc/adr-one-ir.md).
  - The sealed function is the IR, with dense ids and dense containers.
  - Every relation over it is one index, computed at most once; analyses are
    declared on the fixpoint driver.
  - No graph is built outside the seal.
- **D13. One query database** (doc/adr-query-database.md).
  - Every derived program fact is a query with recorded dependencies,
    revalidated red-green.
  - Inputs are the container, the bytes by range, and the user's facts.
  - The eight caches and `Revision`'s axes are deleted.
- **D14. One frame model** (doc/adr-frame-model.md).
  - The frame is one partition of entry-stack offsets, owned by one index.
  - One escape analysis, one extent rule, roles from structure.
  - Memory-to-register promotion is an SSA rewrite reading it.
  - The canary is elided under a stated `UbFreeSource` premise, never
    silently.
- **D15. One machine profile.**
  - What an architecture is — registers and their aliases, stack pointer,
    return address, calling conventions, killed-by-call sets, address spaces,
    delay slots, TLS register — is one typed profile with one owner.
  - It is derived from the trusted Sleigh bundle (`.sla`, `.pspec`, `.cspec`;
    `sleigh-config` already embeds the `CSPEC_*` texts), never from a name.
  - No crate below the lifter matches an architecture name. A new
    architecture is a profile, not a match arm in eight crates.

The program
-----------

Identifiers are kept from plan.md and plan-extension.md (P*, PE, C, H, I, K,
Q, S, E, A). G is gates, F foundation, M the machine profile, R the
renderer as printer, and V the visual mode and shell.

### Foundation — now, blocks the rest

| Item | Design | Depends on | Exit | Status |
|------|--------|-----------|------|--------|
| **F1** Stable ids and stage types | adr-stable-identity.md | G | No fact keyed by position; nothing written into an artifact after the seal; the sealed function validates | **Done** (steps 0–4) |
| **K** One fixpoint driver | adr-fixpoint.md | F1 | No iteration without a lattice and a budget | **Done in r2ssa**; r2types' loops go with C3, r2dec's with R |
| **F2** One IR, indexed once: dense ids and containers; `FunctionIndex` (RPO, dominators, loops, def-use, views, liveness, spans); prepared facts and certificates as indexes; a builder with incremental def-use before the seal; machine projection and term arena as indexes | adr-one-ir.md | F1, K | No graph outside the seal; no entity-keyed map in r2ssa; one liveness model; closes #47, #50, #56 | **In progress**: F2.0–F2.2 done; F2.3 done (facts and certificates as indexes, one build per function); F2.6 done in r2ssa (the Dylint denies entity-keyed maps there, in CI); F2.4, F2.5 and F2.6 in r2types remain (see the ADR's "As landed") |
| **Q** One query database: container and bytes as inputs; discovery, decode, walk, lift, seal, summaries, references and renderings as queries; red-green revalidation | adr-query-database.md | F2.1 | A random-write session equals a fresh open; no cache outside the database; `Revision` deleted | After F2.1, beside F2 |
| **M** One machine profile: registers, aliases, stack pointer, return address, conventions, killed-by-call, address spaces and delay slots read from the trusted Sleigh bundle's `.pspec`/`.cspec`; the hand-written tables in `r2image`, the lifter's tuple gate, `r2ssa::abi`, `r2ssa::machine_context`, `r2types::signature_infer`, `r2dec` and `r2abi::platform` read it | — | F1 | No architecture-name match below the lifter; the tables deleted; RISC-V's profile derives from its `.cspec` with no arm added in r2ssa, r2types or r2dec | Beside F2, before P4 |
| **P4** One frame model: one partition, one escape analysis, one extent rule, roles; promotion as an SSA rewrite; canary elided under its premise; `afv`/`afi` from it | adr-frame-model.md | F2, C, M | One owner of frame objects; the 37 canary residual traps gone; `afv` agrees with `pdd` | After F2 |
| **R** The renderer as a printer: one render plan from the indexes, expressions as r2rewrite terms with proved rules, obligations carried by the tree with one linear checker, bindings from the frame model, no retries | adr-renderer-printer.md | F2, P4, P5 | r2dec reads only sealed facts; the journal, the binding-plan fixpoint and every retry deleted | After P4 |

### Analysis

| Item | Depends on | Exit | Status |
|------|-----------|------|--------|
| **PE** Byte-dependency relation; result widths from written lanes | F1 | `main`, `gt`, `fnv1a32` and `pearson` at their source widths (#58, #63) | **Result widths done**; the demand pass on the same relation goes to F2 (an index), the XMM lane noise to P5 |
| **P1.7** Entry lanes as the caller's lanes | PE, F1 | The sealed function validates; no invented caller bytes | **Done** |
| **C** Provenance as `Fact<T>` | — | Every public answer field is a `Fact` (C2); r2types' candidates and source enums on `Basis` (C3, with the r2types loops of K); references carry `Confidence` (C4) | C0–C1 done |
| **P5** Value domain completed as an index; loads from immutable memory fold | F2 | The XMM lane noise is gone; ranges are one index | |
| **P6** One resolved body per function per revision, as a query; callee summaries by component of the call graph | Q, I | `read_callees` deleted; switch arms in the walked body (the visual mode's resolved-graph fallback deleted) | |
| **I** Unread container facts: CFI extents and save slots as stated entries, LSDA, IBT, RELRO, init arrays | Q | Stripped discovery finds every FDE start | |
| **P7** Call contracts: one ABI classifier, variadic and format roles, result proof over the call graph; prove or delete the address-proven formals no test observes | PE, P6, C | No dropped or invented argument; printf's stack tail renders | |
| **P8** Data objects and strings | P5, P7 | `iz` lists proven strings | |
| **P9** Types over the graph: declared-pointee propagation, inferred aggregates | P4, P8 | A struct pointer is not `uint32_t*` (`rec_index`) | |
| **P11** Names and commands: one spelling of an unnamed function, aliases by occupancy | C, P6 | Differential disagreements all judged | |

### Surface

| Item | Depends on | Exit | Status |
|------|-----------|------|--------|
| **V1** Visual-mode core | G | No host call from the drawing thread | **Done**; its worker asks Q once Q lands |
| **S1** One verb table; `?`; `j` on every verb; `e` | — | Help and completion cannot disagree with dispatch | Done except `j` on every verb |
| **V2** Colour from the engine | V1 | `pd` and `pdd` coloured alike in the shell and the visual mode | Done except `eco` themes |
| **V3** Completion and discoverability | V1, S1 | Every action findable without documentation | Shell done; visual-mode hints, palette and `?` remain |
| **V4** Panels and linked cursors | V1 | A C line lights its instructions in every pane | |
| **V5** Graphs through one renderer | V2, F2 | `agf`, `agc`, `agx` share it; layout off the UI thread | |
| **S2** `@@` iterators, search, pipes, `-i`/`-q0` | Q | `diff_r2.py` covers the `j` forms | |
| **E** Emulation over `r2il::eval`, then verify | — | aarch64 originals checked against host-compiled renderings | |
| **A** Agent surface: stateless queries, `Fact<T>` fields, explain from Q's dependencies | Q, C | A transcript test and a shuffled-order determinism test | |
| **V6** Annotation as user facts, an input of Q | R, Q | An edit shows in every pane without reopening | |

### Gates

| Item | Exit | Status |
|------|------|--------|
| CI under ten minutes; baselines from CI | Every gate passes on a push with no laptop baseline | **Done** |
| Pinned containers; compiled coverage cells as pinned bytes; queued-run alert | A gate result does not depend on the runner | |
| `PipelineTests`/`SelfTestSuite` stall on hosted runners (`tests/equiv/bounded.sh 240 test_equiv.SelfTestSuite` on x86-64 Linux) | Both classes gate again | |
| arm64 equivalence under qemu-user (D6) | `tests/equiv` reports both architectures; judges the arm64 `cset` result width PE takes as `uint64_t` | |
| Census as a CI job, diffed against the base branch | A structural PR shows its census diff | |
| Dylints for D11 (entity-keyed maps, unbudgeted loops, caches outside Q) | Fatal in r2ssa after F2, in r2engine after Q | |

### Order

Single-engineer order:

1. **F2.0–F2.2**: containers, the function index, one liveness model.
2. **Q0–Q2**: the database, discovery and per-function queries, beside
   F2.3–F2.5.
3. **F2.3–F2.6**: facts and certificates as indexes, the builder, the
   projections, the Dylint made fatal.
4. **M, then P4**: the machine profile, then the frame model reading its
   stack pointer and return address.
5. **P5**: values as an index.
6. **R**: the printer.
7. **Q3–Q4 with P6, then I**: summaries by component, the resolved body,
   container facts.
8. **C2–C4**: answers as facts, r2types on `Basis`, references.
9. **P7, P8, P9, P11.**
10. **Surface**, interleaved where it depends on nothing structural: `j` on
    every verb, `eco`, visual-mode hints and palette. V4 and V5 after F2; S2,
    A and V6 after Q and R.

Rules for every item:

- it runs beside the path it replaces and deletes it when the gates agree;
- it deletes more than it adds, or says why not;
- a structural step leaves the census byte-identical, or names each line that
  moved and why;
- no new renderer-side policy lands while R is open;
- no visual-mode feature calls the engine synchronously;
- nothing violates D11.

### After the program

From the vision's tiers, in order, each only once its consumers exist:

- binary diffing over callee summaries;
- exception-handler recovery;
- the outside techniques of issue #65: the switch prover's own harness, SAILR
  idioms as r2rewrite rules one at a time, library identification measured
  before it is built, and Retypd revisited after P9;
- static rewriting;
- deobfuscation;
- trace recording and query.

Issues
------

Triaged against `fe7698e8` on 2026-10-03.

| Issue | State | Owner here |
|-------|-------|-----------|
| #49, #51, #52, #53, #54, #55, #59 | Fixed | closed 2026-10-04 |
| #57 | Obsolete (the plugin is deleted) | closed 2026-10-04 |
| #60 | Fixed on x86-64 | close after the arm64 equivalence run (D6) |
| #47 | The name-matched return carrier is gone; register families rename a lane as its root | F2.2 (byte liveness landed) |
| #50 | Liveness is one model in r2ssa, consumed by r2types (unobserved merges) and r2dec | F2.2, R |
| #56 | Merges pruned by byte-granular liveness; the fnv1a32 header merges only what the loop carries | close after review |
| #58 | Pointers and return widths fixed (PE); pointee types open | P9 |
| #63 | The `ub` records PE fixed are equal on CI | close after review |
| #61 | 85 of 98; tracker kept | P4 (canary), R (unaligned loads), P7 |
| #65 | Slice library and switch prover landed | After the program |

Standing debt
-------------

Carried with a cause, not as a baseline:

- r2types' confidence loops (`globals`, `arrays`, `structs`) rank by `u8`
  scores, and two stop after six rounds; C3 rewrites them.
- r2dec's loops (`placement`, `rules`, `recording`, `prepared_semantic`)
  belong to the renderer R replaces.
- A reload certified as the stored value binds as a copy of the stored
  temporary (three functions in the census); R3.
- Listing claims are made after the demand release, which is valid only for
  the function's meaning; a bound such as `rax in [0, 255]` would claim
  machine state. It is held off today because the release keeps
  `Insert(0, x, 0)`. Annotations are to read the index before the release
  (F2).
- The address-proven formal parameters change no test or census function;
  P7 proves what they are for or deletes them.
- Pointer parameters take the width every certified access reads, so `Rec *`
  renders as `uint32_t *` (P9).
- `pdd` on ARM 32-bit is not admitted until the Sleigh tuple is verified.
- Entry condition flags cannot be booleans until the architecture
  specification carries a flag fact.
- `doc/wip/*.patch` are written against the deleted plugin; each is re-derived
  on the current tree or deleted.

Documents
---------

| Document | Status |
|----------|--------|
| `doc/engine-vision.md` | Live: the why. Its sequencing defers to this file |
| `doc/adr-one-ir.md`, `adr-query-database.md`, `adr-frame-model.md`, `adr-renderer-printer.md` | Proposed: F2, Q, P4, R |
| `doc/adr-stable-identity.md`, `adr-fixpoint.md`, `adr-written-lanes.md`, `adr-provenance.md` | Live, landed or in progress: F1, K, PE, C |
| `doc/adr-access-syntax.md`, `adr-partition-first.md`, `adr-register-identity.md`, `adr-structure-dominator-tree.md`, `adr-floating-point.md` | Live |
| `doc/handoff/review-fixes/plan.md`, `plan-extension.md` | Per-phase specification for the analysis items; order and status here, and structure in the ADRs above |
| `doc/adr-location-ssa.md` | Superseded (D9) |
| `doc/adr-semantic-preservation-kernel.md` | Live in principle; to be rewritten against F2 and R |
| `doc/architecture-plan.md` | History of the binding-spine rewrite; superseded by R |
| `doc/phase1-plan.md`, `phase1-design.md`, `handoff-engine-inversion.md`, `handoff-location-ssa.md` | Plugin era; to archive |
| `doc/beat-angr-end-to-end.md`, `decbench-plan.md` | Kept for method, not for numbers |

Ownership
---------

| Crate | Owns |
|-------|------|
| `r2image` | What the container states: bytes, sections, symbols, relocations, entries, CFI, DWARF |
| `r2abi` | Calling conventions, library prototypes per C library, platform register classes |
| `r2il` | The low tier and its executable semantics (`r2il::eval`) |
| `r2sleigh-lift` | Decoding and lifting through Sleigh |
| `r2ssa` | The IR and its indexes: stable ids, SSA, values, the frame model, memory, liveness, certificates, refusal evidence; the fixpoint driver |
| `r2source` | Contracts between the layers, and `Confidence` |
| `r2types` | Type inference, layouts, signatures |
| `r2rewrite` | Term rewriting and its rule proofs, including every simplification the renderer spells |
| `r2dec` | The render plan, structuring and printing; no proof of its own after R |
| `r2engine` | The query database, requests, discovery, summaries, emulation |
| `r2s` | Commands, the verb table, the prompt, and the only implementor of `Program` |
| `r2s-tui` | The visual mode: layout, keys, drawing; no fact about the program |

One fact, one owner. When two places answer the same question, one of them is
deleted.
