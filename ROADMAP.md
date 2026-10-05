r2sleigh Roadmap
================

The one ordered list: what is done, what is left, in what order. Design lives
in the ADRs linked from each row; the why in [doc/engine-vision.md](doc/engine-vision.md);
the working rules in [AGENTS.md](AGENTS.md). Where this file and an ADR
disagree, this file wins and the disagreement is a defect.

`r2s` is the tool: one engine (discovery, lifting, SSA, memory, types, a
certifying decompiler) under radare2's command language, a visual mode, and an
agent surface. It prints C only where checked facts justify it; otherwise a
counted residual or a refusal that says why.

Gates
-----

In order of authority. A benchmark score is never proof; output is read by
hand before a quality claim.

| Gate | Question |
|------|----------|
| Equivalence (`tests/equiv`) | Does the C compute what the machine code computes? The north star. |
| Census (`pdd` of every coverage, pinned and stripped function) | Did any rendering move? A structural change is byte-identical or names each moved line. |
| Certification (`scripts/certify_render.py`) | Does every rendering read only what it assigns, and never panic? |
| Source-gold (`scripts/differential_truth.py`) | Are signatures what the source declared, or marked? |
| Coverage (`tests/coverage`) | How much of a binary renders; does any regress? |
| Differential (`scripts/diff_r2.py`) | Where discovery, naming, decoding disagree with radare2, and who is right. |
| Structure (`scripts/structure-report.sh`) | Did nesting, length, arguments or clones rise? |

Where this stands (2026-10-05, `engine/roadmap`, PR #67)
--------------------------------------------------------

| Measure | Value |
|---------|-------|
| Equivalence | x86-64 604/756 equal; aarch64 553/756 |
| Census | 665 functions, 8 refused |
| Certification | 113 rendered, 17 refused, 0 undefined reads, 0 panics |
| Coverage | 554/562 rendered |
| Tests | all pass except 2 that fail only under Apple clang 21 |

The 2026-10-04 review rated the code 4/10: sound ideas and discipline (~7),
weak algorithms and structure (~3) — hand-rolled iteration, recomputation,
entity-keyed side tables, eight caches, twelve owners of the frame, a renderer
that proves again. Hence **algorithms and structure before features**.

Decisions
---------

| | Decision | State |
|-|----------|-------|
| D1 | Restructure, not rewrite: replaced parts run beside the old path until the gates agree, then the old path is deleted in the same change | standing |
| D2 | Stable identity before more facts | done (F1) |
| D3 | Stages are types | done (F1) |
| D4 | Provenance on every fact, as `Fact<T>` | C0–C1 done |
| D5 | Gates are blessed in CI, never on a laptop | standing |
| D6 | Equivalence runs on arm64 too | standing |
| D7 | The visual mode never calls the engine while drawing | done (V1) |
| D8 | The observation journal is replaced by R, not kept | standing |
| D9 | Location SSA is superseded; its remainder was F2.2 | done |
| D10 | DecBench is measured again only where PyPI is reachable | standing |
| D11 | No new iteration off the fixpoint driver or a stated worklist; no silent cap; no entity-keyed map; no cache outside the query database. Dylints enforce each as its owner lands | standing |
| D12 | One IR, indexed once ([adr-one-ir](doc/adr-one-ir.md)) | F2 |
| D13 | One query database ([adr-query-database](doc/adr-query-database.md)) | Q |
| D14 | One frame model ([adr-frame-model](doc/adr-frame-model.md)) | P4 |
| D15 | One machine profile from the trusted Sleigh bundle; no architecture-name match below the lifter ([adr-machine-profile](doc/adr-machine-profile.md)) | M |

The program
-----------

### Foundation

| Item | ADR | Done | Left |
|------|-----|------|------|
| **F1** Stable ids, stage types | [stable-identity](doc/adr-stable-identity.md) | all | — |
| **K** One fixpoint driver | [fixpoint](doc/adr-fixpoint.md) | r2ssa | r2types' loops (with C3), r2dec's (with R) |
| **F2** One IR, indexed once | [one-ir](doc/adr-one-ir.md) | F2.0; F2.1 and F2.2 in part (dense dominators, loops, liveness once); F2.3; F2.6 (entity-keyed-map Dylint fatal in r2ssa and r2types, in CI) | F2.1 `FunctionIndex` on `Sealed`; F2.2 one byte-granular liveness model (#47, #50); F2.3's name-keyed readers deleted; F2.4 builder with incremental def-use (one graph build); F2.5 projections as indexes |
| **M** One machine profile | [machine-profile](doc/adr-machine-profile.md) | M0 cspec parsed by the lifter; M1a slots, M1b call effect, M1c name/red zone/variadic tail from the profile and cited ABI rows | M0 rest (`.ldefs` selection, `.sla` lanes, `.pspec` tracked values, `.dwarf` numbers); M1d float slots as lanes of the program root, then delete r2abi `Conventions`; M2–M5 delete the name tables in r2ssa, r2types, r2dec, r2image/r2engine; M6 RISC-V end to end |
| **Q** One query database | [query-database](doc/adr-query-database.md) | Q0 the database (red-green, a random-write session equals a fresh open); Q1 in part (names, import stubs) | Q2 decode/walk/lift/seal per function; Q3 discovery survey, entry modes, summaries; Q4 references and renderings; the caches and `Revision` deleted |
| **P4** One frame model | [frame-model](doc/adr-frame-model.md) | — | one partition, one escape analysis, promotion as an SSA rewrite, canary under its premise; `afv` agrees with `pdd` |
| **R** Renderer as a printer | [renderer-printer](doc/adr-renderer-printer.md) | — | r2dec reads only sealed facts; journal, binding-plan fixpoint and retries deleted |

### Analysis

| Item | Done | Left (exit) |
|------|------|-------------|
| **PE** Written-lane result widths ([written-lanes](doc/adr-written-lanes.md)) | result widths | demand pass as an F2 index |
| **P1.7** Entry lanes are the caller's | done | — |
| **C** Provenance ([provenance](doc/adr-provenance.md)) | C0–C1 | C2 every answer field a `Fact`; C3 r2types on `Basis`; C4 references carry `Confidence` |
| **P5** Values as an index | — | XMM lane noise gone; immutable loads fold |
| **P6** One resolved body per function, as a query | — | `read_callees` deleted; switch arms in the walked body |
| **I** Unread container facts (CFI, LSDA, IBT, RELRO, init arrays) | — | stripped discovery finds every FDE start |
| **P7** Call contracts | Darwin arm64 variadic tail (M1c) | no dropped or invented argument; printf's stack tail on x86-64 |
| **P8** Data objects and strings | — | `iz` lists proven strings |
| **P9** Types over the graph | — | a struct pointer is not `uint32_t*` |
| **P11** Names and commands | — | every differential disagreement judged |

### Surface

| Item | Done | Left |
|------|------|------|
| **V1** Visual-mode core | done | its worker asks Q once Q lands |
| **S1** Verb table, `?`, `e` | done | `j` on every verb |
| **V2** Colour from the engine | done | `eco` themes |
| **V3** Completion | shell | visual-mode hints, palette, `?` |
| **V4** Panels, linked cursors | — | a C line lights its instructions in every pane |
| **V5** Graphs through one renderer | — | `agf`/`agc`/`agx` share it, layout off the UI thread |
| **S2** `@@`, search, pipes | — | `diff_r2.py` covers the `j` forms |
| **E** Emulation, then verify | — | aarch64 originals checked against host-compiled renderings |
| **A** Agent surface | — | transcript and shuffled-order determinism tests |
| **V6** Annotation as user facts | — | an edit shows in every pane without reopening |

### Gate work

| Item | Left |
|------|------|
| Pinned containers; compiled coverage cells as pinned bytes | gate results independent of the runner |
| `PipelineTests`/`SelfTestSuite` stall on hosted runners | both gate again |
| arm64 equivalence in CI (D6) | `tests/equiv` reports both architectures |
| Census as a CI job | a structural PR shows its census diff |
| D11 Dylints: unbudgeted loops, caches outside Q | fatal in r2engine after Q |

Order
-----

1. **M** (M1d–M6), beside **F2.1–F2.5** and **Q1–Q2**.
2. **P4**, then **P5**, then **R**.
3. **Q3–Q4** with **P6**, then **I**.
4. **C2–C4**, then **P7, P8, P9, P11**.
5. **Surface**, interleaved where nothing structural blocks it.

Every item runs beside what it replaces and deletes it when the gates agree;
deletes more than it adds or says why; leaves the census byte-identical or
names each moved line; adds no renderer policy while R is open; and violates
nothing in D11.

After the program, each only once its consumers exist: binary diffing over
callee summaries, exception-handler recovery, the techniques of #65 (switch
prover harness, SAILR idioms as r2rewrite rules, library identification,
Retypd after P9), static rewriting, deobfuscation, trace recording.

Issues
------

| Issue | State | Owner |
|-------|-------|-------|
| #60 | fixed on x86-64 | close after arm64 equivalence |
| #47, #50 | one liveness model in r2ssa; consumers remain | F2, R |
| #56, #63 | fixed | close after review |
| #58 | widths fixed; pointee types open | P9 |
| #61 | 85 of 98 traps | P4 (canary), R, P7 |
| #65 | slice library and switch prover landed | after the program |

Standing debt
-------------

- r2types' confidence loops rank by `u8` scores and two stop after six rounds (C3).
- r2dec's loops (`placement`, `rules`, `recording`, `prepared_semantic`) go with R.
- A reload certified as the stored value binds as a copy of the stored temporary (three census functions; R3).
- Listing claims follow the demand release, valid only for the function's meaning; annotations must read the index before it (F2).
- Address-proven formals change no test or census function: P7 proves their use or deletes them.
- Pointer parameters take the width every access reads, so `Rec *` renders as `uint32_t *` (P9).
- `pdd` on 32-bit ARM is not admitted until its Sleigh tuple is verified.
- Entry condition flags cannot be booleans until the specification carries a flag fact.
- Float convention slots still come from r2abi's sdb (M1d).
