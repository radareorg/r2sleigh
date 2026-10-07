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

Where this stands (2026-10-07, `p4-frame`, PR #69)
--------------------------------------------------

| Measure | Value |
|---------|-------|
| Equivalence | x86-64 629/756 equal; aarch64 600/756 (CI run 37652116576) |
| Census | byte-identical between P4's exit and `h-hostile` |
| Certification | 0 undefined reads, 0 panics |
| Coverage | the baseline blessed at P4's exit (`tests/coverage/coverage-baseline.json`) |
| Tests | all pass on CI (PR #69) |
| Cost | `pdd` grows as instructions^1.39; sort 0x3f50 `pdd` 11.8 s, pumasim `afl` 29.1 s, 30.9 M allocations per `pdd` |

The 2026-10-04 review rated the code 4/10: sound ideas and discipline (~7),
weak algorithms and structure (~3) — hand-rolled iteration, recomputation,
entity-keyed side tables, eight caches, twelve owners of the frame, a renderer
that proves again. Hence **algorithms and structure before features**.

The 2026-10-07 cost model ([next-pass](doc/adr-next-pass.md)) states the bound
each stage must meet, measures today's engine against it by file and line, and
adds the four items that reach it: PF, SM, LX and T.

Decisions
---------

| | Decision | State |
|-|----------|-------|
| D1 | Restructure, not rewrite: one roadmap item per branch replaces its owner outright and deletes the old path in the same branch; the gates run once at the item's exit, and the census diff is read there (was: run beside until the gates agree, 2026-10-06) | standing |
| D2 | Stable identity before more facts | done (F1) |
| D3 | Stages are types | done (F1) |
| D4 | Provenance on every fact, as `Fact<T>` | C0–C1 done |
| D5 | Gates are blessed in CI, never on a laptop | standing |
| D6 | Equivalence runs on arm64 too | standing |
| D7 | The visual mode never calls the engine while drawing | done (V1) |
| D8 | The observation journal is replaced by D, not kept | standing |
| D9 | Location SSA is superseded; its remainder was F2.2 | done |
| D10 | DecBench is measured again only where PyPI is reachable | standing |
| D11 | No new iteration off the fixpoint driver or a stated worklist; no silent cap; no entity-keyed map; no cache outside the query database. Dylints enforce each as its owner lands | standing |
| D12 | One IR, indexed once ([adr-one-ir](doc/adr-one-ir.md)) | F2 |
| D13 | One query database ([adr-query-database](doc/adr-query-database.md)) | Q |
| D14 | One frame model ([adr-frame-model](doc/adr-frame-model.md)) | P4 |
| D15 | One machine profile from the trusted Sleigh bundle; no architecture-name match below the lifter ([adr-machine-profile](doc/adr-machine-profile.md)) | M |
| D16 | One byte relation: every pass that asks which bytes an operation reads or writes reads one relation, and a boundary slot is a lane of a root ([adr-byte-relation](doc/adr-byte-relation.md)) | B |
| D17 | No new crates: a layer boundary inside a crate is a module boundary enforced by a Dylint; the IR depends on neither the lifter nor type inference | L |
| D18 | Untrusted input is bounded: a read stops at the bytes the file holds, and every pass states its cost; a fuzzed or hostile binary meets the same time and memory budget as any other (2026-10-07, [sweep](doc/reviews/2026-10-performance-and-memory.md)) | H |
| D19 | Performance is a gate: release time, peak RSS and allocation count are budgeted on named workloads in CI, beside the census | PF |
| D20 | The decompiler is rewritten, not refactored: r2dec is replaced as a whole from the sealed facts, built beside the old path until the gates agree, then the old path is deleted in the same item (amends D1 for D only; [decompiler-rewrite](doc/adr-decompiler-rewrite.md)) | D |
| D21 | The source language is a profile: the container states each function's language (Go buildinfo and pclntab, rustc markers, DWARF language, mangling); its profile states conventions, premises, compiler-inserted checks, runtime models, names and the printer. The IR, facts and proof name no language, and C is the default profile, not an assumption ([language-profile](doc/adr-language-profile.md)) | LP |
| D22 | Every pass is an index with a stated bound: a per-function pass costs `O((V + E) · h)` or says at its definition why not; the storage version at a point is an index, never a walk; a dataflow state is sparse; a fact computed twice has one owner; a silent cap is a stated budget with typed refusal (2026-10-07, [next-pass](doc/adr-next-pass.md)) | LX |
| D23 | Summaries compose over the call graph: a body is prepared once per session at summary grade and held; a root reads held summaries, and its demand beyond its direct callees reads only what is already held, so no `pdd` pays a transitive closure; components are solved on the fixpoint driver ([next-pass](doc/adr-next-pass.md)) | SM |
| D24 | The lift is a query per address over a compact IL: `Lifted(address, mode)` held under a byte budget, the Sleigh context persisting across decodes, a varnode `(space, offset, size)` whose metadata is the machine profile's ([next-pass](doc/adr-next-pass.md)) | PF |
| D25 | Types are one monotone system: union-find with one lattice meet per class over dense ids, incremental, with no restart and no round cap; the confidence-scored second system is deleted and what it found that the lattice cannot state is a residual ([next-pass](doc/adr-next-pass.md)) | T |
| D26 | Allocation is budgeted: one arena per function, indexes sized at the seal, a global allocator chosen by measurement, and the allocation count gated with time and peak RSS (D19) ([next-pass](doc/adr-next-pass.md)) | PF |

The Sleigh crates (`libsla`, `libsla-sys`, `sleigh-config`) are vendored (`vendor/`), so M0's rest reads `.ldefs` and `.dwarf` by changing `vendor/sleigh-config/build.rs`.

The program
-----------

### Foundation

| Item | ADR | Done | Left |
|------|-----|------|------|
| **G0** Gates real | [testing](doc/testing.md) | the census and release timing (budget 1.3x on the large functions) and the x86-64 equivalence ratchet are CI jobs; the aarch64 equivalence ratchet is a CI job (cross gcc 13, clang 18, qemu-user, the blessed toolchain); the clang-21 failures are fixed | — |
| **B** One byte relation | [byte-relation](doc/adr-byte-relation.md) | B0 one transfer, checked against the evaluator; B1 one closure; B3 call results, returns and reaching values match the program root; argument lanes, entry-lane projections and certificates match by lane, and a declared float slot narrows to its value's low lane; float merges and root writes answer the lane | B3 rest: a recovered interface's float slots (with P7); B4 measured, no instance yet (see the ADR); liveness over locations (B2, r2dec's dead values, moved into D2: the inventory must own liveness first) |
| **L** Layering | — | L2 C typing at render boundaries (`typed`) moved from r2rewrite to r2dec, so r2rewrite no longer depends on r2types; L4 r2sleigh-export merged into r2sleigh-cli (13 crates); L1 the body walk moved to r2engine and `block::to_ssa` takes a spelling, so r2ssa reads the lifter only for the trusted-lift authority types; L3a only a stated import takes its library model by name; L3b the library models are the engine's (`r2engine::library`), handed to preparation as `CalleeEvidence` beside the callees' interfaces, preserved registers and reach |   L5 r2ssa's IR and facts layers as modules with a Dylint boundary |
| **F1** Stable ids, stage types | [stable-identity](doc/adr-stable-identity.md) | all | — |
| **K** One fixpoint driver | [fixpoint](doc/adr-fixpoint.md) | r2ssa | r2types' loops (with T); r2dec's are deleted by D; r2ssa's five silent caps (`promote.rs:144`, `predicates.rs:374`, `expressions.rs:548`, `optimize.rs:974`, `forward.rs:198`) become stated budgets in LX |
| **F2** One IR, indexed once | [one-ir](doc/adr-one-ir.md) | F2.0; F2.1 and F2.2 in part (dense dominators, loops, liveness once; interface recovery reads its provisional graph once); F2.3; F2.6 (entity-keyed-map Dylint fatal in r2ssa and r2types, in CI) | F2.1 `FunctionIndex` on `Sealed`; F2.2 one byte-granular liveness model (#47, #50); F2.3's name-keyed readers deleted; F2.4 builder with incremental def-use (one graph build); F2.5 projections as indexes. All land in LX, which this ADR owns |
| **M** One machine profile | [machine-profile](doc/adr-machine-profile.md) | M0 cspec parsed, languages chosen through `.ldefs`, `.pspec` tracked values, `.dwarf` numbers; M1 slots, call effect, convention rows; M2 r2ssa reads roles and slots only (call reads in the call effect, `AbiProfile` source-only, family enum replaced by the lift's identity, DF role gone); M3 r2types tables gone (stack roots, stated argument registers, no convention guess); M4 r2dec config is a pointer width; M5 DWARF numbers from the language, frame pointer a cited row; M6a RV64 embedded and admitted, `jalr` stubs named, `shapes_zig_riscv64_O0` in the census | M6 rest: RISC-V 64 opens, decodes, names imports and renders 29 of `shapes`' 39 functions with no arm added; the 10 refusals are frame-base homes (P4), and RISC-V has no equivalence target yet |
| **Q** One query database | [query-database](doc/adr-query-database.md) | Q0 the database (red-green, a random-write session equals a fresh open); Q1 in part (names, import stubs); Q3 returns, survey and modes as queries over one `View`, with held lookups and deposits; Q2 the analysis, callee reads and sealing as queries, stops typed and never held, the memo deleted; Q3e pointer parameters as a query; Q4a the reference index as a query; Q4b renderings as a query, capacity keeps dependencies; Q4c machines load lazily, `ensure_current` deleted; Q4d `Revision` deleted; Q4e the cache Dylint fatal in r2engine ; the exit test over the real program holds | Q2 rest: decode and lift per address as queries; Q3 rest: summaries with P6 |
| **P4** One frame model | [frame-model](doc/adr-frame-model.md) | one partition, one escape analysis, promotion as an SSA rewrite, the canary under its premise, a merged extent for the objects an escaped address reaches, an unproven arity refusing its call; `afv` agrees with `pdd`; the exit bar run and blessed (PR #69) | — |
| **H** Hostile input | [performance-and-memory](doc/reviews/2026-10-performance-and-memory.md) | `r2image` clamps every section and segment file range to the bytes the file holds (`fuzzed/elf9` `q` 1.1 s, was a hang); `name_strings` scans only file-backed bytes (`fuzzed/file12` `pd 5` 43 MB, was 1.2 GB); `collect_memory_round_trips` indexed by block, ordinal and value; `accesses_at(inst)` a range query; `return_effects` through its index; `BTreeMap::append` replaced by `extend` in placement (`pe/65535sects.exe` `pdd` 25 s, was over 580 s); `scripts/hostile_sweep.py` with a time and memory budget per file; 886 of 887 fuzzed and PE files within 30 s and 512 MB on `afl` and `pdd` (branch `h-hostile`) | the `hostile-gate` CI job; `65535sects.exe` under 2 GB peak (PF2); every read of a size from a header clamped where it is parsed. Exit: every radare2 fuzzed and PE test binary opens and runs `afl` and `pdd` within the budget, as a CI job |
| **PF** Performance foundation | [next-pass](doc/adr-next-pass.md), [performance-and-memory](doc/reviews/2026-10-performance-and-memory.md) | — | PF0 the Sleigh context persists and only the disassembly cache is cleared (70,543 rebuilds, 36% of pumasim `afl`); the specification loads once per process (0.17 s of a 0.47 s `pdd`). PF1 `Lifted(address, mode)` as a query the walk reads (each instruction lifted twice today, `body.rs:462` and `native.rs:1723`), over a compact IL (`Varnode` 112 B and `R2ILOp` 464 B today) whose varnode metadata is the machine profile's. PF2 jemalloc or mimalloc by measurement (15 to 36% faster measured), one arena per function, indexes sized at the seal (30.9 M allocations and 6.5 GB churned for a 218 MB peak). PF3 query capacities in bytes (a second libz sweep re-prepares 368 bodies); `r2ssa::name::intern` into the database (D11). PF4 the CI timing job gates time, peak RSS and allocation count. Exit: D19's budgets in CI on sort 0x3f50, ls `main`, libz O1 `inflate`, pumasim `afl` and its Gui constructor; pumasim `afl` under 12 s |
| **SM** Summaries | [next-pass](doc/adr-next-pass.md) D23 | `CalleeReads` held per `(address, thumb)`; `ComesBack` as the bounded lazy fixpoint; `Demand` over result owners | the summary grade of preparation (interface, preserved carriers, reach, result, memory effects, signature) as a subset of the passes, measured against the full one; `Summary(f)` the one held value a root reads; components of the call graph solved on the driver; demand beyond direct callees reads only what is held; the summary-grade r2types run (17% of 0pack `pdd` inside callee reads). Exit: a sweep prepares each body once; callee reads under 10% of sort 0x3f50 `pdd` (35 to 42% today); Q3's rest and P6's remainder closed |
| **LX** Linear per function | [next-pass](doc/adr-next-pass.md) D22, [one-ir](doc/adr-one-ir.md) | — | the storage index `version_at(point, location)` replacing the reaching walks (`semantic/shared.rs:990`, `O(C · carriers · B²)`); sparse states in `call_results` (`O(B · V)` today), `liveout`, `liveness` and `promote` at their bound; `DeadPhis`, formals, `FunctionLiveOut`, `class_values` and `ValueViews` computed once; the collector once when there is no interface; the five silent caps as budgets with typed refusal; F2.1, F2.2, F2.4, F2.5 and K's rest. Exit: `pdd` time grows no faster than instructions^1.05 over the 300+ instruction functions, measured by the CI timing job; peak RSS linear in instructions; pumasim Gui constructor under 250 MB with D |
| **T** Types as one monotone system | [next-pass](doc/adr-next-pass.md) D25, [types](doc/types.md) | the union-find solver with one meet per class (`solver.rs`) | the solver incremental, so pointer bases found through accesses join it with no restart (`evidence.rs:93`, at most `2A + 1` rounds cloning the arena today); one solve per function (three today) and one signedness pass (six today); `named_blocks()` copies and the name-keyed def maps deleted; the confidence-scored `structs`, `arrays` and `globals` system deleted (uncapped and 6-round loops, `u8` scores), its findings residuals where the lattice cannot state them; `FunctionTypeFacts` and `FunctionRenderFacts` as indexes over dense ids (about 20 `BTreeMap`s reachable today); C3's r2types part. Exit: one solve per function, no loop off the driver, a struct pointer rendered as its struct (P9's first exit) or refused with the reason |
| **LP** Language profiles | [language-profile](doc/adr-language-profile.md) | — | LP0 each function's language from the container; LP1 conventions per function (Go ABIInternal on x86-64 and arm64, Rust scalar pairs), boundaries with several results and two-register values; LP2 premises and compiler-inserted checks per profile (C's canary, Go's `morestack`, Rust's bounds and overflow checks), the frame ADR restated against the profile's premise; LP3 runtime models (Go runtime, Rust `core`/`alloc`, C++ ABI) and demangling (Rust legacy and v0, Itanium, Go); LP4 equivalence corpora in Rust, Go and C++ on x86-64 and aarch64. Exit: a Go or Rust function renders under its own convention or refuses with that reason, never under the C one |
| **D** Decompiler rewrite | [decompiler-rewrite](doc/adr-decompiler-rewrite.md) | R1 (proved simplifiers) carries over as D3's rule set; SD's structurer and certificate as D1 | D0 render input contract, with the language profile; D1 control; D2 values; D3 terms over a language-neutral render tree (tuples, several results, two-register values); D4 declarations; D5 the C printer and the proof walk; switch at equivalence, census, certification and timing agreement. Exit: `observation_journal`, `binding_plan`, `placement`, `normalize`, `fold`, `analysis/prepared_semantic`, `effect_ledger` and the retries deleted; r2dec under 20k lines; `uncompress2` and `deflateInit2_` render right or refuse |
| **W** Real-binary sweep gate | [real-binary-sweep](doc/reviews/2026-10-real-binary-sweep.md) | jump-table negative cases, PLT stubs by their own transfer, guarded zero-extension bounds (this branch) | coreutils (ls, sort, cp, date, stat) and zlib with DWARF as a CI gate against radare2, objdump and DWARF. Exit: afl finds every function radare2 does (76 missing), survey follows dispatch tables so afl/afb/axt agree with afi/pdf (with P6), the remaining jump-table shapes resolve or refuse, `__assert_fail` and `__stack_chk_fail` are noreturn, preemptible PLT stubs are named, `main` is named in stripped binaries, one function has one spelling, and every disagreement is judged |

### Analysis

| Item | Done | Left (exit) |
|------|------|-------------|
| **PE** Written-lane result widths ([written-lanes](doc/adr-written-lanes.md)) | result widths | the rest is B (one relation, `cover(demanded)`, the eval/Kani check) |
| **P1.7** Entry lanes are the caller's | done | — |
| **C** Provenance ([provenance](doc/adr-provenance.md)) | C0; C1 types and the format parameter | C1 r2dec reads the grade (`from_source_signature` deleted); C2 every answer field a `Fact`; C3 r2types on `Basis` (with T); C4 references carry `Confidence` |
| **P5** Values as an index | — | XMM lane noise gone; immutable loads fold |
| **P6** One resolved body per function, as a query | [resolved-bodies](doc/adr-resolved-bodies.md); P6a the walk through dispatch tables is the `Walked` query; P6c1 a callee resolved as a root is; P6c2 return-only demand (`Resolved`, `Demand`, `result_owners`); `read_callees` kept as the one loop a root reads callees through (the database answers it with `Resolved`, a plain `Program` with each callee resolved alone) | — (parameters stay what each body proves alone: transitive resolution measured at 21 s for pumasim `main`, declined) |
| **I** Unread container facts (CFI, LSDA, IBT, RELRO, init arrays) | — | stripped discovery finds every FDE start |
| **P7** Call contracts | Darwin arm64 variadic tail (M1c); declared `double` arguments reach their calls (B3) | no dropped or invented argument; printf's stack tail on x86-64; a recovered interface's float parameters and float result (a body's float work feeds only the float result, so recovery never observes it; the variadic save area's spills read as parameters in both classes, and the convention's `al` read at entry states the tail) |
| **P8** Data objects and strings | — | `iz` lists proven strings |
| **P9** Types over the graph | — | a struct pointer is not `uint32_t*` (its first exit is T's; recursive and polymorphic types after T) |
| **P11** Names and commands | — | every differential disagreement judged |
| **SD** Structuring quality ([structure-dominator-tree](doc/adr-structure-dominator-tree.md)) | dominator-tree structurer | no more labels than the old structurer; condition chains and irreducible-entry splitting behind a BDD identity check; lexical ancestry as dominance retires `region_does_not_dominate_occurrence` |

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
| arm64 equivalence in CI (D6) | done with G0 |
| Rust, Go and C++ equivalence (LP4) | each language graded on its own corpus on both architectures |
| macOS arm64 equivalence | Mach-O renderings run beside their originals |
| Stage merges of PR #67 to master | finished items land on master |
| "Where this stands" generated from CI artifacts | no hand-typed status |
| Ratchet on file length (largest today 5.2k lines) | no file grows past the cap |
| D11 Dylints: unbudgeted loops | fatal in r2engine (caches outside Q: fatal since Q4e) |
| Hygiene: `long_comments` ratchet (3833), dead code | comments one or two lines; no unreferenced items; the structure ratchets are suspended inside an item and blessed at its exit (AGENTS.md, Validation Bar) |

Order
-----

Done out of order: Q (step 6) landed before G0, B, P4 and R. From 2026-10-06
the order is the dependency path, and nothing jumps it.

Amended 2026-10-07 after the real-binary sweep and the performance review: R
is replaced by D, and H, PF and W enter the path before it. Amended again the
same day by the cost model ([next-pass](doc/adr-next-pass.md)): PF is
restated, and SM, LX and T enter. An item runs beside D when it owns a crate
D does not touch; each is its own branch.

0. **G0**, **B**, **R1**, **P4**: done.
1. **H**: hostile input bounded (in progress on `h-hostile`). Small, and
   first, because a hang or a 2 GB read on a fuzzed binary is a defect in
   every command.
2. **PF**: the performance foundation (PF0 to PF4), so D is measured against
   a fast baseline and not against Sleigh re-initialisation, a double lift
   and allocator churn.
3. **P5**: values as an index, which D2 reads.
4. **LP0–LP1**: each function's language and its convention, before D,
   since D0's contract carries the profile and D2 places several results.
5. **D**: the decompiler rewrite (D0 to D5, then the switch): the critical
   path, on r2dec alone. No renderer policy lands on the old r2dec while it
   is open.
6. Beside D, each on its own branch and crate: **SM** (r2engine and the
   summary grade in r2ssa), **LX** (r2ssa), **W** (r2engine, r2ssa, r2abi)
   and **LP2–LP4** (r2abi, r2image, r2engine). SM lands before LX because
   LX's exponent is measured on `pdd`s whose callee cost SM removes.
7. **T**: types as one monotone system, after D, since D4 reads
   `FunctionTypeFacts` and T changes its shape.
8. **I**, then **C2, C4**, **P7, P8, P9, P11**.
9. Beside the path, as small items when a step waits on CI: **L5**, **M6**
   rest.
10. **Surface** on its own branch: S2, A and V3 now; V4, V5 and the rest after D.

Every item replaces what it owns and deletes the old path in its own branch
(D1, amended by D20 for D); at its exit it deletes more than it adds or says
why, names each moved census line, adds no renderer policy while D is open,
meets D19's budgets, and violates nothing in D11.

Upstream radare2 (differential target, [radare2-function-walk](doc/adr-radare2-function-walk.md)):
`ret` given one definition, one read-ahead cache per walk, predecessor in the
frame, edge-labelled path state, the callee-recursion cap derived. Each its own
pull request, measured alone.

After the program, each only once its consumers exist: binary diffing over
callee summaries, exception-handler recovery, the techniques of #65 (switch
prover harness, SAILR idioms as r2rewrite rules, library identification,
Retypd after P9), static rewriting, deobfuscation, trace recording.

Issues
------

| Issue | State | Owner |
|-------|-------|-------|
| #47, #50 | one liveness model in r2ssa; consumers remain | F2, D |
| 2026-10 sweep | [real-binary-sweep](doc/reviews/2026-10-real-binary-sweep.md), [performance-and-memory](doc/reviews/2026-10-performance-and-memory.md) | H, PF, W, D |
| #63 | fixed on CI | close after review |
| #58 | widths fixed; pointee types open | P9 |
| #61 | 85 of 98 traps | P4 (canary), D, P7 |
| #65 | slice library and switch prover landed | after the program |

Standing debt
-------------

- r2types' confidence loops rank by `u8` scores and two stop after six rounds; r2types solves three times and runs signedness six times per function (T).
- r2dec's loops (`placement`, `rules`, `recording`, `prepared_semantic`) are deleted by D.
- r2ssa walks back from each call site for each carrier (`semantic/shared.rs:990`) and copies a dense state per block in `call_results`; five caps keep a partial result silently (LX).
- Each instruction is lifted at least twice per analysis, and the Sleigh context is rebuilt at every non-contiguous decode (PF).
- A reload certified as the stored value binds as a copy of the stored temporary (three census functions; D2).
- Listing claims follow the demand release, valid only for the function's meaning; annotations must read the index before it (F2).
- Address-proven formals change no test or census function: P7 proves their use or deletes them.
- Pointer parameters take the width every access reads, so `Rec *` renders as `uint32_t *` (P9).
- `pdd` on 32-bit ARM is not admitted until its Sleigh tuple is verified.
- Entry condition flags cannot be booleans until the specification carries a flag fact.
- `StackObjectRefusal::ParameterHomeWidthMismatch` survives S2; shown genuine or deleted.
- r2dec's `NormalizedOpSite` rows are positions in an edited copy; deleted by D.
- `def_use_graph` seals a raw function to answer a listing (F2.1, in LX).
- `seal_body_proven_interface` rewrites the format parameter after the build (C1).
- x87 80-bit floats refuse ([floating-point](doc/adr-floating-point.md)).
- Partition-first's conservatism (read closure, `CallRestore`, return carrier, call-use reads) and the semantic-kernel ADR's rewrite against F2 and D fold into D's ADR.
