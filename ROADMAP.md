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

Where this stands (2026-10-11: `rebuild` merged to master at the D switch, #142)
--------------------------------------------------------------------------------

| Measure | Value |
|---------|-------|
| Pipeline | `pdd` renders through the staged decompiler only (#122); the legacy decompiler is deleted (#123); r2dec 17.5k lines against the 20k exit |
| Equivalence | x86-64 659/756 equal (legacy 635), aarch64 631/756 (legacy 606); no differs, ub, uninit or compile error on either; both baselines blessed at #122 with a cause per moved record |
| Losses at the switch | 8 records equal to residual-trap, each with its owner: `shape_call_chain` aarch64 gcc-O1/O2 (fixed in #126), `combined` aarch64 clang-O1/O2 (fixed in #127), `shape_byte_indexed_buffer` x86 clang-O2 and aarch64 clang-O2/gcc-O1 (a load through `p = a & 1 ? buf : &total`, a select of two frame addresses no offset places, so slot promotion refuses the whole frame: P4; the byte loop's counter is unbounded too, since the value ranges do not read a counted loop's trips, but bounding it moved no census line, so it waits for a consumer), `shape_function_pointer` x86 clang-O0 (an unproven table-call arity, refused by decision) |
| Coverage | rendered 561 of 562 (was 549); gated gaps rise in Mach-O `_main`, `_start`, `shape_function_pointer`, `vfold`, `shape_signed_divmod`, each named in the bless |
| Tests | r2ssa, r2types, r2dec, r2engine, r2s 1550 passed at #127 |
| Cost (release `pdd`, Mac, median of 3) | 0pack `0x58e3d0` 1.96 s and 474 MB (legacy 2.73 s, 560 MB); pumasim `0x23fdf0` 2.83 s (legacy 3.54 s) |
| Structure | at baseline after the deletion (long_comments 2646, too_many_lines 274) |
| LX exit, measured 2026-10-11 at #127 (`scripts/census.py exponent`) | marginal `pdd` cost (instructions retired by `afl; pdd @ f` less `afl`, contabo) grows as instructions^0.80 (R^2 0.44) over 80 functions of 300+ instructions sampled from 0pack and pumasim: met. Peak RSS above the open grows as instructions^1.17 (R^2 0.36): not met; the pumasim Gui constructor peaks at 452 MB against 250 (396 MB after LX1d to LX1j, of which 133 MB is the open and Sleigh) |
| SM exit, measured 2026-10-11 | callee reads are 52.8% of sort 0x3f50 `pdd` against 10%, and 85.8% of pumasim 0x1dc0a0 (300 instructions, 18.6 G instructions, 219 MB above the open): the low R^2 above is callee preparation, not body size |
| Exit left | The maintainer merged `rebuild` to master at the D switch (#142, 2026-10-11), with LX's RSS and SM's callee share not met: both are master's work now, and neither falls far by trimming passes. Measured 2026-10-11 (samply, sort `0x3f50` `pdd`): callee reads 47.3%, interface recovery's provisional fact pass 17.4% (its obligation inventory is read by `ProvenProgramObservations`, so a recovery-only subset saves about 4%), the seal's fact pass about 22% over a graph the seal rebuilds, the walk's preparation to read dispatch tables about 10%. The Gui constructor's 432 MB holds 133 MB fixed and about 50 MB of mimalloc's retained pages; its heap peak is one function in several representations (F2). LX's 250 MB for the Gui constructor, in numbers (2026-10-11, 396 MB today): 133 MB is the open and Sleigh and about 57 MB is mimalloc's retained pages at its default purge delay, which leaves 60 MB for the function's own peak against about 206 today; with the purge delay at 25 ms (13% more wall time), 117 MB. The exit as written needs the allocator set and F2's single representation, or the fixed and allocator shares excluded. |

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
| D20 | The decompiler is rewritten, not refactored: r2dec is replaced as a whole from the sealed facts, built beside the old path until the gates agree, then the old path is deleted in the same item (amends D1 for D only; [decompiler-rewrite](doc/adr-decompiler-rewrite.md)); amended by D27: the old path is deleted once D1 to D5 render, on the `rebuild` branch | D |
| D21 | The source language is a profile: the container states each function's language (Go buildinfo and pclntab, rustc markers, DWARF language, mangling); its profile states conventions, premises, compiler-inserted checks, runtime models, names and the printer. The IR, facts and proof name no language, and C is the default profile, not an assumption ([language-profile](doc/adr-language-profile.md)) | LP |
| D22 | Every pass is an index with a stated bound: a per-function pass costs `O((V + E) · h)` or says at its definition why not; the storage version at a point is an index over what renaming and K1's memory SSA compute (D9 stands), never a walk; a dataflow state is sparse; a fact computed twice has one owner; a silent cap is a stated budget with typed refusal (2026-10-07, [next-pass](doc/adr-next-pass.md)) | LX |
| D23 | Summaries compose over the call graph: a body is prepared once per session at summary grade and held; a root reads held summaries, and its demand beyond its direct callees reads only what is already held, so no `pdd` pays a transitive closure; components are solved on the fixpoint driver ([next-pass](doc/adr-next-pass.md)) | SM |
| D24 | The lift is a query per address over a compact IL: `Lifted(address, mode)` held under a byte budget, the Sleigh context persisting across decodes, a varnode `(space, offset, size)` whose metadata is the machine profile's ([next-pass](doc/adr-next-pass.md)) | PF, LF |
| D25 | Types are one monotone system: union-find with one lattice meet per class over dense ids, incremental, with no restart and no round cap; the confidence-scored second system is deleted and what it found that the lattice cannot state is a residual ([next-pass](doc/adr-next-pass.md)) | T |
| D27 | Contract first, then the layers behind it (2026-10-08): D0's `RenderInput` is the dense input F2 and T must provide, served first by an adapter over today's `SourceOwnedFunctionFacts`; D1 to D5 are written against it and the old r2dec is deleted; LX and T then replace the adapter's backing with no change to D. Old r2dec reads every fact shape r2ssa and r2types produce, so changing those first pays adapters on code D deletes, and writing D against today's shapes pays D twice. The work runs on one integration branch, `rebuild`, where equivalence, certification and the census report instead of block; every commit there still builds and passes the workspace tests, the Dylints and the proofs, so equivalence stays measurable and a regression bisects; master keeps every gate. `rebuild` merges at D's switch criterion with LX's and SM's exits met | done: `rebuild` merged to master at the switch (#142, 2026-10-11) |
| D26 | Allocation is budgeted: one arena per function, indexes sized at the seal, a global allocator chosen by measurement, and the allocation count gated with time and peak RSS (D19) ([next-pass](doc/adr-next-pass.md)) | PF |

The Sleigh crates (`libsla`, `libsla-sys`, `sleigh-config`) are vendored (`vendor/`), so M0's rest reads `.ldefs` and `.dwarf` by changing `vendor/sleigh-config/build.rs`.

The program
-----------

### Foundation

| Item | ADR | Done | Left |
|------|-----|------|------|
| **G0** Gates real | [testing](doc/testing.md) | the census and release timing (budget 1.3x on the large functions) and the x86-64 equivalence ratchet are CI jobs; the aarch64 equivalence ratchet is a CI job (cross gcc 13, clang 18, qemu-user, the blessed toolchain); the clang-21 failures are fixed | — |
| **B** One byte relation | [byte-relation](doc/adr-byte-relation.md) | B0 one transfer, checked against the evaluator; B1 one closure; B3 call results, returns and reaching values match the program root; argument lanes, entry-lane projections and certificates match by lane, and a declared float slot narrows to its value's low lane; float merges and root writes answer the lane; a shift by a constant whole number of bytes moves bytes in the backward relation (#127) | B3 rest: the forward lane relation (`lanes.rs`) still reads that shift as data; a recovered interface's float slots (with P7); B4 measured, no instance yet (see the ADR); liveness over locations (B2, r2dec's dead values, moved into D2: the inventory must own liveness first) |
| **L** Layering | — | L2 C typing at render boundaries (`typed`) moved from r2rewrite to r2dec, so r2rewrite no longer depends on r2types; L4 r2sleigh-export merged into r2sleigh-cli (13 crates); L1 the body walk moved to r2engine and `block::to_ssa` takes a spelling, so r2ssa reads the lifter only for the trusted-lift authority types; L3a only a stated import takes its library model by name; L3b the library models are the engine's (`r2engine::library`), handed to preparation as `CalleeEvidence` beside the callees' interfaces, preserved registers and reach |   L5 r2ssa's IR and facts layers as modules with a Dylint boundary |
| **F1** Stable ids, stage types | [stable-identity](doc/adr-stable-identity.md) | all | — |
| **K** One fixpoint driver | [fixpoint](doc/adr-fixpoint.md) | r2ssa | r2types' loops (with T); r2dec's are deleted by D; r2ssa's silent caps: none left (LX1f, 2026-10-11). Of the five listed 2026-10-07, `promote.rs` is gone, the optimiser's rounds are a stated budget that says when it is met, `forward.rs`'s chain walk stops only at a cycle; `compare_values_equivalent` is a loop over the shorter chain, the loop-phi renderability walk a memo, `O(V + E)`, and the combine fold's depth the stated `FOLD_DEPTH`, reported when met |
| **F2** One IR, indexed once | [one-ir](doc/adr-one-ir.md) | F2.0; F2.1 and F2.2 in part (dense dominators, loops, liveness once; interface recovery reads its provisional graph once); F2.3; F2.6 (entity-keyed-map Dylint fatal in r2ssa and r2types, in CI) | F2.1 `FunctionIndex` on `Sealed`; F2.2 one byte-granular liveness model (#47, #50); F2.3's name-keyed readers deleted; F2.4 builder with incremental def-use (one graph build); F2.5 projections as indexes. All land in LX, which this ADR owns |
| **M** One machine profile | [machine-profile](doc/adr-machine-profile.md) | M0 cspec parsed, languages chosen through `.ldefs`, `.pspec` tracked values, `.dwarf` numbers; M1 slots, call effect, convention rows; M2 r2ssa reads roles and slots only (call reads in the call effect, `AbiProfile` source-only, family enum replaced by the lift's identity, DF role gone); M3 r2types tables gone (stack roots, stated argument registers, no convention guess); M4 r2dec config is a pointer width; M5 DWARF numbers from the language, frame pointer a cited row; M6a RV64 embedded and admitted, `jalr` stubs named, `shapes_zig_riscv64_O0` in the census | M6 rest: RISC-V 64 opens, decodes, names imports and renders 29 of `shapes`' 39 functions with no arm added; the 10 refusals are frame-base homes (P4), and RISC-V has no equivalence target yet |
| **Q** One query database | [query-database](doc/adr-query-database.md) | Q0 the database (red-green, a random-write session equals a fresh open); Q1 in part (names, import stubs); Q3 returns, survey and modes as queries over one `View`, with held lookups and deposits; Q2 the analysis, callee reads and sealing as queries, stops typed and never held, the memo deleted; Q3e pointer parameters as a query; Q4a the reference index as a query; Q4b renderings as a query, capacity keeps dependencies; Q4c machines load lazily, `ensure_current` deleted; Q4d `Revision` deleted; Q4e the cache Dylint fatal in r2engine ; the exit test over the real program holds | Q2 rest (decode and lift per address as queries) is PF1; Q3 rest (summaries) is SM |
| **P4** One frame model | [frame-model](doc/adr-frame-model.md) | one partition, one escape analysis, promotion as an SSA rewrite, the canary under its premise, a merged extent for the objects an escaped address reaches, an unproven arity refusing its call; `afv` agrees with `pdd`; the exit bar run and blessed (PR #69) | — |
| **H** Hostile input | [performance-and-memory](doc/reviews/2026-10-performance-and-memory.md) | `r2image` clamps every section and segment file range to the bytes the file holds (`fuzzed/elf9` `q` 1.1 s, was a hang); `name_strings` scans only the bytes a segment's file range holds (`fuzzed/file12` `pd 5` 43 MB, was 1.2 GB); `collect_memory_round_trips` indexed by block, ordinal and value; `accesses_at(inst)` a range query; `return_effects` through its index; `BTreeMap::append` replaced by `extend` in placement (`pe/65535sects.exe` `pdd` 25 s, was over 580 s; 18 s and 1.76 GB with PF); `scripts/hostile_sweep.py` and the `hostile-gate` CI job: 887 of 887 fuzzed and PE files within 30 s and 512 MB on `afl` and 120 s and 3 GB on `pdd` | — |
| **PF** Performance foundation | [next-pass](doc/adr-next-pass.md), [performance-and-memory](doc/reviews/2026-10-performance-and-memory.md) | PF0 the Sleigh context persists: `SleighBase` keeps its context fields, `Sleigh` records a committed context and marks cached parses stale, and the bridge rebuilds the context only after a commit (`sleigh-compiler` vendored onto the one Ghidra copy). PF1 a varnode is `(space, offset, size)`: `Varnode` 112 to 24 B, `R2ILOp` 464 to 112 B; address spaces map by a scan of a short list. PF2 mimalloc, chosen over jemalloc and the system allocator by measurement. PF3 analyses and sealings held by SSA operations (200,000), not one each. PF4 the timing gate holds peak RSS and allocation count (`alloc-count`) beside time, with `afl` cases. pumasim `afl` 6.0 to about 2.2 s, 0pack `afl` 1.8 to 1.4 s (macOS, profiling build); outputs identical | the walk's lift read by the trusted lift (`Lifted`): each body is lifted again under the certifying specification, and that cost is callee preparation, so it is SM's; one arena per function and indexes sized at the seal (allocator frames are 12% of pumasim `pdd`, none above 1.5%), with LX and D, which rewrite those structures; `r2ssa::name::intern` into the database (D11), with LX's name-keyed readers; the purge delay (D26), the maintainer's to set: libmimalloc-sys 0.1.49's default holds freed pages, so pumasim `afl; pdd @ 0x23fdf0` (contabo, 2026-10-11) peaks at 393 MB by default, 363 MB at `purge_delay` 100 ms and 340 MB at 25 ms, for 10% and 13% more wall time (system time 0.9 to 2.1 s, the purges) |
| **LF** Lift once | [next-pass](doc/adr-next-pass.md) D24 | PF0 and PF1 (the Sleigh context persists; the compact IL); one Sleigh parse per thread: the walk's machine reads the trusted profile's (review item 8), `ls pdd @ 0x4070` 0.741 to 0.659 s and 167 to 140 MB, pumasim `afl` 196 to 173 MB, 0pack `afl` 145 to 122 MB, outputs identical (2026-10-08) | measured by samply (2026-10-08), lifting is 2.6 to 5.1% of a large `pdd` (0pack 0x62ecf0: trusted lift 3.5%, walk 2.6%; pumasim 0x23fdf0: 2.8%), so `Lifted(address, mode)` for the walk, the trusted lift and a restatement is deferred into SM, where a callee is lifted once per session; reconsider if lifting passes 10% of a timed `pdd` after SM. Investigate: `afl` is 79.5% decode (Sleigh's p-code 50.7%, translation into r2il 23.1%), so whether discovery can follow control without translating every operation |
| **MF** Memory footprint | [performance-and-memory](doc/reviews/2026-10-performance-and-memory.md) | measured with dhat at each workload's heap peak: r2rewrite keeps each root's own rewrites and direct substitutions and walks a value's trace and absorbed producers on demand (330 MB of pumasim 0x23fdf0's peak); the sealed `FunctionFacts` shared by `Arc` with the response and r2dec (19 MB per copy on 0pack); a running query records each read range and asked query once (two 32 MB lists in pumasim's survey); the walk's decoded map holds sizes alone. Peak RSS: pumasim `pdd @ 0x23fdf0` 900 to 534 MB, 0pack `pdd @ 0x58e3d0` 678 to 577 MB, pumasim `afl` 351 to 195 MB, 0pack `afl` 270 to 144 MB, times equal, outputs identical; the timing gate's RSS budget 1.3 to 1.1 | the rest is one function held in several representations at once (SSA blocks, graph, r2dec's normalized projection, the binding plan's shadow arena, the observation journal, about 10 to 25 MB each on 0pack): D deletes r2dec's, F2 the rest; interface recovery's provisional full fact pass (the obligation inventory alone 87 MB on 0pack 0x62ecf0) is SM's summary grade; `call_results`' per-block state copies (review item 7) are LX's |
| **SM** Summaries | [next-pass](doc/adr-next-pass.md) D23 | `CalleeReads` held per `(address, thumb)`; `ComesBack` as the bounded lazy fixpoint; `Demand` over result owners; demand stops at the direct callees (2026-10-11: one `pdd` of pumasim 0x1dc0a0 prepares 44 bodies for its 43 direct callees). Measured 2026-10-11 at #129: a sweep of all 209 sort functions in one process runs 2.55 s and prepares bodies 544 times (125 twice, 53 four times: the root's `Analysed`, the callee read prepared alone, and the read again with its result's owners, which nothing holds); preparation is 63% of the sweep and `callee_read` 33.5% (52.8% of a cold `pdd` of 0x3f50). Reading the Gui constructor's interface (8250 instructions) for pumasim 0x1dc0a0 costs one build, 61 ms raw and 102 ms prepared, before recovery and the seal; in one `pdd` an identical (entry, extent) is rebuilt for 0 to 2% of build time, so the sweep's repeats are the same entry walked and prepared under different keys | the summary grade of preparation (interface, preserved carriers, reach, result, memory effects, signature) as a subset of the passes, measured against the full one; `Summary(f)` the one held value a root reads; components of the call graph solved on the driver; demand beyond direct callees reads only what is held; the summary-grade r2types run (17% of 0pack `pdd` inside `CalleeFacts::derive`, which includes it). Its r2engine half (`Summary(f)` held, components on the driver, bounded demand) runs beside D; its summary grade is designed over T's one solve and one projection, after T1 and T2 (Order, step 5.8). Exit: a sweep prepares each body once; callee reads under 10% of sort 0x3f50 `pdd` (35 to 42% today); Q3's rest and P6's remainder closed |
| **LX** Linear per function | [next-pass](doc/adr-next-pass.md) D22, [one-ir](doc/adr-one-ir.md) | LX1 (2026-10-08, shape-neutral, measured by samply on the timed `pdd`s): renaming names a function's call boundary once (`BoundaryIdentities`), not at every call, 1.5 to 2.1% faster; the obligation inventory holds its obligations in one sorted vector (`ObligationTable`), median RSS 1 to 5% lower; census byte-identical. Measured and left: one large `pdd` prepares 39 callees (0pack 0x62ecf0, 71.3% of its time) to 119 (pumasim 0x23fdf0, 26 of them a second time with their result's owners), 9 to 28 ms each, spread over passes of 1 to 5% each (renaming, the inventory's seed maps, objects and memory, certificates, the optimizer); the machine context rebuilt per-architecture tables (1.2 to 5.5%, LX1b below); a callee prepared again with its result's owners is LX2's incremental preparation. LX1b (2026-10-11): the per-architecture tables are built once in one `r2ssa::Arch` over the specification the lifter, the engine and every artifact share (validated projection query, name maps, tracked values, outermost registers, memory model, register families); two global caches and three per-function `ArchSpec` clones are deleted; census byte-identical, release `pdd` 3 to 14% faster on the timed functions. LX1c (2026-10-11): `call_results` copies a `dense::SparseMap` per block (model 8), where its `IdMap` state cost `O(B · V)`: 130 of the Gui constructor's 329 MB heap peak; total allocation 8.16 to 6.88 GB, peak RSS 18 to 31 MB lower, census byte-identical. LX1d (2026-10-11): r2rewrite walks a value's discharged instructions on demand where it held each value's transitive closure, quadratic along a substitution chain: the Gui constructor's dhat heap peak 327 to 275 MB, its peak RSS 457 to 432 MB (contabo, median of 3), 0pack `0x58e3d0` 489 to 474 MB, census byte-identical. Of the Gui constructor's 432 MB, 133 MB is fixed (the open 73 MB, Sleigh loaded 60 MB) and about 50 MB is mimalloc's retained pages (`MIMALLOC_PURGE_DELAY=0` gives 382 MB at 25% more time); the heap peak is next a long tail of one function's representations (the sealed graph 15 MB, r2types' certified expressions 12 MB, the obligation inventory's dense dispositions 13 MB, lane captures 9 MB), which is F2's and D's. LX1e (2026-10-11): a walk stopped at a dispatch reads its table off the sealed function (`dispatch_table_reads_with_callee_interfaces`), not off a full preparation; `construct` is the one build both finish from, and SM's summary grade is another finish: sort `0x3f50` 3.6% fewer instructions retired, census byte-identical. LX1g (2026-10-11): the seal copies the analysed facts only when it refuses (`FinalizationRefused` hands them back): 0pack `0x58e3d0` heap peak 335 to 311 MB, peak RSS 475 to 455 MB; its remaining seal-time double is the guard that rebuilds the render projection to compare, which T's one projection owner removes. LX1h to LX1j (2026-10-11, found by `census.py heap`, sites compared across four functions of 1823 to 12735 instructions): the seal keeps of the lane record only the conventional extensions (its per-operation bytes are recovery's, before the seal; 19 MB on 0pack, growing as instructions^1.17); the obligation inventory holds each instruction's identity once; an analysis shares the walk the query database holds. Since #131, `afl; pdd` peak RSS (contabo, median of 3): pumasim Gui constructor `0x23fdf0` 451 to 396 MB, 0pack `0x58e3d0` 486 to 412 MB; census byte-identical throughout. LX1k (2026-10-11): an instruction's obligations are its run of the sorted table, not a copy of their identities in each disposition and machine entity: heap peak 0pack 280 to 263 MB, pumasim 248 to 238 MB, and 0.2 to 0.5% fewer instructions retired | the storage index `version_at(point, location)`, one dominator-tree walk with a stack per location (`O(B + writes + reads)`), replacing the reaching walks (`semantic/shared.rs:990`, `O(C · carriers · B²)`); `liveout`, `liveness` and `promote` at their bound; `DeadPhis`, formals, `FunctionLiveOut`, `class_values` and `ValueViews` computed once; the collector once when there is no interface; F2.1, F2.2, F2.4, F2.5 and K's rest; interface recovery reads the one pass (its provisional full fact pass held an 87 MB obligation inventory on 0pack 0x62ecf0); LP1's boundary half (several results, two-register values) with the boundaries rewrite. It lands behind D0 and deletes D27's adapter. Exit: `pdd` instructions retired and CPU time grow no faster than instructions^1.05 over the 300+ instruction functions, measured by `scripts/census.py exponent --max-exponent 1.05` at the item's exit (an hour for 80 functions on contabo, so not in per-PR CI); peak RSS linear in instructions; pumasim Gui constructor under 250 MB with D |
| **T** Types as one monotone system | [next-pass](doc/adr-next-pass.md) D25, [types](doc/types.md) | the union-find solver with one meet per class (`solver.rs`) | the solver incremental, so pointer bases found through accesses join it with no restart (`evidence.rs:93`, at most `2A + 1` rounds cloning the arena today); one solve per function (three today) and one signedness pass (six today); the render projection built once: the seal's guard (`seal_with_callee_signatures`) rebuilds it to compare against the analysis's, so at 0pack `0x58e3d0`'s seal the render facts are live twice (12 to 16 MB each) beside an 18 MB compare clone, and `rebuild_source_owned_decompile_evidence` is about 4% of sort `0x3f50` `pdd`; the projection reads the final types and one step rewrites their field certificates in place (`normalize_field_certificates_from_external_layout`), so it is built once after the last type change (measured 2026-10-11); `named_blocks()` copies and the name-keyed def maps deleted; the confidence-scored `structs`, `arrays` and `globals` system deleted (uncapped and 6-round loops, `u8` scores), its findings residuals where the lattice cannot state them; `FunctionTypeFacts` and `FunctionRenderFacts` as indexes over dense ids (about 20 `BTreeMap`s reachable today); C3's r2types part. D0, which D4 reads it through, landed with D (#142, D27); T1 and T2 go first in Order step 5.8, the dense indexes with LX2. Exit: one solve per function, no loop off the driver, a struct pointer rendered as its struct (P9's first exit) or refused with the reason |
| **LP** Language profiles | [language-profile](doc/adr-language-profile.md) | LP0 each function's language as the container states it (DWARF units' ranges, then a symbol's mangling, then the program's: Go buildinfo, rustc, Swift and Objective-C sections, a CLR header, C++ names or runtime, else C), carried on each rendering; `i` prints `lang` and `pddj` `language`; against radare2's `i~^lang`, ELF 171, Mach-O 121 of 126 and PE 233 agree, the rest judged | LP1 conventions per function (Go ABIInternal on x86-64 and arm64, Rust scalar pairs), boundaries with several results and two-register values; LP2 premises and compiler-inserted checks per profile (C's canary, Go's `morestack`, Rust's bounds and overflow checks), the frame ADR restated against the profile's premise; LP3 runtime models (Go runtime, Rust `core`/`alloc`, C++ ABI) and demangling (Rust legacy and v0, Itanium, Go); LP4 equivalence corpora in Rust, Go and C++ on x86-64 and aarch64. Exit: a Go or Rust function renders under its own convention or refuses with that reason, never under the C one. LP1's engine half is done (opens `rebuild`): `.go.buildinfo` states the Go version (go-cdetect 1.18, dwarf_go_tree 1.14); r2abi's `golang` row (ABIInternal) and `golang_abi0` row are chosen by version (1.17 on Linux, macOS and Windows amd64, 1.18 everywhere); Ghidra's Go specifications are corrected to `abi-internal.md` (vendor/README.md); r2engine assembles a second target and picks it by the language at each function's entry; ABI0 refuses (`NativeRefusal::Convention`). go-cdetect's `reflect.(*funcType).Len` renders `return reflect___rtype__Len(RAX_0);` where C rendered `(void)`; the census is byte-identical (no fixture is Go). Follow-ups: the boundary half (several results, two-register values) lands with LX; the two r2dec defects it exposed (a parameter's variable reassigned while its entry value is read; entry RDX's high bits dropped after `sete dl`) are deleted with the old r2dec, not patched; investigate: a Go assembly function is ABI0 inside an ABIInternal binary, and only the linker's `.abi0` suffix (when a wrapper exists) or pclntab's ASM flag (newer toolchains) states it, so today it is read under ABIInternal; conditional: the AArch64 Go specification is corrected but unchecked on a binary until LP4's arm64 Go corpus exists. LP2's Go half is done: the convention row states `g.stackguard0` (R14+16, x28+16) and r2abi's runtime model says `runtime.morestack` re-enters its caller, so r2ssa decides the check under the premise `go-runtime` (the routine's name states it, the premise says it keeps the contract) and the proof says "assuming go-runtime"; on 120 go-cdetect functions `morestack` calls fall 16 to 0 and residual obligations 4157 to 1914; census byte-identical. Follow-ups: `runtime.(*moduledata).textAddr` now refuses where it rendered 321 residuals (its callees' own checks are now decided, their facts changed, and an R8 merge at 0x44c5bb the old render read as a residual is now read by nothing yet owes a volatile-or-unknown effect no outcome speaks for); `afi` reads the prepared function, so a decided check's failing block leaves its block count, as the canary's does; the aarch64 Go prologue is done (2026-10-13): the check matcher reads AArch64's `b.ls` (`!(guard <= sp') || sp' - guard == 0`) as x86's unsigned `<=`, and r2image reads a pclntab whose `textStart` is 0 (Go 1.27 writes 0; `runtime/symtab.go` names the field unused) from the module record's `text` (found by its `pcHeader` and `ftab`), where it had counted entries from 0 and on arm64 marked `runtime.throw` assembly. On a Go 1.27 program (120 functions per arch): arm64 `morestack` mentions 4 to 0, operations marked compiler-inserted 0 to 418, `X28` read as a residual in 89 functions to 19; on both arches the 17 and 18 functions now read as ABI0 are all assembly (`.s`); census byte-identical (`an_aarch64_go_stack_check_is_compiler_inserted_by_the_runtime_model`, `the_module_record_states_where_text_begins`). Follow-ups: immediate, 19 of 120 checks per arch stay a branch because a call to `runtime.throw` or `gopanic` falls through into the growth block, which then merges two stack pointers; Go's compiler ends a block after those calls and seven `panic*` helpers (`ssagen/ssa.go`), so a runtime model saying they never return under `go-runtime` decides them, once the no-return answer carries its premise (LP3's runtime models); next, an assembly function declared `<ABIInternal>` (`runtime.memequal`, `cmpstring`) reads as ABI0 because the ASM flag states assembly, not the ABI (only an `.abi0` suffix states ABI0); C++ and Rust checks remain with LP3's names |
| **D** Decompiler rewrite | [decompiler-rewrite](doc/adr-decompiler-rewrite.md) | R1 (proved simplifiers) carries over as D3's rule set; SD's structurer and certificate as D1. D0 (2026-10-08): `r2dec::render::RenderInput` borrows the sealed facts behind private fields and hands a stage the function, graph, certificates, obligations, control facts and return type; r2engine's `RenderTier::Staged` routes to it and r2s's `e dec.pipeline=staged` selects it. D1: SD's placement (now from the CFG, dominator tree and loops alone) writes every block once, each block's operations one gap, each test and selector a residual, an edge out of the function a residual `return`, a block control never leaves or a targetless dispatch a trap; the §3 certificate holds on every census function (0 refused), every obligation is gapped, the legacy census is byte-identical. Staged against legacy, 5 runs: pumasim `pdd @ 0x4baf30` 1.349 s and 321 MB against 2.386 s and 353 MB, 0pack `pdd @ 0x58e3d0` 1.176 against 1.858 s, so the old r2dec costs 0.68 to 1.04 s there and D2 to D5 have that to spend. D2 and D3, increment 1 (leaf code): statements from the obligation inventory, one inline-or-bind rule shared with r2rewrite's import, phi copies on edges, frame arrays only for storage r2ssa proves the callee's, terms spelled unsigned at their width; calls are gaps. Census: 140 of 361 functions render with no gap or residual, 0 refused (legacy 290 clean, 24 refused); gaps by kind 611 `ValueHasNoCType` (256-bit AVX, one binary), 387 calls, 335 other effects, 257 terms, 216 stores. Staged against legacy, release, 3 runs: 0pack `0x58e3d0` 1.31 s and 471 MB against 1.93 s and 559 MB, `0x62ecf0` 1.41 against 1.49 s, pumasim `0x23fdf0` 2.03 against 2.61 s, `0x4baf30` 1.48 s against 2.71 s. The equivalence matrix grades the staged pipeline beside legacy, gating nothing. D2 increment 2: a call renders from its callsite certificate where a prototype describes it and r2types names the callee; every parameter, return, argument and result takes its register class from the convention slots, a declared type agreeing; a table dispatch switches on its certificate's selector. Three silent miscompiles found by hand and fixed: a tail call written as `return;`, a `double` parameter declared `uint64_t` (passed in RDI), a float stored as a converted integer. Census: 173 of 361 clean; 115 of the 182 call gaps are calls no prototype describes. The workspace suite on the restacked top: 2125 passed, 0 failed (contabo VM). Staged equivalence, x86-64, 756 records against legacy's baseline: run 1 (D2 increment 2) 577 equal, 6 compile errors (a recursive call declared as an extern) and 9 no-records (a panic in parallel copies), both fixed; run 2 (with lane inserts and D4) 622 equal against legacy's 629, no staged-only failure, the same 3 `differs` and 3 `ub` as legacy. Then D4 (one frame array aligned as `entry_stack` states, every object below the entry stack pointer, a literal offset held to its object's extent, a computed index spelled from the one object its address names), D1.1 (SD's readability rewrites on the staged tree: 531 gotos to 83), calls without a prototype where r2ssa proves the arity, indirect calls through their target, floats in a vector register's low lane: census 210 of 361 clean. Run 3 (lanes and calls) 630 equal against legacy's 629: 13 gained, 5 lost to a layout gate on computed frame indices (arrays of records r2ssa refuses as displaced bases), since replaced by the one-object rule; no staged-only failure, the same 3 `differs` and 4 `ub` as legacy. Found by the gate, shared with legacy: `avg` (review.c, stripped) returns `double` in XMM0 and both pipelines render it returning the loop counter from RAX, because the recovered interface picks RAX where the body writes both result registers; the fix is upstream (the interface states the carrier unproven where the body alone cannot tell) Result carriers (2026-10-09, #85 to #87, the fix the gate asked for): a body writing both result registers states its result unproven and names both (`result_carriers`); each call takes the register its own code reads after it (`r2ssa::caller_reads`), and only the rendered root asks every call in the program (the survey), because a survey per callee cost 0pack `pdd @ 0x62ecf0` 35.7 G instructions against 22.8 G and the timing gate caught it; a float carrier is the lane its readers take (AArch64's d0 of Z0), and a wide carrier certified narrower returns its low field; a parameter handed on untouched, or read only for a call of unproven arity, leaves the arity a floor its callers fill. Legacy equivalence x86-64 629 to 638, aarch64 600 to 606, every move judged in the baselines; pumasim `0x4baf30` 34.6 G to 24.0 G instructions. D4 (#88): a function a declaration gives no parameters is `ret (*)()`. #89: the staged proof line from its ledger, the marker id owned by the AST, a table `switch` that reads its selector though the dispatch is elided (siphash24 residual to clean). | Switch criterion: staged against legacy at #88's top, graded on contabo: x86-64 644 equal against 638, aarch64 611 against 606, and staged has no `differs`, `ub` or compile error on either architecture where legacy has 2, 29 and 5 on aarch64. Since (#90, 2026-10-09): calls pass their stack arguments; a register held from entry reads as a residual; population count; a float constant is its bits (a silent miscompile: `x + 1.0` added the integer of 1.0's bits); a declared pointer parameter is declared so; an obligation whose text evaluates a residual is residual on the proof line; both ledgers read one certificate elision (`r2dec::certified`, moved out of the binding plan); wide carriers through the bitvector helpers (aarch64's Z registers): staged census 550 to 561 clean of the 680 the sweep now holds, gaps 66 to 45. Switching `pdd` to staged fails 71 of 497 r2engine and r2s tests: the native behavior tests that compile and run the C pass in staged but four (256-bit moves, `rep scas`/`rep cmps`, a packed extension); the rest assert legacy's spelling or need a staged capability (fences, user operations, system calls, exclusive pairs, `rep movs`, 256-bit loads, the incoming stack slots `_start` reads) or pddj's invariants (control residuals carry cause `gap` without a marker). Call refusals by cause (#91, `R2DEC_TRACE_REFUSAL`): 47 over the census, of which 18 are `_start` passing its realigned stack pointer, 3 a va_list, 16 incomplete arguments r2ssa states (Mach-O `_main`, riscv64), 8 riscv64 variadic declarations that disagree and 2 a result class, which #92 traced to r2ssa recovering `push rbp; mov rbp, rsp; pop rbp; ret` as returning RBP in both pipelines (the PIC-thunk rule took the restored frame pointer for a result; now a register reloaded from its own save is no result). #93: an AArch64 `addv` to B0 left `cnt`'s lanes in bytes 1 to 15 (a Ghidra 11.4 spec bug: staged's `bit_count` returned 0x08080820 for all ones), and an odd-width register zero lifts as aligned pieces. #96 (2026-10-09): staged equivalence at #93 graded 631 of 756 equal on aarch64 (bar 631) with two silent miscompiles, both one cause: a store into a callee-owned frame slot no body access reads was elided as dead though its address escaped or a call reached it (`shape_pointer_to_pointer` clang-O1 faulted, `shape_struct_array` gcc-O2 read `table[0]` uninitialized); the elision now asks `FrameReach`. Census: staged 5 functions gain stores (variadic save areas, `printf` stack slots), legacy 2 move with no refusal added. Follow-ups: r2ssa recovers no parameter for `f` that reads x1 but never x0 (`escape(void)`): the parameter prefix stops at the first unread slot by design (`recover_interface.rs` `in_order`), though an observed read of a caller-saved argument slot implies every slot below it is declared; extending the prefix is sound for the callee's arity where the convention fills integer slots in sequence (SysV, Go ABIInternal; AAPCS64 only for even gaps, rule C.9 pads odd ones) but unsound for its callers, since dead-argument elimination leaves the gap register unset at call sites; deferred until after D, as one contract change: a sequential-fill fact on `SourceConventionSlots`, `unused` gap parameters on the recovered interface, boundary minting that skips them, and a residual argument in r2dec. Investigate (correctness, PE): `r2sleigh-lift` `profile.rs` reads only direct `pentry` children and drops `<group>` and `join align`, so Win64's positional xmm/GPR pairs give no integer argument slots today; a staged obligation neither rendered nor elided counts as residual with no marker (investigate, `values.rs` `close`). #98, D4 slice (c): a constant call argument at text r2engine's `text_at` proves (static, NUL-terminated, never written) is a string literal, read from the one table legacy reads (`display_names().strings()`); legacy census byte-identical, staged 12 functions spell `printf` formats and hash inputs. Follow-ups: `PreparedFunctionFacts::string_literal_for_value` is never filled (delete, next); r2ssa's `source_string_literals` is a second copy of the table (one owner, later). #99, D4 slice (d): an access at a global's exact address is spelled by the container's name, at the DWARF-declared type where C can spell it at the access width, else through the byte helper at `&name` (`extern char name[]`), from the tables legacy's `name_of_constant_address` reads; legacy census byte-identical, staged 22 functions name `g_sink`, `g_counter`, `__dso_handle` and others. D switch progress: 10 tests restated from legacy local names to the facts they check (70 to 60 of 502 failing with `pdd` on staged); left: the `frame.rs` extents (staged's one `frame` array), the proof line's held-from-entry naming. #101 (staged operations): 256-bit loads and stores by byte copy, `rep movs/scas/cmps` as the element loop `r2il::eval` runs, user operations (`svc`, `dmb`, `syscall`) as gaps named by the specification where legacy spelled `CallSupervisor(0)` and dropped the syscall number, an operator on a wide carrier a gap; an entry register no parameter admits reads as a `HeldFromEntry` residual. #102 (declared types): callee carrier widths from `exact_callee_interface`, `noreturn` from the block graph, parameter names from the declaration, an index off a named global spelled off it; legacy census byte-identical, staged 85 functions move with no refusal or residual added. With `pdd` on staged, 52 of 508 r2engine and r2s tests fail (was 70): about 15 control and frame facts (under way), about 13 pddj and other invariants, 4 typed standalone locals that ADR D4's one `frame` array answers by offset (restate to the `afv` range fact), 2 legacy spellings (float constants as bits by #90, memory through helpers by D3). #103 (control and frame facts): `afv` lists the frame model's locals for both pipelines (the second owner in `requests.rs` deleted), plain literals, `(void)` discarded reads, one if/else assignment as a ternary, held-from-entry reads named on the proof line, `__builtin_return_address(0)`; 27 of 508 fail with `pdd` on staged. Staged equivalence at #96: aarch64 633 of 756 (no `differs`, `ub` or `uninit`), x86-64 656 with two `uninit` records, fixed by #104: a store at an unbounded index was elided as a dead slot while a neighbouring object's unbounded read reached it (`extent_assumption` now states `UnboundedIndex` for any unbounded indexed access, and no frame store is elided while a frame read has one). Follow-ups: `stack_array_layout` proves a layout when any one indexed access is bounded, so an object with one bounded and one unbounded write could still be elided (investigate, owner r2ssa certificates); legacy still declares separate scalars past which it indexes (deleted with legacy). The legacy deletion runs beside the switch on `d-delete-legacy`: commit 1 moves the shared items out of the legacy modules; `pdim` and `pdih` are deleted with the legacy driver (maintainer decision, 2026-10-09). #105: a stack array layout is proven only when every index is bounded (one bounded index had proven an extent an unbounded neighbour exceeds); legacy `shape_stack_buffer` then indexes past one-byte scalars, 5 equivalence records blessed `ub` with that cause (deleted with legacy). #106: staged invariants (a stopped body kept, control traps as marked gaps, argument slots read with no parameter named apart from held values, constant arguments plain). #107: an access beside an unbounded index counts as assumed on both proof lines (`obligation_extent_assumption`, r2ssa, one owner). #108: a string literal stands only where a pointer to `char` is wanted (#98 had spelled `hv`'s initializer as `"\t"` and `half_stride` read past it: 2 aarch64 `differs` at #101). #109: D4 slice (e), declared struct and function-pointer types, defined only where C's natural layout reproduces the stated offsets and size, one spelling one layout (review). Quality review (2026-10-10, each item scored, below 8 is rewritten before the switch): the dead frame-store elision (#96, #104, #105) 6/10, r2dec rebuilds a dead-store fact from r2ssa certificates and was patched three times, rewrite as one r2ssa certificate (escape, call reach, extent) r2dec only reads; a staged unread value elided in `close()` 5/10, a deadness fact rebuilt downstream, rewrite at r2ssa's obligation seeding; #103's ternary 7/10, applied after the control certificate, move before it; #101, #106 to #109 8/10. With `pdd` on staged, 3 of 513 r2engine and r2s tests fail; the exit-bar dry run at #108 passed (fmt, workspace clippy, structure, nextest 2176 of 2176). Rewrites (2026-10-10): #110, the dead frame-store fact is one r2ssa certificate (`PreparedFunctionCertificates::dead_frame_stores`: escape, call reach, unbounded extent) r2dec only reads, 8/10; #111, a RISC-V `auipc`+`jalr` whose target its block folds is a direct call (legacy-only clean 19 to 15, the 15 left are unjustified legacy output: 10 float truncations without a range guard, 5 `_start` reads of stack slots it never assigns); #112, the one-assignment selection (ternary) is written by the structurer before the control certificate, which checks it (`StatementRole::Selects`), 8/10, census byte-identical. Blocked: the staged `close()` elision (5/10) rewritten at r2ssa's obligation seeding changes legacy C, because legacy's carrier rules read `DeadPhis` (`sum_array` becomes `for(;;)` with split carriers) and breaks #107's `a_reach_beside_an_unbounded_index_leaves_the_extent_assumed`; it lands after legacy is deleted, and the review fixtures stay a standing switch failure until then. #113: a cspec `<group>` is one argument position (r2sleigh-lift `PrototypeEntry.position`, projected as `SourceConventionSlots.shared_positions`), so Win64 states RCX, RDX, R8, R9 and XMM0 to XMM3 positionally where it stated none; `handed_functions` places through `placed_prefix` (on SysV `f(double, void(*)())` had read the callback from RSI), 8.5/10. #114: every residual the staged proof line counts has a site in the text or a named cause (`census.py sites`: 23 mismatches to 0); the canary address is compiler-inserted (r2ssa `stack_protector`), prologue stack adjustments are `StackGeometryCertificate::frame_setup`, a branch whose arms meet owes a transfer with no inputs, and the one exception, `PendingObligationSeeding` (11 functions, counted on the proof line), excuses only `unobserved_private_reads` members until the seeding fix lands; legacy now refuses syscalls `fcn.401010` (it read an elided condition), 8/10. #115: `StackSlotCertificate::unbounded_index` for every frame object, read by `extent_assumption` and `dead_frame_stores` (an unbounded read of an object with no callee allocation had left its extent unmarked and a store elided), `indexed_past_any_bound` deleted, census byte-identical, 9/10. Staged equivalence at #112: aarch64 633 of 756 equal, no `differs`, `ub`, `uninit` or compile error. Stack 97 closes at #115; the legacy deletion opens the next stack. Deletion branch: shared items moved out of the legacy modules (8/10), a caller's stack-argument slot (7/10, to restate as an r2ssa fact), the jump-table dispatch closed at r2ssa (8/10). #116: staged review fixes (the ledger commits per statement, a literal index of all ones refused, a duplicable term bounded at 64 nodes, `INT_MIN / -1` guarded by an `undefined-quotient` residual), 8/10. #117: pre-merge correctness fixes (a return reads only its declared result's bytes, `PreparedFunctionFacts::demanded`; float reads at two widths leave the carrier unproven; the downward-stack frame rule only under `LowerAddresses`), 8/10. #118: every residual the equivalence corpus counts has its site (31 records #114 refused restored, 0 refused); staged equivalence at #118's head: x86-64 659 of 756 equal, aarch64 631, no `differs`, `ub`, `uninit` or compile error. #119: the shared items move out of the legacy modules (proof line, shape rewrites, string-literal gate), census byte-identical, 8/10. #120: staged reads the caller's stack slots from one r2ssa certificate (`PreparedFunctionCertificates::caller_stack_slots`), its own argument-area rule deleted, 8/10. The switch (#122, 2026-10-10): `pdd`, `pddj`, `pddo` and the visual mode render staged; `e dec.pipeline=legacy` selects legacy until its deletion. Workspace suite 2239 passed, 1 failed: the review fixtures count residuals the proof line names pending obligation seeding, and pddj's proof check now reads that named cause as `census.py sites` does. Census: 322 of 361 functions move, refused 22 to 0, functions with a residual 147 to 207, sites 0 mismatches. Staged equivalence at the switch: x86-64 659 of 756 equal, aarch64 631, no `differs`, `ub`, `uninit` or compile error. Release `pdd`, 3 runs, staged against legacy: 0pack `0x58e3d0` 1.96 s and 474 MB against 2.73 s and 560 MB, `0x62ecf0` 2.01 s and 437 MB against 2.16 s and 446 MB, pumasim `0x23fdf0` 2.83 s and 446 MB against 3.54 s and 507 MB, `0x4baf30` 1.96 s and 321 MB against 2.28 s and 349 MB. Follow-ups: a constant left shift demands only the low bytes (hashes `combined`, aarch64 clang, reads x0's unspecified upper half); constant-pool loads in vectorised loops (`shape_byte_indexed_buffer`) are unspelled terms. Switch re-measured at #93: 70 of 500 tests fail with `pdd` on staged; about 14 need source-declared types (D4 types, under way: callee prototypes first), 16 assert legacy's local names (`RAX_2`, `stack_m120`; restated as the facts they check, since D4's one `frame` array is the design), 15 need staged operations (barriers, `svc`, exclusive pairs, `rep` string operations, 256-bit packed extensions), 15 control and frame facts (jump-table arms, canaries, discarded loads, the return-address slot), 10 pddj and other invariants. Staged 256 clean against legacy 282 on the census before these. Of the 27 functions legacy renders clean and staged does not: 7 truncate a float to an integer (staged refuses `FloatToInteger`, below), 4 are `_start`, whose initial-stack reads staged refuses where legacy reads a `stack_p0` it never assigns, 3 hold 256-bit AVX or Z values, 5 are RISC-V variadic calls (no equivalence target), 2 are siphash24's switch (fixed on `d5-proof`), and 6 others, each to read by hand (rv `main`'s store and call, shapes gcc-O0 0x401176, float_returns aarch64's stores). `TRUNC` out of range is undefined in C: staged spells a range-guarded cast whose out-of-range arm is a residual (#89, ADR floating-point decision 5); legacy still casts unguarded. D5 rest: the old r2dec deleted (`observation_journal`, `binding_plan`, `placement`, `normalize`, `fold`, `analysis/prepared_semantic`, `effect_ledger`, the retries: 53k lines, leaving r2dec 28.6k against the 20k exit), with the r2engine call sites still on the legacy path; `structure` depends on `fold`, `binding_plan` and `normalize` first. Follow-ups, classified: conditional on r2abi stating `__libc_start_main`'s `main` as `int (*)(int, char**, char**)`, manual_limits gcc-O2 `main` and code_pointer_table aarch64 clang-O0 `main` lose their residual return; deferred to SM, an indirect call's arity from the common prototype of its table's entries (shape_function_pointer, table_dispatch at gcc-O0); P7, a void function whose callers read neither result register stays a residual (`crc32_init`, `fill`); investigate, a staged read of a variable whose definition is a gap (sound only because the gap traps first; certification should state it). Legacy deleted (#123, 2026-10-10): r2engine renders one pipeline (`RenderTier`, `dec.pipeline`, `pdim` and `pdih` gone), r2dec/src 84,963 to 17,564 lines, census byte-identical to the switch; a self call whose result nothing reads discharges its definition, which legacy's deleted `CallBoundaryCarrier` elision had answered. #124 (the `close()` rewrite): r2ssa owes a private frame read only once its liveness walk reaches it, and `unobserved_private_reads`, the `close()` branch and `UnsitedReason` are deleted; 176 census functions move their proof lines, no line of C. Not checked here: `uncompress2` and `deflateInit2_` (the zlib corpus is not on these machines). Exit: `observation_journal`, `binding_plan`, `placement`, `normalize`, `fold`, `analysis/prepared_semantic`, `effect_ledger` and the retries deleted; r2dec under 20k lines; `uncompress2` and `deflateInit2_` render right or refuse |
| **W** Real-binary sweep gate | [real-binary-sweep](doc/reviews/2026-10-real-binary-sweep.md) | jump-table negative cases, PLT stubs by their own transfer, guarded zero-extension bounds (this branch) | coreutils (ls, sort, cp, date, stat) and zlib with DWARF as a CI gate against radare2, objdump and DWARF. Exit: afl finds every function radare2 does (76 missing), survey follows dispatch tables so afl/afb/axt agree with afi/pdf (with P6), the remaining jump-table shapes resolve or refuse, `__assert_fail` and `__stack_chk_fail` are noreturn, preemptible PLT stubs are named, `main` is named in stripped binaries, one function has one spelling, and every disagreement is judged |

### Analysis

| Item | Done | Left (exit) |
|------|------|-------------|
| **PE** Written-lane result widths ([written-lanes](doc/adr-written-lanes.md)) | result widths | the rest is B (one relation, `cover(demanded)`, the eval/Kani check) |
| **P1.7** Entry lanes are the caller's | done | — |
| **C** Provenance ([provenance](doc/adr-provenance.md)) | C0; C1 types and the format parameter; C4's references (#196): annotations, references and claims carry `Basis`, `query::Support` is deleted, and its order disagreement is judged for the grades (a declaration outranks a callee's dereference) and pinned | C1 r2dec reads the grade (`from_source_signature` deleted); C2's rest (the function's return and argument types are `Fact`s, #197): the convention, local types, syscalls, and the JSON carrying each confidence; C3 r2types on `Basis` (with T); C4's answer-field Dylint |
| **P5** Values as an index | the value view states lanes: `INSERT(w, x, k)` with `x` another value's bits at `k` grows `w`'s prefix through the lane, and an insert above keeps the bits below it; `ValueViews::low_lane_value` indexes, per root, the value that is exactly its low bits at each width; a register call argument reached as a wider root write names that value, its root write kept as `lane_of` and checked by the certificate (`swap_call`: `return scale(b, a);`); a load from bytes the program never writes folds to them, captured by r2engine where `TableBytes` says read-only and no literal store overlaps (`store(1.25, p)`, `x *= 0.5`); `r2il::eval` refuses an insert past the 128 carried bits | the renderer reads the views (D2): bound lane carriers (`__uint128_t XMM0_5 = (__uint128_t)bits(half(..))`), bitwise vector ops on a scalar lane (`andpd`/`orpd` in `floor_at`) and all-literal lane inserts (`xorps` zeroing) are D's, since folding the inserts to 128-bit literals first loses the lane the argument narrowing reads; a return slot reached as a wider root reads the views as arguments do (with LX's storage index); a load whose literal address SSA folds (aarch64 `adrp`/`ldr`) is captured on the restated preparation, as folded string literals are |
| **P6** One resolved body per function, as a query | [resolved-bodies](doc/adr-resolved-bodies.md); P6a the walk through dispatch tables is the `Walked` query; P6c1 a callee resolved as a root is; P6c2 return-only demand (`Resolved`, `Demand`, `result_owners`); `read_callees` kept as the one loop a root reads callees through (the database answers it with `Resolved`, a plain `Program` with each callee resolved alone) | its remainder is SM: a summary held once per session with demand bounded to what is held, so the 21 s transitive resolution measured for pumasim `main` is never paid by one `pdd`; parameters stay what each body proves alone |
| **I** Unread container facts (CFI, LSDA, IBT, RELRO, init arrays) | init, fini and preinit arrays as entries (`EntryKind`) and RELRO as sealed ranges (`TableBytes::LoaderWritten`), both earlier; CFI (#184): each frame `.eh_frame` states seeds discovery as `Stated`, except a frame in a section of linkage code (the stub walk now returns those sections, `naming::Linkage`, so a CET `.plt` of resolver and lazy entries counts though it names no stub); stripped coreutils `true` 74 of 74 FDE starts found (functions 13 to 78; radare2 `aaa` 26), `ls` 279 of 279 (105 to 283; radare2 145); the rest are GCC `.cold` fragments' own FDEs, judged functions as their local symbols say when unstripped; census: stripped `hashes_gcc_x64_O2` now finds `_dl_relocate_static_pie` at 0x401270, rendered as the unstripped build renders it | LSDA landing pads as statements about their functions (a C++ catch block no edge reaches); IBT `endbr64` markers as candidate starts (decoded, so weaker than a frame, and only where no frame states one); the differential sweep (W) to grade function sets against radare2 and DWARF |
| **P7** Call contracts | Darwin arm64 variadic tail (M1c); declared `double` arguments reach their calls (B3) | no dropped or invented argument; printf's stack tail on x86-64; a recovered interface's float parameters and float result (a body's float work feeds only the float result, so recovery never observes it; the variadic save area's spills read as parameters in both classes, and the convention's `al` read at entry states the tail) |
| **P8** Data objects and strings | — | `iz` lists proven strings |
| **P9** Types over the graph | — | a struct pointer is not `uint32_t*` (its first exit is T's; recursive and polymorphic types after T) |
| **P11** Names and commands | The ELF sweep, 2026-10-12 and 13 (`diff_r2.py`, 235 radare2 test bins): 96 disagreeing pairs, every one judged in `scripts/diff_r2_judged.toml` (#192), which the harness reads: it fails on an unjudged disagreement and lists a judgment nothing matched (`scripts/test_diff_r2.py`, in CI). radare2's defects, each an upstream candidate: ARM stubs named one entry off (`libarm.so` 0x3e110 reads `__cxa_finalize`'s slot, `libflutter.so` 0x4e6da0 `__cxa_atexit`'s), aarch64 PLT entries assumed 16 bytes where they are 24 (`ls-toybox`), `.plt.got` stubs unnamed, objects' Thumb bit cleared, `SHN_ABS` rebased, BE8 read big-endian, LDR (register) spelled as a pool load, M-profile `msr` called invalid, unmapped tails listed as `ff`, a debuginfo `e_entry` dropped. r2s's choices: names only where claimed, pool loads as encoded, `sym.imp.` for every stub. Fixed on the way: a read crosses into a segment beginning where its own ends (`test.ko` `px` stopped at `.init.text`'s end) | Done (#193): of several symbols at one address the strongest binding names it (r2s took the alphabetically first: WEAK `_Exit` over GLOBAL `_exit`; six libc listings now agree), and a string's flag is its escaped text through radare2's flag filter (`.` kept, a newline `_n`). Deferred: a section-less object's stubs (`libarm64.so`), which needs a stub found by the call that reaches it where no section bounds the walk. Done (#194): Sleigh's spellings read as radare2 writes them (`push`/`pop`/`ldm` for the stack's load and store multiple, no ARM zero offset, no x86 `ptr` before a segment or scale of one), and `lea` keeps its brackets around a number and gives them to a name standing for the address, as radare2 does (a stripping rule that claimed otherwise is deleted); seven more listings agree. Deferred, ungraded ARM32: an ARM listing steps one byte past an undecodable word, and PLT0's literal word refuses the stub walk (`libverifyPass.so`). Conditional: a section table past the file's end (`libmemalloc-dump-mem`), ET_REL relocations in listings and NOBITS placement, `e_entry` 0 in a static-pie. The mach0 corpus (125 files, 446 disagreeing pairs at #194, unjudged), first read: in a fat file r2s states a file offset from its slice's start (`a.out` `_main` paddr 0x7f60, radare2 0x1bf60, the file's own), which was r2s's defect across `iS`, `is`, `ie` and `ir`, fixed (#195: `Image::file_base`; six more symbol listings agree); `ie`'s `vhaddr` column, the entry field's address, r2s fills and radare2 leaves empty (r2s right); the two seek different entries in many (`px`, `pd`); the large `is` sets (`TrollStore` 242, `BatteryLife` 231, `core.dwarf` 156). The harness now judges a value by the column r2s prints it in, and a judgment may list binaries (#198); `px` pads its header to a 64-bit address's width as radare2 does (agreeing on 116 files, from 30); ARM's `r10` is `sl`. Judged at #198: `ie` 95 of 98 (the `vhaddr` column radare2 leaves empty), `iS` 116 of 124 (Mach-O section flags radare2 prints as 0, a fat file's `paddr` radare2 counts from the slice), `pd` 46 of 55 (claimed names only, name choice, Swift names until LP3, `LC_FUNCTION_STARTS` names unfilled, the fat slice r2s reads; r2s's defects: Thumb at an ARMv7 Mach-O entry, and symbol flags not filtered as radare2 filters them). Fixed: a header a stub section's own entries jump to is its resolver and names no import (Mach-O's `__stub_helper` was named `imp.dyld_stub_binder` over all 397 bytes; `is` now agrees on 114 files, from 57). Left unjudged: `px` 9, `pd` 8, `iS` 8, `is` 6, `ie` 3 (the dSYMs' symbols, `hellocxx-osx-i386`'s entry, `longIdentifiers.dylib`'s `udf`). The upstream pull requests, each one idea, once the maintainer agrees |
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
| The promotion predicate ([frame-model](doc/adr-frame-model.md)) | a proof or a mutation target: the 2026-10-07 survey verified no published strong-update rule, so the predicate is the engine's own claim |
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

Amended 2026-10-08 (D27): the open stack (#71 to #76) merges to master;
then the rebuild runs contract first on `rebuild`. The old order kept the old
r2dec alive while LX and T changed the shapes it reads, and that is how one
function came to be held in seven representations at once (MF). The
maintainer accepts broken renderings on `rebuild` until it merges.

0. **G0**, **B**, **R1**, **P4**: done.
1. **H**: hostile input bounded: done. It was first because a hang or a
   2 GB read on a fuzzed binary is a defect in every command.
2. **PF**: the performance foundation (PF0 to PF4): done, so D is measured
   against a fast baseline and not against Sleigh re-initialisation and
   allocator churn. Its rest is SM's, LX's and D's.
3. **P5**: values as an index, which D2 reads: done; its rest is D2's and LX's.
   **MF**, the memory footprint, ran here on 2026-10-08 at the maintainer's
   request (sessions ran out of memory and swap): done; its rest is D's, F2's,
   SM's and LX's.
4. **LP0**: each function's language: done (#74). **MF** merges with it (#76).
5. On `rebuild`, each item its own pull request into it:
   1. **LP1**'s engine half, which opens the branch: done.
   2. **LF**: one Sleigh parse per thread, done; the double lift is SM's
      (measured 2.6 to 5.1% of a large `pdd`).
   3. **LX1**, done in part (renaming, the inventory; the rest is a long tail
      of 1 to 5% passes, so D goes next), LX's passes that change no fact
      shape a renderer reads, so they pay no adapter on the old r2dec: the collector once (interface
      recovery reads the pass the seal runs), the per-architecture machine
      tables once (done, LX1b), sparse `call_results` states, `version_at` in place of
      the reaching walks. Measured 2026-10-08 (samply): callee reads are
      39.9% of pumasim 0x23fdf0's `pdd` and 71.3% of 0pack 0x62ecf0's, of
      which the SSA build is 8.3% and 13.3% and recovery's provisional fact
      pass 7.2% and 11.4%; the machine context rebuilds per-architecture
      tables at 1.2 to 5.5%.
   4. **D**: D0 as the dense contract with its adapter, D1 to D5, then the
      old r2dec deleted (27.6 to 36.3% of a large `pdd`). Beside it on
      `rebuild`: **W**. At 2026-10-09: D0 to D4 render, the stack #80 to #88
      waits to merge, and D5 (the proof line, then the deletion) is next;
      the switch waits on the 27 census functions in D's row.
   5. **LX2**, LX's dense fact indexes behind D0, deleting the adapter;
      LP1's boundary half with it.
   6. **SM**'s summary grade over LX's passes, then **T**, behind D0.
      Reversed 2026-10-08: SM had moved before D on the 31.0% callee share;
      a static map of what a callee read consumes (the summary's obligation
      authority needs the inventory, objects, memory, addresses, call sites,
      boundaries and live-out) leaves only the render-only certificate maps
      and r2types' render build to skip, 4.9% of pumasim 0x23fdf0's `pdd`
      and 5.7% of 0pack 0x62ecf0's. Superseded by step 8 (2026-10-11): a
      callee's signature reads almost every type pass, so T's one solve and
      one projection go first and SM's grade is designed over them.
   7. `rebuild` merged to master at D's switch (#142, 2026-10-11), the
      maintainer's call, before LX's and SM's exits held; LX2, SM and T
      continue on master in step 8's order.
   8. On master, the rewrites the 2026-10-11 measurements identified, in
      dependency order, each its own item, its bound the model it names
      ([next-pass](doc/adr-next-pass.md)) and its exit a number the census
      or `census.py` checks:
      1. **T1**, one type solve (model 5): the incremental union-find with
         one meet per class in place of three `solve_evidence_types` runs,
         six signedness passes and the `2A + 1` rounds that clone the arena
         (`evidence.rs:93`); solves and signedness are 3.4 to 4.3% of a
         large `pdd`, in every root and every callee read. Exit: one solve
         and one signedness pass per function, counted. Done (2026-10-11):
         `meet` is the greatest lower bound of the subtype order, its laws
         property-tested (an `int64_t` against an `int` of unknown sign met
         at `Bottom`; arrays and structs met at `Bottom` and broke
         associativity), and the evidence joins one incremental solver, so a
         refinement round adds its bounds with no restart: 0.6 to 1.1% fewer
         instructions retired, census byte-identical. Left (T1c): one session
         across the three solves a root runs (signature inference, recovered
         parameter types, the seal), each later one only adding prototypes.
      2. **T2**, the render projection owned once: the seal reads the
         analysis's projection instead of rebuilding it to compare
         (`seal_with_callee_signatures`): about 4% of sort `0x3f50`, a
         second render copy and an 18 MB clone at 0pack's seal. The
         projection reads the final types (the merged signature, its
         certificate, the field certificates), and one step rewrites the
         field certificates in place
         (`normalize_field_certificates_from_external_layout`), so built once
         it is built after the last type change, and that rewrite becomes
         the type pass's. Done (2026-10-12): enrichment normalises and
         canonicalises the types, then projects once (`project` writes no
         type fact); the seal takes a `ProjectedFacts`, which only
         enrichment makes, and keeps enrichment's evidence solve. 0.8 to
         1.7% fewer instructions retired; peak RSS unmoved (the clone was
         transient, not at the peak); census byte-identical.
      3. **SM1**, the summary grade (model 3) over T1 and T2, measured again
         before its design: callee reads are 47% of sort `pdd` against
         SM's 10%, and a callee's signature reads almost every type pass.
         Measured 2026-10-12 after T2 (samply, sort `0x3f50`): callee reads
         45.3%, of which preparation 33.2% (the SSA build 11.9%, interface
         recovery 8.7%, the seal's fact passes about 10%), type analysis
         8.1% (struct inference 2.2%, enrichment 2.0%), the summary 1.7%
         and the lift 1.8%. The exported signature and
         `PreparedCalleeSummary` read everything but the render-only
         certificate maps (about 1.5%) and the callee's render projection
         (about 1.5%), so a summary grade's ceiling is about 3 points, and
         struct inference only where the signature names no struct. SM's
         10% exit is LX4's (recovery) and F2's (the build), not SM1's.
      4. **LX3**, `version_at` (model 2): Braun's `readVariable` memoised
         per `(block, location)` over the locations a pass asks, a merge
         with no phi answered by its predecessors' agreement as the
         reaching walks answer it. A point inside a block (before an
         `InstId`, a machine instruction's start or end, as
         `reaching_storage_boundaries` keys it) is the last write to the
         location before it in the block, else the block's entry value:
         4.5% of a large `pdd` today. Exit:
         `reaching_storage_boundaries` deleted, census byte-identical. Done
         (2026-10-12): `ReachingStorage` solves a block's entry over the
         blocks backward-reachable from it through blocks that do not write
         the storage (the walk's equations closed over that region, so the
         same least fixpoint), keeps it, and scans a queried block once; the
         walk and its three graph-sized maps are deleted. Sort `0x3f50`
         4.9% to 2.8% of `pdd`; 1.4 to 2.7% fewer instructions retired;
         census byte-identical. Measured beside it: the root is
         constructed twice, once by the walk to read its dispatch tables
         (11.5% of sort `pdd`) and again by `prepare_restated` (13.2%).
      5. **LX4**, recovery's pass: interface recovery collects the full fact
         pass on the preliminary build (17.4% of sort `pdd` across every
         preparation) and reads its inventory, objects, boundaries, call
         sites, loops and liveness; a cheaper recovery is a new algorithm
         whose output is the interface, so it moves the census, every moved
         line judged. Measured 2026-10-12 after LX3 (samply, sort `0x3f50`):
         recovery is 18.3% of `pdd`, nearly all its fact pass (objects 3.8%,
         the inventory 3.1%, certificates 2.4%, addresses 1.3%, loops 1.2%,
         value ranges 1.1%, liveness 0.9%). It reads the inventory's
         observation roots (`ProvenProgramObservations`), objects,
         boundaries, call sites, structured memory accesses and one
         certificate (`machine_return_controls`), whose closure is most of
         the pass: a recovery-grade collector saves under 3 points. The seal
         collects the pass again because its rewrites read the recovered
         interface (lane projections for each formal lane, demand over the
         result carriers) and rebuild the graph, so one collection is F2.4's
         incremental builder: the seal's edits applied to the preliminary
         graph and its facts. LX4 lands with F2.4.
      6. **F2's representations** (models 4 and 9): one function held once,
         the graph, machine projection and term arena indexes over it, the
         obligation dispositions (112 bytes) and `OpMetadata` (about 200
         bytes per op, a tree per block) dense columns: about 206 MB of the
         Gui constructor's peak against the 60 MB LX's 250 MB exit leaves.
         In part (2026-10-12, #152 to #159, each census byte-identical):
         an op's instruction is a run column, the name table holds the
         lowest address per spelling, the graph's instruction index is
         runs, its arrays are sized from the arena's live count, an
         instruction's storage is its output value's, a native-span source
         names no span, the sealed function and graph shrink once edited,
         and certified expressions are a dense index. pumasim `pdd @
         0x23fdf0` heap peak (dhat) 236.9 MB to 199.4 MB; release `pdd`
         peak RSS 16 to 19% under master at #153 (exit bar). Then: the
         struct inference shares the type analysis's named blocks and
         borrows its definitions (about 38 MB off its hump), and the
         graph's inputs are one `Csr` read through `SsaGraph::inputs`
         (graph build 10.9 to 8.4 MB); heap peak 197.0 to 194.7 MB, the
         render phase's now. Left, per `doc/adr-one-ir.md` ("The op after
         the seal"): the graph indexing the function's renumbered
         operations, the machine projection and term arena as indexes
         (F2.5).
      7. **LX2**, D27's adapter deleted: D0 reads T's and F2's dense
         indexes.
      8. **D26**'s purge delay, the maintainer's (PF row).
      9. **MM**, memory as a linear budget
         ([memory-model](doc/adr-memory-model.md)). Two causes, measured
         2026-10-12: a session held whole per-function answers (renderings
         with their facts, analyses and sealings up to 200,000 operations
         each), and one function's peak holds about ten representations of
         it at once, about 2 KB of heap per SSA operation. The only
         functions over 1 GB were a debug file's zero fill decoded as code.
         Done (stack #165): the walk stops at the file's last byte (#166);
         a held rendering keeps its text, ledger and premises (#168); a
         function's walk, analysis, sealing and rendering are held only
         while newest, program-wide facts (summaries, names, returns) held
         (#169); a prepared function keeps its walk's outline, not its lift
         (#170); facts nothing reads are not kept (#171); the ledger holds
         each obligation once (#172); a value's definition, inputs and
         width are the graph's alone (#173: r2ssa's expression
         certificates and r2types' certified expressions each copied them
         per value, 10.6 MB at the render peak); the inventory's seeds are
         a bit per kind owed of the whole instruction, and one backward
         pass taints every return whose interface is unproven (#174: each
         seeded instruction had held its own `BTreeSet`, and each such
         return, every return during recovery, rescanned every
         instruction, `O(k · (B + I))`: 35.5 MB at preparation's peak);
         the term arena holds a type once and a node in 32 bytes, its side
         tables dense, its arrays shrunk once canonical, and the import's
         root steps are runs over two arrays (#175: every value's
         canonical term also built a transitive producer set to fill a
         `reads` list nothing read, and its import held a 32-byte producer
         id nothing read); r2types' array inference borrows the
         operations it indexes by name, the inventory's table is sized
         from its seeds and sorted in place, and the import's roots are
         recorded as runs as each completes (#176: the inference cloned
         every operation twice, 42.6 MB at the type seal; the table kept
         its doubling slack and a stable sort's scratch; the importer held
         a hash map of two vectors per root, 9.2 MB); one open-addressed
         index (`dense::HashIndex`) owns each variable-to-id lookup (#178:
         the value table keyed a `HashMap` by a second copy of every
         variable beside the graph's own index; heap 1.2 to 2.4% lower,
         time unchanged). A 50-function `pdd` session: pumasim 935 to 385 MB, 0pack 765 to
         386 MB, time unchanged. Since #172: heap peak (dhat) pumasim
         `pdd @ 0x23fdf0` 180.6 to 158.6 MB (197.0 at #167), 0pack
         `0x58e3d0` 199.5 to 177.6 MB since #173; release peak RSS, median
         of 5, 0pack 340 to 275 MB, pumasim 311 to 272 MB; pumasim's time
         1.57 to 1.49 s. Each phase's peak is now within a few MB of the
         others (preparation's inventory build, the type seal's array
         inference, render's import), so a cut in one moves the peak to
         the next. 0pack's (177.6 MB, about 1.9 KB per operation) is
         render's: the analysis artifact 58.4 MB, render's own 25.0 MB,
         the machine projection 18.9 MB, the term import 9.5 MB. The array
         inference still keys maps by spelled names, in six rounds that
         keep a partial result when they run out: T deletes it (below).
         Left, largest first:
         1. **MM.6** one encoding of each operation after the seal: the
            graph owns it and the function's blocks, as the builder's, are
            dropped at the seal (0pack's render peak at #179: the
            function's operations, arena and table 14.4 MB beside the
            graph's 19.3); 30 post-seal reader files re-key, 3 readers
            named for a decision ([one-ir](doc/adr-one-ir.md), "The op
            after the seal", amended 2026-10-12: the plan had the graph
            index the function's operations, which hands 216 graph-only
            signatures a handle back). Step 1 done (#182): every
            post-seal reader of the function's operations (22 r2ssa files,
            r2types' named copy, now spelled from the graph by
            `SsaGraph::named_blocks`, r2dec and r2engine) reads the graph;
            the named copies those passes built per call are gone. `pdd` 2
            to 6% faster, the 50-function session 3%, allocations 1% fewer,
            heap peaks unchanged, census byte-identical. Step 2 done
            (#183): the seal drops the function's blocks of operations once
            the graph is built and the function validated, keeping its CFG,
            arena and records; a read of them is a debug assertion
            (`a_sealed_function_refuses_to_read_its_operations`), and the
            tests read the graph (`SsaArtifact::named_block(s)`). Heap peak
            0pack `0x58e3d0` 167.3 to 162.4 MiB, pumasim 147.6 to 143.8,
            the session 191.4 to 187.5; time 2 to 4% lower; census
            byte-identical. Step 3 done (#186): the seal drops the value
            table and the operation origins too. Their one post-seal reader,
            the reaching scan's instruction grouping, asks the graph's
            instruction column (`instruction_for_inst`), and slot promotion
            records its lifted sites while the origins exist. A read of
            either is a debug assertion: the suite's six test readers now
            read the graph. Heap peak 0pack 159.1 to 158.3 MiB, pumasim
            141.1 to 139.9, the 50-function session 187.5 to 179.6 (each
            held function keeps neither); census byte-identical. 0pack's
            peak moved to interface recovery's preparation. Left: a
            compile-time type for the sealed function in place of the debug
            assertions, and the `formal_*` maps keyed by `VarId`, which no
            post-seal reader can reach.
         2. **MM.4** the fixed cost `F` (29.8 MB: the file's bytes 9.5,
            symbols 7.6, names 4.2), PF's. Measured 2026-10-13 (dhat,
            pumasim's 6-byte stub): 36.2 MiB of heap, 93.4 MB RSS. Step 1
            done (#189): the image maps its file read-only (`memmap2`; a fat
            Mach-O's slice is a range of the map) where it read a copy into
            the heap. Heap peak falls by the file's size in every case:
            pumasim `afl` 95.4 to 86.4 MiB, 0pack `afl` 57.5 to 50.0, pumasim
            `0x23fdf0` 130.0 to 120.9, the session 163.4 to 154.3; census
            byte-identical. The mapped pages count in RSS once read, and the
            kernel can drop them without swap. Step 2 done (#191): a
            relocation boxes its symbol (112 to 64 bytes; pumasim's 28,026
            relocations nearly all name none), and a symbol's name is one
            `Arc<str>` shared by the symbol, the name table and its seeks,
            which are one map per namespace keyed by the text past the
            prefix where they were four copies. pumasim's stub 28.46 to
            25.00 MB of heap (12%); census byte-identical. Left: the loader's
            composed writes 2.6, the unwind frames 3.2, the symbols' own
            layout (96 bytes, three `Option<usize>` indexes).

            The exit (`c ≤ 600 B`) is not in reach of MM's contained steps:
            at #191 `c` is 1.07 KB on pumasim's largest function, and the
            cuts left and sized (the type interned 2.3 MiB, value geometries
            3.4, obligation identities about 3, native spans 1.7) reach about
            950 B. The rest is F2's single numbering, F2.4 and F2.5:
            `GraphInst` and `GraphValue` are 64 bytes each (12 MiB on 0pack),
            and interface recovery collects the fact pass the seal collects
            again (LX4). MM pauses here until the stacks merge and that plan
            is agreed.
         3. **MM.7** compact identities: a disposition (48 B per
            instruction) and an imported value carry a 32-byte canonical
            instruction id the graph already implies; an obligation copies
            its instruction's graph inputs where it states none of its own.
            Step 1 done (#188): a graph instruction's disposition is its
            state and its run of the sorted table (12 bytes), the identity
            read off the graph when asked (`CanonicalInstructionId::of`);
            `obligations_for_inst` reads the run in O(1) where it searched by
            a 32-byte key. Heap peak 0pack 148.2 to 144.2 MiB, pumasim 133.1
            to 130.0, session 168.5 to 163.4; census byte-identical. Left:
            each obligation's 80-byte identity and its own copy of its
            instruction's inputs (0pack: 4.5 MiB at the peak), the rewrite's
            substitutions and `discharges` naming producers by canonical
            identity where r2dec maps them back to instructions.
         4. **MM.8** the machine projection (13.6 MB, a 72-byte node, 32
            of it the type) and render's own structures (7.6 MB). Step 1
            done (#185): an entity stated its output and producer beside
            its root (48 bytes, and an index by output), both the graph's
            and the obligations'; the projection now holds one root per
            instruction and builds the entity on read, and validation of
            the copies against their owners is gone with them. 0pack heap
            peak 162.4 to 159.2 MiB, pumasim 143.8 to 141.1, session
            unchanged (its peak is elsewhere); time unchanged; census
            byte-identical. Left: the type interned (0pack: 99,033 nodes,
            28 distinct types; 72 to 48 bytes a node, about 2.3 MiB, 115
            reads to move), the value geometries (40 bytes a value, 3.3
            MiB), and `discharges` returning instruction ids, which r2dec
            maps back from canonical ids (MM.7).
         5. **MM.9** D26: one forced collect at each phase boundary,
            measured.
         5a. Done (#187): the written-lane record held 24 bytes a byte,
            twice (by variable and by operation), through interface
            recovery's preparation, where 0pack peaked after #186; 73,988 of
            the largest function's 74,097 outputs are data throughout. A
            record is now its size where every byte is data, and the pass
            keeps each variable's definition in place of a second copy.
            Heap peak 0pack 158.3 to 148.2 MiB, pumasim 139.9 to 133.1,
            session 179.6 to 168.5; peak RSS 4 to 7% lower; time 1 to 2%
            lower; census byte-identical. 0pack's peak is render's again:
            the graph 17.8, the image 8.0, the projection's nodes 7.1,
            obligation dispositions 10.0, term leaves 5.4. Left: the
            capture's `while` over every block until nothing moves is a
            round-robin fixpoint, owed to `r2ssa::fixpoint` (D11).
         6. **MM.3** (conditional) facts only sealing reads, measured
            2026-10-12 at the render peak: the fact pass holds 28.7 MB (the
            35.7 estimate counted r2types'), of which memory SSA 5.3 MB
            (struct inference, slicing and recomputed liveness read it),
            the inventory's preallocation 4.4 MB, predicates and control
            domains under 0.1 MB. Dropping them at the seal needs the
            analysis and its sealing as one query, since both hold one
            `Arc<SsaArtifact>`: worth it only once the rest are done.
         7. Done (#179, D11): `populate_certified_parameter_exprs` copied a
            parameter's binding along same-width copies in a `while
            changed` loop over every value, `O(V · chain)`; one walk forward
            from the bound values over their uses states the same map,
            `O(V + E)`, census byte-identical.
         Gates (#177): `census.py time` reports and gates each case's heap
         peak from the `alloc-count` build (1.05x the base) and times a
         50-function pumasim session under the RSS, heap and time budgets;
         at #176 the session's heap peak is 196.5 MiB against 151.3 for
         its largest function alone. Exit: `c ≤ 600 B` per operation, then
         `≤ 300 B`.
6. **LP2 to LP4**, then **I**, **C2, C4**, **P7, P8, P9, P11**.
7. Beside the path, as small items when a step waits on CI: **L5**, **M6**
   rest.
8. **Surface** on its own branch: S2, A and V3 now; V4, V5 and the rest after
   `rebuild` merges.

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
- r2ssa walks back from each call site for each carrier (`semantic/shared.rs:990`) and copies a dense state per block in `call_results`; five caps keep a partial result silently (LX).
- Each instruction is lifted at least twice per analysis (LF).
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
