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

Where this stands (2026-10-09, `rebuild` stack #80 to #88, gated at c9361ccc on contabo)
---------------------------------------------------------------------------------------

| Measure | Value |
|---------|-------|
| Equivalence, legacy | x86-64 638/756 equal (was 629); aarch64 606/756 (was 600); both blessed with a cause per moved record |
| Equivalence, staged | x86-64 644/756 at the D4 top, no failure legacy's baseline lacks; gating nothing until D's switch |
| Census | legacy 282 clean, 51 residual, 28 refused of 361; staged 256 clean, 61 gapped, 44 residual |
| Coverage | `crc32_init` x64 O2 gaps its unproven return, blessed with its cause |
| Tests | touched-crate suites 1775 passed, 0 failed; workspace clippy clean |
| Cost (release, instructions retired) | 0pack `pdd @ 0x62ecf0` 22.8 G, `0x58e3d0` 29.2 G; pumasim `0x23fdf0` 38.0 G, `0x4baf30` 24.0 G (34.6 G before #87) |
| Structure | CI at #88 read too_many_arguments 145 and too_many_lines 390 against 141 and 383 blessed; #86's share (3 and 1) is paid back; the rest is suspended inside D and paid or blessed at its exit |

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
| D27 | Contract first, then the layers behind it (2026-10-08): D0's `RenderInput` is the dense input F2 and T must provide, served first by an adapter over today's `SourceOwnedFunctionFacts`; D1 to D5 are written against it and the old r2dec is deleted; LX and T then replace the adapter's backing with no change to D. Old r2dec reads every fact shape r2ssa and r2types produce, so changing those first pays adapters on code D deletes, and writing D against today's shapes pays D twice. The work runs on one integration branch, `rebuild`, where equivalence, certification and the census report instead of block; every commit there still builds and passes the workspace tests, the Dylints and the proofs, so equivalence stays measurable and a regression bisects; master keeps every gate. `rebuild` merges at D's switch criterion with LX's and SM's exits met | standing |
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
| **Q** One query database | [query-database](doc/adr-query-database.md) | Q0 the database (red-green, a random-write session equals a fresh open); Q1 in part (names, import stubs); Q3 returns, survey and modes as queries over one `View`, with held lookups and deposits; Q2 the analysis, callee reads and sealing as queries, stops typed and never held, the memo deleted; Q3e pointer parameters as a query; Q4a the reference index as a query; Q4b renderings as a query, capacity keeps dependencies; Q4c machines load lazily, `ensure_current` deleted; Q4d `Revision` deleted; Q4e the cache Dylint fatal in r2engine ; the exit test over the real program holds | Q2 rest (decode and lift per address as queries) is PF1; Q3 rest (summaries) is SM |
| **P4** One frame model | [frame-model](doc/adr-frame-model.md) | one partition, one escape analysis, promotion as an SSA rewrite, the canary under its premise, a merged extent for the objects an escaped address reaches, an unproven arity refusing its call; `afv` agrees with `pdd`; the exit bar run and blessed (PR #69) | — |
| **H** Hostile input | [performance-and-memory](doc/reviews/2026-10-performance-and-memory.md) | `r2image` clamps every section and segment file range to the bytes the file holds (`fuzzed/elf9` `q` 1.1 s, was a hang); `name_strings` scans only the bytes a segment's file range holds (`fuzzed/file12` `pd 5` 43 MB, was 1.2 GB); `collect_memory_round_trips` indexed by block, ordinal and value; `accesses_at(inst)` a range query; `return_effects` through its index; `BTreeMap::append` replaced by `extend` in placement (`pe/65535sects.exe` `pdd` 25 s, was over 580 s; 18 s and 1.76 GB with PF); `scripts/hostile_sweep.py` and the `hostile-gate` CI job: 887 of 887 fuzzed and PE files within 30 s and 512 MB on `afl` and 120 s and 3 GB on `pdd` | — |
| **PF** Performance foundation | [next-pass](doc/adr-next-pass.md), [performance-and-memory](doc/reviews/2026-10-performance-and-memory.md) | PF0 the Sleigh context persists: `SleighBase` keeps its context fields, `Sleigh` records a committed context and marks cached parses stale, and the bridge rebuilds the context only after a commit (`sleigh-compiler` vendored onto the one Ghidra copy). PF1 a varnode is `(space, offset, size)`: `Varnode` 112 to 24 B, `R2ILOp` 464 to 112 B; address spaces map by a scan of a short list. PF2 mimalloc, chosen over jemalloc and the system allocator by measurement. PF3 analyses and sealings held by SSA operations (200,000), not one each. PF4 the timing gate holds peak RSS and allocation count (`alloc-count`) beside time, with `afl` cases. pumasim `afl` 6.0 to about 2.2 s, 0pack `afl` 1.8 to 1.4 s (macOS, profiling build); outputs identical | the walk's lift read by the trusted lift (`Lifted`): each body is lifted again under the certifying specification, and that cost is callee preparation, so it is SM's; one arena per function and indexes sized at the seal (allocator frames are 12% of pumasim `pdd`, none above 1.5%), with LX and D, which rewrite those structures; `r2ssa::name::intern` into the database (D11), with LX's name-keyed readers |
| **LF** Lift once | [next-pass](doc/adr-next-pass.md) D24 | PF0 and PF1 (the Sleigh context persists; the compact IL); one Sleigh parse per thread: the walk's machine reads the trusted profile's (review item 8), `ls pdd @ 0x4070` 0.741 to 0.659 s and 167 to 140 MB, pumasim `afl` 196 to 173 MB, 0pack `afl` 145 to 122 MB, outputs identical (2026-10-08) | measured by samply (2026-10-08), lifting is 2.6 to 5.1% of a large `pdd` (0pack 0x62ecf0: trusted lift 3.5%, walk 2.6%; pumasim 0x23fdf0: 2.8%), so `Lifted(address, mode)` for the walk, the trusted lift and a restatement is deferred into SM, where a callee is lifted once per session; reconsider if lifting passes 10% of a timed `pdd` after SM. Investigate: `afl` is 79.5% decode (Sleigh's p-code 50.7%, translation into r2il 23.1%), so whether discovery can follow control without translating every operation |
| **MF** Memory footprint | [performance-and-memory](doc/reviews/2026-10-performance-and-memory.md) | measured with dhat at each workload's heap peak: r2rewrite keeps each root's own rewrites and direct substitutions and walks a value's trace and absorbed producers on demand (330 MB of pumasim 0x23fdf0's peak); the sealed `FunctionFacts` shared by `Arc` with the response and r2dec (19 MB per copy on 0pack); a running query records each read range and asked query once (two 32 MB lists in pumasim's survey); the walk's decoded map holds sizes alone. Peak RSS: pumasim `pdd @ 0x23fdf0` 900 to 534 MB, 0pack `pdd @ 0x58e3d0` 678 to 577 MB, pumasim `afl` 351 to 195 MB, 0pack `afl` 270 to 144 MB, times equal, outputs identical; the timing gate's RSS budget 1.3 to 1.1 | the rest is one function held in several representations at once (SSA blocks, graph, r2dec's normalized projection, the binding plan's shadow arena, the observation journal, about 10 to 25 MB each on 0pack): D deletes r2dec's, F2 the rest; interface recovery's provisional full fact pass (the obligation inventory alone 87 MB on 0pack 0x62ecf0) is SM's summary grade; `call_results`' per-block state copies (review item 7) are LX's; `Names` copies `StatedNames` (7 MB on pumasim) |
| **SM** Summaries | [next-pass](doc/adr-next-pass.md) D23 | `CalleeReads` held per `(address, thumb)`; `ComesBack` as the bounded lazy fixpoint; `Demand` over result owners | the summary grade of preparation (interface, preserved carriers, reach, result, memory effects, signature) as a subset of the passes, measured against the full one; `Summary(f)` the one held value a root reads; components of the call graph solved on the driver; demand beyond direct callees reads only what is held; the summary-grade r2types run (17% of 0pack `pdd` inside `CalleeFacts::derive`, which includes it). Its r2engine half (`Summary(f)` held, components on the driver, bounded demand) runs beside D; its summary grade is a subset of LX's passes and lands after LX (D27). Exit: a sweep prepares each body once; callee reads under 10% of sort 0x3f50 `pdd` (35 to 42% today); Q3's rest and P6's remainder closed |
| **LX** Linear per function | [next-pass](doc/adr-next-pass.md) D22, [one-ir](doc/adr-one-ir.md) | LX1 (2026-10-08, shape-neutral, measured by samply on the timed `pdd`s): renaming names a function's call boundary once (`BoundaryIdentities`), not at every call, 1.5 to 2.1% faster; the obligation inventory holds its obligations in one sorted vector (`ObligationTable`), median RSS 1 to 5% lower; census byte-identical. Measured and left: one large `pdd` prepares 39 callees (0pack 0x62ecf0, 71.3% of its time) to 119 (pumasim 0x23fdf0, 26 of them a second time with their result's owners), 9 to 28 ms each, spread over passes of 1 to 5% each (renaming, the inventory's seed maps, objects and memory, certificates, the optimizer); the machine context rebuilds per-architecture tables (1.2 to 5.5%, next with M's machine profile, since 67 call sites build a context from a bare `ArchSpec`); a callee prepared again with its result's owners is LX2's incremental preparation | the storage index `version_at(point, location)`, one dominator-tree walk with a stack per location (`O(B + writes + reads)`), replacing the reaching walks (`semantic/shared.rs:990`, `O(C · carriers · B²)`); sparse states in `call_results` (`O(B · V)` today); `liveout`, `liveness` and `promote` at their bound; `DeadPhis`, formals, `FunctionLiveOut`, `class_values` and `ValueViews` computed once; the collector once when there is no interface; the five silent caps as budgets with typed refusal; F2.1, F2.2, F2.4, F2.5 and K's rest; interface recovery reads the one pass (its provisional full fact pass held an 87 MB obligation inventory on 0pack 0x62ecf0); LP1's boundary half (several results, two-register values) with the boundaries rewrite. It lands behind D0 and deletes D27's adapter. Exit: `pdd` time grows no faster than instructions^1.05 over the 300+ instruction functions, measured by the CI timing job; peak RSS linear in instructions; pumasim Gui constructor under 250 MB with D |
| **T** Types as one monotone system | [next-pass](doc/adr-next-pass.md) D25, [types](doc/types.md) | the union-find solver with one meet per class (`solver.rs`) | the solver incremental, so pointer bases found through accesses join it with no restart (`evidence.rs:93`, at most `2A + 1` rounds cloning the arena today); one solve per function (three today) and one signedness pass (six today); `named_blocks()` copies and the name-keyed def maps deleted; the confidence-scored `structs`, `arrays` and `globals` system deleted (uncapped and 6-round loops, `u8` scores), its findings residuals where the lattice cannot state them; `FunctionTypeFacts` and `FunctionRenderFacts` as indexes over dense ids (about 20 `BTreeMap`s reachable today); C3's r2types part. It lands after LX, behind D0, which D4 reads it through (D27). Exit: one solve per function, no loop off the driver, a struct pointer rendered as its struct (P9's first exit) or refused with the reason |
| **LP** Language profiles | [language-profile](doc/adr-language-profile.md) | LP0 each function's language as the container states it (DWARF units' ranges, then a symbol's mangling, then the program's: Go buildinfo, rustc, Swift and Objective-C sections, a CLR header, C++ names or runtime, else C), carried on each rendering; `i` prints `lang` and `pddj` `language`; against radare2's `i~^lang`, ELF 171, Mach-O 121 of 126 and PE 233 agree, the rest judged | LP1 conventions per function (Go ABIInternal on x86-64 and arm64, Rust scalar pairs), boundaries with several results and two-register values; LP2 premises and compiler-inserted checks per profile (C's canary, Go's `morestack`, Rust's bounds and overflow checks), the frame ADR restated against the profile's premise; LP3 runtime models (Go runtime, Rust `core`/`alloc`, C++ ABI) and demangling (Rust legacy and v0, Itanium, Go); LP4 equivalence corpora in Rust, Go and C++ on x86-64 and aarch64. Exit: a Go or Rust function renders under its own convention or refuses with that reason, never under the C one. LP1's engine half is done (opens `rebuild`): `.go.buildinfo` states the Go version (go-cdetect 1.18, dwarf_go_tree 1.14); r2abi's `golang` row (ABIInternal) and `golang_abi0` row are chosen by version (1.17 on Linux, macOS and Windows amd64, 1.18 everywhere); Ghidra's Go specifications are corrected to `abi-internal.md` (vendor/README.md); r2engine assembles a second target and picks it by the language at each function's entry; ABI0 refuses (`NativeRefusal::Convention`). go-cdetect's `reflect.(*funcType).Len` renders `return reflect___rtype__Len(RAX_0);` where C rendered `(void)`; the census is byte-identical (no fixture is Go). Follow-ups: the boundary half (several results, two-register values) lands with LX; the two r2dec defects it exposed (a parameter's variable reassigned while its entry value is read; entry RDX's high bits dropped after `sete dl`) are deleted with the old r2dec, not patched; investigate: a Go assembly function is ABI0 inside an ABIInternal binary, and only the linker's `.abi0` suffix (when a wrapper exists) or pclntab's ASM flag (newer toolchains) states it, so today it is read under ABIInternal; conditional: the AArch64 Go specification is corrected but unchecked on a binary until LP4's arm64 Go corpus exists |
| **D** Decompiler rewrite | [decompiler-rewrite](doc/adr-decompiler-rewrite.md) | R1 (proved simplifiers) carries over as D3's rule set; SD's structurer and certificate as D1. D0 (2026-10-08): `r2dec::render::RenderInput` borrows the sealed facts behind private fields and hands a stage the function, graph, certificates, obligations, control facts and return type; r2engine's `RenderTier::Staged` routes to it and r2s's `e dec.pipeline=staged` selects it. D1: SD's placement (now from the CFG, dominator tree and loops alone) writes every block once, each block's operations one gap, each test and selector a residual, an edge out of the function a residual `return`, a block control never leaves or a targetless dispatch a trap; the §3 certificate holds on every census function (0 refused), every obligation is gapped, the legacy census is byte-identical. Staged against legacy, 5 runs: pumasim `pdd @ 0x4baf30` 1.349 s and 321 MB against 2.386 s and 353 MB, 0pack `pdd @ 0x58e3d0` 1.176 against 1.858 s, so the old r2dec costs 0.68 to 1.04 s there and D2 to D5 have that to spend. D2 and D3, increment 1 (leaf code): statements from the obligation inventory, one inline-or-bind rule shared with r2rewrite's import, phi copies on edges, frame arrays only for storage r2ssa proves the callee's, terms spelled unsigned at their width; calls are gaps. Census: 140 of 361 functions render with no gap or residual, 0 refused (legacy 290 clean, 24 refused); gaps by kind 611 `ValueHasNoCType` (256-bit AVX, one binary), 387 calls, 335 other effects, 257 terms, 216 stores. Staged against legacy, release, 3 runs: 0pack `0x58e3d0` 1.31 s and 471 MB against 1.93 s and 559 MB, `0x62ecf0` 1.41 against 1.49 s, pumasim `0x23fdf0` 2.03 against 2.61 s, `0x4baf30` 1.48 s against 2.71 s. The equivalence matrix grades the staged pipeline beside legacy, gating nothing. D2 increment 2: a call renders from its callsite certificate where a prototype describes it and r2types names the callee; every parameter, return, argument and result takes its register class from the convention slots, a declared type agreeing; a table dispatch switches on its certificate's selector. Three silent miscompiles found by hand and fixed: a tail call written as `return;`, a `double` parameter declared `uint64_t` (passed in RDI), a float stored as a converted integer. Census: 173 of 361 clean; 115 of the 182 call gaps are calls no prototype describes. The workspace suite on the restacked top: 2125 passed, 0 failed (contabo VM). Staged equivalence, x86-64, 756 records against legacy's baseline: run 1 (D2 increment 2) 577 equal, 6 compile errors (a recursive call declared as an extern) and 9 no-records (a panic in parallel copies), both fixed; run 2 (with lane inserts and D4) 622 equal against legacy's 629, no staged-only failure, the same 3 `differs` and 3 `ub` as legacy. Then D4 (one frame array aligned as `entry_stack` states, every object below the entry stack pointer, a literal offset held to its object's extent, a computed index spelled from the one object its address names), D1.1 (SD's readability rewrites on the staged tree: 531 gotos to 83), calls without a prototype where r2ssa proves the arity, indirect calls through their target, floats in a vector register's low lane: census 210 of 361 clean. Run 3 (lanes and calls) 630 equal against legacy's 629: 13 gained, 5 lost to a layout gate on computed frame indices (arrays of records r2ssa refuses as displaced bases), since replaced by the one-object rule; no staged-only failure, the same 3 `differs` and 4 `ub` as legacy. Found by the gate, shared with legacy: `avg` (review.c, stripped) returns `double` in XMM0 and both pipelines render it returning the loop counter from RAX, because the recovered interface picks RAX where the body writes both result registers; the fix is upstream (the interface states the carrier unproven where the body alone cannot tell) Result carriers (2026-10-09, #85 to #87, the fix the gate asked for): a body writing both result registers states its result unproven and names both (`result_carriers`); each call takes the register its own code reads after it (`r2ssa::caller_reads`), and only the rendered root asks every call in the program (the survey), because a survey per callee cost 0pack `pdd @ 0x62ecf0` 35.7 G instructions against 22.8 G and the timing gate caught it; a float carrier is the lane its readers take (AArch64's d0 of Z0), and a wide carrier certified narrower returns its low field; a parameter handed on untouched, or read only for a call of unproven arity, leaves the arity a floor its callers fill. Legacy equivalence x86-64 629 to 638, aarch64 600 to 606, every move judged in the baselines; pumasim `0x4baf30` 34.6 G to 24.0 G instructions. D4 (#88): a function a declaration gives no parameters is `ret (*)()`. #89: the staged proof line from its ledger, the marker id owned by the AST, a table `switch` that reads its selector though the dispatch is elided (siphash24 residual to clean). | Switch criterion: staged against legacy at #88's top, graded on contabo: x86-64 644 equal against 638, aarch64 611 against 606, and staged has no `differs`, `ub` or compile error on either architecture where legacy has 2, 29 and 5 on aarch64. Since (#90, 2026-10-09): calls pass their stack arguments; a register held from entry reads as a residual; population count; a float constant is its bits (a silent miscompile: `x + 1.0` added the integer of 1.0's bits); a declared pointer parameter is declared so; an obligation whose text evaluates a residual is residual on the proof line; both ledgers read one certificate elision (`r2dec::certified`, moved out of the binding plan); wide carriers through the bitvector helpers (aarch64's Z registers): staged census 550 to 561 clean of the 680 the sweep now holds, gaps 66 to 45. Switching `pdd` to staged fails 71 of 497 r2engine and r2s tests: the native behavior tests that compile and run the C pass in staged but four (256-bit moves, `rep scas`/`rep cmps`, a packed extension); the rest assert legacy's spelling or need a staged capability (fences, user operations, system calls, exclusive pairs, `rep movs`, 256-bit loads, the incoming stack slots `_start` reads) or pddj's invariants (control residuals carry cause `gap` without a marker). Call refusals by cause (#91, `R2DEC_TRACE_REFUSAL`): 47 over the census, of which 18 are `_start` passing its realigned stack pointer, 3 a va_list, 16 incomplete arguments r2ssa states (Mach-O `_main`, riscv64), 8 riscv64 variadic declarations that disagree and 2 a result class, which #92 traced to r2ssa recovering `push rbp; mov rbp, rsp; pop rbp; ret` as returning RBP in both pipelines (the PIC-thunk rule took the restored frame pointer for a result; now a register reloaded from its own save is no result). #93: an AArch64 `addv` to B0 left `cnt`'s lanes in bytes 1 to 15 (a Ghidra 11.4 spec bug: staged's `bit_count` returned 0x08080820 for all ones), and an odd-width register zero lifts as aligned pieces. Switch re-measured at #93: 70 of 500 tests fail with `pdd` on staged; about 14 need source-declared types (D4 types, under way: callee prototypes first), 16 assert legacy's local names (`RAX_2`, `stack_m120`; restated as the facts they check, since D4's one `frame` array is the design), 15 need staged operations (barriers, `svc`, exclusive pairs, `rep` string operations, 256-bit packed extensions), 15 control and frame facts (jump-table arms, canaries, discarded loads, the return-address slot), 10 pddj and other invariants. Staged 256 clean against legacy 282 on the census before these. Of the 27 functions legacy renders clean and staged does not: 7 truncate a float to an integer (staged refuses `FloatToInteger`, below), 4 are `_start`, whose initial-stack reads staged refuses where legacy reads a `stack_p0` it never assigns, 3 hold 256-bit AVX or Z values, 5 are RISC-V variadic calls (no equivalence target), 2 are siphash24's switch (fixed on `d5-proof`), and 6 others, each to read by hand (rv `main`'s store and call, shapes gcc-O0 0x401176, float_returns aarch64's stores). `TRUNC` out of range is undefined in C: staged spells a range-guarded cast whose out-of-range arm is a residual (#89, ADR floating-point decision 5); legacy still casts unguarded. D5 rest: the old r2dec deleted (`observation_journal`, `binding_plan`, `placement`, `normalize`, `fold`, `analysis/prepared_semantic`, `effect_ledger`, the retries: 53k lines, leaving r2dec 28.6k against the 20k exit), with the r2engine call sites still on the legacy path; `structure` depends on `fold`, `binding_plan` and `normalize` first. Follow-ups, classified: conditional on r2abi stating `__libc_start_main`'s `main` as `int (*)(int, char**, char**)`, manual_limits gcc-O2 `main` and code_pointer_table aarch64 clang-O0 `main` lose their residual return; deferred to SM, an indirect call's arity from the common prototype of its table's entries (shape_function_pointer, table_dispatch at gcc-O0); P7, a void function whose callers read neither result register stays a residual (`crc32_init`, `fill`); investigate, a staged read of a variable whose definition is a gap (sound only because the gap traps first; certification should state it). Exit: `observation_journal`, `binding_plan`, `placement`, `normalize`, `fold`, `analysis/prepared_semantic`, `effect_ledger` and the retries deleted; r2dec under 20k lines; `uncompress2` and `deflateInit2_` render right or refuse |
| **W** Real-binary sweep gate | [real-binary-sweep](doc/reviews/2026-10-real-binary-sweep.md) | jump-table negative cases, PLT stubs by their own transfer, guarded zero-extension bounds (this branch) | coreutils (ls, sort, cp, date, stat) and zlib with DWARF as a CI gate against radare2, objdump and DWARF. Exit: afl finds every function radare2 does (76 missing), survey follows dispatch tables so afl/afb/axt agree with afi/pdf (with P6), the remaining jump-table shapes resolve or refuse, `__assert_fail` and `__stack_chk_fail` are noreturn, preemptible PLT stubs are named, `main` is named in stripped binaries, one function has one spelling, and every disagreement is judged |

### Analysis

| Item | Done | Left (exit) |
|------|------|-------------|
| **PE** Written-lane result widths ([written-lanes](doc/adr-written-lanes.md)) | result widths | the rest is B (one relation, `cover(demanded)`, the eval/Kani check) |
| **P1.7** Entry lanes are the caller's | done | — |
| **C** Provenance ([provenance](doc/adr-provenance.md)) | C0; C1 types and the format parameter | C1 r2dec reads the grade (`from_source_signature` deleted); C2 every answer field a `Fact`; C3 r2types on `Basis` (with T); C4 references carry `Confidence` |
| **P5** Values as an index | the value view states lanes: `INSERT(w, x, k)` with `x` another value's bits at `k` grows `w`'s prefix through the lane, and an insert above keeps the bits below it; `ValueViews::low_lane_value` indexes, per root, the value that is exactly its low bits at each width; a register call argument reached as a wider root write names that value, its root write kept as `lane_of` and checked by the certificate (`swap_call`: `return scale(b, a);`); a load from bytes the program never writes folds to them, captured by r2engine where `TableBytes` says read-only and no literal store overlaps (`store(1.25, p)`, `x *= 0.5`); `r2il::eval` refuses an insert past the 128 carried bits | the renderer reads the views (D2): bound lane carriers (`__uint128_t XMM0_5 = (__uint128_t)bits(half(..))`), bitwise vector ops on a scalar lane (`andpd`/`orpd` in `floor_at`) and all-literal lane inserts (`xorps` zeroing) are D's, since folding the inserts to 128-bit literals first loses the lane the argument narrowing reads; a return slot reached as a wider root reads the views as arguments do (with LX's storage index); a load whose literal address SSA folds (aarch64 `adrp`/`ldr`) is captured on the restated preparation, as folded string literals are |
| **P6** One resolved body per function, as a query | [resolved-bodies](doc/adr-resolved-bodies.md); P6a the walk through dispatch tables is the `Walked` query; P6c1 a callee resolved as a root is; P6c2 return-only demand (`Resolved`, `Demand`, `result_owners`); `read_callees` kept as the one loop a root reads callees through (the database answers it with `Resolved`, a plain `Program` with each callee resolved alone) | its remainder is SM: a summary held once per session with demand bounded to what is held, so the 21 s transitive resolution measured for pumasim `main` is never paid by one `pdd`; parameters stay what each body proves alone |
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
      tables once, sparse `call_results` states, `version_at` in place of
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
      and 5.7% of 0pack 0x62ecf0's.
   7. `rebuild` merges to master when D's switch criterion and LX's and SM's
      exits hold.
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
- r2dec's loops (`placement`, `rules`, `recording`, `prepared_semantic`) are deleted by D.
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
