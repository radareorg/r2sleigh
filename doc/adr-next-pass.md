# ADR: the next pass is the cost model

Status: proposed (ROADMAP order after P4, 2026-10-07; decisions D22 to D26)

## The question

After P4 the engine renders 629 of 756 x86-64 and 600 of 756 aarch64
equivalence records and refuses the rest. Its cost is wrong: `pdd` time grows
as instructions^1.39 over the 47 functions with 300 or more instructions, a
`pdd` prepares every callee in full, one `pdd` makes 30.9 M allocations for a
218 MB peak, and each instruction is lifted at least twice. This ADR states
the cost each stage must have, derives it from the structure of the facts, and
names the owner and the item that reaches it. Every bound below is labelled
measured (a profile or the 2026-10 review) or read (from the code, by line).

## Symbols

Per function: `n` instructions, `B` blocks, `E` edges, `V` SSA values, `A`
memory accesses, `C` call sites, `L` storage locations the function names,
`h` the height of a lattice. Per program: `F` functions, `Ec` call edges.

## The model

1. **Every per-function fact is a least fixpoint of a monotone transfer over
   a finite-height lattice, on values or on storage locations.** Chaotic
   iteration on the def-use graph reaches it in at most `(V + E) · h` joins
   (Kildall 1973; Kam and Ullman 1976; sparse form Wegman and Zadeck 1991).
   `r2ssa::fixpoint` is that iteration with the budget `B · (h + 1)` or
   `(V + E) · h` stated by the caller (adr-fixpoint). A pass that costs more
   is recomputing an index it could read.
2. **The version of a storage location at a point is one lookup.** SSA
   renaming defines one version per `(point, register)`; memory SSA (K1)
   defines one per `(point, location)`. A walk backwards from a call site to
   find what reaches it answers a question the renaming already answered. The
   lookup is `O(log W)` for `W` writes of that location when each block keeps
   the versions it ends with and the reader climbs the dominator tree by
   preorder interval (the `readVariable` recursion of Braun et al. 2013, made
   an index).
3. **Interprocedural facts compose bottom-up over the call graph.** A summary
   is a function of the callee's body and its callees' summaries (Sharir and
   Pnueli 1981). Tarjan's components order the call graph in `O(F + Ec)`; a
   cycle is one fixpoint per component (adr-query-database, "cycles are
   values"). A sweep then prepares each body once: `Σ prep(f) + Ec · |summary|`.
   Preparing each callee again for each root costs `Σ_g indeg(g) · prep(g)`,
   which is the sweep multiplied by the mean in-degree.
4. **A lift is a pure function of `(address, mode, bytes)`.** It is a query
   (adr-query-database), paid once per byte revision, and the decoder's
   context is state the bytes do not change. A session that lifts an
   instruction twice, or rebuilds the context between two decodes, pays for a
   fact it holds.
5. **Type inference is unification plus one meet per class.** Union-find with
   a lattice meet is monotone, so constraints found late (a pointer base seen
   through an access) join the same solver; a restart from an empty arena
   computes the same least fixpoint at `O(A)` times the cost. The bound is
   `O((V + A) · α(V))` (Steensgaard 1996 for the almost-linear unification;
   the meet adds `h` per class).
6. **Control structure is the dominator tree.** Placement is total in
   `O(B + E)` (adr-structure-dominator-tree §4). Each readability rewrite
   decreases a stated measure (labels, duplicated blocks, text) and is checked
   by the `I_S` certificate in `O(B + E)`, so the quality layer costs
   `O(k · (B + E))` for `k` rewrites, `k` at most the label count.
7. **Rendering is one walk per stage and never retries.** With refusal in
   place of retry, cost is a function of the input alone, and output does not
   depend on the order failures are found (adr-decompiler-rewrite).
8. **A dataflow state is sparse.** A forward problem whose transfer touches
   `k` cells per block costs `O(B · k + phis)` with a sparse state and
   `O(B · V)` with a dense one copied per block. `fixpoint::sparse` is the
   sparse form; `fixpoint::forward` with a dense `IdMap` state is the dense
   one.
9. **Allocation count is a function of the index count, not of `V`.** One
   arena per function, freed at once, and every dense index sized from the
   seal's counts, gives `O(passes)` allocations per function.

Determinism follows from 1 to 9: every index iterates in dense-id order, every
fixpoint is a least fixpoint and so order-independent, and no stage retries.

## Measured against the model

| Workload | Measure | Cause | Bound today | Source |
|---|---|---|---|---|
| sort 0x3f50 `pdd` 11.8 s, 257 MB | 35 to 42 % preparing 114 callees in full, each with a full r2types run | model 3: depth-1 preparation per root; `CalleeReads` is held per `(address, thumb)` (program/analysis.rs:125) but its value is a full preparation plus `CalleeFacts::derive` (native.rs:906, lib.rs:1218) | `Σ indeg · prep` | measured, review item 5 |
| pumasim `afl` 29.1 s | 36 % in `SleighProxy::clearCache`, 70,543 context rebuilds at 140 µs | model 4: the bridge rebuilds the context database and re-parses the pspec on every non-contiguous decode (bridge.cc:170; `clear_decode_cache` at disasm/mod.rs:2211 on every `lift`) | `O(decodes)` rebuilds | measured, review item 4 |
| every analysis | each instruction lifted at least twice: the walk (body.rs:462) and `lift_owned_function` (native.rs:1723), a third time when restated (native.rs:1254) | model 4: no `Lifted(address)` query | `2n` to `3n` lifts | read |
| every lift | `Varnode` 112 B, `R2ILOp` 464 B, `OpMetadata` 104 B in a `BTreeMap<usize, _>` per block; `op_metadata` lookups are 3.3 % of 0pack `pdd` self time | model 4: a varnode carries nine optional metadata fields the machine profile already states (metadata.rs:78) | 10 × a P-code op | measured (`size_of`, 2026-10-07; opack.report) |
| sort `pdd` | 30.9 M allocations, 6.5 GB churned for a 218 MB peak; `RawVec::finish_grow` 40 % of bytes, `IdMap::insert` 728 MB; jemalloc alone 15 to 36 % faster | model 9: per-pass fresh vectors and maps, indexes grown by insertion | `O(V)` allocations per pass | measured, review item 6 |
| 47 functions of 300+ instructions | `pdd` time grows as `n^1.39` | models 1, 2, 8: the passes below | superlinear | measured, review |
| r2ssa `boundaries` | one reaching walk per call site per carrier, a fresh memo per query, the path map cloned per block step (semantic/shared.rs:990, 1022, 1079) | model 2: the storage version at a point is walked, not read | `O(C · carriers · B²)` | read |
| r2ssa `call_results` | `fixpoint::forward` with an `IdMap<ValueId, _>` state cloned per block visit (certificates/call_results.rs:46 to 69) | model 8 | `O(B · V)` time and memory | measured, review item 7 |
| r2ssa `liveout`, `liveness` | a BFS per return per storage (liveout.rs:69), a walk per value (liveness.rs:398), `FunctionLiveOut` once per candidate register (recover_interface.rs:697) | model 1: one backward liveness over locations, once (F2.2) | `O(R · S · B)`, `O(V · B)` | read |
| r2ssa `promote` | a backward walk per access with recursion to depth 8 (promote.rs:83, 135, 144) | model 2 | `O(Σ k²)`, a silent cap | read |
| r2ssa twice | `DeadPhis` (semantic/mod.rs:344, stage.rs:351), formals (stage.rs:216, boundaries.rs:946), `FunctionLiveOut` (function/mod.rs:570, semantic/mod.rs:261), `class_values` (values.rs:192, function/mod.rs:2631), `ValueViews` rebuilt by liveness (liveness.rs:160); the collector twice with no interface (recover_interface.rs:1012, stage.rs:323) | one fact, one owner | 2 × | read |
| r2ssa silent caps | depth 8 (promote.rs:144), 16 (predicates.rs:374), 32 (expressions.rs:548), a hop cap (optimize.rs:974), a cycle break (forward.rs:198) | D11: a cap that keeps a partial result silently | partial results | read |
| r2types | `solve_evidence_types` 3 times per function, signedness 6 times, the arena cloned and re-solved until pointer bases stop (evidence.rs:93, 672: at most `2A + 1` rounds), `named_blocks()` copying the function twice, `structs.rs:812` uncapped, `arrays.rs:105` and `globals.rs:160` stopping at 6 rounds; 17 % of 0pack `pdd` inside callee reads (`CalleeFacts::derive`) | model 5 | `O(A · (V + A))` | read; measured share (opack.report) |
| r2dec | four retry loops, about 51 whole-body walks and one `CFunction` clone per attempt (lib.rs:2933, 3558; placement/mod.rs:3430); `gap_closure_from_seed` 49.7 % of the pumasim Gui constructor before P4's `GapIndex`; `finish_splitting` 89 % of `pe/65535sects.exe` before H | models 6, 7 | attempts × 51 walks | measured (puma.report, pe2.report) |
| query database | `Analysed` and `Sealed` hold one entry, `Rendered` 16, `Walked` 64, eleven tables unbounded by entries; a second libz pass re-prepares 368 bodies; `prepare_restated` scans every table per block (native.rs:1657) | capacity by entries, not bytes | a second sweep costs the first | measured, review item 9; read |

## Decisions

| | Decision | Owner | Item |
|-|---|---|---|
| D22 | Every pass is an index with a stated bound. A per-function pass costs `O((V + E) · h)` or says at its definition why it cannot. The storage version at a point is an index (`version_at(point, location)`, model 2), and a walk that re-derives it is a defect. A dataflow state is sparse (model 8). A fact computed twice has one owner. The five silent caps become stated budgets with typed refusal. | r2ssa (F2's index layer) | LX |
| D23 | Summaries compose over the call graph. A body is prepared once per session at summary grade (interface, preserved carriers, reach, result, memory effects, signature) and held; a root reads held summaries; a root's demand beyond its direct callees reads only what is already held (`Db::held`, the `ComesBack` mechanism), so a `pdd` never pays a transitive closure. Components are solved on the fixpoint driver. | r2engine (the query), r2ssa (the summary grade) | SM |
| D24 | The lift is a query per address over a compact IL. `Lifted(address, mode)` is held under a byte budget; the Sleigh context persists across decodes and only the disassembly cache is cleared; a varnode is `(space, offset, size)` and its metadata is the machine profile's, read by `(space, offset)`. | r2sleigh-lift, r2il, r2engine | PF |
| D25 | Types are one monotone system: union-find with one lattice meet per class over dense ids, incremental, with no restart and no round cap. The confidence-scored second system (`structs`, `arrays`, `globals`) is deleted; what it found that the lattice cannot state is a residual with its reason. | r2types | T |
| D26 | Allocation is budgeted. One arena per function, dense indexes sized at the seal, a global allocator chosen by measurement, and the allocation count of the named workloads gated beside time and peak RSS (D19). | r2s (allocator), r2ssa (arena, sizes) | PF |

## The algorithms chosen, and the ones not

| Stage | Chosen | Bound | Not chosen, and why |
|---|---|---|---|
| Lift | `Lifted(address, mode)` query; the walk reads it; compact IL | once per byte revision, `O(1)` per read | a whole-program lift cache in bytes: 464 B per op makes pumasim's 2.5 M instructions tens of GB; the budget and the compact IL make residency cheap |
| SSA | iterated dominance frontier with a live-in prune (Cytron 1991, pruned by Choi 1991), CHK dominators | `O(E · d)` dominators, `O(E + Σ DF)` placement | Braun 2013 direct construction: it needs no dominators, but the dominators are an index every later pass reads, so the saving is the construction alone |
| Frame and memory | promotion as an SSA rewrite (P4), memory SSA on `fixpoint::forward` for what is not promoted, one storage index | `O(B · L_live)` once; `O(log W)` per lookup | Steensgaard or Andersen points-to over the whole program: a stack object is reached only through what escapes it (the frame model's rule), so per-function reach with callee summaries is exact where it answers and refuses where it does not |
| Values | strided intervals on the sparse driver with widening at the DFS back-edge phis (doc/ssa.md) | `O((V + E) · h)`, `h ≤ 2 · 64` per value | a solver (SMT) for ranges: no consumer proved its need, and a solver's cost has no `h` |
| Interprocedural | held summaries over the component DAG, demand bounded to what is held | `Σ prep + Ec · |summary|` per sweep | IFDS or IDE (Reps, Horwitz and Sagiv 1995): `O(E · D³)` for a distributive problem over a domain `D`; the facts here (slots, reach, results) are not distributive, and a summary per body is what the renderer reads |
| Types | union-find and meet, incremental (model 5) | `O((V + A) · α)` | retypd (Noonan 2016): polymorphic subtyping with a saturation step that is polynomial but cubic in practice; its gain (recursive types) is P9's exit, reachable as a later layer over the same constraints; TIE's constraint solving restarts |
| Structuring | dominator placement, certified rewrites (SD) | `O(k · (B + E))` | DREAM's condition-based refinement (Yakdan 2015): goto-free, but its conditions grow with nesting and its correctness is not checked against the CFG; rev.ng's comb duplicates to reach reducibility, which the certificate admits only with a complete out-edge set per copy |
| Terms | directed rewriting with a termination measure and a proof per rule (r2rewrite) | `O(terms · rules applied)` | equality saturation (egg, Willsey 2021): saturation is unbounded without a scheduler, and extraction ties break by cost, not by id, so determinism needs a second rule |
| Render | the D pipeline, one walk per stage, no retry | `O(tree)` | the journal: a transaction log over a tree it rebuilds is the retry loop |
| Database | the red-green query database with capacities in bytes | `O(deps)` per revalidation | salsa: no byte-range inputs (adr-query-database); Datalog (Soufflé, ddisasm): whole-program relations are the opposite of demand-driven, and a rendering is not a relation |

## Predictions

Each is a prediction, to be measured by the item that owns it.

| Workload | Today | Cause removed | Predicted |
|---|---|---|---|
| pumasim `afl` 29.1 s | Sleigh context 36 %, allocator 15 to 36 % (27.2 to 17.4 s measured with jemalloc) | PF | under 12 s |
| sort 0x3f50 `pdd` 11.8 s | callee preparation 35 to 42 %, Sleigh 0.7 s, allocator 20 % of self time | PF, SM | under 5 s; under 2 s with LX and D |
| ls `main` `pdd` 5.9 s | the same | PF, SM, LX | under 1.5 s |
| pumasim Gui constructor 780 MB | dense states `O(B · V)`, journal copies | LX, D | under 250 MB |
| `pdd` exponent 1.39 | the quadratic passes in the table | LX, D, T | 1.05 or less |
| a second sweep costs the first | capacity by entries | PF | the second sweep pays renderings alone |

## Items

- **PF** (performance foundation, r2sleigh-lift, r2il, r2engine, r2s): PF0 the
  Sleigh context persists and the specification loads once; PF1 `Lifted` as a
  query with the compact IL and the profile-owned metadata; PF2 the allocator,
  one arena per function, indexes sized at the seal; PF3 capacities in bytes;
  PF4 D19's budgets (time, peak RSS, allocation count) as the CI timing job.
- **SM** (summaries, r2engine and r2ssa): the summary grade of preparation;
  `Summary(f)` held; components on the driver; demand bounded to what is held.
- **LX** (linear per function, r2ssa): the storage index; the eight passes in
  the table rewritten to their bound; each twice-computed fact given one owner;
  the five caps made budgets; F2.1, F2.2, F2.4 and F2.5 land here, and K's rest.
- **T** (types as one monotone system, r2types): the incremental solver, the
  second system deleted, `FunctionTypeFacts` as indexes over dense ids, C3's
  r2types part, and P9's struct pointers as its exit.

Their order and the rest of the program are in ROADMAP.md.

## Citations

Filled from the 2026-10-07 survey where the source states the bound; a claim
whose source hedges it is not cited.

- Kildall 1973, "A unified approach to global program optimization": the
  lattice framework and the iteration bound.
- Kam and Ullman 1976, "Global data flow analysis and iterative algorithms":
  convergence of chaotic iteration in `h` rounds for monotone frameworks.
- Wegman and Zadeck 1991, "Constant propagation with conditional branches":
  sparse (SSA edge) iteration, `O(V + E)` per height.
- Cytron, Ferrante, Rosen, Wegman and Zadeck 1991, "Efficiently computing
  static single assignment form": iterated dominance frontiers; Choi,
  Cytron and Ferrante 1991 for the pruned form.
- Cooper, Harvey and Kennedy 2001, "A simple, fast dominance algorithm".
- Braun et al. 2013, "Simple and efficient construction of static single
  assignment form": the `readVariable` lookup that the storage index makes an
  index.
- Sharir and Pnueli 1981, "Two approaches to interprocedural data flow
  analysis": the functional (summary) approach.
- Tarjan 1972, "Depth-first search and linear graph algorithms": components in
  `O(F + Ec)`.
- Reps, Horwitz and Sagiv 1995, "Precise interprocedural dataflow analysis via
  graph reachability": IFDS, `O(E · D³)`.
- Steensgaard 1996, "Points-to analysis in almost linear time": unification
  with union-find.
- Noonan, Loginov and Cok 2016, "Polymorphic type inference for machine code"
  (retypd).
- Yakdan, Eschweiler, Gerhards-Padilla and Smith 2015, "No more gotos"
  (DREAM).
- Willsey et al. 2021, "egg: fast and extensible equality saturation".
