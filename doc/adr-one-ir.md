# ADR: one IR, indexed once

Status: in progress (ROADMAP F2, decisions D11–D12)

## Decision

The sealed IR is the graph, which owns each operation once after the seal;
the function keeps what is about the function (its CFG and terminators,
dominators and loops, origins, written lanes, premises), and its blocks are
the builder's, dropped at the seal (amended 2026-10-12, below). Everything
else is an index over their ids. Every rebuilt graph, liveness pass or side
table answers a question the IR already determines, and each copy is a place
for two answers to disagree.

- **Dense identity.** `OpId`, `InstId`, `ValueId` and `BlockId` are dense
  `u32`s fixed at seal. Facts about them live in `r2ssa::dense`, generic over
  the id type so a value fact cannot be indexed by an instruction: `IdVec`
  (every id), `IdMap` (some ids), `IdSet` (bitset) and `Csr` (adjacency).
  Iteration is in id order, so it is deterministic by construction.
- **No entity-keyed maps.** A `BTreeMap`/`HashMap` keyed by `SSAVar`,
  `ValueId`, `InstId`, `BlockId` or `OpId` is not allowed in r2ssa, r2types or
  r2dec; the `entity_keyed_map` Dylint enforces it. `SSAVar` is a value's
  presentation, and nothing is keyed by it. Exceptions say why at their item.
  The ones that stay: a few ids attached to one entity (a certificate's member
  set, a return block's values, a component's liveness segments, an affine
  form's terms), where a dense map would cost O(values) per entity; the
  renaming, lane and value-table index maps, which run before the value table
  exists or are its interning index; the per-block value-range maps, which P5
  rebuilds as an index.
- **One index layer.** `Sealed` owns a `FunctionIndex`; each index is computed
  at most once, on first use, from the IR and the indexes it declares as
  inputs: structure (RPO, dominators with frontiers, loops, def-use, use
  sites), values (views, constants and ranges, written lanes, demand),
  lifetime (one liveness model over locations, storage spans) and memory (the
  frame model, memory SSA). A pass reads the index; it never builds its own.
- **Analyses are declared.** An iterating index runs on the fixpoint driver
  (doc/adr-fixpoint.md) with its lattice, height and transfer over dense
  cells. Certificates are views over indexes plus the decisions only they make.
- **A builder before the seal.** `Lifted` and `Prepared` are a mutable
  builder with an incremental def-use, so the optimiser and demand pass edit
  through plans without a graph; the seal freezes it. No graph exists before
  the seal.
- **Other representations become indexes or go.** The machine projection and
  the term arena become indexes; the binding plan and journal go with R
  (doc/adr-renderer-printer.md).
- **Operands are ids.** The function's blocks hold `SSAOp<VarId>` over one
  `ValueTable` (id, storage, width, version, name). `VarId` is the function's
  own id, minted while it is edited; the graph's `ValueId` numbers the sealed
  values in first-seen order. They are distinct types, mapped by a dense
  vector. A plan that names a variable not yet in the table mints it through a
  `Minting`, and asserts the table length it was made against.
- **Cost.** Seal O(n log n) once; each index O(n), or O(n × height) for a
  lattice analysis, once per sealed function; every lookup O(1). If F2.3 needs
  semantic changes rather than re-keying in more than about 40 files, stop
  and reassess.

## Done

- F2.0 (`15ac7a9c`): `r2ssa::dense` and the `ENTITY_KEYED_MAP` Dylint.
- F2.1, in part: `DomTree` is Cooper–Harvey–Kennedy over dense RPO numbers with O(1) `dominates` (`15ac7a9c`); natural loops are one index read by loop facts and placement (`8741ba40`); `SsaQueryIndex` is deleted (`f634efbf`); r2dec's placement reads the function's `domtree()`.
- F2.2, in part: liveness is computed once, after the boundaries that refine it (`09f23ac1`); merges are pruned by pre-SSA liveness, closing the temporary and flag half of #56 (`f9111a28`).
- F2.3 stage 1 (`94bc999f`): `SSAOp<V = SSAVar>` with one operand `map`.
- F2.3 stage 2 (`39f44fec`): the graph's payload is `SSAOp<ValueId>`.
- F2.3 stage 3 (`3aaaca78` for 3a): `SSABlock<V>`/`PhiNode<V>` generic; blocks hold `SSAOp<VarId>` over the `ValueTable`; fixtures write by name through `NamedBlockMut`, passes through `BlockMut`.
- F2.3 stage 4: the optimiser runs on ids; `VarKey` is deleted; SCCP's lattice is an `IdVec`, its uses a `Csr`; plans are over ids.
- F2.3 stage 5a (`99f92add`): `IdMap` packs its entries behind a presence bitset.
- F2.3 stage 5b: prep facts are indexes over sealed values; `ValueViews<I>` is generic over a dense id; stack, entry and indexed roots and formals are `IdMap`s solved on `fixpoint::sparse`.
- F2.3 stage 5c: compare definitions are `IdMap<ValueId, _>`; lifted storage is a `ValueTable` column; seal passes that take the first match read one snapshot ordered by variable, so the match does not depend on interning order.
- F2.3 stage 5d (`074b464d`, `e95ed4be`, `d03f2a46`, `5c746e2f`, `d5332f02`): every function-wide r2ssa map keyed by `ValueId`/`InstId` is dense; `CallSiteFacts::by_inst` is the one call-instruction-to-site map.
- Provisional preparation (`74bf9088`, `5b1a9206`): a function with no stated interface is built once, from what is known before construction; recovery is invariant under lane rooting (`ByteMask::extent_bytes`).
- F2.6 (`ef1ff6a2`, `5f49496a`): `entity_keyed_map` is denied in r2ssa and r2types, with a CI job; signedness is one core over ids (`c30eb1d0`); `Written::is_conventional_extension` replaces register-name matches.

## Left

- F2.1: a `FunctionIndex` on `Sealed` holding RPO, dominators, loops and def-use, and the test-only graph builds replaced by it. Exit: no `SsaGraph` built outside the seal.
- F2.2: byte-granular liveness over locations (a lane write every reader sees whole defines the register), `ValueLiveness::compute_with_relocations` and r2dec's relocated liveness folded into the one model, #47 and #50. Exit: one liveness model, those issues closed. F2.2b is built (below); F2.2a and one value liveness per seal are open with their facts.
- F2.3 transitional readers, left over from stages 4 and 5: `SSAFunction::named`, `named_block`, `named_blocks`, `named_ops` and `SsaGraph::named_op` serve readers still keyed by name; r2types' local struct and stack-slot analyses read named blocks and ask the frame through `FrameRoots` (P9 owns their move); r2dec's prepared semantics asks through `value_of` and `canonical_root_var` until the printer reads values. Exit: those accessors deleted.
- F2.4: the builder with an incremental def-use. The seal still builds the graph twice when the demand pass releases a base (`function/stage.rs`), and the optimiser rebuilds its definition maps once per pass, O(n), until a pass measurably needs better. Measured (2026-10-05): the second build happens in 179 of 1261 census seals and costs at most 10 ms of a 2.7 s `pdd` on the largest pumasim function (92k instructions); interface recovery's duplicate build is gone. Exit: one graph build per function, when a measurement needs it.
- F2.5: machine projection and term arena as indexes. Exit: no per-round rebuild.

## The op after the seal (plan, 2026-10-12; amended the same day)

Measured (dhat, 0pack `pdd @ 0x58e3d0`, render peak 175.4 MB at #179): each
operation is held twice through render.

| Encoding | At the peak | Readers after the seal |
|---|---|---|
| The function's `SSAOp<VarId>` (`block.rs`), its arena (`arena.rs`) and value table | 5.0, 4.6 and 4.8 MB | 30 files (27 read operations or phis): 22 in r2ssa (boundaries 16 lines, shared 14, interproc 16, liveout 7, reaching 6, ...), r2types' one `named_blocks` copy (6 files), r2dec `render/control.rs`, r2engine `native.rs` |
| The graph's `GraphInst` array (`SSAOp<ValueId>`), inputs and value table | 11.6 and 6.2 MB | 235 payload lines in 55 files and 249 input lines in 52, of which 216 signatures take `&SsaGraph` alone |

The plan as first written (the graph indexes the function's operations) would
hand every graph-only reader a way back to the function: a shared handle in 55
files. The graph already states what the function's post-seal readers read
(operations in order, phis with their sources, block extents and edges, a
variable's spelling and storage, an instruction's `OpId` and machine
instruction, the formal projections and roots). So the decision is reversed in
direction and kept in substance: **after the seal the graph owns each
operation once, and the function's blocks are the builder's**, dropped at the
seal. The function keeps what is about the function, not its operations: the
CFG and its terminators, dominators and loops, the arena's origins, the
written-lane record, compiler-inserted and supervisor facts, premises and the
stack pointer.

1. A sealed function exposes no block operations (a type: `Sealed` has no
   `blocks()`), so the compiler lists every reader. The 30 files re-key from
   `VarId` to `ValueId` and from (block address, operation index) to `InstId`
   runs (`insts_between`); r2types' `named_blocks` copy is spelled from the
   graph (P9 still owns its move off names).
2. Three readers need a decision first: the validator (`validate_ssa_function`
   runs on the function's blocks after the final build, `stage.rs:222`) runs
   before the drop; the integrity check of a phi's storage against the value
   table (`integrity.rs:508`) compares against the graph's; the lifted-only
   origin (`reaching.rs:73`) reads the arena, which stays.
3. The value table goes with the blocks once no `VarId` outlives the seal
   (the function's `formal_*` maps have graph twins).

Step 1 is done (#182): the post-seal readers read the graph, and r2types'
named copy is spelled from it (`SsaGraph::named_blocks`, checked equal to the
function's by `the_graph_spells_the_blocks_as_the_function_does`). Step 2 is
done (#183): the seal drops the blocks of operations after validation, and a
read of them is a debug assertion; a type in its place is left.

Exit: one encoding of each operation live after the seal, the census
byte-identical at each step, about 10 to 14 MB of 0pack's peak (5 to 8%).
Bound: each step re-keys in `O(n)`. Stop rule: past 40 files or any semantic
change beyond the three named above, stop and report.

## Condensation (D412, 2026-11-14)

One Tarjan search owns every strongly connected component in the workspace:
`r2ssa::dense::Condensation` over a `Csr<I, I>`. It returns each node's
component, numbered in close order (an edge `u → v` has
`component(v) <= component(u)`), each node's depth-first finish index, each
component's members ascending, and whether a component is cyclic (several
members or a self edge). The start order and the row order of the successors
fix every index, so two runs on one graph agree.

`dense::Reached` numbers a graph the engine states on demand (owner edges,
forwarders): it asks each node's successors once, in the preorder the search
from the root takes, so the query asks run in the order the deleted
`resolved::Search` asked them; nodes are numbered by ascending key, so members
come out in address order.

Cost: `O(V + E)` visits, metered (`Condensation::visits`, and
`AnalysisStats::condensed` for the program graphs). `Reached` adds `O(V + E)`
hash probes and `O(V log V)` to number. The engine search it replaced kept
`BTreeMap`s, `O((V + E) log V)`.

Deleted: `view::strongly_connected_components` (value views and unstructured
cycle blocks read the condensation), `resolved::Search` (resolved components
and component forwarding), and interproc's Kosaraju (`compute_summary_sccs`).
Readers to come: relift order (component and finish rank), callee summaries,
the WTO (D415) and the rescans' no-kill union (R3).

## Register classes (rescans R4, 2026-11-14)

`boundaries::RegisterWalk` answers every unproven machine return's reaching
register definitions (D254). The register bytes a function writes, the
machine-state carriers left out, are cut into classes: two bytes share a class
where no instruction writes one without the other, so they have the same
writers and the same reaching definitions everywhere. `refine` cuts one write
at a time: the bytes a write covers of a class it covers in part leave for a
new class. Each write costs its width; classes are then numbered by their
first byte.

Each block keeps the last writer of each class it writes and one walked set,
built once for every return. A (block, class) pair is walked once per return,
and a visit costs its set's words and the classes the block writes of it:
`O(E x R' x R'/64 + |live| log R')` per return for `R'` classes. Only the
blocks a walk marked are cleared after it. The test `register_class_visits`
grows `2^depth` leaves, each writing the result and a register across its top
byte, and the class visits grow as `T log T`.

D438 (2026-11-15) builds the walk without a search or a list per instruction:
`class_of` is indexed by register offset from the lowest written byte, a carrier
or unwritten byte `UNWRITTEN`, so a write's bytes are a slice found in `O(1)`;
after refinement each instruction's classes are listed once, deduplicated by a
last-lister stamp per class, into one `Csr` dense over `InstId`, which the
block pass and the exit scan read. A write's set of placed bytes, and so every
class, is the one `partition_point` over the sorted bytes gave; a row holds the
same classes in first-byte order, and both readers ignore order. Build
`O(I x w + span)`, one buffer per walk (`REGISTER_CLASS_LISTS`).

## Reaching frame writes (D365, 2026-11-14; D427, 2026-11-15)

`frame_reach::walk`'s `rewritten` names the loaded places a call may write
before the load reads them. Invariant: a load of place `p` at width `w` reads a
call's write iff some path runs from a non-tail call whose spans overlap
`[p, p + w)` to the load with no exact store of `p` at its one width between.
A place loaded or stored at two widths has no killing store.

- Keys: one per loaded `(place, width)`, sorted; `P` keys, `P / 64` words.
- Gen: a call's spans, each found by binary search and filled by word:
  `O(S (log P + P / 64 + W))` per call for `W` keys starting below a span.
  Every non-tail call also writes `[i64::MIN, base)`: its return address and
  its callee's frame lie below its pointer, so a place there never folds
  across it (`mov [rsp-16], 5; call rdi; mov eax, [rsp-16]`).
- Kill: an exact store of a one-width place clears its key.
- Solve: `out = (in & !kill) | gen` on `fixpoint::sparse` over the walk's
  nodes in reverse postorder, the successors as readers. The transfer is
  monotone and a cell only gains bits, so it moves at most `P` times; the
  driver refuses past that and the walk denies every place. A pass costs
  `O((B + E) P / 64)`; reverse postorder settles in `d + 2` passes for loop
  depth `d`.
- Replay: each block once from the join of its predecessors' outs, in index
  order, reading each load's bit: `O((B + E) P / 64 + A log A)`.

Equivalence: with no kill the solution is the old path union per key, so the
new set is a subset of D365's. A place in the difference has every load
reached only by a store executed after the last covering call, so no load
reads a callee's write, and promotion's reaching store for each load is
unchanged. The union's one-pass condensation (D426 R3) was exact only for a
transfer that kills nothing, and is deleted with its tests. The tests
`reaching_rewrites_is_the_kill_aware_union_over_every_path` (200 random graphs
against a path search) and `reaching_rewrites_grows_linearly_in_the_blocks`
(a chain and a cycle) replace them.

### D432 as built: a reloaded format is its stored literal (2026-11-15)

Fact F (round-6 ruling, section 2): a cited printf site whose format register
is a load of frame place `q` takes literal `L` when every store to `q` stores
the constant `L` at `q`'s one width, a store reaches the load on every path
from entry, `q` is eligible apart from `rewritten`, and no covering call write
reaches the load.

- Candidates (`reloads`, per round, body facts only): a non-tail call whose
  site the machine context names as a cited printf its own block folds no
  literal for (`reloaded_format_register`); the `CallUse` of that register
  before the call; the load defining it (`Definitions::load`) in the call's
  block; every store to its place a constant (`Definitions::constant`) and one
  constant. `O(C x u + A log C)`.
- Gate (`conditional`): the place is a candidate no overlap, save,
  declaration, handed address or escape keeps (`kept`, shared with
  `eligible`), the entry is not re-entered, and the context states the call's
  counted row for `L` (`reloaded_call_reads`: `L` immutable, its text a
  literal, `counted_reads` places it). `handed` keeps the pre-verdict read
  area, a superset.
- Keys: `P` loaded keys, then one unset key per gated place. The root enters
  with every unset key set; a write covering `q` sets it; an exact store of
  `q` clears it. Unset bit clear at the load is "a store reached on every path
  and no covering write after it".
- Conditional gen: the call writes `bounded | (unset at its load ? extra : 0)`,
  `extra` its every-location spans less `bounded`. Monotone: more set bits
  give more written bits. A block holding such a call is evaluated event by
  event; every other block keeps its `(gen, kill)` pair.
- Solve: the same `fixpoint::sparse` from 0, so the least fixpoint. Height
  `P + Q`; a pass costs `O((B + E)(P + Q) / 64 + R (P + Q) / 64)` for `R`
  conditional calls. Soundness of the least fixpoint is the ruling's
  induction: the first bounded site that writes past its counted area read
  its unset bit clear, so every earlier call kept `q` and the register held
  `L`.
- Verdicts: `FramePoints::formats` (instruction to `L`). `FrameWalk::restate`
  refuses a restatement whose verdicts move. The builder settles them into the
  context (`settle_reloaded_formats`) after the preliminary build and after
  the final one: the site's `format_tails` entry and its column row restated
  through the same `stated_call_reads`. Nothing between the walk and the
  settle reads a row (`fold_loads`, the three decisions and `prepare` read
  none); a walk after the settle is a debug assertion.
- Meter: a reloaded row (one per gated reload per decided round, one per
  settle) counts as `reloaded` in `call_reads_built`, apart from the column's
  one build per site that D436's gate holds. `reload_bound` counts each
  decided round's reloads and each settle's formats before their rows;
  `a_reloaded_format_builds_one_row_per_reload_a_round_decides` asserts
  `reloaded <= reload_bound` (16 of 16 on its fixture; a row restated at every
  site, every round, reads 52 of 16).
- Test: `reaching_rewrites_with_reloads_is_their_least_path_solution`, 300
  random graphs with a seed and reloads, against the path search iterated from
  no unset reload to its fixpoint.

## D447 as built: a call a decided branch cuts off (2026-11-16)

Fact: a call or tail in a block that a branch over constants cuts off reads and
writes nothing. Owner: r2ssa `StackArguments::of`, which drops each such call
before the frame walk reads its areas; the evaluator is
`crate::optimize::cut`, a child of the SCCP module so it calls SCCP's own
transfer (`eval_const_op`).

- Quantity: the blocks of the walk's calls.
- `cut(b) = cut(idom b) or edge_cut(idom b, b)`, one answer per block, by its
  position in `SSAFunction::blocks`, evaluated up the dominator chain from each
  call block. `edge_cut(d, b)`: `d` ends in a two-way branch with distinct
  arms, `b` is one arm, `d` is `b`'s only predecessor, and `d`'s condition is
  a constant choosing the other arm.
- Values: backward over `frame_address::Definitions` (the walk's own
  definitions index, dense by `VarId`), each variable expanded once on an
  explicit stack (unseen, busy, known). A merge is a constant only when every
  input is the same constant, pessimistic where SCCP is optimistic, so every
  cut is an SCCP cut. A load, call, `CallOther`, `CpuId`, `New`, a busy
  variable (a cycle) and a version-0 input have no value. The value vector is
  allocated at the first condition evaluated.
- Bound: `O(calls + blocks on the call blocks' dominator chains + slice
  operations)`; each block and each variable is visited once. No depth guard,
  no cap.
- Default-deny, each refusing every cut of the body:
  1. `SourceMachineContext::load_base()` other than `LoadBase::Linked` (D451).
     Under `Linked` the slide is 0, so a constant is the address it names
     (gABI chapter 5, "Base Address", quoted on `LoadBase::Linked`). Under
     `Slid` an image-relative constant compared with an absolute one is no
     constant; `Unstated` states nothing.
  2. A `CallOther` without output or an `Unimplemented` anywhere (SCCP's
     `after_unmodelled_effects`): an unstated effect may write what a
     condition read.
  3. No declaration of every block (`SSAFunction::unresolved_transfers` is
     `None`), or a kept block whose last transfer the source could not
     follow (`DeclaredSuccessors::unresolved_in`: the one chunk ending where
     each unresolved source block ends): an edge the graph lacks may enter a
     cut block.
- Tests: `load_base::a_tail_behind_a_compare_of_equal_constants_bounds_no_write`
  (red on e3ee40d1b), five stays-a-write tests (`Slid`, `Unstated`, a loaded
  condition, a kept unresolved transfer, `syscall`), `default_deny`'s row
  "unknown load base", and `optimize::cut::tests` for each refusal. With
  guard 1 removed three engine tests go red, with guard 2 one; guard 3 is
  bitten only by the r2ssa test, since a kept unresolved transfer in a
  rendered callee already writes the caller's slot.
- Records: 8 census goldens return to master 500216e6d, proof-line obligation
  counts only. On x86-64 the cut is in the callee `deregister_tm_clones`
  (`mov eax, __TMC_END__; cmp rax, __TMC_END__; je; ...; jmp rax`), so
  `__do_global_dtors_aux` reads one obligation fewer; on aarch64 zig's
  `__libc_csu_init` compares two `adr` of one address (`subs; b.eq`) and the
  `blr` loop is cut. DecBench's 17 binaries are `ET_DYN`, so none moves.

## F2.2 step 0: what liveness costs (2026-11-17)

Measured at master 718a898b2 on the Mac before any F2.2 code. Shares are samply
inclusive samples of a `--profile profiling` build (1 kHz). Counts come from a
scratch build that printed each `FunctionLiveOut::compute` call with its caller
(`#[track_caller]`) and each `ValueLiveness` build with its collection site; it
was not committed. Instructions and peak RSS are from a clean release build,
`/usr/bin/time -l`, median of 3.

| Command | Instructions | Peak RSS | `liveout::` | `liveness::` | `deadphi::` | `span::` | `demand::` | Union |
|---|---|---|---|---|---|---|---|---|
| pumasim `pdd @ 0x23fdf0` | 18.71 G | 255.0 MB | 0.09% | 2.95% | 2.24% | 1.79% | 0.81% | 6.89% |
| 0pack `pdd @ 0x62ecf0` | 13.06 G | 257.0 MB | 0.13% | 5.50% | 1.97% | 4.98% | 0.92% | 9.31% |
| bash `aa; pdd @ 0x2e630` | 13.48 G | 83.5 MB | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% |
| pumasim `aa; pdd @ 0x3b6b20` | 68.78 G | 261.7 MB | 0.02% | 0.29% | 0.22% | 0.10% | 0.02% | 0.61% |

| Command | `compute` calls | blocks walked | from `recover_interface.rs` | `function/mod.rs:1069` | `semantic/mod.rs:306` | `ValueLiveness` builds (recover / prepare) |
|---|---|---|---|---|---|---|
| pumasim `pdd @ 0x23fdf0` | 743 | 1,829 | 609 | 26 | 108 | 144 / 108 |
| 0pack `pdd @ 0x62ecf0` | 165 | 666 | 134 | 7 | 24 | 27 / 24 |
| bash `aa; pdd @ 0x2e630` | 79 | 51 | 45 | 27 | 7 | 7 / 7 |
| pumasim `aa; pdd @ 0x3b6b20` | 390 | 1,335 | 105 | 263 | 22 | 23 / 22 |

Per timed function: pumasim 0x23fdf0 (85 blocks) 8 calls walking 14 blocks;
0pack 0x62ecf0 (337 blocks) 3 calls walking 3; bash 0x2e630 (3 blocks) 13
calls walking 39; pumasim 0x3b6b20 (47 blocks) 9 calls walking 24.

What the measurement changes in the F2.2 plan:

- The live-out walks cost at most 0.13% of a command (1 of 763 samples on
  0pack; self 0.09% on pumasim). They visit a few blocks next to each return
  (3 of 337 on 0pack's function), so any index swept over every operation of
  every graph costs more than the walks it replaces.
- `ValueLiveness` is built twice per seal, over two graphs. The first build is
  the recovery collection (`PreparedFunctionFacts::collect_for_recovery`, site
  `recover`, `Certified::ReturnControls`) over the provisional graph, before
  the seal applies boundary constants and forwards copies. The second is the
  artifact's (`semantic/mod.rs:364`) over the sealed graph.
  `function/mod.rs:1569` is `#[cfg(test)] recomputed_liveness`, no production
  build. The recovery build's spans feed its loop facts (`semantic/mod.rs:385`);
  `obligation.rs:1220` seeds `LoopCarriedState` from their carriers;
  `DeadPhis::find_from` reads the obligations (`semantic/mod.rs:425`) and the
  return-control certificates read `DeadPhis` (`:455`); `recover_interface.rs`
  reads `facts.obligations` and `facts.certificates.machine_return_controls`.
- `release_undemanded_bytes` (`function/mod.rs:1069`) asks the live-out of the
  graph before the demand release; `semantic/mod.rs:306` asks it of the graph
  after. The two are the same graph only where nothing is released, and no
  `ValueLiveness` exists at the first.
- The liveness share that matters is the value liveness and its readers:
  `liveness::`, `deadphi::` and `span::` together reach 9.3% on 0pack.

Readers at 718a898b2:

- `FunctionLiveOut::by_return`: `liveness.rs:677` (`returned_blocks_by_value`),
  `recover_interface.rs:3177`, and `without` itself.
- `unresolved_blocks`: `recover_interface.rs` 1088, 1160, 1186, 1500, 1530,
  1604, 2123, 2152, 2256, 2272, 3100, 3160, 3192, 3232; `demand.rs:123`.
- `clobbered_blocks`: `recover_interface.rs` 1168, 1187, 1193, 1501, 1990,
  3234.
- `has_returns`: `recover_interface.rs` 1161, 1185, 1192, 1499, 1529, 1984,
  1989, 2151, 3099, 3195.
- `without`: `recover_interface.rs` 2149, 3166, 3191, 3230; `semantic/mod.rs:528`.
- `contains`, `iter`, `is_read`: `demand.rs` (`of_returning`), `deadphi.rs`,
  `function/dead_frame_stores.rs:107`, `semantic/shared.rs:1472`,
  `semantic/loops.rs:352`.
- `over_every_return`: `recover_interface.rs:3274`; `reaching`:
  `semantic/mod.rs:601`.
- `ValueLiveness`: `span.rs` (`StorageSpans::compute`, `ComponentLiveness`,
  `phi_is_unread`) at `semantic/mod.rs:371`; the test-only
  `recomputed_liveness`. The value liveness and spans are dropped after the
  collection (doc/adr-memory-model.md, decision 1).

## F2.2a and F2.2b as built (2026-11-17)

F2.2b, one value liveness with bytes. `ValueLiveness` holds the demanded
bytes of each value as a column (`ValueLiveness::bytes`), built by
`DemandedBytes::of_returning` before the liveness walk at `semantic/mod.rs:370`
and handed to the facts after the spans (`into_bytes`); the second
`demanded()` call at the end of the collection is deleted. A value no reader
needs a byte of holds no range. The witness is the closure itself
(`semantic/mod.rs` `demanded`): it starts at every operation with an effect
(`demand::has_effect` is an exhaustive match), every tail read, and every value
a return reads, which leaves out two kinds of return. A return whose result the
boundary states unproven reads no register (D340, `result_unproven` in the
return boundary), and neither does any return of an interface that returns no
register (`returns_no_register`); a value only such a return hands back is
listed by `FunctionLiveOut` and now holds no range. Reads the certified call
boundaries do not pass are left out (`unpassed_call_reads`). Where an exit
hands registers to code outside the graph (`exits_are_named`) no demand is
stated and every byte counts as needed. `DemandedBytes` is a dense `Vec<u64>` per value, where it was
an `IdMap<ValueId, ByteMask>`: held across the liveness walk, the map cost
15.7 MB of peak on pumasim 0x23fdf0 (+6.2%), the column costs nothing above
the peak. `ValueLiveness::interfering_lanes(graph, a, b)` answers D470: no
bytes where the ranges do not overlap or the two hold one content, the bytes
both have read where they are slices of one location, every byte where they
are two locations live at once; `O(segments of the two)`, no reader yet.
`release_undemanded_bytes` keeps its standalone `DemandedBytes::of` over the
graph before the release, where no value liveness exists.

Measured (Mac, release, median of 3, against 718a898b2; the range rule alone,
with the `IdMap` column, read -0.05%, -0.18%, -0.02%, -0.03%): pumasim 0x23fdf0
-0.257%, 0pack 0x62ecf0 -0.252%, bash `aa; pdd @ 0x2e630` -0.043%, pumasim
`aa; pdd @ 0x3b6b20` -0.098%; peak RSS -1.60%, -0.16%, -0.49%, -0.04%.
`pdd` is byte-identical on the 451 goldens, the 2,621 DecBench functions and
certification's selection (24 ELF binaries, 108 functions). Equivalence,
certification and `scaling.py` on contabo did not run: the queue held three
multi-hour jobs of other chains.

Open, with the fact that stopped each:

- One value liveness per seal. The two builds are over two graphs: the
  recovery collection's provisional graph and the sealed one. The recovery
  facts read the loop facts its liveness feeds (step 0, above), so dropping
  that build changes what `recover_interface.rs` reads; the next step is a
  proof that `LoopCarriedState` seeds cannot move `obligations.unmodelled`,
  `is_complete` or the return-control certificates, or recovery reading no
  loop fact.
- F2.2a, the exit reach read from an index. Built twice: an `ExitWrites` index
  of each block's writes, calls and merges, filled while the graph is built
  (`O(1)` per operation), with `FunctionLiveOut::compute` reading it by a block
  walk that scans no operation. On each build 64,176 old-against-new
  comparisons on DecBench and the 4 timed commands were equal, and the fused
  build kept `pdd` byte-identical on the goldens and DecBench. It costs
  more than the walks: Mac medians over four builds read pumasim `aa; pdd @
  0x3b6b20` +0.12% to +0.16% and 0pack +0.06% to +0.13% (gate +0.10%). The
  index is paid on every graph build; the walks it replaces visit 51 to 1,829
  blocks a command. The graph build moved 1.70% to 1.76% of samples; the rest
  is unattributed. The patch is kept outside the tree; no cache was added.

## D470 local classes: step 0 (round 16, design and proof)

**Withdrawn (round 17).** This design dropped copies at spell time and proved it by listing where
each r2dec pass assigns the class local; its three counterexamples share that cause. It is kept as
the record; "D470 as built" below replaces it, and `current_at` is not built (it had no other reader).

**Invariant I.** For every class `C`, member `m`, and point `q` where the rendered C reads `C`'s
local `L` to mean `m`, the last assignment to `L` executed on every path to `q` is `m`'s.

**Classes (r2ssa, `local_classes.rs`, built in the collection while `ValueLiveness` lives).**
Candidates are phi webs: a bound phi's output with each operand that is a bound instruction
output of the same canonical location and the same value type. Formals, constants, unbound
values and memory are never members. Two webs join only where no member of one interferes with
a member of the other (`interfering_lanes == 0`), checked by the linear class test of Boissinot,
Darte, Rastello, de Dinechin and Guillon (CGO 2009): the two member lists merged in dominator
preorder, each value checked against its nearest dominating member only. A value with no proof
is its own class. Storage: `class: Vec<u32>` by `ValueId`, members per class in preorder,
`O(V α(V) + Σ segments)`. Per class, `joins` is the iterated dominance frontier of its member
definition blocks (Cytron et al., TOPLAS 1991; Sreedhar and Gao, POPL 1995).

**`current_at(C, block, ordinal) -> Option<ValueId>`.** The nearest element dominating
`(block, ordinal)` among `C`'s member definitions and `C`'s joins: a member where that element
is its definition or a join holding one of `C`'s own phis; `None` where it is a join with no phi
of `C`, or nothing dominates. `O(log |C|)` by binary search in the preorder list.

**Every site that assigns `L` in the rendered C.**

1. A bound member's statement `L = e;`, printed at the member's SSA position: a block's
   statements are spelled in instruction order.
2. An edge copy into a phi `p` of `C` on `u -> v`, printed in the arm of `u`'s branch after its
   test, or after `u`'s statements on a single edge. The structurer moves a back edge's copies
   before a `do`/`while` tail test (fnv1a32's `rdi_1 = rdi_2;` before `while (...)`), see
   **Tests** below. It is dropped exactly when its operand `o` is a bound member of `C` and
   `current_at(C, u, end) == o`: `L` already holds `p`'s value on that edge. Otherwise it is
   kept and assigns `L` (an unbound operand, whose expression has no assignment of its own, or
   one outside `C`).
3. A parallel copy whose writes clobber its reads goes through `next_carrier` temporaries: each
   kept copy's operand is read before any write to `L`. With classes, a clobber is a write to
   `L` and a read of any member of `C` in the same parallel copy, compared by class, not by id.
4. The `input == output` edge assigns nothing; `L` holds `p` already (case 2's rule with `o = p`).
5. An arm no path reads (`arm_read` false) assigns nothing; `p` is read on no path from it, so
   no read reaches `q` through that edge.
6. A formal's entry value is the parameter's own symbol; formals are never members, so no
   class local is assigned at entry.

**Lemma (reaching assignment).** Where `current_at(C, b, k) = Some(m)`, on every path to
`(b, k)` the last assignment to `L` is `m`'s. Every assignment to `L` is at a member definition
(site 1) or on an edge into a block of `C`'s phis (sites 2 to 5), and every such block is in
`joins`. The nearest dominating element `x` of definitions and joins is the last of them on
every path to `(b, k)` (Cytron's renaming argument: an element nearer on some path would lie in
the dominance frontier closure, hence be an element dominating `(b, k)` nearer than `x`). If
`x` is `m`'s definition, the statement assigned `m`. If `x` is a join holding `p` of `C`, every
edge into it assigned `p`'s operand (kept copy) or held it (dropped copy, by induction in
dominator order on `current_at(C, u, end)`), or is an arm no path reads (site 5). Members do not
interfere, so no other member's definition lies between `x` and `(b, k)` on a path where `m` is
read. A join without a phi of `C` gives `None`: the value depends on the path.

**Reads and the reading point.** A read of member `m` prints `L` only where
`current_at(C, b, k) == Some(m)` at its reading point; otherwise it is not a variable and the
reader is bound (below). The reading point is where the text stands, not the SSA use:
- a statement's operands, forwarded subexpressions included, read at the statement's
  instruction `r`: `(block of r, ordinal of r)`. `Values.reading` holds the block today; it
  gains the ordinal of the statement being spelled, set where the attempt starts;
- an edge copy's operand reads at `(u, end)`;
- a test or selector reads at `(u, end)`, and is admitted only where no edge out of `u` keeps a
  copy into `C` (**Tests**).

A forwarded value `v` (unbound, its expression printed at its reader) whose expression reads a
member that `current_at` refuses at the reader is bound on the next attempt: it then prints at
its own SSA position, where its operands are current. This covers a read forwarded past a
redefinition, which SSA interference does not see.

**Tests.** A tail test the structurer prints after `u`'s back edge copies reads `L` after a kept
copy assigned `p`. The rule above refuses such a read where `u` keeps a copy into `C`; the
test's value is then bound, printed before the copies at its SSA position. A dropped copy
assigns nothing, so it does not block the test.

**Termination.** The spelling loop (`spell_function`) adds one instruction to the bound set per
refused read, and the set only grows: at most `|instructions|` more attempts, each `O(text)`.

**What r2dec owns.** It declares one symbol per class with bound members, named by the location
with a numeric suffix where two classes share it, ordered by smallest member id; it reads
`class` and `current_at`. It decides no interference and no class.

**Expected cost.** One pass over phi edges and one dominance frontier per class in the
collection; `current_at` `O(log |C|)` per read. Cause line: "D470: local classes, one pass over
phi edges and one dominance frontier per class".

### D470 step 0, review round 1 and the amended rules

Two reviews (the advisor, and an independent headless reviewer reading the code) found two
counterexamples to the section above. Witnesses and the rule that answers each:

1. **A copy moved off its edge.** The latch hoist (`r2dec/src/structure/latch.rs:139-146`,
   `:200`) prints a back edge's copies before the `do-while` tail test, so they also run on the
   exit path. Shape (independent review): outer header `r = phi(a, p)`, inner header
   `p = phi(r, x)`, latch `use(p); x = p + 1; if (t) -> inner else -> outer`; `C = {p, r}`, the
   copy `p := x` kept, `r := p` dropped. Text `do { use(L); Lx = L + 1; L = Lx; } while (t);`
   runs `L = Lx` on the exit, and the next `use(L)` reads 6 where `p = r = 5`. The hoist is
   allowed today only where no printed read of a copied symbol lies outside the loop; a dropped
   copy prints no read. **Rule:** a dropped copy stays in the tree as a statement that prints
   nothing and reads `L` on its edge, so the hoist's existing count (by symbol, and "the test
   reads none of what is written") sees it and refuses. A copy is then always on its edge.
2. **A refused read with nothing to bind.** `interfering_lanes` is 0 for `same_content` pairs and
   for two values of one location live at once with disjoint demanded bytes, so a member's
   statement can overwrite `L` while an earlier member is still read at its SSA use; `current_at`
   refuses, the reader is already bound, and the retry adds nothing (advisor: `m1`, `m2` of one
   content, `store(m1)` after `m2`; the bound "one instruction per refused read" fails).
   **Rule:** r2ssa joins two webs only where no member of one has a live range overlapping a
   member of the other, with no `same_content` or lane exemption (`ValueLiveness::segments`
   overlap, the strict test), and checks at build that each member is current at each of its
   SSA uses and phi-edge uses. Then at every SSA reading point `current_at` returns the member
   read, and a refusal arises only where r2dec prints an unbound value's expression after its
   SSA position. The retry binds the innermost forwarded value holding the refused read, which
   prints it at its SSA position: the bound set grows by one per attempt, at most
   `|instructions|` attempts.

Gaps the reviews named, each answered:
- Classes range over all values with one location and type; "bound" is r2dec's and grows per
  attempt. An unbound member's definition stays an element of `current_at`, so a read after it
  of an earlier member refuses (conservative); its edge copy is kept (site 2), so `L` holds the
  phi on that edge.
- Each phi and operand pair is a join attempt from singletons, under rule 2; a web with an
  interfering operand leaves that operand out (lost copy and swap stay two classes).
- `current_at(C, b, k)` counts elements strictly before ordinal `k`: a statement's own output is
  not current at its operands (`rdi_2 = rdi_1 + 1` reads `rdi_1`).
- A gapped copy assigns nothing and keeps its merge owed, so every read of that phi stays
  residual; any other member read past the join refuses, as the join is the nearer element.
- Reading points apply to the leaves of the rewritten term (`term_reads`), not the SSA inputs.
- Two phis of one class at one join cannot both be members: they are live at once at the join
  entry, which rule 2's strict test refuses.
- `tails.rs` and `guard.rs` statement motion: the same rule as the latch, a dropped copy is a
  read of `L` where it stands; any pass that moves a statement past it sees the read.
- A dropped copy still pays `owed` and accounts its phi in the ledger, so the proof line's
  counts do not move.

### D470 step 0, review round 2: open on a counterexample

The independent reviewer read the amended rules against the code: both round 1 witnesses are
answered, and one new counterexample stands, so no r2dec edit lands (round 16).

- **A dropped copy whose operand is a gapped merge.** `B0 -> B1 | B2`; `B1: a = e1 -> J`;
  `B2 -> J` with an operand r2dec cannot spell; `J: p = phi(a, g) -> K`; `B3: b = e2 -> K`;
  `K: q = phi(p, b); use(q)`. `C = {a, p, b, q}` passes the strict test. `B2`'s copy is a gap
  that assigns nothing; `J -> K` drops its copy (`current_at(C, J, end) == p`), so on
  `B0, B2, J, K` `use(L)` reads a stale value where today `read_name` prints a `NeverAssigned`
  residual (`values.rs:1303-1321`). Candidate answer: drop a copy only where `operand_alone(o)`
  spells the plain variable (owed 0, definition in scope); otherwise keep it with its residual.
- Gaps to answer with it: the silent statement's form (`CStmt::Empty` is discarded by
  `rotate::live` and `flatten`, and `latch::reads_of` counts only `CExpr::Var`; it must be
  counted by `Scan::read` and transparent to the arm shape tests `copies_of`, `is_break`,
  `is_empty`); reading points that are not SSA inputs (switch selectors, call-boundary
  arguments, return values, canonical term leaves) need the build check or a reaching-definition
  proof; the Tests rule's premise that a terminator never reads a bound member directly (shape:
  `movsxd rax, [tbl+rax*4]; jmp rax`); an unbound phi member's role in the Lemma; the closure of
  `arm_read` under dropped copies, asserted at class build.

## D470 as built: renaming under a text certificate (round 17)

r2ssa states which values are one location's successive contents; r2dec renames on the finished
text only where that text proves it. The proof names no r2dec pass.

**Classes (r2ssa, `crates/r2ssa/src/local_classes.rs`).** Every value starts alone. For each
merge in `InstId` order that `phi_is_unread` does not exclude, each operand that is an
instruction's or merge's output of the same canonical storage (register or temporary, one
width) joins the merge's class where `ComponentLiveness::interferes` is false, the smaller
component absorbed. A class is named by its smallest member. Formals, entry values, constants and
memory versions are never members. `O(V alpha(V))` finds plus the segment sweeps; a dense
`Vec<u32>` by `ValueId` on `PreparedFunctionFacts::classes`. It is a necessary condition only.
`StorageSpans` is a different fact: it joins op updates and merge sources of any storage.

**Theorem (renaming).** Let T be the finished tree, one symbol per value; G a set of symbols of
one C type; T' is T with every symbol of G spelled as one member L and each statement that then
reads `L = L;` deleted. Hypothesis H: for every statement W of T writing a member x, every other
member y live in T just after W makes W exactly `x = y;`. Then T and T' compute the same value at
every read. Proof, by induction over execution steps with the relation "every member live at the
current point of T holds L's value in T'": a read of a live member reads L; a write `x = e;`
reads equal values in `e`, and every other member live after it is its right side by H, so x, y
and L agree; a deleted `x = y;` leaves L, which held the live y. Base: no member is live at entry
(a member live at entry is refused). Liveness may over-approximate (more edges, more reads): H
then holds for fewer sets. A write may not be missed, so any occurrence of a member that is not a
plain read or the left side of a statement-level `x = e;` refuses it.

**The reader (r2dec, `crates/r2dec/src/structure/classes.rs`).** Between `select` and the final
`certify_control`, the finished tree is read as C runs it: a node per simple statement and per
test, edges for `if`, `while`, `do`, `for` (init, test, update), `switch` with fallthrough and
`default`, `break`, `continue`, `goto` to its label, `return`; a trap falls through (an edge more
is sound). An unknown or repeated label refuses the function. Candidates are `Carrier` symbols
whose values share an r2ssa class with another carrier and that the text spells. Text liveness is a backward worklist from each read, each node entered once per
candidate: `O(statements + live ranges)`. Per class, members join in `ValueId` order where H
holds both ways against every group member and the C types are equal; the group is spelled as
its member the text declares first, so no name is new. Each `L = L;` becomes an empty statement
under its markers, so the control certificate reads the same tree. A second stage moves the
deleted copies' markers out of a `for (;;)`'s last test's arms and reruns `rotate` on that loop:
`rotate` moves the test and drops only a `break` or `continue` arm. Each stage stands only under
the control certificate (`statement_role` with the selections).

**Witnesses.** Round 2's gapped merge: the `J -> K` copy is spelled `q = <residual>;`, renamed
`p = <residual>;`, not `L = L;`, so it stays. Round 1's latch copy `r = p;` with `r` read after
`p = r + 1;` and the forwarded read past a redefinition both fail H and keep their symbols. Inline
tests: `structure::classes::tests`.

**Departures from the round 17 chain file, recorded.** The group's symbol is its member the text
declares first, not its first `ValueId` (fnv1a32's update has the smaller id; either is sound, the
declared-first one keeps the name the loop is entered with). Step 6's markers: neither in-place
nor dropped; the deleted copies' empty statements move before the loop's last test, and only for
a loop that then rotates. `render/values.rs` gains one read-only getter, `Values::named`, because
the symbol-to-value map has no other owner. `rotate` recurses, so an inner `for (;;)` with no
deleted copy inside a rotated loop may rotate too.

**Measured (round 17, DecBench 2,621 functions).** Carrier locals declared 77,428 to 61,682
(-15,746); 1,278 functions hold candidates, 21,977 members, 15,746 joined (71.6%), kept 236 by
interference and 80 live at entry; the pinned census 3,371 to 3,149. Moved goldens are judged in
ROADMAP "Judged golden moves".
