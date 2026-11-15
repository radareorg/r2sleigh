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
- F2.2: byte-granular liveness over locations (a lane write every reader sees whole defines the register), `ValueLiveness::compute_with_relocations` and r2dec's relocated liveness folded into the one model, #47 and #50. Exit: one liveness model, those issues closed.
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
