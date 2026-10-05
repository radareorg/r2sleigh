# ADR: one IR, indexed once

Status: in progress (ROADMAP F2, decisions D11–D12)

## Decision

The sealed function is the IR, and everything about it is an index over its
ids. Every rebuilt graph, liveness pass or side table answers a question the
function already determines, and each copy is a place for two answers to
disagree.

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
- F2.4: the builder with an incremental def-use. The seal still builds the graph twice when the demand pass releases a base (`function/stage.rs`), and the optimiser rebuilds its definition maps once per pass, O(n), until a pass measurably needs better. Exit: one graph build per function.
- F2.5: machine projection and term arena as indexes. Exit: no per-round rebuild.
- Recovery and the seal each collect prepared facts; sharing them belongs to the query database (Q), not a collector flag.
