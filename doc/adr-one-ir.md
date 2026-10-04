# ADR: one IR, indexed once

Status: proposed (ROADMAP F2, decisions D11–D12)

## Context

F1 gave every operation and value a stable id, and K put iteration on one
driver. The representation those ids index is still scattered, and every pass
rebuilds what it needs:

- **Rebuilt indexes.** Outside tests, preparation builds the graph twice
  (again after the demand release changes operands, `function/stage.rs`),
  computes liveness twice (the second time with what the facts collected
  from the first said about shared content and uncertified call reads), and
  interface recovery prepares a whole provisional fact set before the real
  preparation (`recover_interface.rs`: graph, liveness, spans and
  `PreparedFunctionFacts`). r2dec computes dominators twice more over its own
  control graph (`structure/place.rs`, `structure/certify.rs`). Tests build
  the graph at 39 further sites, because nothing smaller answers their
  questions. Each rebuild answers a question the function already
  determines, and the liveness rebuild is a dependency cycle (liveness,
  spans, facts, liveness) solved by running it twice.
- **Side tables instead of indexes.** 684 maps and sets in production code
  are keyed by a function's own entities (`SSAVar`, `ValueId`, `InstId`,
  `BlockId`, `OpId`, the optimiser's `VarKey`): 373 in r2ssa, 240 in r2dec
  and 71 in r2types, as `ENTITY_KEYED_MAP` counted them on 2026-10-04. Every
  lookup is a tree walk or a hash of a name, every pass builds its own, and
  two passes that need the same relation build it twice.
- **Names as identity.** `SSAVar` (a name, a version, a width and a
  disambiguator) still keys facts, although a value's identity is its
  `ValueId`. The optimiser hashes `VarKey` strings.
- **Facts in bags.** `DecompilePrepFacts` has 6 fields,
  `PreparedFunctionFacts` 15 and `PreparedFunctionCertificates` 24, each a
  set of maps assembled by its own pass. Nothing says which pass owns which
  relation, so the same relation reappears in several. Frame objects have
  twelve owners (doc/adr-frame-model.md).
- **Seven representations of one function**: the blocks, the graph (built
  twice), the views (three times), the machine projection (per plan build),
  the term arena (per inlining round), the binding plan (per render round),
  and the liveness models.

The cost is not only time. A fact computed twice can be computed two ways,
and each copy is a place for the two to disagree.

## Decision

**The sealed function is the IR, and everything about it is an index over its
ids.**

1. **Dense identity.** `OpId`, `InstId`, `ValueId` and `BlockId` are dense
   `u32`s fixed at seal. Facts about them live in dense containers:
   - `IdVec<I, T>`: a value for every id, a `Vec<T>` indexed by it;
   - `IdMap<I, T>`: a value for some ids, a `Vec<Option<T>>`;
   - `IdSet<I>`: a bitset;
   - `Csr<I, T>`: compressed adjacency for def-use, predecessors and
     successors.

   They are generic over the id type (`r2ssa::dense`), so a value fact
   cannot be indexed by an instruction.

   Iteration order is id order, which is deterministic by construction. A
   `BTreeMap` or `HashMap` keyed by a function's own entity is not allowed in
   r2ssa, r2types or r2dec; a Dylint enforces it, the way the existing lints
   enforce the other seams. `SSAVar` stays as the presentation of a value,
   and nothing is keyed by it.

2. **One index layer.** `Sealed` owns a `FunctionIndex`. Each index is
   computed at most once, on first use (a `OnceCell` per index), from the IR
   and from the indexes it depends on:
   - structure: reverse postorder, the dominator tree with dominance
     frontiers, loops, def-use (CSR), use sites;
   - values: views and representatives, constants and ranges (P5), written
     lanes (PE), demand;
   - lifetime: liveness (one model over locations) and storage spans;
   - memory: the frame model (P4) and memory SSA.

   Each index declares its inputs as other indexes, so the dependency order is
   static and no index is computed twice. A pass that needs a relation reads
   the index; it does not build a graph or a map of its own.

3. **Analyses are declared.** Every iterating index is an analysis on the
   fixpoint driver (doc/adr-fixpoint.md): its lattice, its height and its
   transfer, over dense cells. Non-iterating indexes are one pass in a stated
   order. Certificates are views over indexes plus the decisions only they
   make.

4. **Before the seal, a builder.** `Lifted` and `Prepared` are a mutable
   builder over the same arena, with an incremental def-use, so the
   optimiser and the demand pass edit through plans without rebuilding a
   graph. The seal freezes the builder into the IR; no graph exists before
   it. The provisional graph that demand borrows today is replaced by the
   builder's own def-use.

5. **The other representations become indexes or go.** The machine
   projection and r2rewrite's term arena become indexes over the IR. The
   binding plan and the journal go with R (doc/adr-renderer-printer.md). The
   liveness models merge into one model over locations; flag and temporary
   phis nothing reads are pruned by it (issues #47, #50, #56).

## Migration

Each step keeps the census byte-identical unless it says otherwise, and
deletes what it replaces.

| Step | Change | Deletes |
|------|--------|---------|
| F2.0 | Dense containers (`IdVec`, `IdMap`, `IdSet`, `Csr` in `r2ssa::dense`); the Dylint against entity-keyed maps (`ENTITY_KEYED_MAP`), warning only | — |
| F2.1 | `FunctionIndex` on `Sealed`: reverse postorder, dominators, loops, def-use; every reader takes `&Sealed` or the index; r2dec's structuring reads the dominators from it | the second graph build (with F2.4), r2dec's two `DomTree::compute`, the test-only graph builds where the index answers |
| F2.2 | One liveness model over locations, as an index whose inputs include shared content and certified call reads, so it is computed once; dead flag and temporary phis pruned by it | the second liveness pass and `compute_with_relocations`; the duplicate live-in computation in `phi.rs`; closes #47, #50, #56 |
| F2.3 | Prep facts, prepared facts and certificates re-expressed as indexes over dense containers; interface recovery reads the indexes it needs instead of a provisional preparation | every `SSAVar`-keyed and `VarKey`-keyed map in r2ssa; the provisional preparation in `recover_interface.rs` |
| F2.4 | The builder before the seal, with an incremental def-use; optimiser and demand on it | the provisional graph; the per-pass `defs` maps the optimiser builds |
| F2.5 | Machine projection and term arena as indexes | their per-round rebuilds |
| F2.6 | The Dylint made fatal in r2ssa, then in r2types | — |

### F2.3 and F2.4 in stages

Operations name their operands by `SSAVar`, a name, a version, a width and
a disambiguator. About 2,300 `SSAOp::` matches and 1,450 `SSAVar` uses
across 113 files read the IR that way, and the graph keeps a second copy of
every operation so that it can also say each operand's `ValueId`. The
target is one IR whose operands are value ids, with names a presentation
table. It is reached in stages. Each stage compiles, keeps the census
byte-identical, and deletes what it replaces:

1. `SSAOp<V = SSAVar>`, generic over its operand. Every match keeps its
   syntax; only code that reads an operand's name changes.
2. The graph's payload is `SSAOp<ValueId>`, so the graph no longer copies
   names, and graph readers resolve a name only to print it.
3. The function's blocks hold `SSAOp<ValueId>` and one value table that
   renaming fills: id, storage, width, version and name. The graph becomes
   the function's def-use index rather than a second copy of it, and is
   built at the seal from ids alone.
4. The optimiser and the demand pass run on ids: `VarKey` and every
   `SSAVar`-keyed map in them become `IdVec`/`IdMap`, and the per-pass
   `defs` maps become the builder's incremental def-use.
5. The certificates' `SSAVar`-keyed maps become dense. `ENTITY_KEYED_MAP`
   is made fatal in r2ssa once its count there is zero.

## Consequences

- **Cost targets.** The seal costs O(n log n) once. Each index costs O(n), or
  O(n × height) for a lattice analysis, once per sealed function. A lookup is
  O(1), where today it is O(log n) on a name or a hash of one.
- **Ownership becomes checkable.** Every relation has one index, and two
  passes that need it share it. A second implementation of a relation is
  visible as a second index, and is a bug.
- **Risk.** F2.3 touches most of r2ssa's certificates. It goes one index at a
  time, behind the census, and deletes each side table as its index lands.
  The tripwire is the ADR's own: if F2.3 needs semantic changes rather than
  re-keying in more than about 40 files, stop and reassess.
- **Prerequisite for P4, Q and R.** The frame model is an index; the query
  database caches sealed functions with their indexes; the printer reads
  indexes only.

## As landed

- **F2.0** (`15ac7a9c`): `r2ssa::dense` and the `ENTITY_KEYED_MAP` Dylint,
  warning only. It counted 684 entity-keyed maps on 2026-10-04.
- **F2.1, in part**:
  - `DomTree` is Cooper, Harvey and Kennedy's over dense reverse-postorder
    numbers, and `dominates` is O(1) from preorder intervals; a property test
    holds it to the data-flow definition (`15ac7a9c`).
  - The natural loops are one index of the function, read by the loop facts
    and by placement (`8741ba40`).
  - The function's second def-use index, `SsaQueryIndex`, is deleted
    (`f634efbf`).
  - Remaining: a `FunctionIndex` holding these on `Sealed`, and the
    test-only graph builds.
- **F2.2, in part**:
  - Fact collection computes liveness once, after the prefix and the
    boundaries that refine it, and the artifact keeps that one model
    (`09f23ac1`). Collapsing the two passes exposed a call read the old
    second pass wrongly ignored: the argument had been copied, and the call
    read the value the copy carried.
  - Merges are pruned by pre-SSA liveness (`f9111a28`), closing the Sleigh
    temporary and rewritten-flag half of #56.
  - Remaining: byte-granular liveness over locations, so a lane write that
    every reader sees whole defines the register (the `RDX` merge in
    `fnv1a32`); r2dec's relocated liveness folded into the one model; #47
    and #50.
- **F2.3, in stages**:
  - Stage 1 (`94bc999f`): `SSAOp<V = SSAVar>` with one `map` over operands
    in field order, replacing the hand-written source mapper.
  - Stage 2 (`39f44fec`): the graph's payload is `SSAOp<ValueId>`. Graph
    readers resolve a name only to print it.
  - Stage 3a (`3aaaca78`): `SSABlock<V>` and `PhiNode<V>` are generic, as an
    operation is.
  - Stage 3b: the function's blocks hold `SSAOp<VarId>` over one
    `ValueTable` that construction and renaming fill. `VarId` is the
    function's own id, not the graph's `ValueId`: a function is edited
    before it is sealed and mints values as it goes, while the graph numbers
    the sealed function's values in first-seen order so that every
    `ValueId` the census prints is unchanged. The two are distinct types,
    so mixing them does not compile, and the graph maps one to the other
    through a dense vector, O(1) per lookup. Forwarding and the boundary
    rewrites run on ids with `IdMap`/`IdSet`. Fixtures still write programs
    by name through `NamedBlockMut`, which interns as it writes. Passes edit
    ids through `BlockMut` directly.
  - Transitional, and stage 4 and 5 work rather than a resting state:
    `SSAFunction::named`, `named_block`, `named_blocks`, `named_ops` and
    `SsaGraph::named_op` clone a block or an operation with its operands
    spelled as variables, for readers still keyed by name. At stage 3b
    there were 126 such reads in r2ssa's library code, 23 in r2dec and 4
    in r2types. Each one is a reader whose facts are keyed by `SSAVar`. It
    is deleted when its maps are re-keyed by id in stage 4, for the
    optimiser and the demand pass, or in stage 5, for the certificates.
