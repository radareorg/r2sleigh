# ADR: one fixpoint driver

Status: done for r2ssa (ROADMAP K); r2types' loops go with C3, r2dec's with R

## Decision

A computation whose termination is a comment or a round count has an answer
that depends on how long it was allowed to run. Every iteration therefore
runs on one driver, `r2ssa::fixpoint`, or is a worklist whose termination is
stated where it is written.

- The state implements `Join`, a join that says whether it moved.
- An unreached block is bottom: absent from the solution, contributing nothing
  to a join. It never stands for "entry" or "unknown".
- Work is a set of blocks keyed by RPO index, so order is deterministic and a
  round visits only what changed.
- The caller states the lattice height `h`; the budget is `blocks × (h + 1)`
  visits, which no monotone transfer can exceed. Exceeding it is a typed
  `Exhausted` error carrying refusal evidence, and the caller refuses. A
  result is never partial and silent.
- Entry points: `fixpoint::forward` (block dataflow), `forward_on_edges`, and
  `fixpoint::sparse` (def-use, over `IdMap` cells and `Csr` readers). Further
  variants are added when the first pass needs them.
- A pass moved onto the driver states its lattice, iterates with symbolic
  identities and numbers them once at the end, and joins rather than
  overwrites. A pass that cannot be made monotone is replaced by a direct
  algorithm.
- Allowed forms for an iterating r2ssa pass: on the driver; a coupled
  optimistic worklist with a stated budget; a worklist that touches only what
  a change affects; one pass with the reason stated; or budgeted
  meaning-preserving rewriting that says when it stops.
- Out of K: the r2types confidence loops (`globals`, `arrays`, `structs`)
  rank candidates by `u8` scores and are rewritten in C3; the r2dec loops
  (`placement`, `rules`, `recording`, `prepared_semantic`) belong to the
  renderer R replaces. They are not ported only to be deleted.

## Done

- K0: `r2ssa::fixpoint` with `Join`, the height-derived budget and `Exhausted`.
- K1: memory SSA on the driver (`semantic/objects.rs`); each (block, location) slot is unreached, one version, or `Phi(block, location)`, numbered after convergence. Lazy phi minting and loop-header phis from unreached back edges are gone.
- K2: the non-monotone passes rewritten: stack roots (`function/stack_roots.rs`, optimistic on the sparse driver), call-result certificates, control domains, `interproc` call-argument state, `predicates.rs`, and `address.rs` (values and spill slots solved together, optimistically).
- K3: `optimize.rs` runs one stated order of passes to a fixpoint; a run at its budget (one round per operation) leaves a correct, less simplified function and says so. Its silent round cap is deleted.
- Already-sound passes keep their own written termination arguments: views, demand, dead phis, liveness, SCCP, dominators, `interproc` summaries, the loop-carrier worklist.
- D415: value ranges on `fixpoint::wto_sparse` (below).
- r2dec's `prepared_semantic` four-round loop went with legacy r2dec (D, 2026-10-10).

## Weak topological order

`fixpoint::Wto` is Bourdoncle's order of the blocks an entry reaches: each
strongly connected component a contiguous run led by its head, nested. It is
built on `dense::Condensation`, one condensation per nesting level of what is
left once the level's heads are removed, `O(d · (B + E))` for depth `d`. Nodes
are numbered and successors taken by ascending key (the block address), so
neither `BlockId` (reverse postorder, which takes a true edge before a false
one) nor the edge order moves it. A component's head is the member its search
entered first, the one that finishes last. Every edge `u -> v` with `v` not
after `u` enters the head of a component holding `u`.

`fixpoint::wto_sparse` solves cells placed in blocks over that order. A cell
waits at the start of each phase and when a cell it reads moves; a block's
waiting cells run in its order, found a word at a time in a bitset. The search
resumes past each cell it takes and moves back only to a reader requeued inside
the block, so it reads `O(cells / 64 + evaluations)` words per phase
(`Meter::probes`; restarting at the block's first word read `n² / 128` for a
straight block of `n` cells, PR #400's review). A component
runs its head block, then its body in order, and repeats while a head-block
cell waits; the ascent joins and widens, the descent meets and refines. A
component repeats at most `2 + 2 · h · |head cells|` times per stabilisation
for the caller's per-phase move bound `h`, and a cell still waiting at the end
was read before its writer outside any head; both are `Exhausted`, and value
ranges then state every value unknown. Work is each cell times the repetitions
of its enclosing components.

Lemma 1 (every dependency cycle has a phi in the head block of its smallest
component) needs every source to dominate its reader: an operand, the
comparison a select's arms are narrowed by, a reload's first load, and a guard
environment's compared sides. The renumbering test
`values::a_renumbered_function_solves_to_the_same_ranges` failed on the FIFO
it replaced (`p` read `[0,10]` or `[2,10]` by branch sense; base 46ce15d4a).

## Left

- r2types `globals` and `arrays` still stop after 6 rounds (`for _ in 0..6`). Exit: rewritten in C3 with a stated lattice or deleted.

## Consequences

- K1 removed spurious loop-header memory phis, so a load through a loop with no store reads the version that reached it; how the renderer binds such a certified reload is an R item.
