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
- Already-sound passes keep their own written termination arguments: value ranges, views, demand, dead phis, liveness, SCCP, dominators, `interproc` summaries, the loop-carrier worklist.

## Left

- r2types `globals` and `arrays` still stop after 6 rounds (`for _ in 0..6`). Exit: rewritten in C3 with a stated lattice or deleted.
- r2dec `prepared_semantic` still stops after 4 rounds. Exit: deleted with R.

## Consequences

- K1 removed spurious loop-header memory phis, so a load through a loop with no store reads the version that reached it; how the renderer binds such a certified reload is an R item.
