# ADR: one fixpoint driver

Status: accepted, in progress (ROADMAP K)

## Context

A census found about 45 iterative computations in r2ssa, r2types, r2dec,
r2engine and r2rewrite that repeat "until nothing changes". Each states its
own termination, or does not:

- **About a dozen are sound already**: worklists over a lattice with a stated
  height, such as value ranges (`values.rs`, with widening), views, demand,
  dead phis, SCCP and discovery.
- **About 25 rescan the whole function each round** with no stated lattice.
  Examples: memory SSA (`semantic/objects.rs`), stack roots
  (`function/rewrite.rs`), compare propagation (`semantic/predicates.rs`),
  and the r2types and r2dec expression passes.
- **Six stop at a cap and keep a partial result without saying so**:
  `optimize.rs` (whose build paths pass 1, against its own comment),
  r2types `globals` and `arrays` (6 rounds), r2dec `prepared_semantic`
  (4 rounds), and `control_domains` (which skips the remaining blocks).
- **About ten may not be monotone**, because they overwrite instead of
  joining, roll back, or mint and never retract:
  - memory SSA mints a phi in the first round where inputs disagree and keeps
    it if they later agree. It also reads an unreached predecessor as the
    entry value, so every loop header gets phis whether or not the loop
    stores;
  - `address.rs` re-derives each block from its known predecessors;
  - `call_results.rs` writes certificates while still iterating;
  - `interproc` call-argument state reads an unreached predecessor as
    `Unknown`.

A computation whose termination is a comment, or a round count, is a
computation whose answer depends on how long it was allowed to run.

## Decision

**One driver, `r2ssa::fixpoint`.** A forward dataflow over a function's
blocks:

- The state type implements `Join`: a join that says whether it moved.
- An unreached block is bottom, absent from the solution, and contributes
  nothing to a join. It never stands for "entry" or "unknown".
- Work is a set of blocks keyed by reverse-postorder index, so the order is
  deterministic and each round visits only what changed.
- The caller states the lattice height `h`. The budget is
  `blocks × (h + 1)` block visits, which no monotone transfer over a
  lattice of height `h` can exceed. Exceeding it is a typed `Exhausted`
  error carrying refusal evidence, and the caller refuses. A result is never
  partial and silent.

A backward variant and a sparse (def-use) variant are added when the first
pass that needs them moves onto the driver, not before.

**Each pass moved onto it states its lattice.** Iterating with symbolic
identities and numbering once at the end replaces minting identities
mid-iteration. A pass that overwrites is rewritten to join, or is shown not
to be a fixpoint at all and replaced by a direct algorithm.

**Out of K:**
- The r2types confidence loops (`globals`, `arrays`, `structs`) rank
  candidates by `u8` scores; they are rewritten in C3.
- The r2dec loops (`placement`, `rules`, `recording`, `prepared_semantic`)
  belong to the renderer that R replaces.
- K records these and does not port them only to delete them later.

## Migration

| Step | Change | Deletes |
|------|--------|---------|
| K0 | `r2ssa::fixpoint`: forward block dataflow, `Join`, a budget from the stated height, `Exhausted` as a typed refusal — **done** | — |
| K1 | Memory SSA on the driver. Each (block, location) slot is a three-level lattice: unreached, then one version, then `Phi(block, location)`. Versions stay symbolic while iterating and are numbered after convergence; uses, defs and phis come from one pass over the converged states | lazy phi minting, phis that outlive their merge, the loop-header phi from an unreached back edge — **done** |
| K2 | The non-monotone r2ssa passes, rewritten to join or replaced: `rewrite.rs` stack roots (**done**: `function/stack_roots.rs`, optimistic on the sparse driver; the census is byte-identical), `address.rs`, `call_results.rs`, `interproc` call-argument state, `predicates.rs`, `control_domains` | overwriting updates, writes during iteration, silent skips |
| K3 | `optimize.rs`: one stated order of passes run to a fixpoint with a budget that refuses, instead of a round count | `max_iterations` and its silent stop |

## Consequences

- K1 may remove phis that were spurious, so a load through a loop with no
  store reads the version that reached it. The stack-reload certificates and
  the equal-value grouping may then prove more. Every such change is read
  in the census and judged by the equivalence gate.
- Cost: each driven pass costs at most `blocks × (h + 1)` transfers. The
  dense rescans become worklists.
