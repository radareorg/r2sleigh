r2ssa: the medium tier
======================

`crates/r2ssa` turns lifted r2il into function-level SSA and owns the
semantic evidence built on it: prepared facts, certificates and refusal
evidence. `r2s` prints it with `pdim`. Design records:
[adr-one-ir.md](adr-one-ir.md), [adr-stable-identity.md](adr-stable-identity.md),
[adr-fixpoint.md](adr-fixpoint.md), [adr-written-lanes.md](adr-written-lanes.md).

Construction
------------

| Step | Where |
|------|-------|
| Lift a body by recursive descent; unresolved indirect transfers are recorded, never guessed | `body.rs` |
| Promote frame slots nothing outside the function observes | `promote.rs` |
| Build the CFG (`BlockTerminator`: fallthrough, branch, conditional branch/exit, switch, call, indirect branch/call, return) | `cfg.rs` |
| Dominator tree (Cooper-Harvey-Kennedy), `O(1)` dominance from preorder intervals, Cytron frontiers | `domtree.rs` |
| Phi placement on the iterated dominance frontier, then Cytron renaming | `phi.rs`, `rename.rs` |
| Natural loops, merged by header, `O(E + sum of loop sizes)` | `natural_loops.rs` |

An `SSAVar` is an interned name, a version and a width: `RAX_1`,
`tmp:1000_2`, `const:2a_0`, `reg:10_0`; version 0 is a value the caller
supplied. `SSAOp<V>` mirrors `R2ILOp`. `FunctionSSABlock` carries phis;
`block.rs`'s `SSABlock` is single-instruction SSA (see AGENTS.md).

Every operation and phi holds a stable `OpId` (`arena.rs`); operands are
`VarId`s into one growing `ValueTable`. Facts over a sealed function are dense
vectors over its ids (`dense.rs`), never maps keyed by variable.

Stages and the artifact
-----------------------

An `SSAFunction` has three typed stages (`function/stage.rs`): `Lifted` is
open to change and optimised; `Prepared` satisfies `validate_ssa_function`
(single definitions, phis aligned with predecessors, widths, dominance);
`Sealed` has no `&mut` path, so no fact can describe changed blocks.

`SsaArtifact` is the canonical product: the sealed function, its `SsaGraph`
(dense `BlockId`/`InstId`/`ValueId` with CSR use lists), liveness, unobserved
merges, `PreparedFunctionFacts`, the `SourceMachineContext` and aggregate
access projections. The engine builds one with `TrustedSsaArtifact::prepare*`
from a `TrustedLiftedFunction`; `SsaArtifact::for_decompile`, `for_patterns`,
`for_symbolic` and `raw` build untrusted ones for tests and tools.

Optimisation
------------

`optimize.rs` repeats SCCP (when enabled), condition-code folding,
compare-chain fusion and instruction combining until a round moves nothing,
budgeted by operation count; a run that meets the budget is correct but less
simplified, and says so. `DecompilePrepConfig` disables SCCP and keeps memory
reads: the decompiler needs provenance more than folding.

Prepared facts
--------------

| Fact | Module |
|------|--------|
| Objects, memory SSA, predicates, call sites, control domains, structured loops and trips, certificates | `semantic/` |
| Recovered interface: parameters are version-0 reads that meet a convention slot | `recover_interface.rs` |
| Bytes each operation wrote as data, recorded before any rewrite | `lanes.rs` |
| Bytes of each value the function's meaning reads, backwards from returns and call uses | `demand.rs` |
| Merges nothing observes | `deadphi.rs`, `liveout.rs` |
| Live ranges per value, by block and position | `liveness.rs` |
| Which values carry the same bits (`view(v) = (root, prefix_bits, extension)`) | `view.rs` |
| Where a storage starts holding a different value; loop state a register only ferries | `span.rs`, `mirror.rs` |
| Pointer-table entries an indirect call can reach | `indirect.rs` |
| Every instruction and effect that must survive rendering | `obligation.rs` |
| Name-free machine expressions handed to renderers | `machine/` |
| Interprocedural summaries over direct calls | `interproc/` |

`backward_slice` (`slice.rs`) follows value inputs and, through memory SSA,
loads to their defining store. Iterating passes run on `fixpoint.rs`, whose
`blocks × (height + 1)` visit budget is a defect detector, not a cap.

Value ranges
------------

`values.rs` solves strided intervals (`strided.rs`) over the SSA graph;
`origin.rs` reads one lifted block forward and says where a value came from.

### Strided intervals

An element is a width, a stride and two inclusive unsigned bounds.

- **meet.** Two progressions `x = l1 (mod s1)` and `x = l2 (mod s2)` share a
  value exactly when `g = gcd(s1, s2)` divides `l2 - l1` (CRT); otherwise the
  meet is empty. The first common value comes from the extended Euclidean
  inverse of `s1/g` modulo `s2/g`, and common values step by
  `lcm(s1, s2) = (s1/g)*s2`, computed in `u128`. Cost `O(log stride)`.
- **widen.** The stride is `gcd(old.stride, new.stride, |old.low - new.low|)`.
  A falling low drops to `new.low mod s`; a rising high rises to
  `mask - (mask - low) mod s`. Both keep the residue. Afterwards a bound moves
  only when the stride shrinks to a proper divisor, at most sixty-four times.
- **shr.** A stride survives a shift by `k`, divided, exactly when `2^k`
  divides it; otherwise the dropped bits carry (`{1, 11, 21} >> 2` is
  `{0, 2, 5}`) and the stride becomes one.
- **Kani.** CBMC proves eight-bit properties; join, widen, meet, add, sub,
  mul and shl are checked exhaustively below six bits by unit tests instead.

### Termination

The solver widens at the phis of `W`, the back-edge targets of a depth-first
walk from the entry. Every transfer reads values defined at a dominator of the
reader (for a phi input, of the edge's source); dominators are DFS ancestors,
so a cycle of reads passes a phi in `W` on any graph, reducible or not, and a
widened phi moves at most once per stride change per bound. The criterion is
structural, not a visit count. A value wider than sixty-four bits is described
at sixty-four, where top means unknown, never "below `2^64`".

### Branch assumptions

An assumption filed under `B` by edge `P -> B` holds at `B` only when that
edge dominates `B`: `B` is not the entry and dominates every other
predecessor. It is then inherited by every block `B` dominates, which sees
the instance of `v` tested on the last traversal of `P -> B` whenever `def(v)`
dominates `P`.

### Loop trip counts

`StructuredLoopFact::trips` (`semantic/trips.rs`) claims only: if control
leaves through the loop's one exit edge, the header ran `N` times. It requires
a body that neither returns nor leaves the function, one exit edge whose block
dominates the one latch, and an exit test comparing an induction's merge
(`j = 0`) or update (`j = 1`) at width `w` with a bound, so the `k`-th header
run sees `X_k = c + (k + j)·s mod 2^w`.

- Equality exit, solved in the ring: with `s = 2^t·u`, `u` odd, a solution
  exists only if `2^t | b − c`, and `k* = ((b − c)/2^t · u⁻¹ − j) mod 2^(w−t)`.
- Ordered exit, solved over the integers: stated only when the first and last
  iterates lie inside the width as the comparison reads them.
- A symbolic count needs an equality with an odd step; its zero (`2^w` trips)
  is excluded only by a dominating edge assumption (above).

A count carries its evidence, and `StructuredLoopFact::validate_trips`
recounts it from the graph. Inductions are limited to sixty-four bits.

### Block origins

An origin maps a storage only while none of its bytes has been written and no
call has intervened. An output forgets every tracked storage it overlaps
(`O(log s + k)`). A store, guarded or conditional store or compare-and-swap
forgets the bytes it names where its address folds and its whole space
otherwise, since Sleigh writes registers through a space (ARM NEON's
`vld1.8 {d0[3]}`); a block transfer forgets its whole space; RAM is never
tracked; a call forgets everything. A copy keeps its source's origin, a load
through a folded address is that slot, and any operation `r2il::eval` models
holds its number when all operands fold. `pdf` carries this fold between lines
only inside one block of the walked body, so the state at each line is exact.
