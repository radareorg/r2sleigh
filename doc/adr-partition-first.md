# ADR: the object partition is computed once, from liveness, before inlining

## Status

Accepted. Landed on `arch/location-ssa` as the partition-first arc.

## Context

The binding plan used to decide three things in a cycle. The rendered readers
of a value depended on the object partition, because a copy inside one object
is not a read. The inlinable set depended on the rendered readers, because a
value folds only where exactly one reader renders it. And the partition
depended on the inlinable set, because the union-find dropped inlined values
before it ran. Removing a value from the partition can remove an interference
and let a component grow, so the partition as a function of the inlinable set
is not monotone, and no fixpoint over the cycle is both convergent and sound.
Every stuck case of the previous arc was a reader count taken before the
partition existed.

Two proxies stood in for interference: two values read by one instruction,
and an intra-block redefinition between a value's definition and its last
read. Both were sound only while a copy stayed a reader. Once copies are
forwarded, a read can sit past a same-storage redefinition with neither proxy
seeing it.

## Decision

1. **One partition.** The object partition is computed once, over every value
   that can be an object, from the storage spans and the certified entities.
   Nothing downstream refines it. An inlined value is a member whose
   definition prints nothing; a binding is made from a component's remaining
   members, and a component with none is no object.

2. **Interference is liveness.** Two values may share an object if and only if
   their live ranges do not intersect, or the overlapping pair holds the same
   content. `ValueLiveness` gives per-value, per-block half-open segments; a
   merge reads its source at the end of the predecessor; a value the caller
   reads is read at every returning block; a definition holds its object at
   its own position even when unread; merges nothing reads, transitively, read
   nothing. Same content is a copy, a widening, a lane view, the merges one
   block makes over one location, the values a function is entered with in
   one location, and two reads of one memory object with no write between.
   The exemption is per overlapping pair, never per component. Every union,
   in spans and in the plan, is judged over the full merged components.

3. **Copies are value facts.** A same-width `Copy` of a variable is forwarded
   to every reader before the graph is built. The copy stays in place, read by
   nothing, so positions do not move and the dead definition is accounted by
   the existing dead-value chain. Three copies are not forwarded: a copy of a
   constant, because spelling a literal at each reader is the plan's decision;
   a copy whose result a merge reads, because it is that merge's edge write and
   belongs where the program placed it; and a copy into a stack slot the
   function proved private, because it is the source's assignment to a local.

4. **Literals decide no object.** A literal-defined value seeds no component.
   It is offered to whatever its run became after every other union, joins
   only where a merge of that run reads it, and otherwise stays alone and is
   spelled at its readers.

5. **Partition and inlining are brought to agreement.** The partition is built
   over every value; folds are decided against it; the partition is rebuilt
   without the folded values, with each fold's reads relocated to its reader;
   folds still safe against that partition are kept; repeat until the fold set
   is stable. A fold never returns once dropped, so the chain ends, with a
   partition judged against exactly the values the text binds. The final
   liveness travels on the partition so the seal judges the same components.

6. **The hazard is judged against the rendered partition.** A fold is legal
   if and only if the move extends no leaf's live range across a write to an
   object the expression reads. Write hazards are decided per block in
   decreasing definition ordinal, and a write by a candidate already folded is
   no write. A merge edge whose value is already the merge's object writes
   nothing.

7. **The seal checks the plan, not a second derivation.** The partition is a
   sequence of unions whose order matters; the seal asks the one builder and
   checks that the plan's bindings are its components.

## Consequences

The functions this replaces are gone: `blocks_reachable_from`,
`run_is_read_after` and `use_point` in spans; `values_read_together`,
`CoreadValues`, `set_interferes`, `set_outlives_a_redefinition`,
`duplicable_bound_constants`, the `admitted` and `unrendered` eligibility
inputs and the second `inlinable_core` in the rules; the seal's own
component rebuild; `coalescing_pre_partition` in construction.

Residual conservatism, each recorded in the handoff: the read closure keeps a
candidate leaf's own object beside its expansion; a `CallRestore` is not
forwarded; the return carrier is folded by the boundary-read path rather than
forwarded; a call-use read of a register the boundary does not pass is ignored
by the artifact's liveness but the spans still see it.
