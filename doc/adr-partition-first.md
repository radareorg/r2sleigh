# ADR: the object partition is computed from liveness, before inlining

Status: accepted, landed (decision 5 is replaced by R)

## Decision

The binding plan used to decide readers, inlining and the partition in a
cycle. That cycle is not monotone, because dropping a value can remove an
interference and let a component grow. So no fixpoint over it is both
convergent and sound. The partition now comes first.

1. **One partition,** over every value that can be an object, built from the
   storage spans and the certified entities. Nothing downstream refines it.
   An inlined value is a member whose definition prints nothing. A binding is
   made from a component's remaining members, and a component with none is no
   object.
2. **Interference is liveness.** Two values may share an object if and only if
   their live ranges (`ValueLiveness`, per-value, per-block half-open
   segments) do not intersect, or the overlapping pair holds the same content.
   - Liveness rules: a merge reads its source at the end of the predecessor; a
     value the caller reads is read at every returning block; a definition
     holds its object at its own position even when unread; merges that
     nothing reads, transitively, read nothing.
   - Same content means a copy, a widening, a lane view, one block's merges
     over one location, the entry values of one location, or two reads of one
     memory object with no write between them.
   - The exemption is per overlapping pair, never per component. Every union
     is judged over the full merged components.
3. **Copies are value facts.** A same-width `Copy` of a variable is forwarded
   to every reader before the graph is built. The copy stays in place, read by
   nothing, so positions do not move. Three kinds of copy are not forwarded: a
   copy of a constant (spelling a literal is the plan's decision); a copy that
   a merge reads (it is that merge's edge write); and a copy into a stack slot
   proven private (it is the source's assignment to a local).
4. **Literals decide no object.** A literal-defined value seeds no component.
   It joins a run only where a merge of that run reads it. Otherwise it stays
   alone and is spelled at its readers.
5. **Partition and inlining agree by shrinking rounds.** Build the partition;
   decide folds against it; rebuild without the folded values, with each
   fold's reads relocated to its reader; keep the folds that are still safe;
   repeat until the set is stable. A dropped fold never returns, so the
   rounds terminate. The final liveness travels on the partition. A literal
   that a later round leaves alone in its object may be added, since spelling
   it removes a write and no read.
6. **The hazard is judged against the rendered partition.** A fold is legal if
   and only if the move extends no leaf's live range across a write to an
   object the expression reads. Write hazards are decided per block in
   decreasing definition order. A write by an already-folded candidate is no
   write, and a merge edge whose value is already the merge's object writes
   nothing.
7. **The seal checks the plan, not a second derivation.** It asks the one
   builder and checks that the plan's bindings are its components.

## Done

- All seven decisions landed. The proxies for interference are gone
  (`blocks_reachable_from`, `run_is_read_after`, `use_point`,
  `values_read_together`, `CoreadValues`, `set_interferes`,
  `set_outlives_a_redefinition`, `coalescing_pre_partition`, and the seal's
  own component rebuild).

## Left

- R replaces decision 5's rounds with a single render plan
  (doc/adr-renderer-printer.md). `inlinable_core` and
  `duplicable_bound_constants`, with its `admitted`/`unrendered` round inputs,
  still exist in `binding_plan/rules.rs` until then.
- Known conservatism, each a candidate to remove:
  - the read closure keeps a candidate leaf's own object beside its
    expansion;
  - a `CallRestore` is not forwarded;
  - the return carrier is folded by the boundary-read path rather than
    forwarded;
  - a call-use read of a register that the boundary does not pass is ignored
    by the artifact's liveness, but the spans still see it.
