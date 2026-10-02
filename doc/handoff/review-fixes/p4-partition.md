P4.1 design: one frame partition
================================

Status: design. It replaces the four escape analyses and the six extent
owners listed in `review-8527b472.md`.

## The fact and its premise

Binding decision 1 is ISO C under a UB-free-source premise. Under that
premise, a pointer derived from `&x` reaches only the object that holds `x`
(C11 6.5.6p8). Three facts follow:

1. **Reach is containment.** A callee, a store or a return that is handed a
   frame address reaches the object containing that address, and no other.
   "How far a callee reaches" is the same question as "where does the object
   end". It is not a second fact.
2. **One access, one object.** An access never straddles two objects. A
   `w`-byte access at offset `o` lies inside one object.
3. **An index stays inside its object.** An indexed access whose index spans
   `[lo, hi]` covers `[o + lo*s, o + hi*s + w)` inside one object.

So escape and extent have one owner. That owner is the partition of the frame
into objects, with escape as a per-object bit. A missing extent never becomes
"reach upward" or "whole frame". It becomes a merge, up to the nearest
boundary the binary proves.

## Inputs

All of them are r2ssa facts, after SSA construction, the value view and value
ranges.

- **Frame accesses:** offset, width, and exact or indexed (stride and index
  range from `values`). The offset is relative to the entry stack pointer, as
  `ValueView`/`address.rs` give it.
- **Frame addresses that leave the function:** call arguments (with the
  callee's reach, below), stores of the address as a value, returns,
  live-out, and indirect branches. The address is identified through the
  value view, not syntactically.
- **Callee reach per argument:** `SummaryArgumentReach`, multiplied out at the
  callsite with the caller's bound on the scaling argument. One fixed
  summary function produces it (B1'):
  - the reach is a set: every scaled term and the constant span;
  - a transfer length that is an argument becomes the scaled term
    `stride 1, base 0, width 0`.
- **MUST boundaries:**
  - declared slot starts and ends (DWARF `fbreg`, parameter homes);
  - managed slots: the return address and callee-saved round trips
    (`stack_frame_round_trips`);
  - the entry stack pointer (the top of the frame).

## Algorithm: an interval union over byte positions, O(n log n)

1. Collect the spans:
   - each exact access gives `[o, o+w)`;
   - each indexed access gives `[o + lo*s, o + hi*s + w)`. An unbounded side
     extends to the nearest MUST boundary on that side.
   - each escape with a bounded callee reach `r` gives `[o, o+r)`;
   - an escape with unbounded reach gives `[nearest MUST below or o, nearest MUST above)`.
2. Sort the spans and sweep, merging overlapping spans into objects.
   `[a, b)` and `[b, c)` stay separate: a shared edge is not an overlap.
3. **MUST check.** A merged object that crosses a declared boundary
   contradicts the declaration. This case is the CP2 decision item. Until it
   is decided, the object keeps the merge (the sound direction). A refusal
   evidence line records the conflict, and the declaration's type is not
   applied to it.
4. **Escape.** An object escapes if an address into it leaves the function.
   Being private is the complement.
5. **Managed slots are never merged** with a local. A span that would cross
   one is refused (`FrameSpanCrossesManaged`) and ends at the slot. Only a
   stack smash does this, and a stack smash is UB.

Bytes covered by no span belong to no object: nothing reads or writes them.

## Consumers (each becomes a reader, and the old owner is deleted)

| Old owner | Becomes |
|---|---|
| `shared.rs` `evidenced_stack_roots`, `callee_write_spans` | `partition.objects()` |
| `facts.rs` `ObjectModel` stack half, `escaping_addresses`, `callee_write_reach` | partition lookup `object_at(offset)` |
| `DeclaredStackSlots::containing`, `frame_gap_extent`, `accessed_object_storage` extent | `object.extent()` |
| `private_objects.rs` `private_stack_objects` | `!object.escapes` |
| `dependence.rs:441` whole-frame exposure | the stores into escaped objects only |
| r2dec `frame_objects_with_escaped_address`, `escaped_pointee_reach` | `partition.escaped()`, with reach = the object |
| `promote.rs` escape and overlap rules | stage 2: promotion runs on the partition (below) |
| `seed_for_callee_name` spans (name-keyed) | stage 3: library summaries come from r2abi prototypes, as statements |

## Stages (each one merge, gated)

1. **Partition and escape.** Build `FramePartition` in r2ssa, sealed into the
   prepared facts. Switch the readers in the table above, except promotion,
   and delete the old owners. Fix `argument_touch_reach` (B1'). B1 and B2
   close.
2. **Promotion on the partition.**
   - SSA is built once without promotion. The partition is computed, then
     private single-width objects are renamed into SSA values: mem2reg over
     the existing SSA, with phis placed at the iterated dominance frontier of
     the stores.
   - `promote.rs`'s prologue tracking and escape set go.
   - B3 closes too: spill tracking reads MemorySSA definitions for the
     object, not a private slot map.
3. **MemorySSA per object.** Calls define only escaped objects. This replaces
   the O(accesses × locations × iterations) scan in `objects.rs:227`. `pdim`
   prints the partition.

## Tests (behaviour, caller-side; each fails on 8527b472)

All go through `crates/r2engine/tests/native.rs` with in-memory programs:

- `set(int *p, long i) { p[i] = 1; }`, called as `int a[8]; set(a, 5); return a[5];`.
  `a[5]` is not a dead or unrelated slot, and the render reads it back after
  the call.
- `memset(buf, 0, n)` with `n` not a constant: `buf` is one escaped object.
- Forwarding: `outer(p) { inner(p); }`, where `inner` writes `p[3]`.
- `&a[2]` passed to a callee that writes `p[-1]`: `a[1]` is covered.
- Two callsites with different reaches: the union.
- A declared `struct` contradicted by an access: refusal evidence, and the
  merge is kept.

Plus the equivalence ratchet on the whole population, with the records
review.c `main` and `shape_call_chain`, `shape_struct_pointer` and
`shape_pointer_to_pointer` (P4 `differs`) expected to move.
