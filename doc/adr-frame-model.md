# ADR: one frame model

Status: proposed (ROADMAP P4, after F2; decision D14)

## Context

Twelve places decide something about a function's stack frame, by the census
of 2026-10-04:

- **identity**: r2ssa's `ObjectModelBuilder` (an `ObjectId` counter keyed by
  root and space), the pre-SSA `promote.rs` (`PromotedSlot`, never an
  object), r2types' external stack slots (keyed by `StackAddressRoot`), and
  r2dec's binding plan (`stack_m{offset}`, spelled two ways);
- **extent**, decided three ways:
  - the stack certificates (proven layout, accessed storage, placed extent,
    or the gap to the next object);
  - `promote.rs` (its own widths);
  - r2types `prepare.rs` (the largest access width).

  `ObjectFact` itself carries no size;
- **escape**, four independent analyses: `escaping_roots`, `FrameReach`'s
  taint, `private_stack_objects`, and `promote.rs`'s `escaped`;
- **containment**: three rules (`DeclaredStackSlots::containing`,
  `FrameReach`'s nearest start below, and the restatement's `covered`);
- **roles**: r2types' parameter-home and saved-frame-pointer heuristics, and
  r2ssa's `frame_managed_stack_object`. No owner has a canary role, so the
  canary slot is glued into the buffer beside it;
- **a feedback loop**: r2engine restates every proved slot as a *declared*
  slot for the next preparation (`restated_slots`), so a proof comes back as
  a statement.

`afv` lists the promoted slots and the certified slots with names of its own.
The renderer binds other names and refuses objects `afv` lists. The 37
equivalence records whose cause is the stack-protector canary all trap on
`FS_OFFSET_0`, read as a residual.

## Decision

**The frame model is one index of the sealed function (doc/adr-one-ir.md),
and the only owner of what a frame holds.**

- **Inputs:**
  - the stack roots (exact, entry-relative, indexed);
  - the memory accesses with their widths;
  - the call boundaries, including what a callee writes through a pointer;
  - the declared slots (debug information only);
  - the frame boundaries (save slots, return address).
- **One partition.** The frame is a set of disjoint intervals of entry-stack
  offsets, built in one pass over the accesses and the declared slots, with
  an interval tree for containment. An object's identity is its interval,
  and its `ObjectId` is assigned in offset order, so it is stable for a
  sealed function. Its extent comes from one rule, in order:
  1. a declaration;
  2. a proven layout (an array stride over an index range);
  3. the union of the accesses and of what callees are proven to write.

  There is no gap-filling and no largest-width guess.
- **One escape analysis**, on the fixpoint driver. An object escapes if its
  address reaches memory, a call or a return, or an unmodelled operation. The
  other three are deleted.
- **Roles from structure, with their premises:**
  - Local, ParameterHome, SavedRegister, ReturnAddress, OutgoingArguments,
    Padding.
  - **Canary**: a slot written once at entry from a load relative to the
    thread pointer, read only by a comparison whose failing edge reaches a
    call that does not return, and never escaping. Its comparison is elided
    as a `compiler-inserted` obligation, with the premise
    `Premise::UbFreeSource`: the comparison fails only after an access
    leaves its object. The premise is shown, not hidden. A rendering that
    elides the canary says it assumes this, and one whose caller refuses the
    premise keeps the check, as a residual.
- **Promotion is an SSA rewrite.** The memory-to-register promotion of
  private slots moves from pre-SSA `promote.rs` to a rewrite of the prepared
  function that reads the frame model: a private, non-escaping object whose
  every access is a full-width load or store of one value becomes that
  value. `PromotedSlot` and its custom storage space are deleted.
- **No feedback.** r2engine stops restating proved slots as declared ones. A
  declaration is the debug information's; a proof is the frame model's, and
  each stays what it is (C).

**Consumers read it.**
- The certificates, r2types (whose roles and largest-width fallback are
  deleted) and the renderer all read the frame model.
- `afv` and `afi` read the frame model and the render facts' names, so the
  shell and the C name the same objects with the same names.
- Memory SSA's locations become frame objects at known offsets, with phis
  keyed by `BlockId`.

## Migration

| Step | Change | Deletes |
|------|--------|---------|
| P4.0 | The frame model as an index beside the current owners; a test comparing the two partitions over the census, with every disagreement judged | — |
| P4.1 | Certificates and memory SSA read it | `ObjectModelBuilder`'s frame half, `FrameReach`'s containment, `private_stack_objects`, three escape analyses |
| P4.2 | r2types and the renderer read it | `prepare.rs`'s width fallback, r2types' frame roles and its `StackSlotKey` slots |
| P4.3 | Promotion as an SSA rewrite reading it | `promote.rs`, `PromotedSlot`, `promoted_slot_sites`, the `(block, index)`-keyed promoted maps |
| P4.4 | The canary role and its elision under `UbFreeSource`; `afv`/`afi` from the model | the 37 canary residual traps; `afv`'s own names |
| P4.5 | The restatement feedback removed | `restated_slots`' proved half |

## Consequences

- Exit: one owner of frame objects, the canary traps of #61 gone, and `afv`
  agreeing with `pdd` on every local's name and extent.
- Equivalence and the census change at P4.3 and P4.4, and each change is
  read by hand.
- Elision under a premise is the first use of `Premise`. A consumer that will
  not grant it (A's `--strict`, a verification mode) sees the check.
