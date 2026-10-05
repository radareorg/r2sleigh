# ADR: one frame model

Status: proposed (ROADMAP P4, after F2 and M; decision D14)

## Decision

The frame model is one index of the sealed function (doc/adr-one-ir.md) and
the only owner of what a stack frame holds. Today twelve places each decide
part of it: identity (`ObjectModelBuilder`, `promote.rs`'s `PromotedSlot`,
r2types' `StackAddressRoot` slots, and the binding plan's `stack_m{offset}`),
extent (three rules), escape (four analyses), containment (three rules), and
roles. On top of that, r2engine's `restated_slots` feeds proofs back in as
declarations.

- **Inputs:** the stack roots (exact, entry-relative, indexed); the memory
  accesses with their widths; the call boundaries, including what a callee
  writes through a pointer; the declared slots (debug information only); and
  the frame boundaries (save slots and the return address, from the machine
  profile).
- **One partition.** The frame is a set of disjoint intervals of entry-stack
  offsets. It is built in one pass over the accesses and the declared slots,
  with an interval tree for containment. An object's identity is its
  interval, and `ObjectId`s are assigned in offset order, so they are stable
  for a sealed function.
- **One extent rule,** applied in this order: a declaration; then a proven
  layout (an array stride over an index range); then the union of the
  accesses and of what callees are proven to write. There is no gap-filling
  and no largest-width guess.
- **One escape analysis,** on the fixpoint driver. An object escapes when its
  address reaches memory, a call, a return or an unmodelled operation.
- **Roles from structure:** Local, ParameterHome, SavedRegister,
  ReturnAddress, OutgoingArguments, Padding and Canary. A canary is a slot
  written once at entry from a load relative to the thread pointer, read only
  by a comparison whose failing edge reaches a call that does not return, and
  never escaping. Its comparison is elided as a `compiler-inserted` obligation
  under `Premise::UbFreeSource`, and the premise is shown. A consumer that
  refuses the premise (A's `--strict`, a verification mode) keeps the check
  as a residual.
- **Promotion is an SSA rewrite.** A private, non-escaping object whose every
  access is a full-width load or store of one value becomes that value. The
  rewrite reads the frame model, replacing pre-SSA `promote.rs`.
- **No feedback.** A declaration belongs to the debug information and a proof
  to the frame model, and neither is restated as the other (C).
- **Consumers read it:** the certificates, memory SSA (its locations become
  frame objects, with phis keyed by `BlockId`), r2types, the renderer, and
  `afv`/`afi`, so the shell and the C name the same objects the same way.

## Done

Nothing yet.

## Left

- P4.0: the frame model as an index beside the current owners. Exit: a test
  compares the two partitions over the census, and every disagreement is
  judged.
- P4.1: certificates and memory SSA read it. Exit: `ObjectModelBuilder`'s
  frame half, `FrameReach`'s containment, `private_stack_objects` and three
  escape analyses (`escaping_roots`, `FrameReach`'s taint, `promote.rs`'s
  `escaped`) are deleted.
- P4.2: r2types and the renderer read it. Exit: `prepare.rs`'s width
  fallback, r2types' frame roles and its `StackSlotKey` slots are deleted.
- P4.3: promotion as an SSA rewrite. Exit: `promote.rs`, `PromotedSlot`,
  `promoted_slot_sites` and the `(block, index)`-keyed promoted maps are
  deleted.
- P4.4: the canary role and its elision under `UbFreeSource`, and
  `afv`/`afi` from the model. Exit: the 37 canary residual traps (all on
  `FS_OFFSET_0`) are gone, and `afv` has no names of its own.
- P4.5: the restatement removed. Exit: the proved half of `restated_slots`
  is deleted.
- Exit for the whole of P4: one owner of frame objects, and `afv` agrees with
  `pdd` on every local's name and extent.

## Consequences

- Equivalence and the census change at P4.3 and P4.4, and each change is read
  by hand.
- The canary elision is the first use of `Premise` as a condition on output.
