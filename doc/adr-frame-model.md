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
- **Dead frame stores.** `PreparedFunctionCertificates::dead_frame_stores`
  holds every access of a frame object the function allocates at each of its
  accesses (`CalleeStackAllocationCertificate`) when every access is a write,
  the object does not escape, no call reaches it (`FrameReach`: an unbounded
  call reaches every object, a bounded one its argument area), and its extent
  is not assumed (`extent_assumption`, which also covers its own unbounded
  index). The set is empty while any frame read has an unbounded index: since
  objects partition the frame, only such a read can land on another object.
  An object whose extent a declaration, a parameter home or a callee's write
  reach states is not assumed. Filled once per sealed artifact (and per
  `with_assumptions`), O(objects + accesses + calls), plus O(accesses) for
  each object with an assumed extent (its declarability scan); r2dec reads it.
- **No feedback.** A declaration belongs to the debug information and a proof
  to the frame model, and neither is restated as the other (C).
- **Consumers read it:** the certificates, memory SSA (its locations become
  frame objects, with phis keyed by `BlockId`), r2types, the renderer, and
  `afv`/`afi`, so the shell and the C name the same objects the same way.

## Done

- P4.0, measured (2026-10-06): `scripts/frame_agree.py` compares `afv` with
  `pddj`'s declared locals at each entry-stack offset over the census. 99 of
  1218 offsets agree: afv-only 946 (promoted slots and saved registers the
  rendering declares nothing for), afv-twice 49 (one promoted offset at two
  widths), pdd-twice 43 (a slot and a temporary bound to it), pdd-only 31,
  type 29, name 21 (`afv` spells `stack_m{N}` where the rendering uses the
  debug information's name). This is the number every P4 step moves.
- P4.1: one extent rule's forbidden halves deleted (the gap extent and the
  widest-access guess); one escape analysis, `FrameReach`'s O(V + E) taint,
  with every sink stated once, read by the obligations (`private` is the
  frame objects not escaped), the certificates, memory SSA and r2dec's
  binding plan; `private_stack_objects`' per-object walk,
  `escaping_roots`/`escaping_addresses`, `callee_reached` and r2dec's own
  walk deleted; containment one `FrameIndex` (O(log n)). Census: one
  rendering fixed (stores to locals read through a pointer array were
  dropped), 14 `_start` reorderings. `promote.rs`'s escape set is P4.3's.
- P4.2: r2types' own frame-slot map, roles and authorizations deleted
  (3163 lines, unread in production); a frame object has one name
  (`SourceOwnedFunctionFacts::stack_object_name`: the debug information's,
  else `r2ssa::frame_object_name`).
- P4.4, `afv` half (amended 2026-10-06): `afv` lists the frame locals the
  C rendering declares (`VariableLocation::Frame`), read from the cached
  rendering, and the frame model only where the rendering refused. A
  promoted slot's value is reported at its offset (`SymbolRole::FrameValue`);
  a call's own return-address push is no local. `frame_agree`: 385 of 385
  offsets agree over rendered functions (90 refused). Coverage: three
  `_start`s gap 13 to 14, because the read of the caller's `[sp]` now stays
  before the pushes through the realigned stack pointer, in program order.
  Amended 2026-10-09 (D switch): `afv` reads the frame model for both
  pipelines, since staged declares one `frame` array; a promoted copy of the
  return address a return reads is frame management. `frame_agree` moves
  back toward afv-only offsets until P4's exit makes the two agree.
- P4.4, canary half (amended 2026-10-06): the check is decided in r2ssa
  before preparation (`stack_protector.rs`), not as a frame role: gcc at
  -O0 keeps the canary in a slot, but promotion often takes it out of
  memory, leaving two reads of the guard compared. Under
  `Premise::UbFreeSource`, which r2engine grants (`accepted_premises`), a
  check comparing two reads of the platform's guard slot (r2abi states
  it: x86-64 Linux `fs_base+0x28`, i386 Linux `gs_base+0x14`; a
  thread-local read twice is not one), directly or through a slot written once before
  the reload, whose mismatch edge reaches only a call that does not return,
  passes: the failing edge and block go, every reread becomes a copy of the
  first read (so a live `reload - guard` folds to zero), and the reads and
  the slot store are certified `compiler_inserted` unless something outside
  them is observed reading one (a returned carrier holding the canary keeps
  its residual). The removed failure block's instructions stay in the
  inventory as `CompilerInserted` obligations, so `total` does not shrink
  by deletion. The proof line and `pddj`'s `premises` name the premise. Census:
  14 functions lose the canary residual and `__stack_chk_fail`; one array
  shrinks to its own 16 bytes. The x86-64 baseline holds 38 canary traps;
  aarch64's guard is a global (`__stack_chk_guard`), which this rule does
  not read. A consumer refusing the premise is item A's.

## Left

- Extent, amended (2026-10-07, user decision "assume and label"): where
  nothing declares an object and no layout proves it, but code outside its
  own accesses may reach past them (an escaped address, or an index no
  value range bounds), the C declares the accessed extent and every access
  to the object counts in the proof's `assumed` column
  (`SsaArtifact::extent_assumption`). FrameReach closes an escaped address
  upward to the next compiler-owned slot (a save, the canary), so every
  store such an access could read stays (P4.1e). A layout proof (the
  `% d` rewrite) moves an object out of `assumed`. Measured: 46 rendered
  functions with an escaped frame object, 2 with an unbounded index.
- Extent, amended again (2026-10-07, user decision "merge the reach"): an
  escaped address may reach every object from it up to the next slot the
  compiler owns or that holds a register's entry value (a save, the return
  address, a parameter's home), so that run is one object
  (`FrameReach::escape_spans`, seeded into the builder as write spans and
  built once more). C's pointer arithmetic across it is then defined:
  `shape_pointer_to_pointer`'s `rows[4]` and its neighbours are one
  88-byte object, where the assumed extent split them into scalars and
  differed. A run opens at an object whose own address escapes, so the
  outgoing argument area below the locals (Darwin's variadic tail) stays
  the call's. Left assumed: an interior address reaching down past its
  object's base, and indexes no range bounds (39 census functions, from
  43). Cost: one arm64 -O0 `main` spells an interior address of its merged
  run through the stack pointer, a residual (r2dec's address spelling, D).
- P4.0, amended (D1, 2026-10-06): no second model beside the owners.
  `ObjectModelBuilder`, which the certificates, memory SSA, `FrameReach`,
  the binding plan and `afv` already read, grows into the frame model, and
  each other owner is deleted into it. The exit measure is
  `scripts/frame_agree.py`.
- P4.1: certificates and memory SSA read it. Exit: `ObjectModelBuilder`'s
  frame half, `FrameReach`'s containment, `private_stack_objects` and three
  escape analyses (`escaping_roots`, `FrameReach`'s taint, `promote.rs`'s
  `escaped`) are deleted.
- P4.2: r2types and the renderer read it. Exit: `prepare.rs`'s width
  fallback, r2types' frame roles and its `StackSlotKey` slots are deleted.
- P4.3: promotion as an SSA rewrite. Exit: `promote.rs`, `PromotedSlot`,
  `promoted_slot_sites` and the `(block, index)`-keyed promoted maps are
  deleted.
- P4.3 done (2026-10-07): `promote.rs`, its `promoted` map threaded
  through phi placement and renaming, and `promoted_slot_sites` are
  deleted. `slot_promotion.rs` runs after SSA construction, before the
  stack-protector decision, so preparation seals one frame:
  - `frame_address.rs` resolves an address to a root and offset through
    copies, constant arithmetic and merges, the merges solved once on
    `fixpoint::sparse` (height 2). A recursive merge walk took 0pack
    `0x62ecf0` past 49 minutes.
  - An address escapes into a call use, a stored value, or a register a
    call may read (the convention's argument registers, every register
    without one); the stack and frame pointers are bases, never handed on.
  - Saves are entry-block stores of a preserved register's entry value
    (any register without a convention); a save read back stays in memory
    and bounds what an escape reaches.
  - Phis go at the iterated frontier where the slot is live (pruned).
  The census against `promote.rs`: rv_O2 13 -> 11 and branchy_arm64 O1/O2
  one residual fewer each. Pre-index saves kept in memory exposed the
  callee-allocation proof reading sp only at the access: P4.3d lets either
  edge of the access's machine instruction own it, the explicit area
  first (x86-64's red zone would otherwise mark a `push` implicit).
- P4.4: exit measured at P4's exit: the 38 x86-64 canary residual traps
  (all on `FS_OFFSET_0`) leave the equivalence baseline.
- P4 extent, left (2026-10-07): the canary elision let equivalence run
  functions whose residual trap had hidden layout defects. Fixed: the
  escape closure (P4.1e/g) and the `% d` layout proof (P4.1h). Standing:
  gcc -O1 `shape_struct_array` walks a pointer over a frame array
  (`p += 8`, eight steps), which no layout proof reads, so the C splits
  the array (UB in the rendering); a layout proof over an induction
  pointer closes it. gcc -O0 `unaligned_words` dereferences an address
  of unproven alignment as `*(uint32_t*)`: a renderer defect (R), not P4.
  gcc -O1/O2 `shape_byte_indexed_buffer` moved from residual-trap to an
  honest refusal.
- P4.5 done (2026-10-07): the frame owns the slots it proves
  (`SsaArtifact::proved_parameter_home`, `stack_slot_role`,
  `stack_slot_logical_type`); `restated()` restates only declarations,
  `restated_slots` is deleted. Removing the restatement exposed
  `promote.rs` deciding escape upward only: P4.3a-c make a frame address
  stored or held in a register (at a call or the block's end) escape both
  ways to a save slot strictly between, take the frame pointer from the
  convention (`SourceMachineRoles::frame_pointer_storage`), and let an
  indexed address handed on escape both ways. Cost, judged: clang -O0
  `shape_pointer_to_pointer` stores `&rows` into `cursor` below it, so
  `cursor` stays in memory, the callee's reach no longer merges `rows`
  into one 32-byte object, and the rendering (counted `assumed`) differs
  where it was equal.
- P4.5: the restatement removed. Exit: the proved half of `restated_slots`
  is deleted.
- Exit for the whole of P4: one owner of frame objects, and `afv` agrees with
  `pdd` on every local's name and extent.

## Consequences

- Equivalence and the census change at P4.3 and P4.4, and each change is read
  by hand.
- The canary elision is the first use of `Premise` as a condition on output.
