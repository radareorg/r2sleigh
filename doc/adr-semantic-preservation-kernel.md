# ADR: semantic preservation kernel

Status: accepted in principle; to be rewritten against F2 and R

Only the surviving principles are kept here. The ownership spine, the FFI
table and the radare2 snapshot seam that this ADR used to describe are
superseded by AGENTS.md (one owner per fact, `r2engine::program::Source` as
the only input) and by doc/adr-renderer-printer.md.

## Decision

- **Exact-once preservation.** Every live effect in the canonical machine
  representation survives exactly once into an explicitly typed output node,
  or the function residualizes or refuses. Executable C is never justified by
  recognizing a benchmark, matching a symbol name, counting output statements
  or reproducing source-shaped text.
- **Obligation inventory** (`r2ssa::obligation`). Every canonical instruction
  has exactly one initial state (`SemanticInstructionState`): `LiveObligation`,
  `ProvenDead`, `StructuralControlOnly` or `UnsupportedUnknown`. The inventory
  covers observable reads and writes, calls with their arguments and results,
  returns, predicates and transfers, traps and ordering, loop-carried state,
  and every value producer that a live root needs. Obligation ids are
  independent of names, traversal order and output position.
- **Exactly one disposition.** Every obligation receives exactly one final
  disposition. A missing or duplicate disposition fails before structuring.
  Unsupported semantics stay residual or refused and never become guessed C.
- **Authority.** Only a source-retaining trusted lift produces a certifiable
  artifact (`TrustedSsaArtifact`). Hand-built blocks, interfaces or SSA may
  test analysis or an expected refusal, but they cannot produce a certified
  artifact, a ledger or executable C. Proofs derived from one artifact are
  valid only against that exact artifact. Function names are presentation
  only, and are excluded from semantic identities and fingerprints.
- **Typed output ownership.** An obligation is owned by an exact typed output
  node (an expression; a memory, call, control or return producer and
  component). Rendered text, names, output counts and AST positions never own
  an obligation. (R carries the obligations on the render tree.)
- **Structuring contract.** A structuring step consumes certified regions and
  returns the structured region, exact obligation-to-node ownership,
  control-domain evidence, residual obligations, and a deterministic refusal
  reason. A loop rewrite (for example, while to for) must map the exact
  initializer, phi, comparison, update and latch. Topology and widths alone do
  not justify it.
- **Admission rule.** Executable C is admitted only when all of these hold:
  - the source and machine context are coherent;
  - the inventory is complete;
  - every obligation has one preserving disposition with one exact typed
    owner;
  - widths, signedness, wrapping, shifts, casts, memory policy, ABI
    projections, the return address and the exit stack pointer are explicit;
  - no residual, refused, unsupported or open control obligation remains.

  Anything else residualizes or refuses.
- **Test policy.** Production code has no algorithm-specific recognizer,
  route, renderer, formula, binary offset or source-shaped template.
  Algorithm names appear only in test sources and fixtures. Positive tests
  start from real program bytes and drive the public pipeline. Generated C is
  checked against an independent oracle (the equivalence gate); comparing a
  renderer with itself is circular. Unsupported cases are refusal tests.

- **Readers** (D150, built by D253: `SemanticObligationInventory::readers`).
  The inventory owns who reads a value, and r2ssa's dispatch walk and r2dec's
  value placement both ask it. A reader is an instruction that owes something
  or is unknown (`LiveObligation`, `UnsupportedUnknown`); a proven-dead or
  structural one reads nothing. Each `ReturnValue`, `CallArgument` and
  unproven-return input (D254) is a read by that return or call even with no graph use site: a tail call's
  argument and a register a case returns have none. A call's carrier read
  (`CallUse`) is a read by the call unless the call is bounded: its boundary
  is complete and its callee's statement bounds what it reads
  (`!may_read_unlisted`, D326). A bounded call reads exactly its listed
  arguments; a call with no such statement, or with no boundary at all, reads
  every carrier. The inventory holds the bounded calls; the readers are one
  CSR over dense `ValueId`s (`ValueReaders`) built by the pass that asks:
  r2dec once per rendering, the switch certificates once per function that
  has a switch (O(V + uses + boundary inputs · log)); a query is O(1). Built
  for every prepared function, the index cost 0.17% of a cold 0pack `pdd`,
  most of it for callees nothing renders.

- **Seeds** (D253, `SemanticObligationInventory::seed`, `SeedReason`). Every obligation
  records why it was seeded: `Root` (the instruction owes it by what it is,
  or a boundary names its value), `Producer` (a live instruction reads the
  value: the liveness walk, a loop carrier, an edge transition, a private
  read), `UnprovenExit(r)` (the definition may reach return `r`, whose
  interface is unproven), `LoopUpdate` (a carrier update that does not
  validate), `Provenance` (an access whose provenance is incomplete) and
  `Unmodelled` (a user operation, an unproven call, a storage-less merge, a
  span with no semantics). Where several causes seed one obligation, the
  greatest in that order is kept, so `UnprovenExit` names an obligation only
  where nothing else seeds it. The unproven-exit walk labels each block with
  the first return in boundary order that it reaches, one backward walk,
  O(B + E + I). The inventory holds only the seeds a kind's usual reason
  does not explain (`Root`, or `Producer` for liveness) and the exit labels;
  `seed` reads the rest off them, so an obligation carries no seed field.
  Where effect accounting refuses, `pddo` lists each refused or
  unaccounted obligation with its operation (`0x{block}:phi:Register:0xa8:8 (R13_10 =
  PHI(R13_2, R13_16))`) and its seed (D174): the ordinal alone names the sealed
  block's operation, which `pdil` numbers differently. The refusal comment
  keeps its one-line form, which the equivalence and coverage ratchets read.

- **The dispatch a switch owns** (D150, `dispatch_operations` in
  `r2ssa::semantic::certificates`). A switch certificate elides the operations
  that compute its jump target, and the `switch` statement stands for them.
  An operation belongs to the dispatch when every reader of its value is
  already in the dispatch. An operation in the dispatch's own block may join
  whatever it owes (the table load); one in an earlier block, such as the
  guard block's widening of a biased selector, joins only when it owes nothing
  but its whole value, since it runs on the default path too. The selector
  never joins: the `switch` spells it. The walk visits each definition once
  and keeps, per value, the readers not yet found, so it costs O(uses of the
  slice).

  Before D150 the walk stopped at the dispatch block and counted every use
  site. A widening in the guard block (sw3 `base1`, toybox `endtype`) and a
  target left in RAX across an arm's call (diffutils `set_color_context`) were
  then live producers no statement rendered, and the function refused. The
  2026-11 hand audit named dead flag writes; the producers it reported were
  the zero-extension and the target addition. Cycle 1 counted only graph use
  sites, so a widened index a case tail-called with (`return sinkl(op - 1)`)
  joined the dispatch and rendered as a residual; reading the boundary's
  inputs keeps it outside. A value some reader outside the dispatch reads
  never joins (`a_value_read_outside_the_dispatch_is_never_part_of_it`).

- **Unproven machine returns** (D254, `SourceReturnBoundaryFact::live_registers`).
  A return whose machine state is proven (return address and exit stack
  pointer) but whose values are not reads every register a caller may read:
  each register definition that may reach it, as the return's explicit
  inputs. A call's clobber (a `CallDefine` no boundary states as a result) is
  killed, not read, and the two machine-state carriers are left to their own
  facts. The walk is backward over register bytes, entering a block again
  only with bytes not yet walked through it: O(R · (B + I)) for R register
  bytes the function writes. Each input's producer owes its value, and the
  inputs are reads (`ValueReaders`), so a live one renders or the residual
  return covers it. A return whose machine state is unproven keeps the
  block-reachability taint. Before, the taint seeded every definition in a
  block reaching such a return, killed or not: hello_gs and testapp refused
  16 functions at a merge no text could render (RDX after `__security_check_cookie`).

- **Frame addresses** (D254, `StackGeometryCertificate::object_addresses`,
  `ElisionReason::FrameAddress`). An instruction is a frame address when its
  value addresses one own-frame object (a stack slot or frame object at a
  callee-owned offset below the entry stack pointer) at one constant offset,
  with no index, and a merge only when every arm states the same object and
  offset: one pass, O(I + phi inputs). r2rewrite's import records each read
  it spells as the object's address (`Substitution::addressed`), and r2dec
  sets a bit where kept text spells that value `&object` and still names the
  object. A value obligation at such an instruction with the bit set is
  `Elided(FrameAddress)`, checked after residual cover, so a gapped reader
  still wins and an escape stays visible in the text (`FrameReach` owns the
  escape, D290). `thousands_sep` (RBX `lea rbx, [rsp + 8]` on both arms, read
  by two calls) and gzip `main` (R13 `lea r13, [rsp + 0x24]` on both arms,
  getopt_long's fifth argument) rendered nothing for the merge before.

- **Traps** (D352, r2sleigh-lift `ModelledUserOperation::Interrupt`). Sleigh
  spells x86 `int3` and `int1` as `swi(n); call [vector]; return [0]`, its way
  to end flow at an exception (Intel SDM: #BP and #DB). The lift spells `swi`
  with vector 3 or 1 as `Breakpoint`, which ends the instruction; any other
  vector keeps the call Sleigh writes. The `return [0]` had read as a return
  whose interface is unproven, and its taint refused 7 PE functions that end
  `call f; int3`.

- **Declared never-returns** (D255, r2engine `declared_return`). A body whose
  debug information states `DW_AT_noreturn` never comes back, with no premise,
  so a call to it ends its block and demand names the caller's exits.
  diffutils `try_help` ends in `error(EXIT_TROUBLE, ...)`, which glibc's row
  says comes back, so the walk had listed the next function as the call's
  fallthrough and the caller's result kept every byte of RAX. A body-derived
  `Never` still names its exit; RULING 1.4 gives `Return::Never` a proof kind
  so that only a declared one does, which is D255's open half.

## Done

- The obligation inventory, the single disposition per obligation, and the
  `TrustedSsaArtifact` boundary exist in r2ssa.

## Left

- Rewrite this ADR against F2 (obligations and dispositions as indexes over
  dense ids) and R (obligations carried by the render tree, one linear
  checker). Exit: the rewritten ADR names the index and the checker that
  enforce each principle above.
- Exit for the principle as a whole: any deliberate deletion or duplication of
  an effect fails before rendering.
