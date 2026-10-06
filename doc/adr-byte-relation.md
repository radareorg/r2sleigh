# ADR: one byte relation

Status: proposed (ROADMAP B, before M1d and P4)

## Context

Which bytes of which value an operation reads and writes is answered three
times, each with its own per-operation transfer: the demand pass
(`demand.rs::transfer`, backward, rooted at the return registers), program
observation (`deadphi.rs::observed_input_bytes`, backward, rooted at the
obligations and live-out values) and written lanes (`lanes.rs::transfer`,
forward). r2dec answers a fourth time (`binding_plan/rules.rs::
unread_defined_values`, whole values, not transitive). Boundaries compare
storages with `==`, so a slot narrower than the register family's program
root never matches.

Each disagreement has cost a regression: a lane-sized float slot (`XMM0_Qa`)
matches no `CALLDEF` of `XMM0` (M1d); r2dec binds a value r2ssa proved
unobserved and then asks for an operand the plan elided; a callee's
preservation proof once depended on how a clobber list was spelled (M1b).

## Decision

- **One relation.** `r2ssa::bytes` states, per operation, which input bytes
  each output byte depends on and how (copied, extended, combined, filled).
  Backward demand and forward classification are two readings of it; no pass
  has a transfer of its own.
- **One closure, named roots.** Demand and observation are the same backward
  closure over the relation from different roots (return registers;
  obligations and live-out values). The result is an index of the sealed
  function (doc/adr-one-ir.md): an observed `ByteMask` per value, computed
  once.
- **A slot is a lane of a root.** Every boundary slot (parameter, call
  argument, call result, return) is `(root storage, byte range)`, matched by
  containment against the program root's definition. The lane becomes the
  logical value's carrier; nothing compares storages by equality.
- **Consumers read the index.** Liveness, dead-merge pruning, the demand
  release, written widths, parameter widths (`cover(demanded)`) and r2dec's
  dead values read it. `unread_defined_values` is deleted.
- **Checked against the machine.** The relation is checked against
  `r2il::eval`: exhaustively at 8 and 16 bits, under Kani at 32 and 64.
- **Cost.** O(ops × W) once per sealed function, W the widest value in bytes;
  O(1) lookup.

## Done

- B0 (`0ca2d79d`, B0b): `r2ssa::bytes`, one rule per operation checked
  against `r2il::eval`; demand, observation and written lanes read it and
  their three transfers are deleted. The census stayed byte-identical,
  although observation became as precise as demand (or, xor, sign
  extension).
- B1: `bytes::closure` is the one backward closure; `Demand` runs it from the
  return values and every effect's inputs, observation from its obligations.

- B3 (`3b60c019` and the next commit): one identity per family at every
  boundary (`root_slot_for_name`); call results, the reaching-value search
  and the return certificate match a slot against the program root whose low
  lane it is (`is_low_lane_of`). M1d's float lanes render.
- B3, declared floats: the call-argument certificate, the entry lookup, entry
  lane projections (minted for a call's argument lanes too), the reaching
  walk's merges and root writes, and AArch64's float slot (narrowed to the
  value's low lane) match by lane; a literal passes the return gate as a
  temporary does. `float_calls_*`, `float_returns_*` and review.c's `avg`.

## Left

- B2 moves into R (doc/adr-renderer-printer.md, R2). Measured over the
  census, r2dec's `unread_defined_values` holds 934 values that r2ssa calls
  observed. The roots are not the cause; the obligation inventory disagrees
  with r2dec about liveness. It marks `CALLDEF`s read only by non-argument
  `CallUse`s as structural but used; stack-pointer adds that nothing reads as
  `LiveObligation`; never-read values as `UnsupportedUnknown`. The inventory
  has to own that liveness, with one checker, before r2dec can read it. Exit
  (in R2): `unread_defined_values` is deleted.
- B3 rest: a recovered interface's float slots (with P7, ROADMAP.md);
  declared ones match by lane (above). Exit: no boundary match by storage
  equality where a slot is a lane.
  Surveyed 2026-10-06: recovery reads no float slot, so its equalities
  (recover_interface.rs, entry `canonical_storage == Some(slot)` and the
  result's location and size test) are latent. Seven compare a value's
  root with a declared float lane by equality: optimize.rs (return phi kept
  only when its root equals the carrier), interproc/mod.rs (call-argument
  carriers; the return storage and a callee's result storage), and
  semantic/shared.rs (entry, phi and written storage against the wanted
  one; a root `CallDefine` against a lane). None moves a census function
  or a probe of declared and undeclared floats on x86-64, so no failing
  case exists yet; P7's float recovery is what reaches them, and it
  replaces each with `is_low_lane_of`, which needs the machine context the
  shared.rs walks do not take today.
- B4, measured (2026-10-05): over the census no loop header merges two
  overlapping storages, so byte-granular liveness has no instance yet; r2dec's
  relocated recompute costs 1.5–5 ms of a 2–3 s `pdd` on the large 0pack and
  pumasim cases, repeated by R's retries. #50's first gate reads
  `liveout::is_read`; its third is R2's. Exit: a failing case, or #47 and
  #50 closed when R2 lands.
