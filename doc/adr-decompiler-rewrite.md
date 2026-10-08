# ADR: the decompiler is rewritten from the sealed facts

Status: proposed (ROADMAP D, 2026-10-07; supersedes R in
[adr-renderer-printer](adr-renderer-printer.md), whose R1 record stands)

## Why a rewrite

r2dec is 78k lines and the component users read. The 2026-10-04 review rated
it 3/10; its maintainer rates it 1/10. The defects are structural, so R's plan
of cleaning it in place (R0 beside, R2 to R4 one owner at a time) keeps the
shape that produces them:

- It proves again what r2ssa proved. The observation journal (4k lines), the
  binding plan's fixpoint (`binding_plan/rules.rs`, `seal.rs`, 5.3k lines) and
  the effect ledger each re-derive facts the sealed artifact states.
- It retries. A failed placement re-runs the plan without the value
  (`apply_decisions_once`, the gap and split loops in
  `build_product_from_input_with_control`), so cost and output depend on the
  order failures are found.
- It repairs instead of refusing. Wrong C reaches users: `uncompress2` returns
  `case 1`'s constant where the binary returns a stack slot, `deflateInit2_`
  ends `L4: ;` with no return ([2026-10 sweep](reviews/2026-10-real-binary-sweep.md)).
  At P4's exit, records hidden behind the canary trap rendered calls without
  their arguments and arrays split into scalars.
- Policy lives in five places: `placement` (5.2k lines), `normalize` (3.4k),
  `fold`, `analysis/prepared_semantic` and `structure`, each with its own idea
  of what a value is called and where it is declared.

## Decision

A new r2dec is built as one pipeline of pure stages over the sealed artifact.
Each stage reads only earlier stages and the sealed facts, runs once, and
refuses a value with a residual where its facts stop. No stage re-checks a
fact r2ssa, r2types or r2engine owns.

| Stage | Input | Output | Cost |
|---|---|---|---|
| D0 contract | `SourceOwnedFunctionFacts`, `DecompileRouteFacts`, the language profile | `RenderInput`: the sealed IR, certificates, frame model, types, call contracts, route, profile, as indexes over dense ids; nothing else. Served first by an adapter over today's facts, which LX and T replace (ROADMAP D27) | O(1) borrow |
| D1 control | dominator tree, loops, certified predicates and selectors | structured tree over block occurrences, with the §3 certificate of [adr-structure-dominator-tree](adr-structure-dominator-tree.md) | O(blocks + edges) |
| D2 values | the partition, the frame model's bindings, each value's readers | for each value: a declared name, an inlined term, or a residual | O(values + uses) |
| D3 expressions | D2's terms | r2rewrite terms, simplified only by proved rules | O(terms × rules applied), each rule decreasing a stated measure |
| D4 declarations | frame model, `FunctionTypeFacts`, call contracts | locals, parameters, prototypes, globals | O(objects + calls) |
| D5 print | D1 to D4 | the profile's printer's text (C first) and the render tree with each node's obligation ids | O(tree) |
| proof | the render tree | every obligation discharged once, residual, or refused | one linear walk |

Rules every stage keeps:

1. **One spelling per fact.** A value's name comes from D2 alone, a type from
   D4 alone, a control construct from D1 alone. No later stage renames,
   retypes or restructures.
2. **Refuse, never repair.** A value whose binding, type or call contract the
   facts do not state is a residual with its reason. No fallback guesses an
   argument, a width or a declaration. An unproven call arity refuses the
   call (decided 2026-10-07, P4 exit).
3. **No retries.** A stage that cannot place a value refuses that value; it
   never re-runs an earlier stage without it.
4. **Deterministic.** Every map that reaches output is ordered by dense id or
   address, never by hash.
5. **Budgeted.** Every stage states its cost above, and the D gate times each
   on the large 0pack and pumasim functions.

The render tree is language-neutral ([language-profile](adr-language-profile.md)): a
call may return several values and a value may span two registers, and the printer the
profile names spells them. The C printer is the first; it spells several results as a
struct and a two-register value as a pair.

R's invariants carry over unchanged: the partition comes before inlining, every
access has one spelling from facts, every effect survives exactly once with one
typed owner. The three ADRs that state them (partition-first, access-syntax,
semantic-preservation-kernel) fold into this one when D lands.

## D2 and D3, as they are built

The obligation inventory says what must be rendered, so no stage re-derives it.

- **Demand.** An instruction with live obligations owes its statement: a store
  writes its cell, a return hands back its boundary value, a branch test is
  D1's condition, a call is written from the callsite facts (increment 2;
  until then a call is a gap). A value is rendered when a rendered term reads
  it, or when its producer owes more than its value (a non-private load).
  Every other value is dead as the inventory classifies it. r2ssa's
  certificates elide what needs no C: a frame save its restore undoes
  (`stack_frame_round_trip_by_inst`), a compiler-inserted check, the push of
  a call's return address; a spelled C `return` discharges the return
  address and exit stack pointer it consumes.
- **Inline or bind.** One rule, used by r2rewrite's import as its expansion
  policy and by D2 at each statement operand: a producer is absorbed into
  its reader when the reader is its only live reader, later in the same
  block, and, where the term reads memory or can trap, no instruction with an
  effect lies between. A phi reads at the end of the predecessor its edge
  leaves; a return's boundary read counts as a reader with no graph use. A
  literal or a term over entry values never redefined (`Multiplicity::Any`)
  is absorbed anywhere. A merge is never absorbed. A rendered value no reader
  absorbs is bound to its own local, assigned where it is defined, so a term
  is valid wherever its producer dominates.
- **Merges.** A phi is bound to its own variable, assigned on each incoming
  edge by one parallel copy, sequentialised with temporaries when one copy
  reads what another writes. Coalescing a phi web into one variable is the
  partition, r2ssa's to state from `ValueLiveness` and `StorageSpans` (D2.1).
- **Frame.** A stack object is a C byte array only where r2ssa proves the
  storage is the callee's (`callee_allocation`, or a source slot that is a
  local or a parameter home); a slot at or above the entry stack pointer
  holds what the caller put there, which a fresh array does not. A frame
  address is spelled only as the address of an access inside its own
  object's certified extent; anywhere else, held in a value or passed on, it
  is refused until D4 states one frame and its escapes.
- **Spelling (D3).** A term is spelled by its kind as unsigned C at its
  width, computed at least `int` wide so promotion cannot overflow, with a
  shift tested against the width before C shifts, memory read and written by
  byte copy, and a helper where C has no operator. A term with no exact
  spelling refuses, and its statement is a gap whose kind names the missing
  fact (`CallNotRendered`, `TermNotSpelled`, `StoreNotSpelled`,
  `ValueHasNoCType`, `EffectNotRendered`, `UnsupportedInstruction`).

Cost: one canonicalisation, `O(terms × rules applied)`, then one pass over
the operations and their uses.

## What survives

- The dominator-tree structurer and its certificate (SD, done): ported as D1.
- R1's proved rules (`cast.concat_zero_high`, the cast collapses, the ordered
  float comparisons): they are D3's rule set.
- `typed.rs`'s C typing at render boundaries: D4 reads it.
- The `Emission` / `pddj` output contract: D5 produces it, so `r2s` and the
  gates do not change.

## What is deleted

`observation_journal`, `binding_plan`, `placement`, `normalize`, `fold`,
`analysis/prepared_semantic`, `effect_ledger`, `single_evaluation`,
`unrendered` and the retry loops in `lib.rs`. The target is under 20k lines.

## How it lands

D amends D1 (restructure, not rewrite) for this item only. r2dec is replaced
as a whole on the `rebuild` branch (ROADMAP D27): the new pipeline is
`r2dec::render`, and the old path is deleted once D1 to D5 render, without
running beside it. The gates below report on `rebuild` and decide its merge.
Agreement means:

- equivalence: no record moves from `equal` to anything else on x86-64 or
  aarch64, and each other move is read and judged;
- census: each moved line is read; a rendering that gains a residual where
  the old path guessed is a fix, and one that loses a correct construct is
  a defect to close before switching;
- certification: 0 undefined reads, 0 panics;
- release `pdd` timing: no slower than the old path on the 0pack and
  pumasim functions, and peak RSS no higher.

| Step | Exit |
|---|---|
| D0 | `RenderInput` built from the sealed artifact; a Dylint forbids `r2dec::render` from reading anything else |
| D1 | control alone renders the census with every value residual; the §3 certificate holds on every function |
| D2 + D3 | values and terms render; the census residual count is at most the old path's |
| D4 | declarations from the frame model and types; `afv` and `pdd` agree on every local |
| D5 + proof | the proof walk replaces the ledger; `pddj` proof counts agree with equivalence |
| switch | the gates above hold; `rebuild` merges to master |

## Consequences

- No renderer policy lands on the old path while D is open. A wrong-C defect
  found on it is recorded against the D stage that owns it.
- The census moves once, at the switch, and is read by hand there.
- r2dec stops being where a missing upstream fact is hidden: every residual
  D renders names the owner that did not state the fact.
