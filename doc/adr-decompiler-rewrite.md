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
  reads what another writes. An edge whose operand is the phi's own value
  (a latch that leaves a carried value alone) writes nothing and joins no copy
  set, so it stages no temporary. r2ssa states that edge: `forward_copies` at the
  seal points a merge source that is a copy, through any chain, of the merge's own
  output at the merge itself, and r2dec compares ids, never spellings. Coalescing a phi web into one variable is the
  partition, r2ssa's to state from `ValueLiveness` and `StorageSpans` (D2.1).
  A merge reads as a variable only when every distinct placed *forward* edge into its block renders its
  copy (`Values::owed`: one per forward edge spelled before the merge, set by `forward_in` from the CFG's
  predecessors and `DomTree::is_back_edge`, paid once per edge by `account_copy`). A back edge, a self copy
  and a gap pay nothing, so a latch copy never justifies a read at the header and one gapped forward copy
  keeps every read residual. A gap traps where it stands
  (`a_gap_is_written_as_the_residual_call_whose_helper_traps`), which would make "any forward copy renders"
  sound at run time, but the certificate lets control go on past a gap
  (`GapKind::ValuesNotRendered.ends_control()` is false) and a verdict does not lean on what the
  certificate denies; the weaker rule is ledgered in "D2's spelling order".
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

## D2's spelling order

Every verdict D2 gives (a statement rendered or a gap, a name read as a variable or as a NeverAssigned
residual, an edge copy, an extern, a local) is a function of the sealed facts and the reverse postorder
of the placed blocks. It is never a function of the order `control::Writer` composes blocks, which
the placement chooses to put an exit inside a loop or after it and a merge in this region or that.

- **One pass, then the layout.** `render::spelled::spell` walks `function.block_addrs()` (r2ssa's block
  order, which is the CFG's reverse postorder, filtered by `place::is_placed`) and spells each block's
  statements, then its edges (the copies of a target's merges, `transferred`, or a tail call and the
  gap that stands for it), then the operand the block ends on, in the order `Writer::arms` used to.
  No verdict depends on that order: a block's test reads no merge its own forward edges pay, since a
  merge the block's test reads dominates the block and so enters it only by a back edge, which pays
  nothing. The result is a typed table (`Spelled`, by
  block address) that the Writer takes once per block. The Writer holds no `Values`: it decides
  regions, loops, labels and switch case grouping, and `crates/r2dec/tests/architecture.rs` keeps
  `control.rs` free of `Values` and `spelled.rs` free of the placement.
- **Why a pass and not a prediction.** Whether a block's statements render is not knowable from the
  facts alone: a term with no spelling, a type with no C type, a callee the symbol table shadows and an
  identifier a global claimed first each decide it, and a predictor of those would be a second copy of
  the spelling rules. So the order of spelling is made a fact of the CFG, and cost stays `O(B + E +
  statements + phi inputs)`, one sweep, no fixpoint.
- **Forward edges are exact.** The first arrival at a merge is never over a back edge, since a back
  edge's source is dominated by the merge, and every read the merge dominates follows an arrival. A
  forward predecessor comes before the merge in reverse postorder where the region is reducible. In an
  irreducible region an edge can be forward by dominance and still retreat in reverse postorder (a
  *late* edge): its copy is spelled after the first reads of the merge it enters. The merge is not owed
  that copy; it is verified. The first attempt reads the merge as a variable on the promise that the
  copy renders, and `Values::broken` names every merge whose late copy gapped; `render` then spells the
  function again with each of those owing one definition more than any edge pays, and stops when an
  attempt breaks no promise. Each attempt adds a merge to the set, so there are at most as many attempts
  as merges; over bash, ls-toybox and pigz (2,508 functions) 43 hold a late edge (280 edges) and one is
  spelled again, over 0pack and pumasim (23,201 answered) 123 hold one (1,084 edges) and none is. The rule stays "every forward edge renders its copy", checked by the attempt that
  stands, and the attempts are a function of the facts and the order. Owing the late copy at the early
  reads instead made 36 functions read 424 more sites as residuals that the copy would have defined.
- **The gate.** `placement_mutants` (a cargo feature, off by default and absent from release builds)
  permutes the placement's write order: O1 keeps every loop exit after its loop, O2 reverses each
  loop's exits, O3 reverses each region's merges. `census.py orders` runs `pddj` of every function of
  bash, ls-toybox and pigz under each and compares what no write order may change (the ledger's
  columns, the never-assigned names, the residual sites by instruction address, cause and gap kind, the
  declared names and links, and the set of statement lines apart from control). The rendered text
  itself cannot be equal: O1 turns an inlined exit into a `goto`, and O2 and O3 move blocks, so the
  labels and the site numbers move. The structure stages (chains, tails, latch, rotate) read text
  order, copy text and never call `Values`; their shapes differ by layout by design and are not
  gated, and nor is the selection pass (`if (c) x = a; else x = b;` against `x = c ? a : b;`), which
  the fingerprint counts apart.

Measured (2026-10-23) over bash, ls-toybox and pigz, 2,508 functions, one mutant build per step:

| Step | O1 differ | O2 differ | O3 differ | Functions whose text moves (O1, O2, O3) |
|---|---|---|---|---|
| the knobs alone (write-order dependent) | 0 | 120 | 187 | 64, 338, 722 |
| spelled in reverse postorder | 0 | 0 | 0 | 64, 332, 720 |
| and the forward-edge rule | 0 | 0 | 0 | 64, 332, 720 |

One function under O2 and seven under O3 differ only in a selection. Against the base, the natural
order moves 13 of the 2,508 functions (+9 residual sites): the lazily declared locals of seven bash
functions' block-transfer loops are numbered in reverse postorder (`reached_5` for `reached`), bash
`0x8ee40` lists its `_next` temporaries in another order, and five hold a gapped forward copy (bash
`0x2dd90`, `0x48140`, `0x85d70`, ls-toybox `0x392dc`, `0x501c8`). 0pack `0x476982` has 9 residual
sites under all four orders: the base's 7 under O1 read `rsp_8` after a loop whose entry copy at
`0x4769b1` is a gap, so nothing assigns it on a zero-trip path, and that read is what the rule refuses.

Ledgered: ROADMAP D62 (a callee's result presence is one fact per callee, not each call site's to
spell), D63 (reading a merge as a variable when any forward copy renders, which waits on the
certificate agreeing that a gap traps) and D64 (`Values` immutable once spelled).

### A name is read where its definition has run (D68)

D58 reads a bound name as a variable when every write to it is spelled (`owed` is 0) and spells the
blocks in reverse postorder. Reverse postorder is not dominance: a block spelled first can lie on the
other arm of a branch from the block that reads. At `15486ea7` pumasim `0x279d80` and `0x27b040`
read `tmp_lane_279e4c_0_0_1` and `tmp_lane_27b110_0_0_1` at an `atan2f` the lane's block does not
dominate (4 reads, assigned only on the other arm), and the proof line said `0 residual`. The
parents print the same C on a mirrored layout (`lane_nondom8`) and a residual at the tip, so D58
moved which functions show the error; it was r2ssa's fact that was wrong.

```text
lane_nondom9(flag rdi, p rsi, q rdx): xmm1 = flag ? p[0] : p[1]; ucomiss xmm4, xmm2 (q[4], q[5])
  jbe call; comiss xmm1, xmm2 (reads xmm1's low lane); jbe out; ret
  call: movaps xmm0, xmm4; call atan2f; ret        out: ret
```

- **The fact.** `narrowed_argument` took `ValueViews::low_lane_value`, the first value of the lane's
  class in definition order, as the call argument's `value` (the carrier as `lane_of`). The class
  holds values of the same bits wherever defined: the carrier XMM1_6 is defined in `0x279e1c`, the
  lane (a `SUBPIECE` the `comiss` reads) in `0x279e4c`, the call is in `0x279ec8`, and `0x279e3e`
  branches to either. The first of a class need not dominate a read.
- **r2ssa owns it.** `integrity::defined_before(function, graph, value, block, ordinal)` is the one
  rule: an entry value, a phi or an earlier operation of the block, or a definition in a strictly
  dominating block, `O(1)` from the dominator tree's preorder intervals. `narrowed_argument` keeps a
  lane only where it holds at the call and otherwise states the carrier the walk reached with no
  `lane_of`, which renders `(uint32_t)xmm1_6`, a truncation of a value that dominates (the state
  before lane narrowing, for those calls). Where a later member of the class would have dominated,
  the carrier is used instead (left, below). `validate_boundary_values` checks every value a sealed
  fact reads against the place it reads it, `O(facts)`: call arguments and their carriers, call
  targets, return values, the return address and the exit stack pointer, branch conditions and
  switch selectors. A violation refuses the function (`IntegrityRule::BoundaryValueNotDominated`,
  `SSA integrity: a boundary fact names a value its definition does not dominate`), as
  `validate_ssa_function` does for an operation. It is beside that function and not in it:
  `validate_ssa_function` runs on the `SSAFunction` before the seal, and the boundary facts exist
  only after the seal has dropped the operations it reads. Call results are definitions the call
  makes, not reads, and a comparison's operands (`PredicateFact::comparison`) name the copy classes
  the condition compares, the same first-of-class pick; no renderer reads them, and checking them
  refused 44 of bash's 1,568 functions in the first version of this check, so they are not checked.
- **r2dec holds the line, as a hard rule.** `Values::read_name` asks r2ssa
  (`SsaArtifact::value_defined_before`, the same rule) whether the name's definition has run in the
  block being spelled (`Values::enter`, once per block in `Spelling::block`); if not, the read is a
  residual with refusal evidence (`read-not-dominated`) and a proof-line cause of its own ("assigned
  on only some paths to its read"). It is not a `debug_assert`: it is the one check on the text
  itself, where the validator checks facts at their reads and the terms the arena expands read
  names no fact mentions; it costs `O(1)` per read; and a `debug_assert` would abort in the build
  that shows a violating read becoming a residual (rule 8: a visible residual beats plausible
  unproven C). It decides nothing r2ssa owns: the rule is r2ssa's, the policy (a residual the proof
  line names) is the renderer's. With the lane pick and the check both gone (`fact_mutants`, a
  test-only feature) the guard alone makes the read a residual, under the four write orders; with the
  pick gone and the check kept, r2ssa refuses the function. `Values` holds the block as a `Cell`,
  set only by the spelling pass (D64).
- **Siblings.** `low_lane_value` had one caller. The other first-of-class picks and where they go:

  | Pick | Used as | Verdict |
  |---|---|---|
  | `low_lane_value` in `narrowed_argument` | a call argument the text reads | the defect; fixed |
  | `proven_low_lane` in the callsite certificate | a proof that the bits are equal | unchanged: it proves the bits, `defined_before` the scope |
  | `class_value` in `PredicateFact::comparison` operands | class names for range narrowing, trip and tail counts, certificates; r2types copies them into `PredicateComparisonFact` | not a read, no renderer reads it |
  | `StackReloadSourceCertificate::canonical_source` | a key for r2types' address steps and field inference | not rendered |
  | `class_value`/`class_key` in `values.rs`, `uncertified_call_reads`, `expression_phi_has_single_canonical_root`, `tail_offsets`, `address_candidates`, `predicates` | equality keys | safe |
  | `copy_root`, `same_integer_root` | the view's root, which dominates what it is the copy root of | safe by construction |

  r2ssa alone was enough for the 25,735 functions measured: with the guard turned into a report, the
  five binaries read 0 names out of scope. The guard is the second line, not a second owner.

Measured at the code tip, against `15486ea7` (the same dumps, `pddj` of every function):

| | bash | ls-toybox | pigz | 0pack | pumasim | 10 more binaries |
|---|---|---|---|---|---|---|
| functions | 1,568 | 827 | 127 | 8,437 | 14,776 | 14,034 |
| changed | 0 | 0 | 0 | 0 | 2 | 0 |
| newly refused | 0 | 0 | 0 | 0 | 0 | 0 |
| reads out of scope, tip (the dominance audit) | 0 | 0 | 0 | 0 | 4 in 2 functions | |
| reads out of scope, now (also under O1, O2, O3) | 0 | 0 | 0 | 0 | 0 | |

The two pumasim functions keep their ledger (rendered 352 and 327, residual 39 and 30 obligations,
11 and 7 sites) and read `(uint32_t)xmm1_6` where they read the lane; the guards build, which made
the argument a residual by an accident of order, has 47 and 38. Residual sites (135,070 in the five,
226,226 in the ten) and gotos (27,108 and 48,832) are equal. clang `-Wuninitialized` (with
`r2sleigh_residual_void` noreturn), functions that warn: bash 1, ls-toybox 1, pigz 0, 0pack 5 and
pumasim 13 before, 1, 1, 0, 5 and 11 now; the 18 left all say `may be uninitialized`, and each
binary has as many as at the parents. 240 generated float objects (1,920 functions, `libm`
callees): 56 functions warn at the tip and 0 now, under the natural order and O1, O2 and O3 alike;
90 change text, none is newly refused, and residual sites go 63,560 to 63,531 (34 functions have
fewer; `s106_O1` `0x8000540` has 19 to 25 and one more `goto`, since the call now reads the
carrier, whose chain holds a register read from entry, and renders that chain as residuals).
`census.py orders` over bash, ls-toybox and pigz (2,508 functions): O1, O2 and O3 differ 0, 0, 0
(the text moves in 64, 332 and 720; 0, 1 and 7 differ only in a selection), now over the refused
functions' ledgers as well; 0pack `0x476982` has 9 residual sites under all four orders. Release
`pdd` with `aa`, instructions retired, two runs each, tip then now: 0pack `0x62ecf0` 71.86G and
71.73G, 71.89G and 71.86G; pumasim `0x23fdf0` 85.01G and 84.98G, 85.13G and 85.06G (+0.1%, the
renderings md5-identical), peak footprint 251 to 261 MB and 255 to 257 MB in both.

**Mutation.** `scripts/mutants_d68.py` applies each of 25 mutants of the checks and runs the tests
that should kill it: 22 die (the lane pick unfiltered, with and without the check of the facts; the
check unwired; the guard unwired, never told its block, letting a name through or naming the wrong
cause; each of the validator's eight fact families dropped; `defined_before` off by one, with its phi
case wrong, its entry case wrong or always true; the production write order changed three ways).
Three live, each with its reason: the guard with r2ssa's pick and check both gone (by design: the
guard holds alone, and the tests that accept a residual accept it), `strictly_dominates` for
`dominates` in `defined_before` (equivalent: the same block returned above), and the block-end read
placed at the block's start in the validator (no fact the fixtures hold reads a value its own block
defines; the SSA validator orders those reads).

Left: a later member of the lane's class that does dominate the call is not looked for (the carrier is
used; `O(k)` per argument for k members, and `low_lanes` holds only the first of each class); the
`canonical_source` of a stack reload and a comparison's operands are not checked, since nothing
renders them; the production-order mutants are pinned by one unit test, the feature-on build being
the one the workspace tests compile.

## D4's frame, as it is designed

The machine stack below the entry stack pointer is one region; C must see one
object there, or a pointer formed from one slot and moved to another leaves
its array.

- **One array.** The function's own frame is `uint8_t frame[size]`, spanning
  `[low, 0)` in entry-SP coordinates: `low` the least entry offset of any
  object whose coordinates r2ssa states (`callee_allocation.entry_offset`, or
  `objects().entry_stack_roots`). Every byte below the entry stack pointer is
  the running function's by the ABI; an object with any byte at or above
  offset 0 is the caller's (the return address, stack arguments) and is never
  in it. An access at a literal offset or index is spelled only inside its
  object's extent. One at a computed index is spelled from the one object its
  address names, as the machine computes it, so the C stays inside `frame`
  wherever the program's index stays inside the object: the assumption r2ssa's
  array layout proof makes too, whose index range is MAY evidence clamped to
  the frame. That proof's geometry (stride, element) types an array; byte
  arithmetic on `frame` needs none of it.
- **Addresses.** An object's address is `frame + (offset - low) + pad`. A frame
  address may be held in a value, stored or passed to a call as such a
  pointer, because every place it can reach in the machine's frame is a byte
  of the array. Escapes stay r2ssa's (`FrameReach`); the array changes only
  how they are spelled.
- **Alignment.** A callee may use an escaped address for an aligned access
  (`movaps`), so the array keeps the machine's alignment: `_Alignas(16)`, and
  `pad` chosen so `frame + pad` is congruent to `entry_sp + low` modulo 16.
  The entry stack pointer's residue is the convention's to state
  (`r2abi::CallingConvention`): SysV AMD64 makes `%rsp + 8` a multiple of 16
  at entry (psABI §3.2.2), AAPCS64 makes SP a multiple of 16 at any public
  interface. A convention that states none declares no frame array.
- **Contents at entry.** The array starts indeterminate, as the machine's frame
  does; a read before any write is the program's own, and the gate sees it.

Cost: one pass over the frame objects, `O(objects)`.

## D4's callee declarations

C declares a callee once, so every call to it in a function states one prototype. That prototype is
a fact of the function, not of the order its blocks are written in: `Values::decide_prototypes`
takes, per named callee, the declaration of its first call in address order (block, then place in
the block) among the calls whose plan states one, `O(calls log callees)`, before any block is written.
A call that states another is `DeclarationDisagrees` wherever it is written, and the declarations
the function emits are those of the calls written. A declaration is a function of the call's plan
alone (`Values::declaration`): its argument classes, its declared prototype where there is one, its
result class and `variadic`/`noreturn`.

Before this the first call rendered won, so the placement of a loop's exits (SD, 2026-10-22) changed
which call that was. pumasim `png_decompress_chunk` (`0x003b6b20`) calls `png_free` seven times, two
of them with `rax` overwritten after the call and five not; libpng's `png_free` returns nothing and no
summary reads its body (it jumps through a loaded pointer), so each call declares from its own result. Written in
address order the first call overwrites `rax`, so `void png_free` won and 23 sites were residual;
with an exit written in the loop a call that does not overwrite it was first (`uint64_t png_free`,
20 sites, 25 obligations moved from residual to rendered with no new evidence). The invariant is the
first outcome, whichever block is written first, and the engine test
`a_callee_is_declared_by_its_first_call_in_address_order_whichever_block_is_written_first` holds it
under two layouts. A callee's result is a program fact the call sites should not each spell (ROADMAP
D62).

## The import-stub route

A function is an import's stub when the program says its address is one and its body is only the
transfer through the import's slot. Discovery owns the first half: `program::naming::imports` reads
the stubs the container states (Mach-O `S_SYMBOL_STUBS`) and decodes the linkage sections (`.plt`,
`.plt.sec`, `.plt.got`), and `Program::import_at(entry)` answers it in `O(log stubs)`. The body owns
the second (`stub::import_stub`): one tail call, no store or other call, no register written that the
transfer does not carry, so a stub that flushes a cache line first is a body
(`an_effect_before_the_jump_keeps_a_stub_a_body`). The transfer must also reach that import:
`import_at` of the address it goes to names the same one, so a container-stated stub patched to jump
through another import's slot is a body (`a_stub_whose_jump_goes_to_another_import_is_a_body_not_the_stated_stub`),
never `free` declared with `malloc`'s types. The stub's name is the one discovery states, not the
callee identity's.

The route used to ask only the second half. A function in `.text` whose last instruction was a jump to
an import's stub, or through its slot, was declared away as the import, with its branch and its
argument arithmetic: bzip2 `default_bzfree` (`0x5b00`: `test rsi, rsi; je; mov rdi, rsi; jmp free`) and
`default_bzalloc` (`0x5b20`: `imul esi, edx; movsxd rdi, esi; jmp malloc`) printed "import stub `free`
has no body" and no C, while `afl` listed neither as an import. Two owners decided one fact and
disagreed. Of the 63 DecBench rows r2s declined this way (2026-10-23), 52 write an argument register
before the jump, 2 test first, and 9 are a bare `jmp` to the stub. All 63 render now: 22 without a
residual, 24 with a parameter the body reads and nothing declares (P7), 16 with an `int` result whose
upper half is a residual (W47), 1 with both.

## The proof line

The proof line states what the rendering did and did not show. "Nothing was
marked" and "everything was shown to be right" are different claims, and only
the second earns silence. No stage makes the second claim, so the line is
always emitted: it counts the constructs carrying a residual marker, then the
ledger, which says what became of every effect the source obliges. The
ledger's columns sum to its total, so a missing effect is a number in the line
rather than an absence from it. The unaccounted count is zero only when every
obligation was reached by a rule that named its fate.

## What survives

- The dominator-tree structurer and its certificate (SD, done): ported as D1.
- R1's proved rules (`cast.concat_zero_high`, the cast collapses, the ordered
  float comparisons): they are D3's rule set.
- `typed.rs`'s C typing at render boundaries: D4 typed in `render::terms` and
  `render::tags` instead, so `typed.rs` had no reader and went with legacy.
- The `Emission` / `pddj` output contract: D5 produces it, so `r2s` and the
  gates do not change.

## What is deleted

`observation_journal`, `binding_plan`, `placement`, `normalize`, `fold`,
`analysis/prepared_semantic`, `effect_ledger`, `single_evaluation`,
`unrendered` and the retry loops in `lib.rs`. The target is under 20k lines.
Done (2026-10-10), with `structured_region`, `typed`, `stage_timing`, the legacy
structurer and `pdim`/`pdih`: `crates/r2dec/src` went from 84,963 to 17,564 lines.

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
| D4 | declarations from the frame model and types: each local `afv` lists is the range of `frame` at its entry offset that `pdd` reads it through, and every parameter, callee prototype and global the source declares is spelled at its declared type |
| D5 + proof | the proof walk replaces the ledger; `pddj` proof counts agree with equivalence |
| switch | the gates above hold; `rebuild` merges to master |

## Consequences

- No renderer policy lands on the old path while D is open. A wrong-C defect
  found on it is recorded against the D stage that owns it.
- The census moves once, at the switch, and is read by hand there.
- r2dec stops being where a missing upstream fact is hidden: every residual
  D renders names the owner that did not state the fact.

## D659 step 0: the 1,390 gap residuals

Measured at 5f39d32a6 over DecBench (2,621 functions) with a local trace in `render::values`
(`gap` and `effect_gap`, not committed) joined to the call gap at the same instruction. Every one of
the 1,001 `ValueNotComputed` and 389 `EffectNotRendered` sites is a `CallDefine`: a register the call
defines, where the call itself is a `CallNotRendered` gap. `ValueNotComputed` is a defined register
the body reads later (named); `EffectNotRendered` is one it does not name. 0 sites are unclassified,
and 0 sit beside a rendered call. r2dec states no fact here: each site closes when its call's owner
states the boundary, and the call's own gap closes with it.

| Call refusal | `ValueNotComputed` | `EffectNotRendered` | Sites | Owner of the missing fact | Witness (`pd`) |
|---|---|---|---|---|---|
| `MayHandOn` | 509 | 128 | 637 | r2ssa `boundaries.rs` (argument slot may hand on what the caller was passed) | bzip2 O2 `0x42c8 call 0x3ef0` |
| `ImportUnstated(Undeclared)` | 180 | 42 | 222 | r2abi rows (the import has no cited row) | diff O2 `0x7df1 call sym.imp.re_search` |
| `CountFromRegisters` | 152 | 46 | 198 | r2ssa call boundary, P7 (indirect call reads registers) | bzip2 O2 `0x6089 call qword [rbp + 0x38]` |
| `VariadicCount` (5 kinds) | 35 | 142 | 177 | r2ssa, D464 | gzip O2 `0x3c8e call 0xf830` |
| `Floor` | 91 | 29 | 120 | r2engine arity floors | find O2 `0x12cce call 0xd490` |
| `CountRegisterSet` | 18 | 2 | 20 | r2ssa call boundary | bzip2 O2 `0x7ebb call 0x7700` |
| `SlotSkipped` | 16 | 0 | 16 | r2ssa call boundary | gzip O2 `0x9cba call 0xd7d0` |
| Total | 1,001 | 389 | 1,390 | | |

`VariadicCount` splits as `MissingFormatParameter` 137, `FormatArgumentNotLiteral` 26,
`FloatingVariadicArgument` 10, `FlagNotConstant` 4. Proposed rows: D666 (`MayHandOn`), D667
(undeclared imports), D668 (indirect calls), D669 (arity floors); `VariadicCount` stays with D464.
