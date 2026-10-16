# ADR: every layer verified, and the root causes behind 2026-10's defects

Status: accepted (2026-10-15); D34 to D39 and D41 in [ROADMAP](../ROADMAP.md)

## Context

Most of the deep defects fixed in October 2026 share one cause. A layer the
engine trusts had no independent check, so its errors reached the output and
were found by chance.

| Defect | Layer trusted | Found by |
|---|---|---|
| Ghidra's C++ engine 3,928 commits behind its specifications (#280) | vendored engine | a crash whose fix upstream already had |
| `ParserContext` written past its fixed arrays (#278) | Sleigh parser | `pd 2000` on one binary |
| a backward `blx`'s `globalset` leaking into the next decode (W2, #277) | Sleigh context | a listing compared by hand |
| FCVT saturation and fraction bits; x86 AF; `lodsd`; unhidden scratch registers | specifications | the AArch64 CPU oracle, the AO register gate |
| BE32 ARM decoded little-endian (W26, #282) | container byte order | the audit |
| a label inside an instruction naming the op before its own (#280, #281) | the lift's own passes | review, twice |
| 1,477 census lines renamed by a resync | temporary names | every spec change |
| a recursive function's arity left a floor (#279) | r2ssa's arity evidence | equivalence |
| a register only a conditional write defines never merging, so a `cmpxchg` retry or a 64-bit `cmovcc` loop reads its pre-loop value on every pass | SSA construction's def sites, a stale copy of `R2ILOp::output()` | reading the atomic item's output, once a LOCK residual stopped hiding it |
| an op property restated outside r2il behind a wildcard arm, which drops each operation added later: phi placement's `output()` (#287), and the trap, store and read-only lists D41's audit found | each crate's own op classes | #287, then the `r2il_op_property_outside_r2il` Dylint (D41) |

Every fix that held came with a gate: the CPU oracle, `diff_r2`, AO's register
sets, `decode_sweep`. D31 already states the rule ("every layer has an
executable oracle"). This ADR lists where the rule is not yet met, and the
structural decisions that close each gap.

## Layers and their verifiers

| Layer | What it states | Verifier | Status |
|---|---|---|---|
| Container (`r2image`) | bytes, sections, symbols, relocations, byte orders | `diff_r2` against radare2, DWARF | present; field relocations open (I) |
| Decoder (Sleigh, vendored) | instruction length and text | `diff_r2 pd`; `decode_sweep` (random words per language, no fault) | present |
| Lift semantics (specs) | each instruction's effect | the CPU oracle: AArch64 (Apple M5) and x86-64 (contabo, D35) present; ARM32 refused (D32) | present |
| Lift passes (`translate.rs`, `internal_control`) | a rewrite of one instruction's ops | **none**: no eval before and after (D34) | missing |
| Temporary names (`r2il::number_temporaries`, r2ssa `naming.rs`) | which value a `tmp_` name is | `stable_temporaries`: every census function's `pdd`, `pdil` and `ao` byte-identical with Sleigh's temporaries shifted or reversed (D36) | present |
| Register effects | reads and writes per instruction | AO against radare2's `aeaj` | present (#284) |
| r2ssa rewrites | value-preserving IR edits | `EditPlan` with stable ids ([stable identity](adr-stable-identity.md)), the semantic kernel | present |
| Arity | how many arguments a callee takes | certification and equivalence; the floor's cause **not typed** (D37) | partial |
| Rendered C | the function's behaviour | equivalence on x86-64 and aarch64; a loop runs on the single-threaded path only, so `tests/gold/loop_carried.c` forces a second pass where a conditional write carries the value | present |
| Cost | time to render | wall time, which **depends on host load** (D38) | nondeterministic |
| Upstream pins | Ghidra, testbins, radare2 releases | **none**: the drift was found by hand (D39) | missing |

## Decisions

**D34. Lift passes edit through one instruction plan, and each is checked by
`r2il::eval`.** Owner: `r2sleigh-lift`.
- A pass over one instruction's ops states insertions before or after an op
  and replacements. It never pushes into a fresh `Vec`.
- One applier keeps every instruction-relative label on the op it named, as
  r2ssa's `EditPlan` does for the IR. The per-pass `starts`/`at` vectors of
  `whole_unique_reads` and `canonicalize_memory_operands` are deleted (D1).
- `canonicalize_memory_operands` exists because SSA would rename a ram-space
  varnode like a register, making a read undefined and a write invisible. A
  read loads into a fresh temporary, a written output stores from one, and a
  copy needs none. A direct transfer's target (`R2ILOp::transfer`) is code,
  not memory; an indirect transfer's slot is loaded like any other operand.
- Gate: `decode_sweep` runs each pass's input and output through `r2il::eval`
  from the same seeded states and compares registers and memory. A pass that
  moves a label or drops an effect fails it. This is D31's "each IR rewrite
  against `r2il::eval` before and after" applied to the lift.

**D35. x86-64 has a CPU oracle, and a spec change merges with oracle
evidence.** Owner: VC.
- The AArch64 harness's format (case, input state, the CPU's result, replayed
  through the trusted lift on every host) is reused on x86-64. contabo runs x86-64
  natively; the cases are recorded there and replayed everywhere.
- Gate: CI fails a pull request that changes a `.sinc`, `.slaspec` or `.pspec` under
  `vendor/sleigh-config` unless it also adds or changes an oracle case or an
  `r2il::eval` test, as D28 requires.
- Order: before further x86 spec fixes; the AF and `lodsd` fixes gain cases
  when it lands.
- Done (2026-10-16): 374 cases, 12 listed (VC row); `scripts/spec_evidence.py`.

**D36. A temporary's name comes from where it is defined, not from its
unique-space offset.** Done (2026-10-16). Owners: r2il lays out an
instruction's temporaries, r2ssa names them, r2dec and the low tier spell them.
- The lift's last step (`r2il::number_temporaries`) places each temporary of
  one instruction by first appearance, each after the last, so its offset is a
  function of that instruction's operations, never of Sleigh's allocator.
  `pdil`, `ao` and `r2il::eval` see that layout.
- r2ssa names a temporary `tmp:<instruction>:<offset>`, spelled
  `tmp_<instruction>_<offset>_<version>` in C. Sleigh scopes the unique space
  to an instruction and an instruction lies in one block, so a temporary takes
  no phi and no liveness bits; a read of a temporary its instruction did not
  write is an undefined value, not another instruction's.
- A lane temporary is `tmp:lane:<instruction>:<op in it>:<serial>`.
- Gate: `crates/r2s/tests/stable_temporaries.rs` runs every census function
  with `R2S_MOVE_TEMPORARIES=shift` and `=reverse` (the lift moves each
  instruction's raw temporaries before its passes) and requires `pdd`, `pdil`
  and `ao` byte-identical.

**D37. r2ssa states why an arity is a floor.** Owner: r2ssa (boundaries);
r2engine reads it.
- The cause is a typed fact: `SourceArityFloor`, a sorted set of
  `SourceFloorCause` on the recovered `SourceFunctionInterface`, one variant per
  branch of `recover_interface`'s floor: an unresolved transfer; a supervisor
  entry; an argument area no exit places; an argument area read past an
  unproven register prefix; a register slot read past the prefix; or the next
  slot handed to a call of unproven arity (`SourceUnprovenCall`), split by what
  its callee's statement says: no callee (indirect), no statement (a missing
  prototype, or a body a cycle has yet to resolve), a floor of its own, or an
  arity the call's arguments do not reach. Cycle membership is r2engine's
  fact (`Component`), so r2ssa states the callee's statement and r2engine asks
  whether its owner is a member.
- r2engine's `arity_owners` reads the causes: callees own a floor only where
  every cause is a call to a callee that states nothing or a floor; any other
  cause keeps the whole floor. The old `reads_past_parameters` boolean and the
  `arity_owners` set `SourceMachineContext` carried are gone.
- The cycle fixpoint (#279) needs no discovery round: an open member's callees
  are the ones its causes name, so `Cycle::index` walks nothing. As outside a
  cycle, a statement flows along owner edges only: a member's call to another
  member that is no cause (counted off registers, complete) is not restated.
- A cycle's results as the same fixpoint over return values: next. Recovery
  states an unproven result by `result_owners` alone, so it needs the same
  typed cause before the engine can assume and check a member's result.
- Gate: an engine test per cause variant (`crates/r2engine/tests/engine/arity.rs`),
  and the `shape_mutual_even` records unchanged.

**D38. The cost verdict counts retired instructions.** Owner: GT.
- Native runs count user-space instructions with `perf_event_open`
  (HW_INSTRUCTIONS, `exclude_kernel`) and stop past the budget. Emulated runs
  count retired guest instructions with qemu's instruction-count plugin
  (`-plugin libinsn.so`). CPU time (`ITIMER_VIRTUAL`) is only a hang guard,
  never the `slow` verdict: the host's load moves it.
- Each record states its measure and budget, and the ratchet refuses to
  compare across measures.
- Gate: `slow` verdicts are identical on an idle and a loaded host.

**D39. Upstream drift is a gate, not a discovery.** Owner: GT, with VC.
- A scheduled CI job reports how far each pin is behind its upstream (the
  Ghidra fork's base against Ghidra master, `TESTBINS_REF` against
  radare2-testbins, the radare2 release in the judgments against the latest),
  and fails past a stated budget.
- The budget is a resync, not a waiver: D33 says the engine moves with the
  specifications.

## Order

The six decisions slot into ROADMAP's order. D35 and D34 come after LS's
typed atomic read-modify-write and before AO's spec follow-ups ship further x86
fixes. D36 is done. D37 is P7's next item. D38 and D39 are
GT's, beside the path whenever a step waits on CI.
