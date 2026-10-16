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
| an op property restated outside r2il behind a wildcard arm, which drops each operation added later: phi placement's `output()` (#287), and the trap, store and read-only lists D41's audit found; the same for `SSAOp`'s calls, where the stack-protector check matched a direct `Call` only and missed a `-fno-plt` `CallInd` | each crate's own op classes | #287, then the `r2il_op_property_outside_r2il` and `ssa_call_class_outside_op` Dylints (D41) |

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
| Lift passes (`translate.rs`) | a rewrite of one instruction's ops | `decode_sweep`: each pass's input and output through `r2il::eval` from the same seeded states, and per language the passes that must have edited an instruction the evaluator ran (D34) | present |
| User-operation expansion (`expand_user_operation`) | what a modelled user operation stands for | AArch64 oracle (`ext`, `tbl`, `ushl`, `rev64`, `umaxv`, `uaddlv`); `packed_extension` and `word_shuffle` against the SDM through `r2il::eval`; shape tests for `umax`/`umin` (`neon_lanes`). **Not the sweep**: `r2il::eval` runs no user operation, so only a run that skips one is compared (edited 0 on x86-64 and aarch64) | partial: a reference per operation next to the sweep (D34) |
| `internal_control` | an instruction's local loops and skips as values and guarded accesses | `local_control_tests`: Sleigh's p-code and the lift through `r2il::eval::run` | present (x86 loops) |
| Temporary names (`r2il::number_temporaries`, r2ssa `naming.rs`) | which value a `tmp_` name is | `stable_temporaries`: every census function's `pdd`, `pdil` and `ao` byte-identical with Sleigh's temporaries shifted or reversed (D36) | present |
| Register effects | reads and writes per instruction | AO against radare2's `aeaj` | present (#284) |
| r2ssa rewrites | value-preserving IR edits | `EditPlan` with stable ids ([stable identity](adr-stable-identity.md)), the semantic kernel | present |
| Arity | how many arguments a callee takes | certification and equivalence; the floor's cause **not typed** (D37) | partial |
| Rendered C | the function's behaviour | equivalence on x86-64 and aarch64; a loop runs on the single-threaded path only, so `tests/gold/loop_carried.c` forces a second pass where a conditional write carries the value | present |
| Cost | time to render | retired instructions natively with a counter (D38); wall time elsewhere, which **depends on host load** | present natively on request; emulated open |
| Upstream pins | Ghidra, testbins, radare2 releases | **none**: the drift was found by hand (D39) | missing |

## Decisions

**D34. Lift passes edit through one instruction plan, and each is checked by
`r2il::eval`.** Done (2026-10-16). Owner: `r2sleigh-lift`.
- A pass over one instruction's ops states insertions before or after an op,
  a replacement or a removal (`plan::Plan`), in operation order. It never
  pushes into a fresh `Vec`; an empty plan returns the ops untouched.
- One applier keeps every instruction-relative label on the op it named, as
  r2ssa's `EditPlan` does for the IR: a label naming op `t` names the start of
  what `t` became (its insertions before it, or what follows if it was
  removed). A replaced branch keeps its label; inserted ops carry none. The
  per-pass `starts`/`at` vectors and `relabel_local_branches` are deleted
  (D1). `whole_unique_reads`, `canonicalize_memory_operands`,
  `split_odd_register_zeroes`, `forward_repeated_loads` and user-operation
  expansion all edit through it. The last three kept no label (the middle one
  declines an instruction that has one), so an expansion beside a local label
  would have moved it.
- The label's encoding has one owner in r2il: `Varnode::signed_label`,
  `R2ILOp::local_offset` and `set_local_offset`, which `internal_control` and
  its tests read too; `r2il::eval::run` follows the labels of one instruction.
- `internal_control` is not on the plan. It resolves every label into values
  and guarded accesses, so none survives it, and it departs from the
  specification by design where BSF's or BSR's source is zero. It keeps
  `local_control_tests`, now on `eval::run`.
- `canonicalize_memory_operands` exists because SSA would rename a ram-space
  varnode like a register, making a read undefined and a write invisible. A
  read loads into a fresh temporary, a written output stores from one, and a
  copy needs none. A direct transfer's target (`R2ILOp::transfer`) is code,
  not memory; an indirect transfer's slot is loaded like any other operand.
- Gate: `decode_sweep` lifts each word with `Disassembler::lift_passes`, which
  records every pass's input and output, and runs both through `eval::run`
  from four seeded entry states (the registers the input reads, memory every
  byte of which is mapped). The exit, every register either writes and every
  store with its value must agree. A user operation, which `r2il::eval` does
  not run, is given the same seeded value on both sides, except in the pass
  that expands it: there an input that executes one is inconclusive, so the
  sweep compares that pass only where the run skips the operation, and edits
  none on x86-64 or aarch64. It is outside the floor there; its semantics
  stay with the oracles in the table above. A pass that moves a label, drops
  an effect or reads the wrong piece fails it
  (`the_gate_fails_a_pass_that_moves_a_label_or_drops_an_effect` tests the
  comparison, and three live mutants of the passes failed it). Per language,
  the passes that edit in the sweep are listed, and one that stops editing
  (a no-op `forward_repeated_loads` agreed with its input) fails the floor.
  This is D31's "each IR rewrite against `r2il::eval` before and after"
  applied to the lift.
- A piece Sleigh writes into a live temporary (GP-5581: MOVBE bytes, VPADD*
  lanes) is a `replace` of the write plus an `insert_after` that rebuilds the
  holder, so a label naming the next op skips the rebuild. Random words reach
  it about once in 60,000, so the gate names its words
  (`x86_pieces_written_into_a_live_temporary_rebuild_their_holder`: each must
  rebuild a holder and evaluate equal) and live mutants (a dropped write-back,
  the rebuild before the write) failed it. ARM's immediate `vmov`/`vorr`/`vbic`
  read the local back through a `Load` from the const space, which
  `r2il::validate` rejects and `eval` does not run, so no ARM word is judged.
  The gate skips a pass that changed nothing (identical operations evaluate
  identically), which cut its debug time from 72 s to 3 s.
- A label crosses an inserted op in few real instructions (a skip over a
  store of a piece of a temporary: AArch64's `stxrb`, `stxrh`), so the
  applier itself is also tested against random programs of forward branches
  with neutral ops inserted around them (`plan::tests`).

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
- A result is unproven for stated causes too (`SourceUnprovenResult` on the
  interface, replacing `result_owners`): a return path holds what a call
  defined and the callee states no result (`Returned`, direct or indirect), a
  tail transfer to such a callee (`Tailed`), tail transfers whose results
  differ, no return path, a supervisor call or unseen transfer left a value
  nothing states, the body hands back what the caller left, two result
  registers with no caller to choose, or a value outside the carrier. r2engine
  reads the callees of `Returned` and `Tailed` as the result's owners where
  every cause is one. The seed of a cycle's fixpoint is stated beside them.
- A cycle's results are the same fixpoint over return values, on the same
  worklist and on every request's result demand (doc/adr-resolved-bodies.md,
  "A cycle's results"). Recovery's own read decides whether a seed stands.
- Gate: an engine test per cause variant
  (`crates/r2engine/tests/engine/arity.rs`, `results.rs`), the cycle tests, and
  the `shape_mutual_even` and `shape_mutual_odd` records moved by the fixpoint.

**D38. The cost verdict counts retired instructions.** Owner: GT.
- A budget is one measure, stated: `time` (wall milliseconds) or
  `instructions` (user-space instructions the call retires). The runtime,
  `tests/equiv/rt/equiv_rt.c`, is the only thing that counts or stops a run, so
  Python carries the measure as a typed `Cost` (`tests/equiv/cost.py`) and
  never infers it from outcomes.
- Native `instructions`: the child opens `perf_event_open` (HW_INSTRUCTIONS,
  `exclude_kernel`, `exclude_hv`) with the budget plus one as sample period, an
  owner signal (`SIGPWR`) and `PERF_EVENT_IOC_REFRESH 1` just before the call.
  The counter overflows once, at the first instruction past the budget, and
  the default action ends the run
  (outcome `budget`); a call that retired more than the budget by the time it
  returned ends the same way, so the verdict is the count and not the
  overflow's skid. Only `budget` is `slow`.
- Wall time is a hang guard under `instructions` (`ITIMER_REAL`, not
  `ITIMER_VIRTUAL`: a blocked call retires nothing and uses no CPU, so a
  virtual timer never fires). Its outcome, `hang`, grades nothing: an original
  that hangs is dropped, a rendering that does leaves the vector ungraded.
- Each record, `config` and baseline states its measure and budget. The
  ratchet refuses a run whose measure or budget differs from the baseline's
  before it grades anything, and `merge_shards.py` refuses shards that counted
  differently. A host that cannot count refuses `--measure instructions`
  (`perf_event_open` denied, no virtual PMU, a counter that reads zero); it
  never falls back to time quietly.
- Emulated runs are **open**. The decision named qemu's instruction-count
  plugin (`-plugin libinsn.so`), and the measured toolchain has none:
  Ubuntu 24.04's `qemu-user` 8.2.2 (what CI installs) rejects `-plugin` and
  ships no `libinsn.so`, and qemu-user answers `ENOSYS` to `perf_event_open`
  in the guest. An emulated target therefore keeps `time`, labelled, and
  refuses `instructions`. The route is a qemu built with `--enable-plugins`
  (cached in CI) and a small plugin that counts guest instructions per forked
  child and answers a magic syscall (qemu 9's syscall filter) so the runtime
  can arm and read the budget as it does the counter. Rejected: logging
  executed blocks (`-d exec`, `-one-insn-per-tb`), which is orders of
  magnitude slower and not a budget.
- The alternative considered for native runs: run x86-64 under `qemu-x86_64`
  too, so one software count is host-independent everywhere. It needs the same
  plugin build and makes every shard about five times slower, so it is the
  follow-up that serves a runner without a counter, not the first step.
- Hosted CI may have no counter: a GitHub-hosted runner is a virtual machine
  that commonly exposes no PMU, and runs unprivileged with
  `perf_event_paranoid` at its distribution default. The baselines therefore
  stay `time` until a counting runner is chosen; blessing an `instructions`
  baseline there (`--measure instructions --write-baseline`, the shard
  commands gaining the flag) is the flip.
- Gate: `slow` verdicts are identical on an idle and a loaded host. Measured
  on contabo (2026-10-16, a KVM guest already at load 6): review.c `fact`,
  `fill`, `dispatch` and hashes.c `crc32_bitwise`, `crc32_init` at clang `-O2`
  wrote the same `records.json` byte for byte as it was and beside four more
  busy loops (`fact` `slow`, 47 graded, 1 dropped, 2 slow), and the counts of
  839 runs differed by at most 163 instructions in 3.3 billion. `--measure
  time` on the same five moved `fact` from 48 graded, 0 dropped, 3 slow to 46,
  2 and 1. A fake counter (`Cost.fake`) makes two self-test cases run on every
  host: a rendering one instruction past four times the budget is `slow`, one at
  exactly that is `equal`.

**D39. Upstream drift is a gate, not a discovery.** Owner: GT, with VC.
- A scheduled CI job reports how far each pin is behind its upstream (the
  Ghidra fork's base against Ghidra master, `TESTBINS_REF` against
  radare2-testbins, the radare2 release in the judgments against the latest),
  and fails past a stated budget.
- The budget is a resync, not a waiver: D33 says the engine moves with the
  specifications.
- Measure (`scripts/upstream_drift.py`): a pin's drift is the age in days of
  the oldest upstream change it lacks, 0 when it lacks none. A Ghidra pin lacks
  the commits of the default branch after it that change the paths its copy
  vendors (the base: `libsla-sys`'s decompiler `cpp` and `zlib`; a processor: its
  `data/languages`), counted by `git log` over a blobless clone (38 MB, about 4 s;
  trees, no contents), so the count is exact. `TESTBINS_REF` lacks any commit;
  the radare2 judgment lacks the releases published after it. Each pin lives where
  it is used (`vendor/README.md`'s table, `ci.yml`, `diff_r2_judged.toml`) and the
  alarm only reads it.
- A pin is a claim, so the alarm checks it: a vendored file that differs from the
  pin's and equals another upstream version of that file (read from the raw log,
  no blob fetched) refutes the claim, and a file that equals none is the fork's
  own change. A README pin missing a vendored processor, a pin that is no commit
  of the branch, or an unreachable remote is exit 2, never green; the other pins
  are still measured.
- Budget, in days: Ghidra 90 (about one release cycle), `TESTBINS_REF` 180 (the
  corpus is the certification gate's input, so it moves by a reviewed resync, not
  by drift), radare2 90 (about three point releases). `vendor/README.md` states
  the same table and a test holds them equal.
- Cost: one clone per remote, then `git log` over the commits since each pin,
  and one `git log` per vendored file that differs from its pin; the weekly job
  takes under a minute. Rejected: GitHub's commits API, which filters by
  date, not ancestry (RISC-V 11 where git counts 12, AArch64 31 where it counts
  32: a commit dated before its pin can still be unabsorbed), and is rate-limited.
- First run (2026-10-16): the Ghidra base, `TESTBINS_REF` and radare2 6.2.4 are
  within budget; ARM, MIPS, RISC-V and x86, still on 11.4, lack commits 458, 422,
  491 and 443 days old against a budget of 90 (VC's resync); AArch64's pin is
  refuted by five files (`AARCH64.ldefs`, `.opinion`, `_swift.cspec`,
  `_win.cspec`, `AppleSilicon.ldefs`) that are older than `918acd744d`.

## Order

The six decisions slot into ROADMAP's order. D35 and D34 come after LS's
typed atomic read-modify-write and before AO's spec follow-ups ship further x86
fixes. D36 is done. D37 is P7's next item. D38 and D39 are
GT's, beside the path whenever a step waits on CI.
