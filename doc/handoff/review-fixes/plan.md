# Plan: make r2s output correct, then source-exact; fix radare2 PRs

## Context

A review of `r2s` on `review.c` (x86-64 gcc `-O0 -g`, `-O2`, `-O2` stripped, `-O2 -no-pie`) plus the arm64 Mach-O fixtures found these problems.

**Wrong C that carries no mark.** I confirmed each one by compiling the output and comparing it against the source:
- `mul_div` at `-O0`: the cqo sign word overwrites parameter `a`.
- `classify` at `-O2`: the CSWTCH.12 `int[8]` table is rendered as the string `"\n"`.
- The variadic arguments of `printf` are dropped.
- Arrays are split into adjacent scalars and passed as `&stack_m200`.
- Entry registers and FS values that were never written are read (`sext`, `FS_OFFSET_15`).
- `x >> 32` is emitted, which is UB in C.

**Crash.** An `-O0` switch runs `pdd`/`pdf` out of memory: a 2^32-entry table vector.

**Inconsistent views.** A caller's declaration of a callee disagrees with the callee's own header. DWARF types never reach the rendered output.

**Command gaps:** `iz`, `ir`, `is`, `afl`, `afv`, `axt`, `pdf`, naming, and `baddr`.

A read-only workflow traced each defect to its origin: 8 tracer agents, 6 adversarial critiques, and 1 planning agent. The full evidence (file:line references, root causes and tests) is in:
- `/root/.claude/projects/-home-user-r2sleigh/21f32657-b293-542a-abb6-f78a3cbef7ac/subagents/workflows/wf_00286c1c-05f/journal.jsonl` (use the `critique:*` entries first);
- the index at `…/scratchpad/findings_index.txt`.

**Goal:** fix every defect at its owner, by rewriting the bad seams, with no caps and no hacks. Then drive DecBench on its official stripped protocol toward 100% by recovering real facts. We also act on the radare2 PR reviews.

## Binding decisions (from the user)

1. **Output C** is ISO C with a UB-free-source premise. A signed or narrow operation appears only when a Proven declaration backs it; otherwise the spelling is total: unsigned wrap, guarded shifts, a rotate helper.
2. **Aliasing.** Where the effective type is proven, write `*p`, `p->f` or `a[i]`. Where it is not, use static-inline memcpy helpers (`r2sleigh_load_u32(p)` and similar).
3. **Unproven construct:** a visible, compilable residual `r2sleigh_residual_<T>(site)` that traps if executed and is counted in the proof line. The function is not refused.
4. **Full memory model now.** r2ssa gets one frame-partition owner. Proven-private slots are promoted to SSA, including DWARF locals and parameter homes (this reverses `promote.rs`). Each escaped or aggregate region is one object, versioned with MemorySSA.
5. **Closed-world facts** are allowed when proven, and carried with confidence and premises. They serve three purposes: void results, result narrowing, and function-pointer target sets.
6. **The stack-protector idiom** is elided on structural proof and counted as a `compiler-inserted` obligation.
7. **A stripped handoff name** (`main` from `__libc_start_main` argument 0) becomes a name with confidence Inferred. A symbol always wins.
8. **The command surface uses radare2's spelling exactly:** `fcn.%08x`, and a headerless `afl` with `addr nbbs size name`. Confidence moves to `aflj`.
9. **DecBench** is measured here through the official `scripts/run_benchmark.py` on stripped input. GED needs Joern egress (github.com release assets), which the user will allow. An in-repo compile-and-diff equivalence gate is mandatory.
10. **radare2:**
    - `../radare2` is fork branch `anal/subregister-argument-spills`, rebased onto radareorg master `469956e`.
    - New fix branches are pushed to radareorg/radare2, and PRs open from there, superseding the fork PRs.
    - Approved: close #26708 and #26762; rework #26743 to trufae's series; fix the review asks on #26768, #26629 and #26682; rework #26765 and #25942.
    - Upstream commits are one line with no assistant attribution (AGENTS.md).

## Execution method

- **Branch.** Fast-forward `engine/review-fixes-vfmgfv` to `origin/engine/review-fixes` (`5c5f880d`, which fixes the red r2types test), then push to `engine/review-fixes-vfmgfv`.
- **Environment.** `libz3-dev` is installed. Install Kani for the proof harnesses.
- **Per phase:** a Workflow runs implement, then an adversarial review (correctness, soundness, complexity, AGENTS.md ownership), then the gates, then a manual check with the command and output recorded. One logical commit per invariant, with a message stating the invariant, owner, evidence and complexity.
- **Gates for every phase:**
  - Std: `cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace --all-features --no-fail-fast` (report the printed count), and `scripts/structure-report.sh`.
  - Render: `certify_render.py` plus the coverage sweep, re-blessed only after reading the diff.
  - Equiv (ratchet): no function may leave `equal`, and any new `differs`, uninit or UBSan finding blocks the landing.
  - Diff: `diff_r2.py`, with each disagreement judged.
  - Every DWARF test gets a `strip --strip-all` twin.

## Phases (dependency order)

**P0 — Foundation**

The invariant: every function produces exactly one record, nothing crashes, and an oracle exists.

- **Fixtures.** Move `review.c` to `tests/gold/`, and the `rv_*` builds to `tests/fixtures/`.
- **Dispatch soundness** (`r2ssa/src/strided.rs`, `indirect.rs`, `body.rs:513`, `r2engine/src/native.rs` `pointer_table`):
  - checked cardinality;
  - lazy `case(k)` labels;
  - the span must lie inside one mapped segment before any read, and immutability is added in P2;
  - `count == 0` is refused.
- **Isolation** (`program/requests.rs`):
  - listings survive an analysis refusal;
  - `NativeRefusal::Panicked{location}` at the memo and `prepared_callee` boundary, and CI fails on it;
  - an entry outside executable memory is refused.
- **`pddj`:**
  - code, signature, variables, line-to-address map, link map and proof counters;
  - r2dec emits exactly the helpers it uses as `static inline`;
  - the residual form of decision 3 replaces `/* r2dec gap */`;
  - new proof counters: residual, split, compiler-inserted, assumed.
- **`tests/equiv/`**, a compile-and-diff gate on r2s:
  - x86-64 non-PIE, gcc and clang at O0/O1/O2, over `tests/corpus`, `tests/gold` and `review.c`;
  - r2s sees only the stripped binary;
  - fork-differential in the original image, a register-level thunk, and a link-map shim;
  - two `-ftrivial-auto-var-init` builds to detect uninit reads, and UBSan;
  - self-tests first, then a baseline with a recorded cause for every non-`equal` record.
- **Retire the plugin era:** the plugin parts of `tests/corpus/verify_rendering.py`, and a grep test that forbids `r2plugin`, `a:sla` and `pd:s`.
- **DecBench adapter** (`tests/decbench/r2sleigh_raw.py`):
  - handle stripped input and pass addresses through;
  - typed declines;
  - a streamed progress pickle, and a restart after a crash;
  - fail closed on `.debug_info`;
  - drop the plugin backend and invalidate the old baseline.
- **radare2 base:** clone, rebase, drop the upstreamed commits and `86e4cffea1`, build, and record an r2r baseline.
- **Dylints:** revive the 32 rotted tests in CI and delete the plugin-era lints.

**P1 — One bit-identity fact, and sound reads** (r2ssa, r2dec)

- **`ValueView`.** `view(v) = (root, prefix_bits, ext)`, computed optimistically over SCCs in O(V+E).
  - It replaces the `canonical_value_roots` rules (`function/rewrite.rs:785-826`) and `adapt_root_width` (`function/mod.rs:3940`).
  - `same_bits`, `copy_class`, `constant::root_of` and address provenance become projections of it.
  - A constant lane comes only from the folder.
  - The reload certificate becomes `{Identity, Derived}`, and only Identity feeds the parameter homes and carriers.
  - Delete the depth>8 recursions (`prepared.rs:1431`, `:1535`).
- **Liveness.** `same_content` reads the view. `same_content_reads` is keyed on (object, offset, width, reaching MemorySSA version set). An uncertified call clobbers escaped memory (`objects.rs:106`).
- **Reaching-values validator** in `r2dec/src/binding_plan/seal.rs`:
  - an independent check, iterated round-robin in reverse postorder;
  - a stale read evicts the value from its binding class (the partition only gets finer, so this terminates) and is counted as a `split`.
- **Definite assignment** keyed on SSA versions. Delete `CallClobberedDeclaration` and the flow-insensitive `written` excuse. An unclaimed CallDefine or unspecified entry read becomes a residual.
- **`SystemReserved` register class**, in a new r2abi platform table (FS base, GS, TPIDR_EL0, Darwin x18, MXCSR). Calls do not redefine it, and `SourceCallEffect` becomes three-valued.
- **Parameter homes by dataflow:** drop the `||` in `promote.rs`, and exclude the return register.
- **`Unspecified(width)` leaf** for partial entry-lane writes.
- **Callee-reach soundness:** poisoning is decided by formal dependence, and a constant-based address is classified Global.

**PE — Byte-dependency relation** (`r2ssa/src/deadphi.rs`, `recover_interface.rs`; runs in parallel with P2–P4)

- One `dep(op, out_byte)` relation, checked by a per-op proof harness: exhaustive at 8 and 16 bits, Kani at 32 and 64.
- Forward definedness closures derived from it.
- Parameter width is `cover(demanded)`. Result width comes from the written-lane lattice, never from value ranges.
- Delete `narrow_zero_extend_input_size`. The XMM lane noise disappears.

**P2 — Container statements** (r2abi, r2image, r2engine, r2s; parallel with P1)

- **One set of statement types** in `r2abi::statement`. Delete the duplicates in `r2engine/src/program/source.rs` and the copying in `r2s/src/session.rs:95-159`.
- **One relocation reader.** Mach-O stubs are kept separate, and chained fixups are decoded.
- **`LoaderWrite{place, width, kind, value}`**, read through `stated_word`, which replaces the raw reads in `records.rs`, `pointer_table` and `text_at`.
- **Immutable-after-load ranges:** non-writable PT_LOAD, RELRO, Mach-O read-only segments.
- **`SectionRole`** from container statements.
- **Command facts:** `baddr` is a presentation fact only; `iS`, `is`, `ir` and `ie` get their columns; stub sizes come from structure.
- **Platform evidence:** libc from PT_INTERP and the Android note. r2abi tables are scoped per libc (glibc, bionic, darwin), and lookup is exact.

**P3 — Declaration model** (P3.1–3.3 in parallel with P1 and P2)

- **Rewrite `r2image/src/debug.rs`:**
  - memoise nodes by DIE offset;
  - follow `abstract_origin` and `specification`;
  - read structs, unions, arrays, bitfields, enums, `Code{sig, variadic}`, `Opaque{tag}` and qualifiers;
  - read globals, lexical blocks and `fbreg` formals;
  - key subprograms by `low_pc`/ranges;
  - refuse per node.
- **Types:** an r2abi `TypeGraph`, and in `r2source` a `SourceTypeGraph` (`contracts.rs:525-842`) with Opaque, flexible arrays, Code and `closure(roots)`.
- **r2engine:**
  - delete `DeclaredTypes`;
  - key the DWARF map by address, separate from the sdb names;
  - make typed ParameterHomes;
  - take the frame-pointer offset from the prologue proof;
  - declarations are authoritative in `restated()`;
  - one owner of the logical return.

**P4 — Memory model** (decision 4; after P1 and P3)

- **New `r2ssa/src/memory/partition.rs`, the single owner of frame objects.**
  - MUST evidence (exact accesses, declarations, machine roles) creates boundaries.
  - MAY evidence (index ranges, callee reach, escapes) only merges, within a barrier window.
  - Promotion and value ranges are stratified: the promoted set only grows, which bounds the loop.
  - Delete the rival owners: `ObjectModelBuilder` root/span, `shared.rs:1741-1881`, `DeclaredStackSlots::containing`, `frame_gap_extent`, and promote's escape rule.
- **Promotion.** `promote.rs` becomes a consumer of the partition: private whole or lane slots are promoted, and so are stack-passed parameters.
- **MemorySSA** over the objects, replacing the O(accesses × locations × iterations) scan in `objects.rs:227-273`.
- **Declaration precedence:** declared type, then atom struct or byte array, then scalar. BitVector is never an object's type.
- **Delete the reload-reconciliation layer** (`prepared.rs:391-406`, `construction.rs:94-168` and 1456-1620). Then add store-as-definition interference, and only after that the rule "one identity, one binding".
- **Stack-protector elision** on structural proof.
- **`afv`/`afi`** built from the sealed entities, with one slot speller.

**P5 — Value domain and dispatch** (`values.rs` stays the one range owner)

- Add an IntSExt transfer, signed narrowing, σ-narrowed symbolic affine bounds, and `trips::max_count`.
- Loads from immutable memory fold to constants.
- Replace the `optimize.rs` iteration cap with a real fixpoint, whose termination is argued from the lattice.
- **Callee reach** becomes an affine `{lo, hi}` interval, which the partition clips.
- **`indirect.rs`:**
  - index-chain steps are typed, and labels are per-step preimages, so biased and negative selectors work;
  - struct-array tables and two-level tables are handled;
  - labels are computed on the final artifact.

**P6 — One resolved body per function per Revision** (r2engine)

- **Body fixpoint.** Walking and table resolution run to a fixpoint, and each table is re-validated on the closed body.
- **One body for all consumers:** the survey, the reference index, callee facts (bottom-up over SCCs, memoised per Revision) and the listing all use it.
- **`function_at`** over an interval partition.
- **Command output:**
  - `afl` gets radare2's columns;
  - `axt` gets interval references and data-word references;
  - `pdf` gets the header, arg/var and XREF lines.
- **Closed-world proof object.** Its conditions:
  - no export;
  - no escaping relocation or entry kind;
  - no data word equal to the entry;
  - executable bytes fully covered by bodies.

**P7 — Call contracts** (after PE, P3 and P6)

- **One ABI classifier** in r2source, with float, vector-count and variadic rules, for SysV, AAPCS64 including Apple, AAPCS32, Win64 and RISC-V.
- **`SourceFunctionInterface`** gains:
  - `variadic`;
  - a format role from a new r2abi `format(archetype, m, n)` table;
  - `arity: Exact|AtLeast`;
  - `result: Void|Register(class)|Unproven`.
- **Channels:** delete the dead advisory-prototype channel and the name-based format rule.
- **Result proof:** the carrier is defined on every return path **and** a caller demands it (an interprocedural least fixpoint). A function is void only under the closed world. Delete `body_proven_return` and the result override at `r2engine/src/lib.rs:1360-1407`.
- **Indirect calls:**
  - `Code{sig}` targets;
  - the tail transfer is classified in r2ssa;
  - an assumed arity renders as a residual;
  - closed-world target joins.
- **One sealed signature per function.** Delete the caller-width fallback in `r2dec/src/fold/op_lower/calls.rs:174-197`, and make interproc project boundaries instead of re-deriving them.

**P8 — Data objects and strings** (after P2, P5 and P7)

- **ObjectMap** (r2engine):
  - extents from `st_size`, Mach-O atoms and DWARF;
  - mutability, initializer, and a unique C identifier per object.
- **Provenance.** An r2ssa per-use provenance pass. r2types decides, per use, whether a constant is a string, an object reference, a code pointer or an integer.
- **Strings:** a per-section NUL index.
- **Deletions:** `referenced()`, `string_literal_serves`, the strings branch of `name_of_constant_address`, the dead global scorers, and the prefix-stripping C identifiers.
- **`iz`** lists proven strings, and `izz` scans everything.

**P9 — Types over the graph** (after P3, P4 and P8)

- **Declared-pointee propagation,** a height-2 lattice, with member and element path resolution: `n->next`, `c.tag[0]`. Delete `aggregate_access.rs` and the parameter-keyed field certificates.
- **Inferred aggregates without DWARF:** union-find with field congruence, and Retypd-style subtyping keyed by `AggregateId`. Delete the `sla_struct_` hash names and the vote thresholds.

**P10 — C contract and lowering** (P10.1 can start after P0)

- `r2dec/fold/op_lower` becomes render-only: one typed expression per value, and one `spell_shift`.
- **`r2rewrite/src/typed.rs`:**
  - the admissibility of each C operation is proven from r2ssa ranges;
  - total helpers for shifts, signed div/rem and narrow multiplies;
  - a `Rotate` rule with proofs;
  - signed carriers only where a Proven declaration exists;
  - memcpy helpers where the effective type is unproven.
- **Value identity:** hash-consed numbers, and a `MatchView` API (enforced by a Dylint). A boolean leaf stays Bool, so `cmp; b.le` renders as `(int32_t)x <= 2`.
- **Deletions:** r2dec's C-AST algebra.
- **Structuring:** return duplication, break/continue and loop un-rotation, so that `find` has no goto.

**P11 — Names and commands**

- **P11a (after P2):**
  - `NameText{Stated, Inferred, Discovered}`, one spelling rule `fcn.%08x`, and the 7 fallback spellers deleted;
  - aliases ordered by occupancy;
  - `main` from the handoff;
  - one error prefix, radare2's exit codes, address expressions, `axt (nofunc)`;
  - `lea` brackets from Sleigh, and the AArch64 `lsl` fix in the sleigh-config fork with a Ghidra PR.
- **P11b (after P6):** the body-dependent commands.

**R — radare2 track** (in parallel throughout)

| PR | Action |
|---|---|
| #26768 | An `elf_arm_symbol_selects_isa` predicate covering FUNC, ARM_TFUNC and GNU_IFUNC, also used by `get_bits`. Drop the comments, add tests, reply to the threads. |
| #26629 | Key the cache on (callconv, gen); fix the nit; rewrite the description under the new subject; ask for re-review. Follow-up: an O(1) register-parent link. |
| #26682 | Bump the generation only on a real edge change; ask for the ABI decision. |
| #26762 and #26708 | Close with a note, and answer the `ts` question. |
| #26743 | trufae's 5-patch series. This feeds the P2 platform tables. |
| #26765 | A capability profile of one gdbr, with checked growth and transcript tests. |
| #25942 | ABI-correct syscall number, executable sections only, encodings behind `RArchInfo`. |
| #25935 | Waits for #26765. |

For each PR: `make -C ../radare2 -j4`, then r2r on `db/cmd/cmd_af`, `db/json/json1` and the PR's own databases. I show drafts before any comment, close or force-push. Rosetta and debugserver runtime checks need your Mac.

## Parallel versus sequential

- **The analysis spine:** P1 → P4 → P5 → P6 → P7 → P8 → P9, in order.
- **Side tracks:** PE, P2, P3.1–3.3, P10.1/10.3/10.4, P11a, the tooling and R run in parallel with the spine.
- **Hard edges:**
  - P0 before any change to output.
  - P1.1, P1.3 and P1.6 before P4.
  - P1.5 before stack-protector elision.
  - P2.1 before the rest of P2 and before P3.4.
  - P2.3 and P2.4 before P5, P6 and P8.
  - P3 before P4 and P9.
  - P7.6 before any P10 change touches `calls.rs`.
- **Serialize merges** in `r2source/src/contracts.rs`, which P1.5, P3.3 and P7 all touch.

## Checkpoints (I stop and show you results)

- **CP0:** equiv self-tests and baseline census, local DecBench on the stripped protocol, perf baseline, and the radare2 rebase log.
- **CP1:** mul_div `equal`, and every proof line that changed.
- **CP2 (P3+P4):** rv_O0g `main`, `copy_name`, `list_len` and `classify` rendering a real switch, before and after. Decisions needed: lexical-block names, ICF, and a DWARF declaration that an access contradicts.
- **CP3:** switch census, afl/afi parity, axt deltas, survey cost.
- **CP4:** signature-equality census, closed-world facts, residual counts, stripped type_match.
- **CP5:** strings, objects and members. Decisions needed: `static const` for known initializers, and how inferred aggregates are named.
- **CP6:** UBSan, `-Werror` and the memcpy-cost census.
- **CP7:** `diff_r2.py` results and golden churn.
- **CP-D:** an official DecBench run once egress is in place, repeated at CP2, CP4 and CP6.

## Verification (end to end)

- `tests/equiv`: every function in the corpus and `review.c` is `equal` or carries a counted residual. No UBSan finding, no uninit read, no `differs`.
- The review binaries: `pdd` of every function compiles with `-Wall -Werror` at `-O2` under strict aliasing, and matches the source on random and boundary inputs. That includes classify at O0 and O2, mul_div, main's `printf(fmt, r, buf)` and `sum_array(v, 4)`, and `n->next`.
- `ulimit -v 1000000` holds for every command on every fixture.
- `diff_r2.py` against `../radare2`, with every disagreement judged.
- DecBench's `run_benchmark.py` on the official sample set, with all three metrics.
- Std, Render and Equiv gates green, with the full printed test counts reported.

## Known limits (stated, not hidden)

- Runtime equivalence covers x86-64 only; there is no qemu here.
- The Apple fixtures and the Rosetta PRs need your Mac.
- Struct names and register-allocation noise on stripped input cap DecBench below a literal 100%. Every cause the engine owns is in scope.

## Status and next steps (current)

**Landed on `engine/review-fixes-vfmgfv`, pushed**
- P0: dispatch soundness, per-function isolation, `pddj` with the residual form, the equivalence gate, the plugin-era retirement, and the DecBench adapter.
- The gate, at 2010 passed and 0 failed.
- The equivalence baseline, `3fbea1dc`: 565 of 756 equal, with the cause of every other record triaged.
- The gate's `slow` status (`1e53fc79`).

**In flight** (worktree tracks, each going through implement, adversarial review and fix)
- P1 identity and P1 reads.
- P2 container statements and P3 declarations.
- PE byte dependency, plus the triage causes appended to it.
- The Dylints revival.
- The core fixes: the INSERT mask and store width, the SSA entry edge, and the `bsr`/`bsf`/`tzcnt`/`pshuflw` lifting.
- Two tasks you asked for, both based on `track/core-lift`:
  - **Lzcount:** a machine expression, a typing rule, and a helper that is total at zero, plus the `bsr`/`lzcnt` native test; the 6 `value_count_bits` records must become equal.
  - **CMPXCHG:** acyclic if-conversion inside one instruction, checked by `r2il::eval` against Sleigh's raw P-code, plus a native compare-exchange loop test.

**Merge order when the tracks finish**
1. core-lowering, core-ssa-entry and core-lift.
2. lzcount and cmpxchg, on top of core-lift.
3. p1-identity, then p1-reads.
4. pe-bytes.
5. p2-container, then p3-decl.
6. Dylints.

After each merge, in the main tree from a clean build:
- the Std gate;
- equivalence on the full population with the ratchet;
- re-bless the baseline, recording the records that became equal;
- a manual `pdd` of `mul_div`, `classify` and `main`.

Then CP1 and CP2 reports, and the P4 wave (the memory model) on top.

**radare2**
- **Published:**

  | Old PR | New PR |
  |---|---|
  | #26768 | #26803 |
  | #26629 | #26804 |
  | #26682 | #26805 |
  | #26743 | #26806 |
  | #26765 | #26807 |

- **Split-outs:** #26801 (xref delete) and #26802 (typedef cycle crash).
- **Merged upstream:** #26802 (typedef cycle crash) and #26803 (the Thumb bit fix, which replaced #26768).
- **Closed with notes:** #26708 and #26762.
- **Watching:** hourly check-ins are scheduled. #26804's `macos-acr` failure was the artifact upload (ENOTFOUND) after a green build; a single re-run is scheduled once the run completes.
- **Pending:**
  - #25942 is being slimmed to a v3 that uses radare2's own ESIL VM instead of a private propagator. I will show it to you before it is published.
  - Drop `8af3aa2` from #26805 once #26801 lands.

**Operational rules learned**
- Every worktree gets a private `CARGO_TARGET_DIR`, with `CARGO_INCREMENTAL=0` and debug info off. A shared target is unsafe, because workspace crates are fingerprinted by relative path.
- A disk janitor prunes rebuildable caches when free space drops below 4 GB.
- Never `SendMessage` a running workflow agent: that forks a second copy into the same worktree.
- With ultracode off, new parallel work runs as `Agent`-tool tracks; I start a new `Workflow` only if you ask for one.

## Triage additions (equivalence census at P0, baseline 3fbea1dc: 565/756 equal)

Every non-equal record has a cause and owning phase in `tests/equiv/baseline.json`. The triage found 16 new root causes, which are routed as follows:

- **PE (appended to its track):**
  - A result is narrowed to an INSERT lane even when the base bytes are defined by the machine (`xor eax,eax; setcc al`).
  - A zeroing idiom (`pxor x,x`, `pinsr` pairs) still reads the entry value.
- **Core wave, now running:**
  - The INSERT mask `~(uintN_t)0` is widened by C integer promotion (silent miscompile: siphash24).
  - A store's C width is taken from a type hint instead of the op's width.
  - SSA construction ignores the implicit entry edge, so an entry that is also a branch target gets no phi.
  - `bsr`/`bsf`/`tzcnt`/`pdep`/`pext`/`enter` (loops inside one instruction's P-code) are lifted as Unimplemented.
  - The `pshuflw` family of user operations is not modelled.
- **After P1 merges:**
  - An SP carrier used as data gets a C binding.
  - One Unimplemented op vetoes every entry stack root (`function/rewrite.rs:546`).
- **P4:**
  - An indexed frame access whose index has no bound becomes a scalar at its base.
  - `promote.rs` takes an outgoing pointer-argument register for the frame pointer.
- **P6/P7:**
  - A self-recursive call takes its arity from the caller's register writes; the root is never prepared as its own callee.
  - Callee facts are one level deep.
- **P10:** a typed dereference is emitted without effective-type or alignment proof; the fix is the memcpy helpers of decision 2.
- **Gate:** a timeout of the rendering run is graded as a disagreement between -O0 and -O2 (`ub`); it should be its own status.
