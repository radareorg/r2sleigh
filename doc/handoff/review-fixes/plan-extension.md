> Amendment 2026-09-25 (after approval): DecBench is skipped on this machine because the PyPI file host is DNS-blocked, so CP-D and the allowlist PR are deferred. Quality is judged by reading pdd against the source (see eyeball-93934abc.md), with tests/equiv as the mechanical oracle.

# Plan: r2s becomes correct, source-exact, and a radare2 replacement

## Context

This plan extends `doc/handoff/review-fixes/plan.md` (P0–P11, CP0–CP7). That plan's binding decisions stay in force, except where this one amends them. Measured at HEAD 93934abc on 2026-09-25:

**Correctness.** The equivalence gate has 565 of 756 functions `equal`. 36 are `differs` (silent wrong C) and 47 are `ub`. Meanwhile certify reports "0 refused". Ten track branches are unmerged; four are WIP and two have review blockers.

**Unused analysis.** About 6.8k LOC has no consumer:
- `taint`, `fingerprint`, `slice`, the `defuse` backward slice, `mobility`, `execution`, and r2types `oracle`;
- `binding_audit`, which is built on every render and never read.

**Missing core facts:**
- no memory model;
- two owners of bit identity;
- no byte-dependency relation;
- callee facts one level deep.

**Caches and caps instead of design:**
- a single-entry memo, and `afl` re-surveys the program on every call;
- eight hand-rolled caches in `OpenProgram`;
- about 30 silent caps: round caps that ignore convergence, and depth-8 def-chain walks. One of them (`semantic/shared.rs:2439`) fails in the unsafe direction.

**Facts the binary states that go unread:**
- CFI (`.eh_frame` survives `strip --strip-all`: function extents, SP deltas, save slots), LSDA, `.pdata`, `__unwind_info`, IBT notes;
- DWARF location lists, inlined subroutines, globals and members; `by_address` is unused;
- RELRO, IRELATIVE, relocation addends;
- PE imports.

**Confidence.** It lives only on function starts, with a second ladder (`query::Support`) for references.

**Command surface.** About 27 verbs, with no iterators, pipes, `?`, `e`, JSON, search, r2pipe or emulation.

**DecBench.** No valid number.

**User direction.** Fix everything at its source, and rewrite bad seams. Replace caches and caps with algorithms. Recover and use every stated fact. Aim for 100% DecBench through proofs, not hacks. Challenge every decision. Radare2 fixes go upstream. Act on the open PRs. Ask instead of taking shortcuts.

## Decisions (the user's, 2026-09-25)

1. **Execution.** Agent-tool tracks, at most about 8 at once.
   - Each track: its own worktree, its own `CARGO_TARGET_DIR`, and `CARGO_INCREMENTAL=0` with debug info off.
   - An independent adversarial reviewer attacks each track before it merges.
   - Merges are serialized.
2. **Scope.** P1–P11, DecBench, and the new tracks H, K, I, Q, C, S, E, A (below). Debugger and traces are out.
3. **radare2.** `../radare2` follows upstream master (c1ebe0e5e4, installed at /usr/local). The spill branch is retired, because its fixes are upstream or in #26806. 86e4cffea1 is dropped.
4. **Stale routine.** trig_01GgtdPS2qX2bCx9rqcG5pxv gets disabled (RemoteTrigger has no delete). The PRs are watched from this session.
5. **Unused analyses.** Each is wired where a planned consumer exists; the rest is deleted now.
6. **DecBench.** Upstream a PR adding r2sleigh to the address-matching allowlist for locals, once pddj offsets are relative to the frame base. I show the draft first.
7. **Decision 1 amended.** A signed or narrow operation is admitted on a declaration **or** a range proof that it cannot overflow or reach UB (P5). Totality is spelled inline in ISO C, with no helper calls:
   - shifts: `x >> (n & (w-1))`, where the mask is dropped when a range proves the amount;
   - rotate: `(x<<(n&m))|(x>>(-n&m))`.
8. **Decision 2 amended.** Typed access through a pointer is allowed under the UB-free-source premise when every access through that base agrees on width and on int/float class. The premise is counted as `assumed`.
   - A compiler-merged copy (a wide load, then a store) renders as `memcpy`.
   - Mixed or overlapping accesses keep the memcpy helper.

## Invariants for every change

- **One fact, one owner.** A defect is fixed where it originates.
- **No depth or round cap returns a silent answer.** A walk over a finite graph uses a visited set or an SCC memo, costing O(V+E). A fixpoint terminates by lattice height, with the argument written in a comment and checked by a Kani harness where it is algebraic. A genuine budget exists only where termination is undecidable (emulation), and it refuses visibly with a reason.
- **Every non-source spelling is a missing proof.** Each DecBench loss is attributed to the proof that would remove it, never to a new spelling.
- **Nothing is hand-written per architecture.** Semantics come from Sleigh and `r2il::eval`.

## New tracks

**C: one confidence type.**
- `r2source::confidence::Confidence{grade: Stated|Proven|Inferred|Guessed, basis, premises: u8 bitset}`, which is `Copy`.
- `Basis` absorbs `query::Support` (Decoded, Folded, Certified, Solved, Declared, Dereferenced) and the discovery reasons, then both old ladders are deleted.
- When two derivations meet: compare grade first, then the premise-set subset order. Fix the p2-container branch's lexicographic `BTreeSet<Premise>` min, which is backwards.
- `Fact<T>{value, confidence}` has no constructor without a confidence, and a Dylint rejects any unwrapped public answer field.
- Kani proves the lattice laws.
- Lands with p2-container. It must come before P7 and P11a, whose `NameText` becomes `Fact<Text>`.

**H: wire or delete** (one commit per module; the `pddj` census stays byte-identical).
- **Delete:**
  - `execution.rs`, `mobility.rs`, `fingerprint.rs`;
  - r2types `oracle.rs`;
  - `shadow_report/` and `binding_audit`;
  - `defuse::backward_slice_from_var`, a second owner of slicing;
  - `taint.rs`, which is nondeterministic and name-keyed;
  - the `R2SLEIGH_SLICE` hook, and the empty `crates/r2sym`;
  - the unused `route.rs` CFG guard, the uncalled guard helpers, and the never-built `BudgetExhausted`.
- **Wire:**
  - `slice.rs` becomes the one slicer: backward, forward, and forward with labels (which is taint). It runs over SSA plus P4's MemorySSA, is exposed as the query `slice(entry, seed, dir)`, and costs O(V+E). Interprocedural summaries come after P7.
  - `observation_journal` stays: it feeds the obligation ledger.

**K: removing caps** (a rolling track, with each fix owned by its crate).
- **Immediately (W0):**
  - `semantic/shared.rs:2439`, which fails unsafe;
  - `r2types/solver.rs:19` plus `evidence.rs:673`, where `read_back` ignores `converged` and the round cap is removable;
  - `evidence.rs:87`;
  - `debug.rs` `SPELLING_DEPTH`, which drops whole prototypes;
  - `r2engine/lib.rs:1161`, which drops struct fields at depth 4.
- **Walks that P1's `ValueView` replaces:** the depth-8 identity and root walks in `optimize.rs`, `prepared.rs`, `interproc/mod.rs:2582`, `predicates.rs`, `certificates/expressions.rs`, `binding_plan/rules.rs` and `prepared_semantic`. Each becomes a view projection or a visited-set walk.
- **Walks rewritten by their own phases:** `promote.rs` (P4), `arrays.rs`/`globals.rs` (P9, including the silent ±16 KiB `offset_bound`), and the `optimize.rs` fold rounds (P5).
- **Kept as class (b):** `LITERAL_LIMIT`, which becomes the per-section NUL index in P8.
- **Guardrail:** a Dylint flags a constant-bounded `depth` or `round` loop with no refusal path.

**I: information recovery** (parsed in `r2image`; `r2abi::statement` types; all Stated facts; after P2.1).

| Source | Consumers |
|---|---|
| `.eh_frame_hdr` and FDE extents (gimli) | discovery seeds `EntryKind::Unwind`; P6 interval partition; closed-world coverage |
| CFA rules (SP delta per address) | cross-check for P4's frame partition and P7's stack arguments; a disagreement is refused |
| Saved-register rules | P4 save slots; closes p1-reads blocker 5 |
| LSDA | P6: landing pads become stated entries |
| PE `.pdata`/`.xdata` | function starts and extents |
| PE import/export names; PE platform no longer `Other` | naming, prototypes |
| Mach-O `__unwind_info` | same consumers as CFI |
| `.note.gnu.property` IBT flag plus `endbr64` sites | a function with no `endbr64` has only direct callers, which discharges closed-world per function |
| RELRO, IRELATIVE targets, relocation addends and RELATIVE targets | P2.4, pointer provenance for P8 |
| `DT_INIT_ARRAY`, `.preinit_array`, `.ctors` | discovery seeds |
| `st_size` | object and function extents (P8/P6) |
| ARM `$d` | data-in-code |
| `.gnu_debugdata` | stated symbols; needs pure-Rust xz, so last |
| DWARF location lists, inlined subroutines, lexical-block ranges, call sites, globals, members; `by_address` keying | P3 follow-up |

- Cost: O(log n) per lookup through the sorted hdr table. CFI rows are evaluated lazily as a Q query.
- Tests run on stripped twins. Stripped discovery must find at least every FDE start, and each disagreement is judged in `diff_r2.py`.

**Q: a demand-driven query database** (`r2engine/src/query/db.rs`, hand-rolled red-green, not salsa).
- Inputs are byte ranges, taken from `Image::written`.
- There are no cyclic queries: discovery and callee summaries are aggregate queries (`survey`, `scc_summary`).
- Early cutoff compares results with `Eq`.
- Large `Prepared` artifacts sit behind a firewall: they are recomputed on demand and their dependents cut off on small summaries. There is no LRU cap.
- **Invariant:** the answer at revision r equals what a fresh open computes at r.
- **Deletes:** `memo.rs`, `Consulted`/`Moved`, the eight `OpenProgram` cache fields, the names/entries axes of `Revision`, and the `afl` re-survey.
- **Gate:**
  - `tests/incremental.rs`: random `wx` writes, compared against a fresh open;
  - a session trace (`afl;afl;axt`, `pdd @@f` survey counts) recorded in the first commit, as AGENTS.md requires;
  - one survey for `afl;afl`.
- **Timing:** lands after p2 and I's seeding, before P6, S `@@`, and A. P6 becomes the queries `body(entry)`, `call_graph()` and `scc_summary(scc)`.

**Medium IL.** `pdim` becomes the `Display` of the prepared `SsaArtifact`, owned by r2ssa. It prints:
- values as `ValueView` gives them;
- partition objects, and MemoryDef/Use/Phi;
- promoted variables;
- calls with their contracts;
- no dead flags.

The renderer's Values text moves to `pdih`. It lands with P4.

**S: command language** (r2s; byte search in `r2engine::query`).
- **Invariant:** each construct means what radare2 means, or is refused before anything runs. `@@` iterates over typed answers.
- **One verb table:** verb, arity, help text and JSON shape. `?` is generated from it. This amends AGENTS.md's flat `match` and its public-verb list in the same change.
- **`e`:** presentation keys only. An analysis key becomes a request parameter.
- **JSON:** `j` on every verb, with radare2's field names. `r2engine/src/json.rs` moves to r2s, because the engine never formats output.
- **Scripting and r2pipe:** `-i`, `-e`, and `-q0` (radare2's null-terminated protocol, which lets `r2s_batch.py` drop its markers).
- **Pipes and redirects:** `|`, `>`, `>>`, gated by a documented `cfg.sandbox`.
- **Iterators:** `@@=`, `@@ glob`, `@@f`, `@@b`, `@@i`, `@@s:`. These wait for Q.
- **Search:**
  - `/`, `/x hex:mask`, `/w`, `/v` and `/ad` are linear per segment, with hits named `hit0_N`;
  - `/r` is `axt`;
  - `/a` is refused, because Sleigh here cannot assemble.
- **Tests:** a happy-path and a failure test per verb in `crates/r2s/tests/`; `diff_r2.py` gains the `j` forms.

**E: emulation and verify** (`r2engine/src/emulate.rs`).
- **Semantics:** `r2il::eval::step` over the lifted ops is the only statement of what an instruction does. User-defined ops, imports and syscalls stop with a typed reason.
- **Machine:**
  - reads memory through a `Mapped` implementation over `Source`, a write overlay, and `stated_word` (P2.3);
  - `EmulateRequest{entry, regs, memory, budget, stop_at}` returns `{stop, steps, regs, accesses}`;
  - the op budget is legitimate here (whether a run halts is undecidable) and stops visibly with `Stop::Exhausted`.
- **Commands:** `aei aeim aer aes aeso aesu aecu aeC`. `ae <esil>` is refused.
- **Tests:**
  - `tests/oracle.rs` moves onto the machine;
  - an equiv cell compares emulation with native x86-64;
  - emulating aarch64 originals against renderings compiled on the host lifts the "x86-64 only" limit for pure functions.
- **Verify** (second merge): a hypothesis is `Returns`, `Equivalent`, `NoOverflow` or `Bound`.
  - The answer is `Proved` only from a range proof, a certificate or an exhausted finite domain.
  - `Disproved` comes with a counterexample run; otherwise the answer is `Unknown`.
  - No solver.

**A: agent surface** (typed API in `r2engine::query`; the server is `r2s --serve`).
- **Rules:** no cursor; every field is a `Fact<T>`; every answer names its `Revision`.
- **Answers:** `Answer<T>` gains `elided: Vec<Elision{what, handle}>` and `Completion::Budget`.
- **Handles:** `FactHandle{program, revision, query, local}`.
- **Explain** joins, through that handle:
  - `ObligationLedger`;
  - `PreparedFunctionCertificates`;
  - discovery evidence;
  - `r2types::EvidenceNode`.
- **Tokens and errors:** budgets are estimated deterministically. A bad query returns the schema and the nearest valid form.
- **Tests:** a transcript test, and a determinism test that shuffles request order.
- **Timing:** after Q and C. Compound taint queries come after P5, P7 and the H slicer.

**D: DecBench infrastructure** (W0).
- Clone `noelo-lab/decbench` into `../decbench`, with a python3.12 venv.
- Joern comes via pyjoern (GitHub release egress).
- Check cgroup v2 and `systemd-run --user`.
- Make pddj local offsets relative to the frame base, then open the allowlist PR.
- CP-D runs on the official stripped protocol: sailr projects at O0, O2 and O2-noinline.

## Changes to the existing phases

- **Split p1-reads:**
  - part (a), SystemReserved and definite assignment, lands now with blockers 3 and 5 fixed (5 through I's save slots, or through "every returning path restores");
  - the reaching-values validator is a downstream repair of P4's fact. It is rebuilt in P4 as a MemorySSA checker whose failure becomes a residual.
- **New hard edges:**
  - PE before P1.7;
  - p1-identity before pe-bytes (both edit `recover_interface.rs`);
  - Q before P6, S `@@` and A;
  - C before P7 and P11a;
  - I before P6;
  - P5 before P10 admissibility;
  - P4 before P10's memcpy rule;
  - P2.3 before E.
- **P10:**
  - `MatchView` is a projection of `r2ssa::ValueView`, not a second identity fact;
  - flag rules in `r2rewrite/src/rules/flag.rs`: carry is `(a+b) <u a`, borrow is `a <u b`; adc/sbb chains stay counted helpers;
  - loop un-rotation needs a `ForLoopCertificate` proof that the guard equals the condition at entry.
- **P4:** stack-protector elision is on DecBench's critical path, so prioritize it within P4.
- **p1-identity blockers:** fix them as README.md lists. For blocker 2 (`value_abs_minmax` `ConflictingValue`), trace the cross-block content pairing to its origin. P1.7 lands after pe-bytes.
- **Merge order in `r2source/src/contracts.rs`:** p1-reads(a), then p3-decl, then C, then P4, then P7.

## Waves

The gate runs after every merge. Checkpoints are marked in bold.

- **W0:**
  - Step 1: verify core-lowering. The Std gate is running now; once `cargo fetch` via system git fixed the fetch, `CARGO_NET_GIT_FETCH_WITH_CLI=true` was added to the gate script. Then the ratchet, then re-bless siphash24.
  - H deletions; K immediate items.
  - core-ssa-entry and core-lift (review, then Kani), then lzcount and cmpxchg (finish, review).
  - p1-identity fixes; p1-reads(a).
  - D setup; disable the routine; commit this plan into `doc/handoff/review-fixes/plan.md`.
  - Merge: core, then lz and cmpxchg, then p1-identity, then p1-reads(a). **CP1.**
- **W1:**
  - p2-container review and fixes, with C.
  - p3-decl review.
  - pe-bytes redo, then P1.7.
  - I parsing and seeding.
  - S without `@@`.
  - E machine.
  - p0-dylints, plus the `Fact` and cap Dylints.
- **W2:**
  - P4, in three merges: partition and promotion; MemorySSA with the validator and `pdim`; SSP elision with `afv`/`afi`.
  - Q.
  - P10.1 (render-only lowering, `spell_shift`).
  - P11a.
  - E verify.
  - I, DWARF depth.
  - **CP2**, CP-D.
- **W3:** P5; the H slicer; S `@@` and search; A core and explain; P10.3/P10.4 structuring.
- **W4:** P6 on Q, with FDE, IBT and closed-world facts. **CP3.**
- **W5:** P7; ARM32 `pdd` admission; an x86-32 render test. **CP4**, CP-D.
- **W6:** P8; the P10 memcpy and admissibility rules; A compound queries. **CP5.**
- **W7:** P9, then P11b. **CP6**, CP-D, then **CP7**.
- **R (throughout):**
  - Watch #26804, #26805 and #26806 at each merge point.
  - #25942 v3 on radare2's ESIL VM (trufae wants arm32/arm64 performance).
  - #25935 is unblocked now that #26807 has merged, but needs a Mac.
  - Re-sync `r2abi/data` after #26806 lands.
  - Raise new fixes as their own upstream PRs.
  - Commits are one line with a `##tag` and no attribution. Drafts are shown before any post.

## Per-track protocol

1. `git worktree add` from the current integration tip, and confirm the base with `merge-base`.
2. Use a private target: `CARGO_TARGET_DIR=<wt>/target`, plus `CARGO_NET_GIT_FETCH_WITH_CLI=true`.
3. Implement against the spec (`tracks/*.txt`, or this plan), one invariant per commit. Each message states the invariant, owner, evidence and complexity.
4. An independent reviewer attacks the diff, hunting for:
   - soundness counterexamples;
   - a second owner of a fact;
   - caps posing as fixes;
   - ratchet regressions.

   Fix every blocker, then re-review.
5. Merge into `engine/review-fixes-vfmgfv`, then run the full gate:
   - fmt, clippy, the workspace tests with `--no-fail-fast` (report the printed count), `structure-report`;
   - `certify_render.py`, `diff_r2.py` (judged), and Kani where there are harnesses;
   - the equivalence ratchet on the WHOLE population. Coverage needs macOS, which is a recorded gap.
6. Check `pdd` by hand: mul_div, classify and main on `tests/fixtures/rv_O0g`, plus an -O2 build of `tests/gold/review.c`.
7. Re-bless the baseline with a cause for every non-equal record. Push. Delete the worktree's `target/structure` and incremental caches.

## Verification (end to end)

- **Equivalence:** every function is `equal` or has a counted residual. No `differs`, `ub` or uninit.
- **Review binaries:** `pdd` compiles with `-Wall -Werror -O2` under strict aliasing and matches the source on random and boundary inputs.
- **Memory:** `ulimit -v 1000000` holds on every command.
- **radare2:** `diff_r2.py` against upstream master, with every disagreement judged.
- **DecBench:** the official stripped run reports all three metrics at every CP-D, and each loss is attributed to its proof.
- **Incremental:** `tests/incremental.rs` stays green, with session-trace survey counts recorded.
- **Caps:** no silent caps remain (the Dylint enforces it). Every cap is class (a) with a termination argument, or class (b) with a visible refusal.
