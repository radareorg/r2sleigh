Hand-off: the review-fixes program
==================================

**Resumed 2026-09-25** on a larger machine (64 CPUs, 125 GB RAM). The program
now follows [`plan-extension.md`](plan-extension.md), which extends
[`plan.md`](plan.md). The extension adds eight tracks:

- C: one confidence type
- H: wire or delete the unused analyses
- K: remove silent caps
- I: read CFI and the other unread container facts
- Q: a query database
- S: command language
- E: emulation and verify
- A: agent surface

It also amends binding decisions 1 and 2 and orders the work in waves W0–W7.
The "before" manual review is [`eyeball-93934abc.md`](eyeball-93934abc.md).
The rest of this file is the hand-off as written when the work paused.

Written 2026-09-25 when work stopped because of machine limits: 4 CPUs,
about 3 GB of free disk, and a cargo target of 5–8 GB per worktree. Start with
this file. The approved plan, with every binding decision, is in
[`plan.md`](plan.md).

The work began with a review of `r2s` on `tests/gold/review.c`. That review
found C that is **silently wrong**, which I confirmed by compiling the
rendering and running it against the source:

- `mul_div` at -O0: the cqo sign word overwrites parameter `a`.
- `classify` at -O2: the CSWTCH `int[8]` table is rendered as the string `"\n"`.
- `printf` loses its variadic arguments.
- arrays are split into adjacent scalars and passed as `&stack_m200`.
- a read of FS or of an entry register that nothing wrote.
- `x >> 32`, which is UB in C.

It also found an out-of-memory crash on an -O0 switch, and gaps in commands
against radare2. The plan fixes each defect at its owner and aims DecBench at
source-exact output without hacks.

What is on `engine/review-fixes-vfmgfv`
----------------------------------------

**P0, the foundation (merged, with the full gate green: 2010 passed, 0 failed).**

- **Dispatch soundness.**
  - `StridedInterval::count` is checked, so a count of 2^64 is `None`.
  - `DispatchTableRead` computes its case labels lazily through `case(k)`.
  - Before any byte is read, the table's span must lie inside one region the
    file maps, and every target must be executable.
  - `Some([])` is unresolved.
  - An unresolved `jmp reg` is no longer taken for a tail call.
  - Files: `crates/r2ssa/src/{strided,indirect,body}.rs`,
    `crates/r2engine/src/native.rs`.
- **Isolation.**
  - `crates/r2engine/src/isolation.rs`: a panic becomes that function's
    `Panicked{location}` refusal, at the memo and in `prepared_callee`.
  - `pdf` survives an analysis refusal.
  - An entry in non-executable memory is refused.
- **`pddj`**: a self-contained C translation unit, with only the
  `r2sleigh_*` helpers it uses, `static inline`. The pddj record also carries:
  - the proof counters: `residual`, `split`, `compiler_inserted` and `assumed`;
  - variables, and a line-to-address map;
  - a link map naming the address of every external identifier.

  An unproven construct renders as `r2sleigh_residual_<T>(site)`, which traps
  if executed.
- **`tests/equiv/`**: the compile-and-diff equivalence gate. It is the most
  valuable thing this program built. Read `tests/equiv/README.md`.
- **DecBench adapter** (`tests/decbench/r2sleigh_raw.py`): it handles stripped
  input and passes addresses through unchanged. Failures become typed declines,
  and it restarts after a crash. It fails closed on `.debug_info`. The plugin
  backend is gone.
- **Retired plugin-era scripts.** `tests/test_no_plugin.py` forbids
  `r2plugin`, `a:sla` and `pd:s`.

**Equivalence baseline** (`tests/equiv/baseline.json`, at `3fbea1dc`).
565 of 756 records are `equal`. **Every other record carries its root cause
and the plan phase that owns the fix.** The new root causes are also in
`equiv-triage-new-causes.json`.

**Gate `slow` status** (`1e53fc79`): a timeout is not graded as UB or as a
wrong result.

**core-lowering** (merged at the hand-off, `902cd724`).

- The INSERT lane mask is `(lane_t)-1`, not `~(lane_t)0U`. The latter is
  integer-promoted and erased the root: the siphash24 miscompile.
- A store's C width is the operation's width. Type facts are admitted only
  through `r2types::admissible_declaration_type`.
- **Unverified on the merged tree.** fmt and clippy pass. The workspace suite
  and the full equivalence ratchet were interrupted by the pause and still
  need a run. The track's own crate tests passed, and a 756-function `pddj`
  census was byte-identical apart from the intended fixes.

Branches with work that is not merged
-------------------------------------

All of these are pushed as `engine/review-fixes-vfmgfv-<track>`. A commit
whose subject starts with `WIP` is a snapshot of an interrupted worktree: it is
unreviewed and may not build. Each track's own report is in
`track-reports.txt`, and its full specification is in `tracks/<name>.txt`.

| Track | State | What it does / what blocks it |
|---|---|---|
| core-ssa-entry | Implemented, gate evidence recorded; review interrupted | An empty `cfg::ENTRY_EDGE` block goes in front of an entry that is a branch target (Cytron's entry node). `SSAFunction::root()` is distinct from `entry`. Fixes `shape_mutual_even` and `shape_mutual_odd`. Merge risk: `function/rewrite.rs` has `insert_ops(self.entry,…)` → `self.root()`. |
| core-lift | Implemented; review interrupted | Instruction-local P-code loops decided by constants are unrolled (`internal_control/unroll.rs`, with a step budget of 16384 that refuses when exceeded). BSF, BSR and TZCNT become closed forms, and BSR is `(w-1)-Lzcount`. PSHUFLW, PSHUFHW and PSHUFW are modelled. **Needs core-lowering first**, because `mem_scan2` would otherwise be a new `differs`. |
| lzcount | WIP on core-lift | Your task: `Lzcount` as a machine expression, a typing rule, and a helper that is total at zero. Done when the six `value_count_bits` records are equal and the native `bsr`/`lzcnt` test passes. |
| cmpxchg | WIP on core-lift | Your task: acyclic if-conversion of the diamond inside CMPXCHG's P-code, checked against `r2il::eval`. |
| p1-identity | Implemented; review found 4 blocking issues; the fix round was partway through | **`ValueView`** (`crates/r2ssa/src/view.rs`): one bit-identity fact that replaces the identity rules of `canonical_value_roots`. This fixes the root cause of the mul_div miscompile: 0 mismatches at the tip against 5 at the base. The blocking issues are below. |
| p1-reads | Implemented; review found 5 blocking issues; WIP | SystemReserved registers (FS/GS/TPIDR_EL0/x18/MXCSR), definite assignment keyed on SSA versions, and a reaching-values validator in `binding_plan/seal.rs`. The blocking issues are below. |
| pe-bytes | WIP only (one large uncommitted snapshot) | A byte-dependency relation `dep(op, out_byte)` in `deadphi.rs`, plus interface widths. Start over from its spec, and use the snapshot as a reference only. |
| p2-container | Implemented, 14 commits; not reviewed | One set of statement types in `r2abi::statement`. One relocation reader, covering ELF REL, RELA, RELR, APS2 and JMPREL, and Mach-O rebase/bind streams and chained fixups. `LoaderWrite` read through `stated_word`. Immutability after load. Section roles. The `iz`/`izz`/`is`/`ir`/`iS`/`baddr` columns. Libc platform evidence and exact prototype lookup. 485 tests passed. |
| p3-decl | Implemented, 8 commits; not reviewed | `r2abi::TypeGraph`. A rewritten DWARF reader (structs, arrays, bitfields, `Code`, `Opaque`, globals, `fbreg`). DWARF keyed by address, with per-item interning. A `SourceTypeGraph` that accepts packed and i386 layouts. Global types taken from DWARF. |
| p0-dylints | 1 commit plus WIP | Reviving `tools/dylints`: 32 rotted tests, and the lints that only fired on plugin code. |

**p1-identity blockers** (from its review):

1. **P1.8 callee reach is unsound.** A formal stored into a frame object and
   passed by address hides the formal. Fix: a formal-derived value stored into
   a frame object that is not proven private must add its formals to
   `unplaced_reach`.
2. **The ratchet fails.** `values.c::clang-O0::value_abs_minmax` goes from
   equal to refused with `ConflictingValue` (bisected to `ac876632`, since
   rebased).
3. **P1.7 is not landed.** This is the `Unspecified(width)` leaf, and the rotl
   listing still claims `defines rcx in [0x0, 0xff]`. It probably needs PE's
   widths first, so amend the plan with that edge.
4. **Address provenance is not yet a projection of the view.** `address.rs`
   still carries expressions through SEXT and through casts of any width.

**p1-reads blockers** (from its review):

1. **The validator certifies miscompiles.** Reloads of a frame object and
   stack-access reads are never checked. It needs a model of whether each
   frame-object binding is in sync with its slot.
2. **Folded reads are keyed on the wrong block.** Key each rendered read or
   write on the block the text renders it in.
3. **An elided ZExt or SExt is treated as held wherever its source is held.**
   Rename only through Copy and CallRestore.
4. **The ratchet fails: 18 records leave `equal`.** Place residual copies for
   unspecified merge inputs on their incoming edge.
5. **A noreturn function's save of a preserved register still traps.** Accept a
   save slot when every returning path restores it; that is vacuously true when
   no path returns.

Suggested merge order when work resumes:

1. core-lowering (verify it first).
2. core-ssa-entry and core-lift.
3. lzcount and cmpxchg.
4. p1-identity and p1-reads, once their blockers are fixed.
5. p2-container.
6. p3-decl.
7. pe-bytes.
8. dylints.

After each merge, run the full gate and `tests/equiv/run_equiv.py --baseline
tests/equiv/baseline.json`. The ratchet must hold. Then re-bless the baseline,
recording the causes of records that are now equal. After P1 and P3 comes P4,
the memory model, which fixes the split arrays, the -O0 switch and the name
noise. See the plan for P4 through P11.

What was learned (read before resuming)
--------------------------------------

**Method**

- **Trust the equivalence gate, not the proof line.** Every silent
  miscompile found here printed `0 refused`.
  - The gate caught what 2000 unit tests missed. It found 36 wrong
    renderings in the corpus on its first run.
  - Run it on the **whole** population, because tracks that ran only
    `review.c` missed regressions.
  - Command: `python3 tests/equiv/run_equiv.py --r2s target/debug/r2s --jobs 1
    --baseline tests/equiv/baseline.json`. It takes about 15 minutes on 4
    CPUs.
- **Adversarial review earns its cost.** Every track sent to review came back
  with 1–5 real blocking defects, including unsound validators, a second owner
  of a fact, and ratchet regressions. Never merge a track that no reviewer has
  attacked.
- **Root causes cluster.** The first review listed about 60 defects, and they
  reduce to about 12 model gaps (the evidence is in
  `root-cause-findings.json` and `findings-index.txt`):
  - bit identity;
  - object provenance;
  - variadic contracts;
  - C operator admissibility;
  - byte definedness;
  - the frame partition;
  - the type graph;
  - one signature per function;
  - dispatch extent;
  - the name table;
  - loader values;
  - isolation.

  Fixing symptoms one by one would have added hacks.
- **Two identity facts existed for one thing.** `canonical_value_roots` and
  the reload certificate both treated SUBPIECE at any offset, SEXT and ZEXT as
  "the same value". That is the mul_div bug. When you see an identity or
  "same content" relation, check it against full-width bit equality.

**Tooling and machine**

- **Never share a `CARGO_TARGET_DIR` between worktrees.** Cargo fingerprints
  workspace crates by *relative* path, so one worktree's build is taken as
  fresh for another's sources. Use a private target per worktree with
  `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`,
  which brings a target down to about 2–3 GB.
- **Disk goes first.** `scripts/structure-report.sh` writes
  `target/structure`, about 1.5 GB per worktree, and radare2 builds take about
  550 MB each. A janitor loop that clears incremental caches and idle
  `target/structure` directories kept things alive.
- **Worktree agents may start on the remote's default branch**, not yours.
  Make the first step `git checkout -B <track> <base>` and verify the base with
  `merge-base`.
- **`SendMessage` to a running workflow agent forks a second copy into the same
  worktree.** Do not do it.
- **A radare2 build after `make clean` needs `./configure` again.** Run tests
  with `LD_LIBRARY_PATH=<prefix>/lib`.
- **`--all-features` needs `libz3-dev`.** Kani is not installed, so the Kani
  harnesses written in core-lift and pe-bytes have never run.
- **Coverage and certification.** `tests/coverage/run_coverage.sh` needs macOS
  `clang -arch`. `certify_render.py` needs radare2 test binaries, which are in
  `radare2-testbins`.

**Decisions to keep** (they are in `plan.md`; recorded here too because they
are easy to lose)

1. Output is ISO C under a UB-free-source premise. A signed or narrow
   operation appears only with a Proven declaration; otherwise the spelling is
   total.
2. Where an access's effective type is unproven, use memcpy load and store
   helpers.
3. An unproven construct becomes a compilable residual that traps if executed,
   and the function is not refused.
4. Build the full memory model: promote proven-private slots, including DWARF
   locals and homes.
5. Closed-world facts are allowed, but only when proven, and they carry their
   premises.
6. The stack-protector check is elided on structural proof and counted.
7. `main` taken from a handoff is Inferred; a symbol always wins.
8. Command output is spelled exactly as radare2 spells it.
9. DecBench runs on the official stripped protocol.

**DecBench**

- **The type metric reads DWARF.** r2s reads the evaluated binary's DWARF, so
  only stripped runs are honest. The adapter refuses an input that carries
  `.debug_info`.
- **GED needs Joern**, whose GitHub release download is blocked here. Allow
  `github.com` and `objects.githubusercontent.com` in the environment's network
  policy.

radare2 (upstream work from this session)
-----------------------------------------

**Merged**

- #26801: keep the other xrefs when deleting a missing edge.
- #26802: typedef cycle crash.
- #26803: the Thumb bit on data symbols (supersedes #26768).
- #26807: lldb/debugserver registers through one gdbr (supersedes #26765).
  debugserver has not been tested on a Mac; the PR lists the checks.

**Open** (opened by this session from branches on radareorg)

- #26804: argseq cache per calling convention (supersedes #26629).
  - phix33's review asked to unhook the cc db before `r_anal_free`; that is
    fixed in `f2e0d5f`.
  - An earlier macOS job failed only at the artifact upload.
- #26805: xref generation bumped only when an edge changes (supersedes
  #26682). The conflict with #26801 is resolved in `043d608`, and the ABI
  question is waiting on trufae.
- #26806: fortified `_chk` prototypes per libc, trufae's series (supersedes
  #26743).

**Closed with notes**

- #26708: its consumer, the r2sleigh plugin, is gone.
- #26762: it landed via #26763.

**Not published: #25942 (`/as` syscall search)**

- v2 is correct but +2161/−645 in `cmd_scsearch.inc.c`, with a private ESIL
  constant propagator. The patches are in `radare2/patches/25942-v2/` and the
  draft is `radare2/drafts/25942*.md`.
- The decision was to slim it onto radare2's own ESIL VM (v3) before
  publishing. v3 had not started beyond its first commit.
- It needs radare2-testbins fixtures, which are not committed anywhere.

**Other open items**

- #25935 waits on #26807.
- `crates/r2abi/data` still vendors the old, unmerged #26743 renames. Re-sync
  it with #26806's normalized keys once that lands.

The PR drafts and the action index are in `radare2/drafts/`, with `INDEX.md`
as the index. Local radare2 worktrees under `/home/user/r2wt` are lost with this
container.

Files in this directory
-----------------------

- **`plan.md`**: the approved plan. It holds the binding decisions, the phases
  P0–P11 with their owners and files, the checkpoints, and the triage
  additions.
- **`findings-index.txt`**: an index of the first review's root-cause trace,
  about 60 findings.
- **`root-cause-findings.json`**: the full critique findings, with file:line
  evidence, invariants, fixes and tests for each defect. The DecBench and
  radare2 PR triage is in it too.
- **`equiv-triage-new-causes.json`**: 16 root causes the equivalence census
  found.
- **`tracks/*.txt`**: the specification handed to each track.
- **`track-reports.txt`**: each track's report and each review's blocking
  findings.
- **`radare2/`**: the PR drafts, and the #25942 v2 patches.
