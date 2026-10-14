# Handoff, 2026-10-14

State of the roadmap work at the pause, what to do next, and how. This
branch is notes only: it is master `95225b13` plus this directory. Do not
merge it.

## Where things stand

- master is `95225b13` (merge of #217). Every roadmap pull request is merged.
  Merged on 2026-10-14:
  - stack 209 (#205 to #228);
  - stack 236 (#231 to #235): P9's first exit, T one-pass, T3e, the review
    fixes, and the P7 float carrier;
  - #237: the dead visible-binding pipeline was deleted;
  - #238 (P9b): an inferred structure parameter's accesses are spelled at
    the member's address. Each is a byte copy,
    `r2sleigh_load_u16((void*)&arg0->f_2)`, so the C asserts neither the
    struct's effective type nor its alignment. Members are mapped only on
    little-endian targets, where the byte copy is already proven;
  - #217: the golden test files, re-blessed after #238 (4 functions moved:
    `mixed_touch`, `rec_spread`, `out_param_parse` at -O0 and -O2).
- Master's CI is green. Its timing gate was red once, after #228. The cause
  is in "Findings" below; it is not a defect.
- The open PRs are dependabot bumps (#40, #229, #230) and the docs PR #146,
  none of them roadmap work.

Re-bless the golden files whenever rendered output moves (they ran on
contabo; `scripts/chain-gold.sh`):
1. `cargo build -p r2s --all-features`.
2. `python3 scripts/census.py golden --r2s target/debug/r2s`.
3. `R2S_BLESS=1 cargo test -p r2s --all-features --test golden`.
4. The same test again without `R2S_BLESS`, to verify.
5. Read the diff, then commit `tests/db` only. Do not commit
   `crates/r2s/dhat-heap.json`.

## radare2 (upstream, fork `0verflowme/radare2`)

| PR | Branch | State |
|---|---|---|
| #26960 | `elf-abs-symbol-values` | green; needed testbins#155 (merged) |
| #26961 | `elf-nobits-entry` | green |
| #26963 | `macho-entry-vhaddr` | green |
| #26964 | `as-maxhits-maps` | green |
| #26965 | `as-align-first-read` | trufae asked for a candidate-driven `/as` loop; done in `f9a920155a`, replied, waiting on him |
| #26970 | `mach0-fat-hpaddr` | trufae doubts `hpaddr += boffset`. Our reply: Mach-O's `addr_t.haddr` is the in-slice file offset of the thread `pc` field (`mach0.entry.offset`), so adding `boffset` makes it the raw on-disk offset, as `paddr` already is. Bytes: `0x1570` holds `f80e0000 01000000`, `0x570` holds zeros. We offered to rename `addr_t.haddr` to `hpaddr` in its own PR. Waiting on him. |

Rules for radare2 commits:
- one idea each, with a one-line message;
- no assistant attribution;
- author `Priyanshu Kumar <priyanshukumarpu@gmail.com>`, never the work
  email.

Address a review by amending the one commit. `scripts/r2watch.sh` polls the
open PRs for new comments.

## Next roadmap items, in order

1. **P9: callers' prototypes of an inferred structure parameter.**
   - Symptom: a caller still declares `uint64_t mixed_touch(uint64_t)` and
     passes `(uint64_t)(frame + 32U)`.
   - Cause: the callee does hand callers `Pointer(Struct("fcn_4017ac_arg0"))`
     (refusal evidence `exact-source-signature`). But r2dec
     `calls::pointee_spelling` accepts a struct pointee only where the unit
     defines the tag (`Tags::defines`), so the caller falls back to the
     machine class.
   - Fix direction: a pointer needs only a forward declaration
     (`struct fcn_4017ac_arg0;`). Allowing it changes every prototype that
     points to an undefined struct (`FILE*` and others), so design it with
     the advisor and measure the census and equivalence.
2. **P9: declared (DWARF) aggregates' members.** P9b spells only inferred
   structures. Declared ones need the all-or-nothing check against the
   declared layout (doc/adr-aggregates.md).
3. **T: the inferred signature's type strings.** Audited: the two parsers
   disagree on all 11 C base names.
   - `parse_c_type_like` gives sized `Int`s.
   - `parse_signature_type_preserving_c_typedefs` gives
     `Typedef { name, ty: Unknown }`, and maps `uintptr_t` to `size_t`.

   So typing `InferredSignature` is a per-site rewrite of about 40 sites,
   each choosing its reading. `type_name_is_generic` is spelling-based and
   quirky: it erases pointer depth, so `void**` counts as generic. Replace
   it with the lattice's ordering.
4. **P7: the closed world's second register.**
   - Closed-world `void` needs x1 overwritten wherever the body writes x1
     (`result_register_written`), while a pair needs it written on every
     return (`written_on_every_return`). Aligning them is a precision gain.
   - aarch64 gcc-O1 `mixed_touch` lost its equal cell to this rule (blessed
     with its cause). Recovering it needs the caller's liveness past the
     next call, the same deferred item as `crc32_init`/`fill`.
5. **G0: the timing gate.** It has no verdict where the base refuses and
   the head renders, so the ratio is meaningless there. Report "base
   refused" and require an explicit bless.
6. The ROADMAP rows hold the rest: LX2's 106 item-level `entity_keyed_map`
   allows, Q3 held marks (done), and the SM and PF items.

## Findings from this session

- **#213 (monotone stack-roots meet) slowed 0pack `0x58e3d0` from about
  4.3 s to 6.7 s.** The function used to refuse fast and now renders: 32,785
  obligations, 682 residuals. Bisected on contabo over #210 to #215 (#213's
  two commits, then #214); `scripts/chain-bisect.sh`.
- **P9's per-formal reach walk costs nothing measurable:** 5.0 to 6.4 s on
  the large functions with and without it.
- **Stack 236 is timing-neutral** on 0pack `0x58e3d0` and `0x62ecf0`, and on
  pumasim `0x23fdf0` and `0x4baf30`.
- **Cancelling the runs of lower stack PRs skips their per-PR timing gate
  and Dylint.** That is how #213's timing and P9's entity-keyed `BTreeSet`
  reached the top unseen. Before merge-async on such a stack, run Dylint
  and the large-function timing on contabo (`scripts/chain-dylint.sh`).

## How the work runs

- **Stacks:** see `memory/stacked-prs.md`. merge-async on the top PR merges
  every PR below it. The ruleset requires every review thread resolved;
  Codex re-reviews each push.
- **CI tiers:** tier 2 (equivalence, timing, coverage) runs only where the
  base is master or the PR carries the `full-ci` label. About 4 runners
  serve the repo, so cancel the runs of PRs above the merging one.
- **Blessing equivalence:** only from CI artifacts.
  - `gh run download <run> -n equivalence-<run>-1` (x86) and
    `-n equivalence-aarch64-<run>-1`.
  - Fill each empty `cause` in `baseline.proposed.json` and commit it as
    `tests/equiv/baseline*.json`.
  - Check `gate.ratchet` against the run's `records.json`; it must report
    0 problems.
  - Bisect a changed reason before blessing it.
- **Contabo** (`memory/contabo-build-host.md`; the host is in your
  `~/.ssh/config`):
  - Push branches to the `contabo` remote (`/root/r2s-stack`).
  - Run `git checkout --detach` there first, so the push may update the
    branch it has checked out. Make a separate worktree for a second job.
  - Chain scripts go in `/root/r2s-logs/chain-*.sh` and run under `nohup`.
    Poll the logs' `^EXIT` at 120 s or more.
  - The `scripts/chain-*.sh` here are templates; adjust branch names and
    paths.
- **Conflicts on restacks:** `scripts/union.py` keeps both sides of
  conflict blocks, and `scripts/push209.sh` is the atomic, lease-checked
  push of a whole stack. `scripts/replies236.py` replies to and resolves
  review threads by id.

## Memory

`memory/` is Claude Code's auto-memory for this repo: feedback rules,
recipes and project facts. The contabo address is redacted. To use it on the
new machine, copy the files into
`~/.claude/projects/<the repo path with / replaced by ->/memory/`.
`MEMORY.md` is the index.

## Archived local branches

Local branches whose commits exist on no remote branch are now pushed under
`archive/` on origin. Nothing else was overwritten.
- This session: `t5s2-measure`, `t5s-measure`, `t34-measure`, `t4-measure`,
  `t3c-measure`, `t3-experiment`, `q7-experiment`, `q7-ceiling`. These are
  measurement switches; their outcomes are in the ROADMAP.
- Earlier sessions: `d-trip-ranges`, `engine/roadmap`,
  `engine/review-fixes-vfmgfv`, `worktree-agent-a30122da925a0bad3`,
  `track/*`, `memory-value-provenance`, `artifact-ci`,
  `predicate-flag-correctness`, `codex/*`, `types-writeback`,
  `state-integration`, `pr-13-*`, `meta-handle`, `phi-removal`.

Delete any of them with `git push origin --delete archive/<name>`.

## Cleanups left

- On contabo, `/root/r2s-gold` was removed after #217 merged.
- On the old Mac, remove the scratchpad worktrees once their branches merge.
