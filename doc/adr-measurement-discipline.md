# ADR: measurement discipline, from Kuna's loop

Status: accepted (2026-10-17); D46 to D50 in [ROADMAP](../ROADMAP.md)

## Context

[Kuna](https://github.com/Noelo-Lab/kuna) (Apache-2.0, Rust, a port of Ghidra's decompiler,
refined by agents against DecBench) was read at `82d5253`: 6,344 files, about 796,000 lines
of Rust. Its strength is process and speed, not new semantics. Its output tuning targets a
benchmark's metric, which AGENTS.md's Anti-Hack standard forbids for us, so this ADR takes
the measurement ideas and rejects the output-shape ones. No Kuna source is copied.

What Kuna's own documents say about its standing (`docs/decbench-loop.md`, 2026-08-03):
GED perfect share is ida 36.06%, kuna 35.93%, angr 34.20%, ghidra 25.13%. The README's
"top position for optimized C" is not shown by that table, and the document calls its tree
"a mining instrument, not a publishable cross-tool leaderboard". The benchmark ran
`--mode auto`, which resolved to the aggressive preset on 768 of 803 binaries, so the score
includes speculative passes.

Not verified: the "19 MB binary in under 3 minutes" claim (the repository documents an
18 MB PE with 33,214 functions, `docs/cli.md:1904`); current DecBench leaderboard numbers.
The head-to-head run of Kuna and r2s on DecBench could not run (the study's host lost its
network); it stays an open measurement under D46. A first study pass reported that Kuna has
no held-out split; that was wrong: `docs/features/structsynth/dedup_heldout.py` and
`record.json` report layout precision "over 169 held-out builds". The split exists for
struct synthesis and not for the scored DecBench pool.

## What we take

| Idea | Kuna evidence | Disposition |
|---|---|---|
| Paired nightly with exact tests | `docs/nightly.md` | **adopt** (D46) |
| Whole-corpus sweep, per-hunk audit | `docs/decbench-loop.md` | **adopt** (D48) |
| Ship gate is improved and worse, not the perfect count; layout scores | `docs/decbench-loop.md` rule 10 | **adopt** (D47) |
| Held-out project split for mining | `structsynth/dedup_heldout.py` | **adapt** (D47) |
| Refusal catalog with a symptom index and a remedy | `docs/options.md` | **adapt** (D49) |
| Deterministic worker pool, longest first, positional merge | `docs/cli.md` | **adapt** (D50) |
| Callee-first order with per-function budgets and a memory stop | `docs/cli.md` | **adapt** (D50) |
| Symptom is evidence, diagnosis a hypothesis | `docs/decbench-loop.md` | **adopt**, process only: AGENTS.md Task Protocol |
| Two-direction regression tests | `docs/features` | already ours (AGENTS.md Testing) |
| Queryable phase registry | `docs/phases.md` | conditional: generate from the query-db definitions if a consumer needs it |
| Natural-language spec per feature and an anchor checker | `docs/spec` | conditional: `check-doc-anchors` beside `structure-report.sh` |
| Agent skill embedded in the binary | `skills/kuna/SKILL.md` | conditional: one VERBS entry and a test that every verb it names exists |
| Assertions with strength | `docs/modes.md` | covered by `Confidence` and `Basis` (ROADMAP C); an assumed fact never upgrades |
| Agents record where the tool fails, with executable acceptance predicates | `docs/improvement-pipeline.md` | deferred: `doc/command-gap.md` is the seed |
| Mine rival-perfect cases | `docs/decbench-loop.md` Route B | deferred: needs D47's held-out split first |
| Proof-carrying idiom recognizers, switch exhaustiveness certificate, structure synthesis, libc-derived local names | `docs/features` | deferred: each only with a native proof (r2rewrite rule plus `r2il::eval` check) |
| Output-shaping transforms matched to a rival (`iteexpr`, `returndup`, `gotoreduce`, `loweredswitch`) | `docs/options.md` | **reject**: output tuned to a metric |
| Mode preset chosen by file size (`auto`) | `docs/modes.md` | **reject**: one function would render differently by the binary around it |
| Automatic re-run under a degraded pipeline | `docs/cli.md` | **reject**: `r2engine` owns fallback policy typed |

Kuna's own documentation admits its output varies with the worker split
(`docs/cli.md`), which D50 forbids.

## Decisions

**D46. Moves are separated from noise by paired tests.** Owner: GT.
- A nightly job scores a pinned sample against the previous night. Pass and fail
  transitions are tested with McNemar's exact test (perfect rate) and a sign test
  (value). The p-values are Holm-adjusted together and a change is significant below 0.01.
- Timing is an A/B of tonight's build against last night's in alternating order, with a
  bootstrap interval over binaries. A slowdown counts only when the interval excludes 0 and
  the total is over 5% slower. It counts retired instructions (D38).
- Gate: the nightly job fails on a significant bad move; the harness reproduces published
  DecBench values on a pinned revision where PyPI is reachable (D10).

**D47. A type or layout change records what it improved and what it worsened.** Owner: GT,
with `r2types`.
- A PR that moves types or layouts records per project `n`, `perfect_off`, `perfect_on`,
  `improved` and `worse`, with the option set explicit in both arms. `improved` and
  `worse` decide shipping: a change flipping 400 functions each way moves the total by zero.
  Layout work also records layout F1 and nesting F1, because `type_match` cannot see
  structures.
- A pinned project list splits mining from reporting. The report prints both columns, and
  a PR citing a held-out regression is rejected (AGENTS.md: tests must not train the
  engine).
- Gate: `report_decbench.py` prints the split and the improved and worse counts; a PR with
  `worse > 0` states each function's cause.

**D48. The census audits its own hunks.** Owner: GT.
- A census move is classified by a per-feature audit script (the same statements
  respelled, a dead arm removed, a residual turned into rendering); only hunks no script
  classifies need a human, who reads each.
- Gate: blessing a census change needs zero unclassified hunks, each class named in the
  commit message with its count. This is AGENTS.md's "each moved line read and judged",
  automated where it can be and never skipped.

**D49. Every refusal and residual has a catalog row.** Owner: `r2engine`, with `r2ssa`.
- A catalog maps each typed refusal and residual cause (D29 records, `SourceArityFloor`
  and `SourceUnprovenResult` causes, `CallNotRendered`) to its symptom, the closing fact
  and the owner. The same table feeds `?` help for a residual, so an agent or a person can
  see what would close it.
- Gate: a test fails when a cause variant has no row; a golden holds the catalog.

**D50. Batch decompilation is parallel and byte-identical.** Owner: `r2engine`; `r2s`
writes the files.
- A pool schedules longest functions first, runs callees before callers, enforces a budget
  and a memory stop per function (a refusal that names the limit, never partial C), and
  merges results by position.
- Gate: output is byte-identical for one worker and eight on the census set, with no
  known exceptions; D19's release budgets hold.

## Order

D48 first (small, and every later change is graded by it), D46 and D47 with the DecBench
harness (D10 decides where they run), D49 beside RF, D50 after the cost path (ROADMAP
order, item 8): a pool over a slow per-function path only multiplies the cost.
