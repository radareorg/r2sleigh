Getting measured on DecBench
============================

[DecBench](https://decbench.com) ranks decompilers by how often they recover
source *exactly*: control-flow structure by graph edit distance, variable and
signature types against DWARF, and assembly similarity after recompiling with
the original toolchain. Its Union score is the share of functions perfect on at
least one of the three.

**Valid numbers start at [RESULT-2026-10-17.md](RESULT-2026-10-17.md) and are
corrected by [RESULT-2026-10-23.md](RESULT-2026-10-23.md): the first scored no bash
row for any decompiler. [RESULT-2026-10-24.md](RESULT-2026-10-24.md) is the latest r2s run.** Everything this directory recorded before
2026-09-25 -- `baseline.json`, the tables that used to be here, and the figures
in the since-deleted planning documents -- was measured
through the deleted radare2 plugin with `decbench run`, which hands the
decompiler the unstripped `-g` binary. r2sleigh read that binary's DWARF (the
prototypes, parameter and local names and types that `type_match` is scored
against) and its symbols (every function boundary and name), and the
population included CRT functions the leaderboard excludes. `baseline.json`
carries an `invalid` field saying so, and `report_decbench.py` refuses to
compare against it or merge into it; the next accepted run starts a new record.

The official protocol
---------------------

Measurement goes through DecBench's own driver, `scripts/run_benchmark.py`,
and nothing else:

* the decompiler gets a `strip --strip-all` copy of each binary;
* it is told the DWARF `low_pc` of every source function, and nothing about
  names;
* its answers are relabelled to the DWARF names afterwards and scored against
  the unstripped build.

```
git clone https://github.com/noelo-lab/decbench ../decbench
python3.12 -m venv ../decbench-venv && ../decbench-venv/bin/pip install -e ../decbench
tests/decbench/run_decbench.sh --decbench ../decbench --python ../decbench-venv/bin/python \
    --compile --project bzip2 --opt-level O0 --opt-level O2
tests/decbench/run_decbench.sh --plan          # print the commands, run nothing
```

`run_decbench.sh` builds `target/release/r2s` (or takes `--r2s`), installs this
tree's backend into the DecBench checkout (`install_backend.py`), refuses to
measure unless the installed backend reports the sha256 of that r2s, runs
`scripts/run_benchmark.py` through `decbench_cli.py` (which registers `vj_ged`
when DecBench does not), checks every result names that sha256, and reports
against `baseline.json` (`--accept-baseline` to record the run).

The driver needs cgroup v2 and a user systemd manager (`systemd-run --user`)
for its per-binary limits, and GED needs Joern, which `pyjoern` downloads from
github.com release assets. `angr` is the reference column and needs Python 3.12.

The backend
-----------

`r2sleigh_raw.py` registers one backend, `r2sleigh_native`, which asks `r2s`
one `pddj` per function, one stdin line each to a single `r2s -q <binary>`,
through the streaming runner it shares with the equivalence gate
(`tests/equiv/r2s_batch.py`). A binary of any size is one process; opening it
has its own deadline (`R2SLEIGH_STARTUP_TIMEOUT`, default 600 s) and each
function its own from the moment r2s starts on it
(`R2SLEIGH_FUNCTION_TIMEOUT`, default 300 s). It guarantees:

* **Exactly the targets.** It renders the addresses the driver gave it, with no
  symbol lookup; with no targets it renders what `afl` finds, through
  DecBench's shared skip rule.
* **Addresses pass through.** r2s reports ELF link addresses, which are
  DecBench's file space for PIE and non-PIE alike.
* **The name is the definition.** `FunctionDecompilation.name` is the
  identifier the rendering defines (`pddj.definition`), so DecBench's relabel
  renames the code and the key together.
* **Every function is accounted for.** Each is rendered or declined with a
  typed cause -- `refused: ...` (r2s's own), `r2s: ...` (a failed statement),
  or `harness: r2s <ending> while rendering <addr>` (a crash or deadline, after
  which r2s restarts at the next function) -- and
  `rendered + declined == requested` is checked.
* **Checkpoints.** The partial result is pickled to the driver's progress path
  every `R2SLEIGH_CHECKPOINT_SECONDS` (default 30) and at the end, so the driver's
  hard kill loses one interval of answers at most. (One pickle per function was
  quadratic: 2.5 MB each on bzip2, 18 MB on bash, and the backend took 9 to 13
  times r2s alone.) A re-run that finds the checkpoint of the same r2s build,
  binary bytes and targets asks r2s only for the addresses it has no answer for;
  the official driver gives each attempt a fresh path, so this serves a manual
  re-run. `r2s_batch.py` hands each answer over while r2s is still running, which
  is what makes a checkpoint taken mid-process hold anything.
* **Fails closed.** A binary carrying `.symtab` or any debug section
  (`.debug_*`, `.zdebug_*`, `.gnu_debugdata`) is declined
  whole: nothing r2s says about it is admissible.
* **Structured facts.** `variables` and `line_mappings` come from `pddj`.
  `r2sleigh_native` is not on DecBench's `ADDRESS_CORRESPONDENCE_BACKENDS`
  allowlist, but a function whose `line_mappings` carry instruction addresses
  is scored by address correspondence anyway (`has_line_address_evidence`):
  argument position, then stack offset, then address overlap of the lines
  naming a variable. In the 2026-10-23 run that is every function with a
  `type_match` row (the legacy offset rule, fed by `pddj`'s stack offsets,
  scored 20 functions of zlib in the 2026-10-17 run and none now).

Declines and residual counts are written per binary to
`r2sleigh-refusals-*.json` (schema 4) beside the run, and
`census_decbench.py` ranks their causes.

Memory and coverage
-------------------

Evaluating r2s's `bash` (a 13 MB C file for 1,540 functions) takes 5.2 GB in one
`evaluate_project` worker. Four workers on the 8 GB benchmark host are killed by
the OOM killer, `evaluate_project` then returns `{}` for the binary, and the
scoreboard silently drops it: the 2026-10-17 run scored no bash row for any
decompiler (angr kept 692 rows of one build). Two gates in `run_gate.py` now stop
that, and `run_decbench.sh` runs both:

* `--workers` above 1 is refused for a binary whose decompiled C exceeds 8 MB
  (exit 72): before the run, for C already in `--out`; inside the driver, before
  `evaluate_project` (`decbench_cli.py` installs the guard, and it raises
  `SystemExit` because the driver catches `Exception` there and carries on with
  `{}`); and by `evaluate_checkpointed.py`. Run `bash` with `--workers 1`.
* After the driver, every binary it decompiled in this run needs an
  `evaluated/<binary>.toml` that carries a score key of each decompiler that
  rendered functions of it; a missing file, the 16-byte `binary = "bash"` and a
  file that scores only other decompilers stop the run (exit 71) and name the
  cells. Checked on the 2026-10-17 tree it reports 55 of 192 cells, all bash.

`report_decbench.py` is the third gate. It compares decompilers only over the rows
every compared decompiler scored (a row is scored when the results hold a metric
value for it), prints how many rows that left out and, per decompiler and per
project, how many rows have no score, and exits 73 when a compared decompiler
scored nothing in a project (`--min-scored-fraction F` raises that to fewer than
F of the project's rows; `--compare a,b` picks the decompilers, by default every
one the results name, and `run_decbench.sh --compare` forwards it). On the
2026-10-17 results it stops at `kuna scored 0 of 4144 rows of bash`; on the
2026-10-23 results it passes and reports 3,814 common rows of 6,978 (angr
scored 1,285 of bash's 4,131). The scoreboard's own denominator is every row
*anyone* scored, so a row only one decompiler has counts as a miss for the
others (`compare_runs.py --exclude-project bash` is the same cut for a tree that
has none). A re-run of one decompiler is
`DECBENCH_REDO_DECOMPILERS=r2sleigh_native` on a copy of the tree; DecBench's
`finalize_results.py --allow-drops` is needed when functions that used to be
declined (rows named by their address) are now rendered.

Analysis tools
--------------

All read a results tree (`checkpoints/*.pkl`, `function_results.json`) and need the
DecBench venv (`PYTHONPATH=<decbench checkout>`); only `evaluate_checkpointed.py` writes
into the tree (the scores it adds to a checkpoint).

* `compare_runs.py`: the four-decompiler table, the delta against an earlier tree
  (`--old`), the same over a row subset (`--exclude-project bash`), paired
  better/worse/newly-perfect counts (`--paired`), the goto/residual split.
* `type_causes.py`: one verdict per DWARF variable from DecBench's own matcher
  (asserted equal to the stored `type_match`), grouped by cause with the number of
  functions each cause alone keeps imperfect; `universe` says why a function has no row.
* `ged_causes.py`, `counterfactual_ged.py`: block-graph deltas of the not-GED-perfect
  functions, and a re-score after a respelling, to bound what a renderer change gains.
* `mined_set.py`: the mined-set comparison of two r2s builds (next section).
* `run_gate.py`: the lost-evaluation and worker gates `run_decbench.sh` runs.
* `evaluate_checkpointed.py`: evaluates decompilers already in a checkpoint (the driver
  only evaluates what it has just run); `r2s_timing.py`: r2s alone, without the backend's
  checkpoint, with peak RSS; `show_function.py`: source, rendering, scores and DWARF of one function.

The mined-set comparison
------------------------

`mined_set.py` is how a structurer change is graded (ROADMAP D47): every function of
the pinned mining set, bzip2, zlib and grep, at O2 and O2-noinline, rendered by two
r2s builds and scored with DecBench's GED, then paired. It reads a results tree the
driver wrote (`<tree>/<opt>/<project>/{stripped,compiled,decompiled}`: the targets
are the addresses its `decompiled/*.toml` name) and runs where DecBench and Joern
are installed.

```
tests/decbench/mined_set.py dump  --tree RUN --r2s base/r2s --out base --set mining
tests/decbench/mined_set.py dump  --tree RUN --r2s new/r2s  --out new  --set mining
../decbench-venv/bin/python tests/decbench/mined_set.py score --tree RUN --dump base --out base.json --decbench ../decbench
../decbench-venv/bin/python tests/decbench/mined_set.py score --tree RUN --dump new  --out new.json  --decbench ../decbench
tests/decbench/mined_set.py pair base.json new.json            # -u: one entry per function; -v: name them
```

`pair` prints, over the functions both runs scored: perfect count with the ones newly
perfect and lost, mean and total GED with better, worse and same, gotos (all, and over
the scored functions) and the functions with a goto, the functions whose text changed,
refusals (newly refused) and the functions with no source to score against. Each
rendering is scored against the CFG of the unit the compiled binary's DWARF names as the
owner of its address (the driver's `source_function_owners`, so the same
`DECBENCH_DWARF_ABSTRACT_ORIGIN` as the run); a function with no owner, or whose owner
yields no CFG, is not scored and is counted, never matched by name. `--set heldout`
selects the other five projects (bash, diffutils, findutils, gzip, libexpat): those are
run nightly and at an item's exit, never to choose a rule, and `pair` refuses to compare
a mining run with a held-out run. The source CFGs are cached beside the scores (`srccache/`, by unit and function);
delete it when the sources are recompiled.

Local measurement
-----------------

Two censuses run on one binary, on this machine, without the driver. Both show
r2s a stripped copy and take the targets from the binary's own DWARF:

* `compile_census.py <binary>` compiles every rendering exactly as `pddj`
  printed it, at `-std=gnu11` (implicit declarations are errors, so a unit that
  calls a helper it does not define fails) and at
  `-std=c11 -O2 -Wall -Wextra -Werror`, and groups failures by first message;
* `byte_match_census.py <binary built with -g> --decbench ../decbench` scores
  every rendering with DecBench's own `byte_match` implementation.

Tests
-----

```
python3 -m unittest discover -s tests/decbench -p 'test_*.py'
../decbench-venv/bin/python -m unittest discover -s tests/decbench -p 'test_*.py'
```

The backend tests drive `tests/equiv/testdata/stub_r2s.py`, which answers
`pddj` per the contract and fails on request in every way r2s can (a failed
statement, an abort, a hang, garbage, a contract breach, death before the first
answer). They run against DecBench itself when it is importable and against
minimal stand-ins otherwise.
