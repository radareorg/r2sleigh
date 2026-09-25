Getting measured on DecBench
============================

[DecBench](https://decbench.com) ranks decompilers by how often they recover
source *exactly*: control-flow structure by graph edit distance, variable and
signature types against DWARF, and assembly similarity after recompiling with
the original toolchain. Its Union score is the share of functions perfect on at
least one of the three.

**No valid number exists yet.** Everything this directory recorded before
2026-09-25 -- `baseline.json`, the tables that used to be here, and the figures
in `doc/decbench-plan.md` and `doc/beat-angr-end-to-end.md` -- was measured
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
one `pddj` per function through the streaming runner it shares with the
equivalence gate (`tests/equiv/r2s_batch.py`). It guarantees:

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
* **Checkpoints.** The partial result is pickled after every function, so the
  driver's hard kill keeps what was answered.
* **Fails closed.** A binary carrying `.debug_info` or `.symtab` is declined
  whole: nothing r2s says about it is admissible.
* **Structured facts.** `variables` and `line_mappings` come from `pddj`.
  DecBench uses address correspondence for `type_match` only for the backends
  on its `ADDRESS_CORRESPONDENCE_BACKENDS` allowlist; until `r2sleigh_native`
  is on it upstream, locals are matched by the legacy offset rule, fed by the
  stack offsets `pddj` states.

Declines and residual counts are written per binary to
`r2sleigh-refusals-*.json` (schema 4) beside the run, and
`census_decbench.py` ranks their causes.

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
