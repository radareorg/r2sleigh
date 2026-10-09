# Unmigrated radare2 commands: what is worth taking

Draft, 2026-10-06, reviewed 2026-10-09, not yet on the roadmap. The numbers
come from `scripts/command_gap.py` and reproduce at the review (`ar` 700, `ao`
308, `pi` 231, 38 verb names); the ranking is section 3. This file records an
analysis. An item enters `ROADMAP.md` only when its owner crate and its gate
are named, and section 5 names the gates the first two ranks need.

## 1. Method

Three measurements, each one flag of `scripts/command_gap.py`:

- **The radare2 surface** (`--what help`): 3529 help triples from 331
  `RCoreHelpMessage` arrays in `../radare2/libr/core/cmd_*.c`, rolled up to
  families. Leaf flags are not ranked on their own.
- **What r2sleigh has** (`--what verbs`): 38 names (33 commands) from `VERBS`
  in `crates/r2s/src/commands.rs`.
- **Which commands radare2 itself checks** (`--what tested`): for every
  `CMDS` block in `../radare2/test/db`, the last command that prints, since
  `q`, `?e` and `echo` produce no output. Earlier lines are fixture setup.

The last-command rule approximates: `EXPECT` checks the whole block's
concatenated output, so a count attributes a block to one command. The
distinction still decides the ranking. Counting every invocation gives `e`
7171 and `wx` 3228, which are config writes and byte patches in fixtures;
counting the checked command gives `e` 88 and drops `wx` out of the top rows.
Ranking on raw counts puts byte-writing above emulation and types.

A tested count is evidence a command is maintained and its output is relied
on. It is not evidence a user wants it, and a low count does not prove the
opposite. Where a count is weak the ranking cites an `AGENTS.md` rule or a
`ROADMAP.md` row.

## 2. What is out of scope before ranking

A project rule already answers these, so they need no usefulness argument.

| Family | Tested | Rule |
|---|---|---|
| `!`, `!rabin2` 224, `!rahash2` 128, `!rasm2` 98, `rm` 113, `cat`, `mkdir`, `k` 50, `m`, `o`, `om`, `b`, `ec`, `prj`, `?v` 138 | 1000+ | Non-negotiable 2: `r2s` opens a binary and spells the answer. A shell escape, a file system verb, an sdb key and a project file state nothing about a program. The `!r*` counts are radare2 testing its own command line binaries through r2 |
| `aa`, `aaa`, `af`, `af+`, `afb+`, `afn` | — | Command Surface, "should it be automatic?" Functions arrive from `r2engine::program::Source` and discovery. A verb that triggers analysis, or defines a function by hand, adds a second owner for a fact discovery owns |
| `d*` 194 (`dr` 19, `dk` 32, `di` 30, `dc` 9) | 194 | `doc/debugger.md` section 1: the debugger is a separate design that must not start before row D switches `pdd` to the staged pipeline. It binds to register names and a renderer that D replaces |
| `agf` 17, `agc`, `agx` | 17 | ROADMAP V5: `agf`/`agc`/`agx` share one renderer, already planned |
| `afv` 195, `afl` 70, `afi` 59, `afb` 36 | 360 | Already in `VERBS`. P4 holds the rest: `afv` agrees with `pdd` |

## 3. The ranking

Score: the tested count, then whether the IL and SSA state a stronger fact
than radare2's mechanism, then whether an owner crate exists today. A family
with no owner is parity work however high its count.

### Tier 1: the IL and SSA state a stronger fact

| Rank | Family | What radare2 does | Tested | Owner | What ours adds |
|---|---|---|---|---|---|
| 1 | `ae`, `ar`, `aer`, `aes`, `aei` | ESIL expression evaluation, the emulation register file, emulated stepping | 1152 (`ar` 700, `aer` 137, `aes` 130, `ae` 81) | `r2il::eval` (`State::register`, `set_register`, `step`, `apply`) | The largest unmigrated count in the corpus, and `r2il::eval` already implements it. `ar` reads `core->anal->reg`, the ESIL virtual machine, so 1122 of the 1148 blocks that use `ar` also run `ae*` and 3 run `d*`: this is emulation surface, which is why it is not in the debugger row above. ROADMAP E ("Emulation, then verify"). radare2's ESIL yields a value where its per-opcode string is incomplete; `r2il::eval` carries a budget and returns `Stop`. Exposing it turns the engine's own B0 checker into a user command |
| 2 | `ao`, `aoj`, `aoe` | "analyze Opcodes (or emulate it)": per-instruction type, esil string, registers read and written | 383 (`ao` 308) | `r2sleigh-lift`, `r2il` | Ours reads the lifted semantics where radare2 reads a hand-written esil string per opcode. `pdil` renders the ops already, so `ao` is the per-instruction projection of that fact, with reads, writes and effects taken from the IL. One owner, one table |
| 3 | `pi`, `p8`, `pD`, `pr` | instructions only, raw bytes, N bytes disassembled | 496 (`pi` 231, `p8` 203) | `r2dec` rendering | High count for pure projections of `pd` and `px`: `pi` is `pd` with the addresses dropped. The count is fixture-driven, because a test wants bare instructions to diff, so user value sits below what 496 suggests. Cheap, and the Command Surface answer is one flag on `pd` covering all four |
| 4 | `aft`, `afts`, `afs`, `afc` | "type matching analysis", function signature, calling convention | 115 (`afts` 41, `afs` 18, `afcl` 13) | `r2types`, `r2abi` | radare2 propagates a callee's format string over a linear scan. Ours holds `FunctionTypeFacts` with `Confidence`, a frame model (P4) and cited ABI rows (M1), which is what P7 and P9 are proving. `afs` prints the signature `pdd` already computes, so it needs no new inference. `afc` prints a cited convention row where radare2 prints a guess |
| 5 | `pdc`, `pdct` | "pseudo disassembler output in C-like syntax" | 106 (`pdc` 79) | `r2dec` | `pdd` supersedes it: `pdc` transliterates each instruction into C shapes with no CFG and no dataflow. The work is an alias that prints `pdd`, or a refusal that says so. Listed because the count is real and the answer is already built |
| 6 | `axq`, `axf`, `axv` | references from an address, value cross-references | 45 (`axq` 33) | `r2ssa` def-use | `ax` and `axt` exist and already print coverage and refusal text. `axf` reads the same index in the other direction, so this extends the `ax` view. `/r` 7 asks the same question through a byte search |

### Tier 2: parity, cheap, little or no uplift

| Rank | Family | What it does | Tested | Verdict |
|---|---|---|---|---|
| 7 | `i*` extras: `ii` 32, `iI` 31, `iD` 23, `ic` 15, `iw` | imports, binary info, demangle, classes, write map | 205 | `r2image` states all of these; the work is a table per verb. Zero uplift, zero risk, one commit each when a user asks |
| 8 | `t*`: `tsc` 48, `ts` 23, `te` 9, `tcc` 8, `td` | list loaded structs, enums, define a type from C | 159 | `r2types` owns layouts. `ts` printing an inferred struct is a real view no radare2 command can produce from analysis. `td` parses C so a user can state a fact the engine cannot derive, which earns its place |
| 9 | `pf`, `pf.name` | "print formatted data" through a format string language | 119 | The useful half is `pf.name` over a struct `r2types` inferred, which is a typed memory view. The format string DSL itself (58 tests in `cmd_pf`) duplicates what the type store holds |
| 10 | `ps`, `psz`, `psj` | zero-terminated, pascal and wide strings at an address | 74 | `iz` and `izz` own string discovery already. `ps` reads one string at the seek, so it enriches `px` |
| 11 | `C`, `CC`, `CL`, `Cs` | comments, metadata, address to source line | 78 (`CL` 16, `C*` 14) | `CL` maps an address to `file:line`, which `r2image` reads from DWARF, so that view is free. `CC` user comments need a store the engine does not have, and the cost outweighs 5 tested calls |
| 12 | `pv`, `pv4`, `pv8` | "show value of given size (1, 2, 4, 8)" | 59 | A typed read of memory. With `r2types` it prints the value as its inferred type, which radare2 cannot do. Small uplift, small demand |

### Tier 3: skip, with the reason

| Family | Tested | Why not |
|---|---|---|
| `z`, `za`, `zb`, `zf` | 61 | Zignatures match a function by a byte and graph hash. The engine's answer is stronger already: an IL-level summary with evidence and confidence, owned by `r2engine`. The Anti-Hack Standard blocks name- or signature-owned summaries presented as proof, so importing radare2's format imports the hack. Absent from `ROADMAP.md` |
| `/` search: `/x` 34, `/g` 9, `/r` 7 | 209 | Byte, gadget and reference search. Discovery and the reference index answer the engine's questions, and the 35 `cmd_rop` tests exercise a gadget finder. `/as` 9 is already a verb |
| `tk` | 37 | An sdb query over a stringly keyed store, which non-negotiable 4 rules out: typed contracts, no stringly maps |
| `pa`, `pad`, `pade` | 22 | An assembler. The engine lifts bytes to IL and does not assemble. `wa` the same |
| `agg`, `aggk` | 21 | "custom graph": a graph the user draws, holding no program fact |
| `ah`, `ahi` | 17 | A hint forces an opcode size or type by hand, overriding a derived fact, which collides with one fact one owner. If it returns it returns as an **assumed** scope in `doc/debugger.md`'s vocabulary |
| `ab`, `abp` | 17 | One block by address. `afb` lists a function's blocks already, so one flag on `afb` covers it |
| `as`, `asl` | 15 | "analyze syscall using dbg.reg" needs register state, which makes it debugger work. `/as` lists syscalls statically today |

## 4. What this says to do

Two families carry real engine work, in order: `ae`/`ar`/`aes` at 1152 tested
calls, where `r2il::eval` already holds the semantics and ROADMAP row E holds
the plan, and `ao` at 383, where the IL holds the per-instruction facts
radare2 writes by hand. Both have an owner crate and a contract to extend,
which is the test `AGENTS.md` sets before a verb is added.

`aft`/`afs`/`afc` follow P7 and P9. Until those rows close, the signature
printed by `afs` is the one `pdd` prints, and a second verb adds no fact.

Tier 2 is projections of views that exist. Those belong in the views they
project from, under the Command Surface question "should it enrich an existing
view?". Tier 3 totals 379 tested calls that the engine either answers better
or has a rule against.

## 5. The gates ranks 1 and 2 need

The tested counts that rank `ae`/`ar`/`aes` and `ao` first are radare2's tests
of its own ESIL. Our answers differ by design: the register file is Sleigh's,
where each flag (`CF`, `ZF`, ...) is its own register the P-code writes on
every arithmetic operation and ESIL derives `rflags` bits instead, and `ao` has
no ESIL string to print. So `scripts/diff_r2.py`
cannot gate either rank, and a verb added without its own gate would have none.

- `ae`, `ar`, `aes`: the oracle is `r2il::eval` itself for the register file
  and stepping, and row E's host-compiled originals for what a step computes.
  The same verb on radare2 is compared only where both state the same fact: a
  general register's value after a step on code with no flag reads. Rank 1
  extends ROADMAP row E; it is not a second row.
- `ao`: the fields radare2 states from the instruction (size, address, bytes,
  the read and written registers by name) diff against radare2; the semantics
  field is the lifted IL that `pdil` already prints, gated by the lift's own
  tests, never by text equality with an ESIL string.
