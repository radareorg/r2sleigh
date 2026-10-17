The equivalence gate
====================

Does the C that `r2s` prints compute what the binary computes? This gate
answers that per function by running both, inside the program the rendering
was recovered from.

```
cargo build -p r2s --features sleigh
tests/equiv/run_equiv.py --r2s target/debug/r2s                 # measure
tests/equiv/run_equiv.py --r2s target/debug/r2s \
    --baseline tests/equiv/baseline.json                         # gate (ratchet)
tests/equiv/run_equiv.py --r2s target/debug/r2s --target aarch64 \
    --baseline tests/equiv/baseline-aarch64.json                 # the same, for arm64
tests/equiv/run_equiv.py --r2s target/debug/r2s --measure instructions   # cost counted, not timed
python3 -m unittest discover -s tests/equiv -p 'test_*.py'       # the gate's own tests
```

For x86-64 (the default target) it needs x86-64 Linux, `gcc`, `clang` (for the
Clang cells), and binutils. For aarch64 it needs Linux, `qemu-aarch64`
(qemu-user), `aarch64-linux-gnu-gcc` with its binutils and its sysroot in
`/usr/aarch64-linux-gnu` (Ubuntu: `gcc-aarch64-linux-gnu`,
`qemu-user`), and a `clang` that can target it with that sysroot. It uses
only the Python standard library.

What it does
------------

**Population.** Every `tests/corpus/*.c` and `tests/gold/*.c` (or
`--sources`), built with GCC and Clang at `-O0`, `-O1` and `-O2`, non-PIE,
with `-g`. The function set is what that build's DWARF names in the source's
own compile unit.

**Capture.** `r2s` is shown only the `strip --strip-all` copy. One streaming
process per binary answers `s <low_pc>; pddj` for every function, one stdin
line each, so a binary of any size is one process, with stderr merged so an
`r2s:` message lands inside the markers of the statement that printed it. A
crash or a per-function deadline costs that one function (its record is
`no-record` with the ending and the last lines printed) and the batch restarts
at the next address; opening the binary has a budget of its own
(`--startup-timeout`), charged once (`r2s_batch.py`, shared with the DecBench
adapter).

**Oracle.** The unstripped build's DWARF says how to call each function
(`dwarf.py`, `spec.py`): which register or stack word carries each parameter,
what it points at, and at which class and width the return is compared. The
immediates in the original's own code seed the vectors, so a boundary the
source wrote is tested on both sides.

**Execution.** The rendering is compiled into a shared object. Its link map
(`pddj.links`) becomes a shim: a function is a trampoline to its address in the
image, an object an absolute symbol at its address, an import binds to libc
(`link.py`). `rt/equiv_rt.c` is preloaded into the *original* binary and takes
over after libc and the program's constructors have run. For each vector it
fills a fixed-address arena, then forks one child per run from that same
state: the original at its link address, the original again through a
trampoline (identity), and the rendering built four ways. Every child enters
its function through one register-level thunk (`rt/call_x86_64.S`,
`rt/call_aarch64.S`) with the same registers (and x86-64's AL) and stack
words, so a rendering is judged against the machine ABI rather than the
prototype it declares. Each child records how it
ended, its return registers, the arena, the program's writable segments, and
fd 1 and fd 2.

**The rendering replaces the function.** In a rendering's child every byte of
the original function's code (its symbol's extent) becomes a trap (`int3`;
`brk #0` in every instruction word on AArch64) before the
call. When the program enters the function's entry -- a caller, a function
pointer, a mutual recursion through another function -- the entry is
redirected to the rendering, so the rendering is graded at every depth the
program reaches it, not only at the top. When control reaches the original's
entry from the rendering's own code (or a tail call from it), the rendering has
handed its work back to the original: the run ends there and the record is
`differs` with `guard: delegated`. Entering the original's body anywhere else
ends the run the same way (`guard: body`). A rendering reaches itself through
its own definition; a `function` link to the graded function's entry is bound
to that definition, and a link to any other address inside the function is
refused as `compile-error`.

**Comparison** (`gate.py`):

| pair | meaning when different |
|---|---|
| original vs identity | the program does not agree with itself: the vector is dropped as `unstable` |
| original vs `-O0` | `differs`, or `residual-trap` when the rendering stopped in a counted `r2sleigh_residual_*` |
| `-O0` `=zero` vs `-O0` `=pattern` | `uninit`: a local nothing wrote was read |
| `-O0` vs `-O2` | `ub`: the optimiser changed the meaning |
| UBSan build | `ub` when it reports |

The return is compared at the source's width and class (two NaNs agree); the
arena, the writable segments, stdout and stderr byte for byte. A vector the
original does not return or exit from lies outside its domain and is dropped. A vector
on which the original returns but the `-O0` and `-O2` renderings both fault at their stack
pointer (`stack` in the run, counted as `stack`) is not graded: the builds make no sibling
call, so a tail-recursive original that runs in constant stack asks the C for a frame per
step. Without it the verdict follows host speed, since a fast host finishes the original's
2^31 steps inside the budget where a slow one drops the vector.

**State at a residual trap.** A rendering that traps in its own code is
snapshotted in the fault handler: its stdio is flushed, the arena and the
writable segments are copied, how much fd 1 and fd 2 held is noted (qemu-user
reports the signal on fd 2 after it), and the trap's site (the residual helper's
`site` argument, still in the first argument register at `-O0`) and depth are
recorded. The depth says whether the trapping activation of the rendering is
the one the thunk called (`outermost`), one the rendering or the program
reached again (`nested`), or one the unwinder could not place (`unknown`).
`gate.py` then grades the trap against the original's end:

| compared | when | `differs` if |
|---|---|---|
| stdout, stderr | every trap at a residual | what the rendering wrote is not a prefix of what the original wrote |
| arena, writable segments | the site's `pddj` cause is `unproven-return` (a whole return statement), the trap is `outermost`, and the original returned | any byte differs |

A residual of any other cause may stand anywhere in the body, so the original
may still write after the point the rendering stopped at: its memory is not
compared, and the evidence says the output was. A trap the gate could not
snapshot compares nothing, and a vector that compared nothing does not count
towards the floor (below).

Records
-------

One record per function, always, in `artifacts/records.json`, sorted by key
`<source>::<config>::<function>`, where the configuration is
`<compiler>-<opt>` on x86-64 and `<target>-<compiler>-<opt>` on any other
target (`aarch64-gcc-O0`):

| status | graded by | meaning |
|---|---|---|
| `equal` | engine | every surviving vector agreed |
| `slow` | engine | agreed wherever it finished; a rendering ran past its budget (below), which is a cost and not an answer |
| `residual-trap` | engine | agreed wherever it ran; some vector reached a counted residual, and the state before it agreed |
| `differs` | engine | a vector returned, wrote, printed or ended differently, or had written or printed differently by a residual trap |
| `uninit` | engine | the rendering read a value nothing wrote |
| `ub` | engine | UBSan reported, or `-O0` and `-O2` disagree |
| `compile-error` | engine | a build or load failed; the diagnostic is kept |
| `refused` | engine | r2s refused the function, with its reason, in a `pddj` that keeps the contract |
| `no-record` | engine | r2s printed no usable `pddj` (crash, deadline, failed statement, broken contract), with the cause |
| `unsupported` | harness | the thunk cannot call the signature (aggregate by value, variadic definition, a compiler clone) |
| `untested` | harness | fewer than a quarter of the vectors survived the original, too few to rest an `equal` on |
| `harness-error` | harness | the gate itself failed, never asked r2s, or cannot bind an object link on this target |

Each record carries the first vector that shows its status (inputs, the field,
the first differing address and bytes; for a trap, the helper, the site and its
`pddj` cause), the vector counts (`compared`: vectors compared with the
original; `trap_compared` and `trap_memory`: traps whose output, and whose
memory too, were compared), the proof counters
from `pddj`, and whether the rendering also compiles under
`-std=c11 -Wall -Wextra -Werror -O2` (`strict`, evidence only).

The self-tests come first
-------------------------

`selftest.py` grades hand-written renderings of `selftest/fixture.c` whose
verdicts are known: source-equivalent identities must be `equal`; a flipped
operator, an off-by-one, swapped stack arguments (past six integer registers,
and past eight) and a 32-bit parameter read
as 64 bits must be `differs`; an uninitialised read `uninit`; a signed
overflow `ub`; a write to the wrong global and a wrong byte through a pointer
`differs` (memory, arena); swapped printf arguments `differs` (stdout); a
reached residual `residual-trap`, also in a function that prints on every
vector and traps on some, but a trap outside every residual helper `differs`;
a wrong global written before a returned residual (on every vector, or only
where it traps) and a wrong value printed before any residual `differs`, a
right global before a returned residual `residual-trap` with its memory
compared, and a residual before a write the original makes, or a returned
residual in an inner activation, `residual-trap` with only its output
compared;
a function that writes to stderr and faults on its NULL vector `equal` on the
vectors after it; a libm call `equal` (the rendering links against the
original's `DT_NEEDED`); a recursion through a link to the function's own
entry, and one through a program function that calls it back, `equal`; a
rendering wrong only where the program calls it back `differs`; a rendering
that calls the original's own entry `differs` (delegated); a link into the
original's body, and an identifier missing from the link map,
`compile-error`; a refusal `refused`. Every gate run runs them first and
grades nothing (exit 2) if one misses. There is no flag to skip them.

The self-tests run on the target being graded: an aarch64 run grades them
built for AArch64 and run under qemu-user, so the gate's own verdicts are
proven on the machine model it then applies.

`test_equiv.py` then runs the whole pipeline over the fixture (built, stripped,
asked through the batch runner with `testdata/stub_r2s.py` standing in for
r2s): the known renderings keep their verdicts end to end, and the stub's
`delegate` renderings, which call the original by its address, are `differs`
for every function.

The ratchet
-----------

`tests/equiv/baseline.json` (x86-64) and `tests/equiv/baseline-aarch64.json`
name the measure and budget they were blessed under (`cost`), and hold, per
key, a status and -- for every record
that is not `equal` -- the person's recorded `cause`, its `owner` (the
ROADMAP.md item that owns the fix) and `site` (the repository path where it
lands, or that states the limitation), and the machine's `reason`
(`gate.reason`: the refusal cause, the differing field, the residual helper and
its site's `pddj` cause, with addresses, generated names and source line
numbers erased); a `residual-trap` also holds what it `compared` before its
traps (`memory`, `output` or `none`). It also names the compilers it was
blessed on. With `--baseline` the ratchet is exact:

- every function's status must be the baseline's. Falling short blocks, and
  so does an improvement the baseline does not hold yet: the next change could
  lose it silently, and a refusal that stops producing any record at all is a
  status change like any other;
- a `differs`, `uninit` or `ub` the baseline does not record is reported as
  `new` under its own message, the worst departure;
- a non-`equal` record must fail for the baseline's reason, where the baseline
  records one;
- a `residual-trap` must compare what the baseline says it compared, so a
  record cannot silently go back to comparing nothing before its traps;
- a function the baseline knows, inside the run's selection, must still be
  graded, and one it does not know must be blessed;
- a non-`equal` baseline record whose cause does not stand is itself a
  failure: a cause that is missing, shorter than six words or a placeholder
  (`gate.PLACEHOLDER_CAUSES`: "not yet triaged", "TODO", ...), an owner that is
  no item ROADMAP.md names, or a site that is no path in the repository;
- a run built by other compilers than the baseline names is refused before
  anything is graded, since another compiler makes other binaries.

CI runs this on every push (`equivalence` in `.github/workflows/ci.yml`) for
x86-64. No CI job runs the aarch64 target yet: its baseline was blessed from a
full run on an x86-64 Linux host under qemu-user, and is held by running
`run_equiv.py --target aarch64 --baseline tests/equiv/baseline-aarch64.json`
there.
The baseline is written only with `--write-baseline PATH`, which keeps any
cause, owner and site already recorded for an unchanged status and reason,
records each reason, what each trap compared and the toolchain, and leaves the
others `null` for a person to fill in after reading the records.

Targets
-------

`--target` picks the machine (`target.py`, one `Target` value each). A target
names its compilers (`gcc` is `aarch64-linux-gnu-gcc` there, `clang` is
`clang --target=aarch64-linux-gnu`), its binutils prefix and sysroot, its
calling convention, the thunk and the shim's jumps, how its programs run, and
the signal `__builtin_trap` raises. What a compiler built is read back
(`readelf -h`), so a compiler that built for the wrong machine is a failed
build, never a binary graded under the wrong ABI.

| | x86-64 | aarch64 |
|---|---|---|
| arguments | rdi..r9, xmm0..7, then 8-byte stack words; AL counts vector registers | x0..x7, v0..v7, then 8-byte stack words |
| a narrow integer argument | extended to 32 bits by its type, bits 32..63 arbitrary | every bit above the type arbitrary (AAPCS64) |
| results | rax (rdx), xmm0 | x0 (x1), v0 |
| a function link | `movabs $addr, %r11; jmp *%r11` | `movz/movk x16, addr; br x16` |
| an object link | `.set name, addr` | the same, bound by the loader (below) |
| guard, residual trap | `int3`, `ud2` (SIGILL) | `brk #0`, `brk` (SIGTRAP) |
| runner | `setarch -R env VAR=... prog` | `setarch -R qemu-aarch64 -L /usr/aarch64-linux-gnu -seed 1 -E VAR=... prog` |
| per-call budget | `--budget-instructions`, or `--timeout-ms` under `--measure time` (four times it for a rendering) | `--measure time` only, five times `--timeout-ms` |
| `DT_NEEDED` libraries | as `ldd` resolves them | the files in the sysroot |
| keys, baseline | `gcc-O0`, `baseline.json` | `aarch64-gcc-O0`, `baseline-aarch64.json` |

x86-64's keys predate the target axis and carry no target name, so its
baseline is unchanged; every other target's keys and work directories carry
its name, so records of two machines never share a key. A `records.json`
names its target in `config.target`, and `merge_shards.py` refuses shards of
two targets.

*Layout.* qemu-user gives its guest no address randomisation of its own: it
places the guest's image, stack and mappings by a first-fit search from fixed
bases. That search runs over the host address space qemu itself occupies, so
qemu runs under the same `setarch -R` as a native target, and two runs write
the same records (`AArch64PipelineTests.test_two_runs_write_the_same_records`).
`-seed 1` fixes the bytes qemu gives the guest as `AT_RANDOM`, from which
glibc derives the stack-protector canary, so a UBSan report that shows stack
memory is the same on every run too. (Natively the kernel gives every process
fresh `AT_RANDOM` bytes, and such a report can differ in the canary's bytes
between two x86-64 runs.) The runtime's variables go to the guest with `-E`,
never into qemu's own environment, where the host loader would try to preload
a foreign object.

*Cost.* A budget counts one measure, and every record and baseline says which
(`cost.measure` and `cost.budget`; `config.cost` in `records.json`). The
original gets the budget and a rendering four times it; a call past it is
stopped, and a rendering stopped is `slow`, an original stopped lies outside
the domain and is dropped (`cost.py`, ADR D38).

- `--measure instructions` counts the user-space instructions the call
  retires. The child opens `perf_event_open` (`HW_INSTRUCTIONS`,
  `exclude_kernel`, `exclude_hv`) with the budget plus one as its sample
  period, so the counter overflows once, at the first instruction past the
  budget, and raises `SIGPWR`, whose default action ends the run (outcome
  `budget`). A call that retires more than the
  budget before the signal lands ends the same way, so the verdict is the
  count and never the skid. The runtime also writes each run's count as
  `insns` to `result.jsonl` (kept by `--keep`) and never into a record, since
  the last digits of a count vary. Wall-clock time (`--hang-ms`, 120 s) only
  ends a run that retires nothing, a blocked call: that run is `hang`, which
  grades nothing (an original that hangs is dropped, a rendering that does
  leaves the vector ungraded and the record `harness-error`).
- The default budget, `--budget-instructions` 4 billion, is about the second
  the time measure gave on the host it was measured on (x86-64, AMD EPYC under
  KVM). review.c's clang `fact` retires 2.5, 3.3 and 4.5 billion on its three
  largest vectors and every other original in review.c and hashes.c under 3
  million, so no vector lies within 12 % of the budget (the 4.5 billion one is
  12.5 % over and dropped, the 3.3 billion one 18 % under). The `-O0` rendering retires 51 and 67 billion on the other two (20
  times the original), so `fact` stays `slow`. Load barely moves a count
  (839 runs beside four busy loops differed by at most 163 instructions in 3.3
  billion); a CPU model does (libc picks its string routines by CPU feature),
  so a baseline is blessed on the kind of runner that grades it. A `time`
  budget is wall milliseconds on the runner it was blessed on: a native
  aarch64 host, which does not scale, is refused against `baseline-aarch64.json`'s
  5000 until given `--timeout-ms 5000`.
- `--measure time` (the default) counts wall-clock milliseconds, `--timeout-ms`
  in native time, five times that on an emulated target
  (`Target.time_scale`: qemu-aarch64 ran a bitwise CRC 3.5 to 5 times slower than
  x86-64). It is what a host without a counter can do, and it depends on load:
  on a loaded host the `-O0` build of a clang `-O2` crc32_bitwise needed 1.6 to
  4 s of its 4 s, and a vector whose original needs about its whole budget
  (review.c's clang `fact` at n near 2^31, 3 to 5 s under qemu and about 1 s
  natively) can be graded in one run and dropped in the next, so the vector
  counts of such a record differ between two runs while its status does not.
  Two full aarch64 runs side by side wrote 754 of 756 records byte for byte and
  the other two with the same status.
- The gate refuses rather than fall back. `--measure instructions` on a host
  without a working counter (`perf_event_open` denied by
  `kernel.perf_event_paranoid`, no virtual PMU, or a counter that reads zero)
  exits 3 and names the cause. It is refused on an emulated target: the guest
  cannot call `perf_event_open` (qemu-user answers `ENOSYS`) and the packaged
  qemu-user 8.2 has no `-plugin`, so its guest instructions are not countable
  there yet. A run whose measure or budget differs from `--baseline`'s is
  refused before anything is graded (exit 1), and `merge_shards.py` refuses
  shards that counted differently.
- The self-tests include two cases under a fake counter (`Cost.fake`, a count
  the runtime reports for every rendering run in place of the counter): one
  retires one instruction more than four times the budget and must be `slow`,
  one exactly that and must be `equal`. They need no performance counter, so
  they run on every host and target and pin the verdict path.

*Object links on AArch64.* GNU ld for AArch64 (2.42, and gold) resolves the
GOT entry of an absolute symbol a shared object defines as if it were
section-relative (an `R_AARCH64_RELATIVE` of the address), so the loader adds
the rendering's load base and `&name` lands a load base past the image's
object. There the object links are listed in a `--dynamic-list`: the loader
binds them, and glibc's loader places an `SHN_ABS` definition at its value.
The loader searches the program and its libraries first, so a rendering whose
object link one of those would capture (a name the program exports at another
address, or one a library exports) is `harness-error` with the conflict named,
never graded against an object it did not name (`link.loader_conflicts`).

Limits, stated
--------------

- Linux ELF for x86-64 and AArch64 only (`target.py`); aarch64 runs under
  qemu-user unless the host is AArch64.
- Non-PIE only: a rendering may spell image addresses as integers, which are
  run-time addresses only when the link address is the load address.
- A parameter's pointee is built from its DWARF type: bytes, a NUL-terminated
  string, linked structures (depth up to four), a NULL-terminated pointer
  table, or a function of the pointee's own type. A length that walks off what
  was built is outside the domain and dropped, never a false `differs`.
- Aggregates passed or returned by value, `long double`, and variadic
  definitions are `unsupported`, with the reason.
- Equal on the vectors is evidence, not proof. An `equal` or `residual-trap`
  rests on at least a quarter of the vectors compared with the original
  (`Config.floor`; every function of the default population grades 13 or more
  of 48; a trap counts when its state was compared), fewer is `untested`, and
  the counts are in every record. A defect one vector shows
  stands however few were graded. A vector a rendering run could not be made
  on is not graded, and leaves the record `harness-error`.
