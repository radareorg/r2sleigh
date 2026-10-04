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
original does not return or exit from lies outside its domain and is dropped.

Records
-------

One record per function, always, in `artifacts/records.json`, sorted by key
`<source>::<config>::<function>`, where the configuration is
`<compiler>-<opt>` on x86-64 and `<target>-<compiler>-<opt>` on any other
target (`aarch64-gcc-O0`):

| status | graded by | meaning |
|---|---|---|
| `equal` | engine | every surviving vector agreed |
| `residual-trap` | engine | agreed wherever it ran; some vector reached a counted residual |
| `differs` | engine | a vector returned, wrote, printed or ended differently |
| `uninit` | engine | the rendering read a value nothing wrote |
| `ub` | engine | UBSan reported, or `-O0` and `-O2` disagree |
| `compile-error` | engine | a build or load failed; the diagnostic is kept |
| `refused` | engine | r2s refused the function, with its reason, in a `pddj` that keeps the contract |
| `no-record` | engine | r2s printed no usable `pddj` (crash, deadline, failed statement, broken contract), with the cause |
| `unsupported` | harness | the thunk cannot call the signature (aggregate by value, variadic definition, a compiler clone) |
| `untested` | harness | fewer than a quarter of the vectors survived the original, too few to rest an `equal` on |
| `harness-error` | harness | the gate itself failed, never asked r2s, or cannot bind an object link on this target |

Each record carries the first vector that shows its status (inputs, the field,
the first differing address and bytes), the vector counts, the proof counters
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
hold, per key, a status and -- for every record
that is not `equal` -- the person's recorded cause and the machine's reason
(`gate.reason`: the refusal cause, the differing field, the residual helper,
with addresses, generated names and source line numbers erased). It also
names the compilers it was blessed on. With `--baseline` the ratchet is exact:

- every function's status must be the baseline's. Falling short blocks, and
  so does an improvement the baseline does not hold yet: the next change could
  lose it silently, and a refusal that stops producing any record at all is a
  status change like any other;
- a `differs`, `uninit` or `ub` the baseline does not record is reported as
  `new` under its own message, the worst departure;
- a non-`equal` record must fail for the baseline's reason, where the baseline
  records one;
- a function the baseline knows, inside the run's selection, must still be
  graded, and one it does not know must be blessed;
- a non-`equal` baseline record without a cause is itself a failure;
- a run built by other compilers than the baseline names is refused before
  anything is graded, since another compiler makes other binaries.

CI runs this on every push (`equivalence` in `.github/workflows/ci.yml`) for
x86-64. No CI job runs the aarch64 target yet: its baseline was blessed from a
full run on an x86-64 Linux host under qemu-user, and is held by running
`run_equiv.py --target aarch64 --baseline tests/equiv/baseline-aarch64.json`
there.
The baseline is written only with `--write-baseline PATH`, which keeps any
cause already recorded for an unchanged status and reason, records each
reason and the toolchain, and leaves the other causes `null` for a person to
fill in after reading the records.

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
| per-call budget | `--timeout-ms` (four times it for a rendering) | five times that under qemu |
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

*Time.* `--timeout-ms` is native time. qemu-aarch64 ran a bitwise CRC 3.5
(`-O2`) to 5 (`-O0`) times slower than x86-64 natively, so under it every
per-call budget is five times longer (`Target.time_scale`). Unscaled, a
rendering keeps a fraction of its native margin: on a loaded host the `-O0`
build of a clang `-O2` crc32_bitwise needed 1.6 to 4 s of its 4 s on three
vectors, and one run in two graded it `slow`. A budget in wall-clock time
still has a boundary: a vector whose original needs about its whole budget
(review.c's clang `fact` at n near 2^31, 3 to 5 s under qemu and about 1 s
natively) can be graded in one run and dropped in the next, so the vector
counts of such a record can differ between two runs while its status does
not. Two full aarch64 runs side by side wrote 754 of 756 records byte for
byte and the other two with the same status.

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
  rests on at least a quarter of the vectors graded (`Config.floor`; every
  function of the default population grades 13 or more of 48), fewer is
  `untested`, and the counts are in every record. A defect one vector shows
  stands however few were graded. A vector a rendering run could not be made
  on is not graded, and leaves the record `harness-error`.
