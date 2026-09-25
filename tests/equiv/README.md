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
python3 -m unittest discover -s tests/equiv -p 'test_*.py'       # the gate's own tests
```

It needs x86-64 Linux, `gcc`, `clang` (for the Clang cells), and binutils. It
uses only the Python standard library.

What it does
------------

**Population.** Every `tests/corpus/*.c` and `tests/gold/*.c` (or
`--sources`), built with GCC and Clang at `-O0`, `-O1` and `-O2`, non-PIE,
with `-g`. The function set is what that build's DWARF names in the source's
own compile unit.

**Capture.** `r2s` is shown only the `strip --strip-all` copy. One streaming
process per binary answers `s <low_pc>; pddj` for every function, with stderr
merged so an `r2s:` message lands inside the markers of the statement that
printed it. A crash or a per-function deadline costs that one function (its
record is `no-record` with the ending and the last lines printed) and the
batch restarts at the next address (`r2s_batch.py`, shared with the DecBench
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
its function through one register-level thunk (`rt/call_x86_64.S`) with the
same registers, AL and stack words, so a rendering is judged against the
machine ABI rather than the prototype it declares. Each child records how it
ended, its return registers, the arena, the program's writable segments, and
fd 1 and fd 2.

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
`<source>::<compiler>-<opt>::<function>`:

| status | graded by | meaning |
|---|---|---|
| `equal` | engine | every surviving vector agreed |
| `residual-trap` | engine | agreed wherever it ran; some vector reached a counted residual |
| `differs` | engine | a vector returned, wrote, printed or ended differently |
| `uninit` | engine | the rendering read a value nothing wrote |
| `ub` | engine | UBSan reported, or `-O0` and `-O2` disagree |
| `compile-error` | engine | a build or load failed; the diagnostic is kept |
| `refused` | engine | r2s refused the function, with its reason |
| `no-record` | harness | r2s printed no usable `pddj`, with the cause |
| `unsupported` | harness | the thunk cannot call the signature (aggregate by value, variadic definition, a compiler clone) |
| `untested` | harness | no vector survived the original |
| `harness-error` | harness | the gate itself failed |

Each record carries the first vector that shows its status (inputs, the field,
the first differing address and bytes), the vector counts, the proof counters
from `pddj`, and whether the rendering also compiles under
`-std=c11 -Wall -Wextra -Werror -O2` (`strict`, evidence only).

The self-tests come first
-------------------------

`selftest.py` grades hand-written renderings of `selftest/fixture.c` whose
verdicts are known: source-equivalent identities must be `equal`; a flipped
operator, an off-by-one, swapped stack arguments and a 32-bit parameter read
as 64 bits must be `differs`; an uninitialised read `uninit`; a signed
overflow `ub`; a write to the wrong global and a wrong byte through a pointer
`differs` (memory, arena); swapped printf arguments `differs` (stdout); a
reached residual `residual-trap`; an identifier missing from the link map
`compile-error`. Every gate run runs them first and grades nothing (exit 2)
if one misses. There is no flag to skip them.

The ratchet
-----------

`tests/equiv/baseline.json` holds, per key, a status and -- for every record
that is not `equal` -- the recorded cause. With `--baseline`:

- a function the baseline holds `equal` must stay `equal`;
- a `differs`, `uninit` or `ub` the baseline does not already record for that
  function blocks;
- a function the baseline knows, inside the run's selection, must still be
  graded;
- a non-`equal` baseline record without a cause is itself a failure.

The baseline is written only with `--write-baseline PATH`, which keeps any
cause already recorded for an unchanged status and leaves the others `null`
for a person to fill in after reading the records. No baseline is checked in
yet: the gate needs `pddj` (plan P0), and the first blessing is the
integrator's.

Limits, stated
--------------

- x86-64 ELF only; there is no emulator here, so the arm64 fixtures get the
  static tiers only.
- Non-PIE only: a rendering may spell image addresses as integers, which are
  run-time addresses only when the link address is the load address.
- A parameter's pointee is built from its DWARF type: bytes, a NUL-terminated
  string, linked structures (depth up to four), a NULL-terminated pointer
  table, or a function of the pointee's own type. A length that walks off what
  was built is outside the domain and dropped, never a false `differs`.
- Aggregates passed or returned by value, `long double`, and variadic
  definitions are `unsupported`, with the reason.
- Equal on the vectors is evidence, not proof. The vector counts are in every
  record so a thinly tested `equal` stays visible.
