Fixtures the repository ships as bytes
======================================

Built once and committed, so the same test means the same program on every
machine and the compiler on the machine running the test cannot move the
answer.

| Binary | Source | Exercises |
|---|---|---|
| `code_pointer_table_O0` | `tests/gold/code_pointer_table.c` | a jump table the engine has to derive for itself |
| `manual_limits_O0` | `tests/gold/manual_limits.c` | walk and preparation limits, unoptimized |
| `manual_limits_O2` | `tests/gold/manual_limits.c` | the same source through the optimizer |
| `hashes_gcc_x64_O2_stripped` | `tests/corpus/hashes.c` | discovery with no symbol table, which has to reach `main` through `__libc_start_main` |
| `rv_O0g` | `tests/gold/review.c` | the review fixture: x86-64 PIE, GCC 13.3.0 `-O0 -g`; `classify`'s jump table is read through a spilled index nothing bounds |
| `rv_O0g_stripped` | `rv_O0g` after `strip --strip-all` | the same program with no debug information: every declared fact has to come from the DWARF, and none may appear without it |
| `two_units_O0g` | `src/two_units_a.c`, `src/two_units_b.c` | GCC 13.3.0 `-O0 -g`: two units each defining a `static helper` of its own, so a declaration found by name would be the other unit's |
| `syscalls_static_O2` | `src/syscalls.c` | GCC 13.3.0 `-O2 -nostdlib -static`, stripped: system calls whose number is a constant, the same constant on two paths, folded in the body, and a parameter; and `0f 05` as an immediate |
| `frame_pointer_locals_clang_O0g` | `src/frame_pointer_locals.c` | Clang 18.1.3 `-O0 -g`: locals stated against `DW_OP_reg6` in a function that spills no parameter, so only the prologue says where the frame pointer points |
| `rv_O2` | `tests/gold/review.c` | the same source, x86-64 PIE, GCC 13.3.0 `-O2`, no debug information; `sext` reads the entry value of `rax` it only partly overwrites, and `main` reads `avg`'s float result after a call nothing claims it from |
| `shapes_zig_riscv64_O0` | `tests/corpus/shapes.c` | RISC-V 64 (RV64GC, LP64D), `zig cc` 0.17.0 `-target riscv64-linux-gnu -O0 -g0 -fno-pie -no-pie -fno-sanitize=all`: the call-heavy corpus on the one architecture the census otherwise never sees |
| `float_calls_zig_x86_64_O2g`, `float_calls_zig_aarch64_O2g` | `src/float_calls.c` | `zig cc` 0.17.0 `-O2 -g`: a declared `double` parameter, written as a constant before one call and passed through from the caller's own formal to another; on AArch64 the cspec's float slot is `q0`, wider than the `double` |
| `float_returns_zig_x86_64_O2g`, `float_returns_zig_aarch64_O2g` | `src/float_returns.c` | `zig cc` 0.17.0 `-O2 -g`: declared `double` results, one a vectorised sum whose result register is written by lane inserts and merged as its root, one a literal `0.0` |
| `float_moves_zig_x86_64_O2g`, `float_moves_zig_aarch64_O2g` | `src/float_moves.c` | `zig cc` 0.17.0 `-O2 -g`: two `double` arguments swapped by whole-register moves (`movaps`, `fmov`) before a tail call |
| `float_compares_zig_x86_64_O2g`, `float_compares_zig_aarch64_O2g` | `src/float_compares.c` | `zig cc` 0.17.0 `-O2 -g -fno-sanitize=all`: ordered comparisons of `double` in conditions and results, including `!(a < b)` and `a == b \|\| a < b`, which a NaN makes differ from their integer negations |
| `fuzzed_elf9`, `fuzzed_file12` | radare2-testbins `fuzzed/elf9`, `fuzzed/file12` (not executable, so the census skips them) | hostile headers: an `.init_array` and a `__cstring` stating sizes far past the file's end, which once hung on open and read 2 GB |

`src/` holds sources the equivalence gate must not build as programs of their
own: a multi-unit program, and fixtures that exist for their debug information
rather than for their behaviour. Each binary is built with
`-fdebug-prefix-map=$PWD=.` so its debug information names no machine's paths.

`tests/coverage/pinned/` carries the whole-binary coverage cells, which are the
same idea for a different question: those are gated as a population, these are
named by individual tests.
