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
| `frame_pointer_locals_clang_O0g` | `src/frame_pointer_locals.c` | Clang 18.1.3 `-O0 -g`: locals stated against `DW_OP_reg6` in a function that spills no parameter, so only the prologue says where the frame pointer points |

`src/` holds sources the equivalence gate must not build as programs of their
own: a multi-unit program, and fixtures that exist for their debug information
rather than for their behaviour. Each binary is built with
`-fdebug-prefix-map=$PWD=.` so its debug information names no machine's paths.

`tests/coverage/pinned/` carries the whole-binary coverage cells, which are the
same idea for a different question: those are gated as a population, these are
named by individual tests.
