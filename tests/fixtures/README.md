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

`tests/coverage/pinned/` carries the whole-binary coverage cells, which are the
same idea for a different question: those are gated as a population, these are
named by individual tests.
