# The corpus sources

Four programs whose functions are chosen for the shapes a decompiler gets
wrong:

- `hashes.c` -- fifteen byte-loop hashes, each keeping its accumulator in a
  register at `-O1`/`-O2`: the loop-carried recurrence a renderer has to bind;
- `shapes.c` -- structs, arrays of structs, recursion, variadic calls, signed
  division, multi-word returns, pointers to pointers, function pointers;
- `values.c` -- sign and zero extension, arithmetic shifts, narrow wrap,
  carries, high multiplies, byte order, overflow flags;
- `branchy.c` -- nested guards, affine and masked predicates, bounded fetches,
  constant branches.

They are graded by the equivalence gate, `tests/equiv`, together with
`tests/gold/*.c`: built with GCC and Clang at `-O0`, `-O1` and `-O2`, rendered
by `r2s` from the stripped build, and run beside the original inside its own
image. See `tests/equiv/README.md`.

That gate replaces the corpus matrix that lived here (`run_matrix.sh`,
`run_shapes.sh`, `verify_rendering.py`, the three `*_oracle.c` programs and
the raw baselines). The matrix drove radare2 with the r2sleigh plugin, which is
deleted, and re-hosted each rendering outside its program by rewriting its
text. What it did well carries over: every function is a record even when it
fails (one record per function), the strict compile tier is kept as evidence
(`-std=c11 -Wall -Wextra -Werror`), and the vectors start at the boundary
lengths it used (`{0,1,2,3,4,7,8,15,16,17,31,32,61}`).

## Tools that stay

- `lldb_r2s.sh` stops `r2s` at one source line and dumps the frame;
  `lldb_mcp.sh` serves an interactive lldb session on `r2s` over MCP
  (`.mcp.json` registers it).
- `growth_fit.py` and `work_fit.py` fit each render stage's time and counted
  work against the size of the body, from a timing log:
  `R2SLEIGH_TIMING=1 tests/coverage/sweep_binary.sh <binary> > log`.
- `cast_census.py` counts casts and narrowing reads in rendered C.
- `arg_census.py` and `structure_census.py` measure the Rust tree itself
  (parameter counts, identifier lengths, loop nesting).
