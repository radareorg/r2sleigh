Manual review at 93934abc (the "before" for CP1 onwards)
========================================================

DecBench is skipped on this machine: its PyPI dependencies cannot be installed.
Quality is judged by reading `pdd` against the source, and the equivalence
gate stays the mechanical oracle.

Fixture: `tests/gold/review.c`, built with gcc 13.3.0 at `-O0 -g` and `-O2 -g`.
r2s is shown only the `strip --strip-all` twin, and each function is addressed
by the unstripped build's `nm`. Command, per function:

    r2s -q -c 's 0x<addr>; pdd' rv_<O>_s

The renderings are kept in the session scratchpad (`eyeball/before_O0`,
`eyeball/before_O2`).

Classes: **WRONG** = silent wrong C; **UB** = the rendering has undefined
behaviour; **REF** = refused or residual; **TYPE** = wrong width, class or
pointee; **SHAPE** = control structure unlike the source; **NOISE** = names
and temporaries.

| # | Function | Opt | Class | Evidence | Owner |
|---|---|---|---|---|---|
| 1 | mul_div | O0 | WRONG | the second `cqo` reassigns the temporary that holds `a` (`tmp_11f80_2 = (uint64_t)(tmp_3d800_2 >> 64)`), and the remainder then divides the sign word | P1 ValueView (p1-identity) |
| 2 | classify | O2 | WRONG | the CSWTCH `int[8]` table becomes `(uint64_t)"\n"`, so the table read goes through a string literal | P8 ObjectMap, per-use provenance |
| 3 | main | O2 | WRONG | `__printf_chk(2, "%d %s\n")` drops `r` and `buf` | P7 variadic contract and format role |
| 4 | main | O2 | WRONG | `fcn_15e0(0x1370, argc, 7)`: dispatch gets a third argument, a leftover RDX from `find`, because the refused callee has no signature | P7 one sealed signature |
| 5 | rotl | O0, O2 | UB | `x >> (uint8_t)(32 - n)` is UB when n = 0; the machine's `rol` is total | P10 Rotate rule (decision 7 idiom) |
| 6 | sext | O2 | UB, TYPE | reads `RAX_0`, which nothing wrote (an INSERT into the entry value); returns 32 bits where the source result is 16 | P1.7 Unspecified leaf after PE; PE result width |
| 7 | dispatch | O2 | REF | refused: `RenderedValueRequired` (an indirect tail call `jmp rax`) | P7 tail-transfer class in r2ssa |
| 8 | dispatch | O0 | REF, WRONG | an indirect call with 4 arguments (`fn` and a duplicate passed too); the return is a residual | P7 indirect calls, `Code{sig}` |
| 9 | classify | O0 | REF | refused: `RenderedValueRequired` (a switch through a spilled index) | P4 memory, P5 dispatch |
| 10 | avg | O2 | REF, TYPE | the double return is a residual; the `addsd` accumulation vanishes; the parameter is `int64_t*` for `const double*` | P7 float result class; P9 pointee |
| 11 | main | O2 | REF | the canary: FS read as a residual and the check spelled out | p1-reads SystemReserved; P4 SSP elision |
| 12 | main | O2 | TYPE, NOISE | frame objects are split: `struct node a,b,c` become `stack_m200[8]`, `stack_m192`…; `buf[16]` becomes `stack_m72[24]` | P4 frame partition |
| 13 | main, fill, find | O2 | TYPE | globals are raw addresses: `*(uint64_t*)0x4018` (g_msg), `0x4040` (g_table), `*(uint32_t*)0x4010` (g_counter); `add` is passed as `0x1370` | P8 ObjectMap, code-pointer naming |
| 14 | fill | O2 | NOISE, SHAPE | the SSE loop is `__uint128_t` lane soup; the source is a scalar affine loop | PE lanes; lane-induction recovery (new, see below) |
| 15 | fill | O2 | TYPE | a void function returns RAX (the end pointer) | P7 result proof (closed world) |
| 16 | mul_div | O0, O2 | NOISE | the `cqo; idiv` pair is spelled as 14 `__int128` temporaries; `a*8-a` is not folded to `a*7` | P10 r2rewrite: sext-dividend division idiom with ValueView proof; strength-reduction inverse |
| 17 | add, bit_count, sum_array, list_len, find, fact | O2 | TYPE | parameters take register width (`uint64_t RDI_0` for `int`); results are uint64 where the source is 32 | PE `cover(demanded)`, written-lane result width |
| 18 | list_len | O2 | TYPE, NOISE | `struct sla_struct_28d371d39d586e37**`: a hash name, and `n->next` is lost | P9 inferred aggregates |
| 19 | sum_array, find | O2 | TYPE | `uint64_t RDI_0` is indexed as `uint32_t*` but not typed as a pointer | P9 pointer typing |
| 20 | find | O2 | SHAPE | `goto L1` where the source has `break` and `return -1` | P10 return duplication |
| 21 | sum_array, list_len, bit_count, fact | O2 | SHAPE | `if (c) for(;;){…; if(!c) break;}` where the source has `while`/`for` | P10 loop un-rotation (ForLoopCertificate) |
| 22 | all | O2 | NOISE | `tmp_70400_1`, `tmp_lane_14a0_0_1_1`, `RDI_0_2` | P11 names, P4 one binding per identity |
| 23 | copy_name | O2 | TYPE | `uint64_t strlen(const int8_t*)` where libc says `size_t strlen(const char*)` | P7/P3 exact prototypes and typedef names |

New item found by this review, not in the plan: **lane-induction recovery**.
gcc -O2 vectorises `fill`'s affine loop. The scalar source is what a recompile
turns back into the same vector code. Recovering it requires proving that each
lane is an affine induction variable (lane k starts at base+k and steps by the
lane count). That is value-domain work, so it belongs to P5 or P10. Its place
in the waves is to be decided at CP2.
