# r2s hand audit (2026-11-09, master 14d384c3b)

Eight auditors read r2s output by hand next to the truth: C source, DWARF, radare2 6.2.5, Ghidra and kuna. A skeptic reran every wrong-C, wrong-type, wrong-fact and refusal finding, and the top ux and missing ones. The rank stage reran the top candidates again. Scripts only listed candidates and counted populations. Every finding below was read in real output. The new rows are numbered from D150, since D78 to D149 are held by open branches; [ROADMAP.md](../../ROADMAP.md) cites a finding as `hand audit 3.1`.

The binary under audit is a release build of master 14d384c3b with the `sleigh` feature, on an Apple M5. The repros use these names:
- `R`: that build, called as `$R -q -c 'aa; pdd @ <addr>' <binary>`.
- `B`: `../radare2/test/bins`.
- `A`: the audit scratch tree (`audit-2026-11-09`). It holds the probe sources, the stripped copies and every dump cited here. The tree is not in the repository: a repro naming it rebuilds the probe from its description.

## 1. Summary

r2s is stable. 27,150 functions over 11 binaries gave 0 crashes and 0 timeouts. 20 fuzzed files gave 0 crashes and 0 hangs. Most C that renders computes what the source computes.

The losses sit in a few owners:
1. A switch dispatch block refuses the whole function. This one cause is about 64% of the refusals outside bash.
2. r2abi is missing library prototypes or degrades them. This hits 426 of 2,668 rendered DecBench functions and 149 of 238 unrendered calls in `ls`.
3. C++ catch pads are dropped from the C with no residual. This is the one silent wrong-C class found at scale.
4. `aa` makes a later `pdd` up to 120 times slower, with identical output.
5. Result width and presence are often wrong. 81% of source-void functions return a value, and 149 functions carry a residual upper half.
6. Frame boundaries that the ABI states are read as residuals. The cases are Win64 home space, the gcc canary load, callee-saved restores through `leave`, and AArch64 d8 to d15.

The ROADMAP order puts four of these behind work that does not unblock them. Section 6 names the moves.

## 2. What was read

| Surface | Auditor | Read by hand | Swept and counted |
|---|---|---|---|
| x86-64 against C source | a-src-x64 | About 100 functions: 22 everyday (clang -O0, -O2), 17 probes, 25 zlib (gcc 13.3 -O2), 26 bzip2 (gcc -O0), 2 loop fixtures | `ls` 273, zlib `example` 143, bzip2 -O0 114 |
| AArch64 against C source | a-src-a64 | About 115 functions: LSE atomics, zig floats, noreturn guards, corpus objects at -O1/-O2, 22 ls-toybox functions against toybox `lib/` | `pddj` over all 1,148 ls-toybox functions |
| Against other decompilers | a-vs-decompilers | 25 DecBench rows, each rerun on master | 2,668 rendered non-bash functions |
| Types against DWARF | a-types | 22 functions in 4 builds, 6 float functions in 2 builds, 108 bzip2 -O0 and 120 gzip -O2 signatures, 15 `rv` functions | 586 `afv` slots |
| First-session user | a-user | `ls`, `bomb`, `pigz`, `pumasim`, zlib: the first radare2 commands | 296 ELF files |
| Discovery and listing | a-analysis | `afl`, `iz`, `is`, `iS` and switch tables against radare2 on 10 binaries | `.pdata` on 4 PE files |
| Refusals and cost | a-refusals-perf | Refusal families read; `time -l` on large functions | 27,150 functions, 20 fuzz files |
| Skeptic | skeptic | Every finding rerun; new MSVC x64 and C++ probes | `pddj` dumps of hello_gs and testapp-msvc64 |

## 3. Findings by root cause

### 3.1 A switch dispatch block refuses the whole function (refusal, new)

Repro: `$R -q -c 'aa; pdd @ 0x100000480' $A/a-src-x64/sw3_O2_s`.

r2s prints `refused ... 1 unaccounted (live-value-producer at 0x100000480:op:9)`. The source is `switch (op) { case 1: ... case 5: }`, and `pdf` solves the table. The cases-0-to-4 twin renders correctly.

Op 9 is `SF = EDI s< 0` from `dec edi`. The `cmp edi, 4` that follows overwrites it, so the unaccounted producer is a dead flag write in the block that ends at the table jump. The case base is a trigger, not the cause. Two more cases show this:
- diff `0xed00` is a base-0 switch and refuses on the carry flag of `add rax, rdx`.
- ls-toybox `0x49bb4` refuses on `tmpCY` of `cmp w9, 9`.

Merged findings: SX1, A5, AVD-1. Owner: r2ssa obligation accounting. RF and audit W43 name the class but not this cause.

Impact:
- 10 of 12 refusals across `ls`, zlib and bzip2.
- 18 of 28 refused non-bash DecBench functions.
- 6 of 12 ls-toybox jump-table functions.
- 104 of 498 refusals over 27,150 functions are effect ops at a dispatch or a call push.

### 3.2 Library prototypes missing or degraded (missing, wrong-type, wrong-C)

1. **glibc linked names have no row.** The names are `__errno_location`, `__assert_fail`, `fputs_unlocked`, `__overflow`, `putc_unlocked`, `rawmemchr`, `__ctype_b_loc`, `fwrite_unlocked`, `wcwidth` and `closedir`. r2abi keys radare2's unprefixed `assert_fail` and `errno_location`, which no program links.
   - In `pigz`, every `__assert_fail` call is a gap and the C runs on past it.
   - Counts: DecBench 426 functions (`__errno_location` 239 sites, `__assert_fail` 148); `ls` 96 of 238 gaps from 6 imports; `pigz` 99 asserts.
   - Merged: SX3, AVD-5, and audit W24 for the noreturn half.
2. **`FILE` degrades the whole prototype.** Any prototype naming `FILE` becomes all `uint64_t`, for example `uint64_t fopen(uint64_t, uint64_t)`. This hits every stdio call. (SX2, U7.)
3. **`error` has no ellipsis.** `error(2, 0, "%s")` drops the `dcgettext` result, which is wrong C. 84 sites in 52 functions. Repro: DecBench diff3 `0x4360`. (AVD-4.)
4. **A shared object with no `PT_INTERP` has `Platform::Unknown`.** libz.so's 22 `__stack_chk_fail` calls are undeclared. r2s does not read `DT_NEEDED libc.so.6` as evidence. (AVD-14.)
5. **bionic rows are thin.** 38 rows exist. `__errno`, `__strchr_chk`, `__open_2`, `getline`, `_exit` and `dup2` are missing. 703 residuals in ls-toybox. (A8.)
6. **No libstdc++ rows.** 0pack has 7,621 sites in 1,153 functions; pumasim has 4,942 in 357. (M4.)
7. **KERNEL32 imports are undeclared.** 98 sites in hello_gs and 96 in testapp.

Owner: r2abi, with r2engine for item 4. D71 A1 covers items 1 to 3, and P7 names the W24 keys. Items 4 to 7 are new.

### 3.3 C++ landing pads dropped with no residual (wrong-C, new)

Repro: `$R -q -c 'aa; pdd @ 0x100000690' $A/skeptic/cxx/shapes_x64_s`.

r2s prints `rax_1 = fcn_100000630(arg0, arg1) | residual(1) << 32; return rax_1;`. The source is `try { return checked_div(a,b); } catch (const std::exception &e) { puts(e.what()); return -1; }`.
- The catch pad at `0x69b` to `0x6bf` belongs to no function.
- The C says `safe_div` never returns -1, and no mark shows the exceptional edge.
- demangle-test-cpp `main` loses its cleanup pad the same way: the FDE covers 143 bytes, `afl` lists 117.

Owners:
- r2image: the LSDA call sites. Item I already plans them.
- r2engine: attach each pad to its function.
- r2dec: a mark on each call until the pads are recovered.

The ROADMAP Order puts exception recovery "after the program". The silent omission is new and breaks AGENTS rule 8.

Impact: 2,712 of 8,430 FDEs in 0pack carry an LSDA. Every C++ `try` and every destructor cleanup is affected.

### 3.4 `aa` makes a later `pdd` up to 120 times slower (perf, new)

Rerun by the rank stage, one process at a time, on pumasim:

| Command | Instructions | Peak footprint | Output md5 |
|---|---|---|---|
| `pdd @ 0x1fad00` | 1.23 G | 66 MB | 700a4a38 |
| `aa` | 64.0 G | 198 MB | (none) |
| `aa; pdd @ 0x1fad00` | 148.9 G | 434 MB | 700a4a38 |

After `aa`, the same `pdd` costs 85 G more and prints the same bytes. 0pack `0x475520` goes from 1.0 G to 104.8 G, and bash `0x2e630` from 0.7 G to 19.4 G.

Owner: r2engine (the closed world and caller evidence) and SM. This breaks D23.

### 3.5 Result width and presence (wrong-type)

1. **Source-void functions are declared with a value.** 541 of 670 in DecBench (81%), 49 of 59 in bzip2 -O0, 25 of 34 in gzip -O2. Two examples:
   - `to_upper` returns the last char it loaded.
   - toybox `dlist_add_nomalloc` returns `*arg0 + 8`.

   This is D72.
2. **A 32-bit callee result gets a residual upper half.** For example `return strcmp(a,b) | residual(2) << 32` (DecBench diff `0x9e70`). Counts: DecBench 149 functions, `ls` 14, zlib 9. In gzclose, one tail call returns whole and the other gets the residual. Rows: P7's "callee's logical width on the call fact", and D73.
3. **`int` returns are declared `uint64_t`.**
   - bzip2 -O0: 15 of 17. gzip -O2: 22 of 40. ls-toybox: 698 of 814 signatures.
   - branchy.c: 16 of 33 on AArch64 against 5 of 33 on x86-64.
   - Rows: D74 and T (W49).
4. **Vectorized reductions make every return residual, constant paths included.** Examples are `sum_arr`, `value_count_bits` and `spread`. T (W47) covers part; the constant-path collapse is new.

### 3.6 Parameter recovery (wrong-fact, wrong-type, wrong-C)

1. **An unread first parameter drops every later one.** libz `zcalloc` renders `fcn_e160(void)` and reads RSI and RDX as residuals. 203 DecBench functions. P7 (W12).
2. **A parameter handed on untouched is lost.** AArch64 `exit` renders `_exit();`, and `_exit` is declared `void _exit(void)`. The machine code is `mov w0, w19; bl _exit`, so the exit status is dropped. This is wrong C (switch-hello-world). P7 (W7).
3. **Float parameters are lost without DWARF.** 0 of 8 builds recover them. `fdiv(float, float)` renders as `float fcn(void)`. Stripped `store(double, double*)` renders as `fcn(uint64_t*)`. P7 (W11).
4. **Signed parameters are never typed signed.** 0 of 128 parameters and 0 of 286 `int` locals. `sdiv7(int)` prints `uint32_t fcn(uint32_t)` while its body casts `(int32_t)arg0`. New: T's signedness map does not reach the declaration.
5. **Pointer parameters are typed as integers.** 63 of 114 right in bzip2 -O0 and 29 of 58 in gzip -O2. AArch64 post-index loads lose 7 of 15 where x86-64 loses 0. D71 A2, D74.
6. **`afv` and `pdd` disagree on names.** `afv` says `arg1 @ edi` where `pdd` says `arg0`. T (W46).

### 3.7 Calls with no stated target arity (refusal)

1. Indirect calls through struct fields are residual. zlib `inflateEnd` loses both of its `ZFREE` calls. 145 DecBench functions.
2. C++ virtual calls are residual. 0pack: 959 functions, 3,667 sites. pumasim: 2,688 functions, 8,277 sites.
3. A tail jump to a function start becomes `TailTransferNotRendered`, and the C then falls into the error return (zlib `inflateReset`). There are 376 sites. 205 follow a residual call and 62 follow `error`, so most of them close with 3.2.

Rows: P7 and D37. RF names the tail gap. The C++ scale and the tail cause are new.

### 3.8 Frame boundaries the ABI states (refusal)

1. **Win64 home-space stores are residuals.** hello_gs: 71 of 246 functions. testapp: 51 of 174. `MICROSOFT_X64` states no home area. New.
2. **MSVC variadics are declared with 4 fixed parameters.** UCRT's inline printf homes 4 registers, so it gets 4 parameters, and hello_gs `main`'s only call is refused. radare2 prints `printf("Hello %s\n", fcn.140001000())`. New.
3. **`/GS` cookie reads are never elided.** 21 functions read the cookie and none is elided. New.
4. **The gcc canary entry load stays a residual.** Its check is elided. bzip2 -O0: 16 of 27 protected functions. bash: 59. 0pack: 218. New. W48 covers only the trampoline variant.
5. **A `mov rbx, [rbp-8]; leave` restore reads as an entry residual.** bzip2 `mapSuffix`. New.
6. **AArch64 `stp d9, d8` saves are residuals.** 5 of 5 toybox functions that save them. New.

Owners: r2ssa frame boundary, r2abi rows for items 1 to 3, and r2image for the cookie. P4 is at step 9.

### 3.9 Container facts and first-session surface

1. **PE `.pdata` starts are not seeds.** `afl` misses 140 of 346 functions in hello_gs (radare2 misses 82), 136 of 150 in cpp_sample and 1,332 of 1,889 in notputty. New.
2. **`.gnu_debugdata` is not read.** ls-toybox lists 363 symbols against radare2's 1,192. New.
3. **`s main` fails on every stripped glibc ELF tried.** radare2 seeks to `0x4070`. `pdd @ entry0` refuses `__libc_start_main` because its 7th, stack-placed argument is not placed. 9 of 9 x86-64 binaries. Rows: the P7 conditional and D74.
4. **`aa` turns `ls` `main` from 2,233 lines into a refusal.** pumasim `0x4baf30` too. Rare (bash: 1 of 1,568). RF.
5. **A mid-function address invents a function.** `pdd @ 0x415b` on `ls` prints `fcn_415b`. W45.
6. **The `iz` floor is low.** `ls` 123 against 429, ls-toybox 189 against 3,344, 0pack 6,624 against 17,874. W32.
7. **String addresses print as integers.** 388 DecBench functions pass one and 178 assign, select or return one. P8 (M17); the non-argument cases are new.
8. **`elf_stripped` does not open.** radare2 opens it. New.

### 3.10 Readability (ux)

1. Literal overshift guards: 480 of 2,668 DecBench functions, and 307 of 814 toybox functions with 1,312 guards. D75 found-not-built.
2. Empty then-arms: 394 of 814 toybox functions and 1,274 DecBench sites. SD.
3. Magic-multiply division is not recovered (the `% 65521` in adler32). New, r2rewrite.
4. `sborrow(x, 0)` is left unfolded in 45 toybox functions. New. Not rerun.
5. SIMD lane masks, 256-bit z roots and frame byte arrays. B, P5, P4.
6. A 32-bit `idiv` becomes 5 statements. New; downgraded from wrong-C.

### 3.11 Lower impact, confirmed

- x86-64 `.o` jump tables are unrelocated (I).
- An AArch64 ET_REL `CALL26` truncates `main` to 44 of 712 bytes (I, FS).
- AArch64 x1 is open by policy where x86-64 gives `__uint128_t` for the same source (P7).
- An LL/SC store is a residual (LS M2).
- A static printf body gets no format parameter, and `iz` drops the ESC byte (P7, P8).
- `main` is renamed `fcn_640` when its body ignores `argv` (P7).
- Varargs wrappers are residual (P7 W14).
- `UnsupportedInstruction` is printed over ordinary code with no reason: testapp 209 sites, hello_gs 212, pumasim 256. New, r2ssa.

## 4. Checked and right

- 27,150 functions with 0 crashes and 0 timeouts. 20 fuzz files with 0 crashes; the longest `pdd` took 1.06 s.
- `aa; pdd` and cold `pdd` give identical bytes on pumasim `0x1fad00`.
- `afl` matches radare2 on dectest64 (20/20) and pigz (222/222).
- `afv` slots match DWARF on 585 of 586.
- These clang -O2 functions compute the source's result with correct loop exits: `count_char`, `hash_str`, `parse_int`, `copy_until`, `bsearch_int`, `list_sum`, `list_find`.
- `char` at -O0 compares through `int8_t`.
- Base-0 jump tables render as `switch` with correct arms. `day_name`'s relative lookup table is right.
- Noreturn is recognized for `exit` and outlined cold paths. The Darwin stack-guard check renders correctly.
- Structures laid out from accesses have the right offsets and widths: `point_dot`, `gztell64`, `mixed_touch`, `rec_index`.
- zlib `zError`, `compressBound`, `bi_windup` and `inflateStateCheck` match the source.
- `*__error()`, `__snprintf_chk` with 7 arguments, and unsigned division all render correctly.
- DWARF `deflateTune` has `int32_t` and no residual.
- The 10 LSE atomics are right (audit W17 fixed). NaN-correct `fcmp`/`csel` in 4 functions. `ccmp` chains are right. AArch64 divide-by-zero is 0. 10 compares choose signedness correctly.
- ADRP/ADR fold to absolute addresses. PAC and BTI are elided.
- These toybox `lib/` bodies match the source: `comma_iterate`, `strstart`, `strend`, `strafter`, `stridx`, `chomp`, `llist_pop`, `crc_init`, `xzalloc`, `xstrdup`.
- `ls`: 273 functions in 6.1 s at 112 MB. ls-toybox: 1,148 functions in 40 s at 155 MB.

## 5. Since the 2026-10 audit

**Fixed, seen in output:**
- PE mapping and imports (W1, M1).
- Floor-invented arguments (W7) and `call [GOT]` (W8).
- ObjC prototypes (W10), the SysV save area (W14) and `ud2` (W23).
- AArch64 specification defects (W15 to W21).
- The broken-pipe panic (W52).
- The D75 noreturn guard.

**Still open:**
- W11 float parameters.
- W12 parameter prefix.
- W24 `__` keys.
- W32 `iz` floor and M17 strings.
- W43 live-value-producer refusals, now traced to the switch dispatch block.
- W45 mid-function addresses.
- W46 `arg1`/`arg0`.
- W47 and W49 return types and widths.
- W48 canary trampoline.
- M2 LL/SC.
- W5's AArch64 half.

**New:**
- The switch dispatch cause and the silent C++ landing pads.
- The `aa` cost.
- Win64 home space, MSVC variadics and `/GS`.
- The canary entry load, `leave` restores and d8 to d15 saves.
- `.pdata` and `.gnu_debugdata`.
- bionic, libstdc++ and shared-object platform rows.
- Signed parameters never typed signed.
- The dropped `_exit` status.
- The `UnsupportedInstruction` mislabel.
- `elf_stripped`.

## 6. What to address first

1. **D150 (new): a dead flag producer in a dispatch block is accounted.**
   - Owner: r2ssa, with RF.
   - Repro: sw3 `0x100000480`, diff `0xed00`, toybox `0x49bb4`.
   - Gate: an engine test per case; the refusal count on `ls`, zlib, bzip2 and DecBench falls; certification and equivalence unchanged.
   - Timing: immediate.
   - Impact: about 64% of non-bash refusals.
2. **D71 A1 to the front of the order, plus D151 (new): platform from `DT_NEEDED`.**
   - Owner: r2abi, plus r2engine `platform()`.
   - Rows: the glibc linked names, `__assert_fail` as noreturn, `FILE`/`DIR` handles, the `error` ellipsis, `__isoc99_*scanf`.
   - Gate: `library_named_type` falls; the undeclared-import residual count falls; pigz asserts end control.
   - Timing: immediate.
   - Impact: 426 DecBench functions and 149 of 238 `ls` gaps.
3. **D152 (new): a call with a landing pad carries a residual until pads are recovered.**
   - Owner: r2image LSDA, r2engine, r2dec.
   - Gate: an engine test where a catch changes the result; no LSDA function renders without the mark.
   - Timing: the mark is immediate; recovery is deferred.
4. **D153 (new): `pdd` after `aa` costs only what the function needs.**
   - Owner: r2engine and SM.
   - Repro: pumasim `0x1fad00`.
   - Gate: `aa; pdd` stays within 2 times (`aa` + cold `pdd`) on pumasim, 0pack and bash, with byte-identical output.
   - Timing: next, after measuring where the 85 G goes.
5. **P7 callee result width before D72.**
   - Owner: r2ssa and r2types.
   - Gate: the `residual_u64(n) << 32` count falls from 149 to near 0; equivalence.
   - Timing: next.
6. **D154 (new): Win64 frame boundary.**
   - Owners: r2abi (home-area row and Windows guard row), r2image (`SecurityCookie`), r2ssa (homed registers are not arity).
   - Gate: hello_gs `main` renders printf with 2 arguments; home-space residuals go from 71 to 0; add a Win64 equivalence target.
   - Timing: next.
7. **D155 (new): ELF frame-boundary forms.**
   - Owner: r2ssa `stack_protector` and frame boundary.
   - Cases: the canary entry load, the `leave` restore, d8 to d15 saves.
   - Gate: engine tests; the FS_OFFSET residual count falls.
   - Timing: next, as a P4 slice.
8. **I extension: `.pdata` and `.gnu_debugdata`, plus `declared::Placement` for x86-64 stack arguments.**
   - Owner: r2image and r2engine.
   - Gate: `diff_r2.py` on `afl` and `is`; entry0 renders `__libc_start_main`; `s main` resolves.
   - Timing: next.
9. **P7 W12, W11 and handed-on floors before "one object per web".**
   - Gate: an arity census against DWARF; `_exit` is `AtLeast(1)`.
   - Timing: next.
10. **D75's literal overshift guard to the front of the order.**
    - Owner: r2dec lowering.
    - Gate: the census is read; the guard count (2,100 of 2,708) goes to 0; equivalence.
    - Timing: immediate.

**Where the ROADMAP order is wrong:**
- D71 A1 is data rows waiting at step 7 behind items that do not unblock it.
- Silent landing pads break rule 8, so the mark cannot wait until "after the program".
- RF should do D150 before its other rows.
- The `aa` cost breaks D23 on the first command users type. Its measurement belongs beside the path now.
- P4's boundary slices are most of the PE and gcc -O0 residuals, so they should be pulled forward.
- The literal guard is 78% of the `?:` in the mined set and hides no fact. It is a measured fix, not "last".

## 7. Refuted or corrected

- SX1: base 0 refuses too. The cause is the dead flag write.
- A5: the producer is `tmpCY` of `cmp`, not `mov w0`.
- SX13: the guard is r2dec's own UB guard. Now ux.
- A1: the proof line does state that x1 is open.
- A18: radare2 prints the same `ADD_32 275`.
- SX6: true only for `array_max`.
- SX11: `0xf49a` is below both tools' string floor.
- T2: the return is a residual, not wrong C.
- "double args correct": only with DWARF present.
- SX7: the addresses were the O2 binary's. The finding holds at `0x1000008f0` and `0x1000009f0`.
