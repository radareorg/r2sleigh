# r2s real-binary test sweep (2026-10-06, master 9e917428)

Corpus: coreutils ls, sort, cp, date, stat (stripped PIE); system libz 1.3 (stripped);
zlib 1.2.13 O0/O1 with DWARF; minigzip_O1; radare2 test bins (fuzzed, PE, arm64).
Reference: radare2 `aaa`, objdump, DWARF, zlib source.

## Fixed on this branch (`engine/real-binary-sweep`)

1. r2ssa `values.rs` `assume`: a guard on `eax` now also bounds `rax = ZEXT(eax)` written
   before the branch. Test `a_guard_bounds_the_zero_extension_written_before_it` fails on old code.
2. r2ssa `indirect.rs` `IndexChain::preimage`: case labels are two's complement at the
   selector width, so `getopt` cases -130/-131 label. ls main: 291 -> 376 blocks (r2: 381),
   0 unresolved dispatches.
3. r2engine `naming.rs` `cells`: each stub is the cell its own transfer lies in (gcd stride).
   libz O0/O1 wrong import names 17/16 -> 0. Test `a_stub_is_the_cell_its_own_transfer_lies_in`.

r2ssa + r2engine + r2s suites: 1080 passed, 0 failed. Full exit bar not run.

## High

- afl misses 76 functions vs r2 (ls 26, stat 21, cp 9, date 9, sort 10). Survey walk
  (`function_extents`) follows no dispatch table, so afl/afb/axt disagree with afi/pdf.
  sort 0x3f50: pdf resolves table, `axt 0x7890` returns 0. Owner r2engine (P6 not wired to survey).
- Remaining jump-table patterns: bound checked in memory then reloaded (ls 0xb993, 0x10622),
  `cmp dl; movzx` (ls 0x12978, sort 0xae51), index spilled across call (stat 0xab73, cp 0x16e03),
  loop phi (libz_sys 0xe411), SSA not built (date 0x680a, stat 0x98be). Owner r2ssa.
- `__assert_fail` not noreturn: r2abi row is `assert_fail`; lookup does not strip `__`.
  cp 0x19d5a falls into next function. `__stack_chk_fail` falls through in libz_sys (no PT_INTERP,
  no platform). Owner r2abi/r2engine.
- PLT stubs for preemptible self-exports (30 in libz) unnamed; calls render `fcn_3610(adler, buf, len, buf)`
  with invented 4th arg. `WriteKind::Preemptible` already states symbol and default. Owner r2engine.
- uncompress2 (O1): switch on `ebx` and return slot `0xc(%rsp)` merged into `stack_m188`;
  `case 1` returns 1, binary returns slot. Wrong C. Owner r2dec binding / r2ssa frame.
- deflateInit2_ (O1) ends `L4: ;` with no return. Owner r2dec.
- Hangs: `fuzzed/elf9` hangs on open (even `-c q`). `pe/65535sects.exe` pdd > 580 s.
  `fuzzed/file12` 2.1 GB, `file-rs-bf838568` 1.6 GB for iz/afl/pd.

## Medium

- main never named in stripped binaries (entry `lea rdi, main` before `__libc_start_main`).
- Function verbs at a mid-function address invent `fcn_<addr>` (pdd 0x6d34, afi 0x4e05).
- One function, five spellings: `fcn.00004da0`, `fcn.4da0`, `fcn_6d34`, `fcn.00006d34`, `<unnamed>`.
- DWARF prototype with stack args ignored (deflateInit2_ 8 params). DWARF struct types unused:
  `*(uint32_t*)(RDX_2 + 48)` for `s->wrap`.
- Slow-then-refuse: sort 0x3f50 28 s / 252 MB, inflate O1 10.7 s, ls main 8.4 s, all refused.
- iz length floor drops 323 of r2's 482 ls strings, 131 referenced by code.
- Tail-jump targets copied into caller (21 functions, ls 0xdc60 holds 0x7ed0).
- Magic-number division not recovered (`* 0x800780708697e2e7 >> 15` for `% 65521`).
- Shell: `s +4` goes to 0x4; no `$$`, `sym+4`, `s-`, hex counts, negative counts; `#` comments
  refused; `-c` stops after second failing line; stdin exits 0 on failure; bad section headers
  make file unopenable (r2 uses program headers); arm64 .so `is` empty (DT_SYMTAB unread).

## Low

- "r2s: r2s:" on wx/ax errors (commands.rs 647, 653, 654, 670, 697). `ax?` advertises `[addr]`.
- afl/afi bbs disagree (292 vs 291; afi undercounts by 1-4 in 49 functions).
- Broken pipe on `| head` panics.
- Extra arguments ignored (`i junk`, `afl 0x10`); `wx` empty prints "0 bytes".
- Decode: `66 66 2e 0f 1f 84` printed as `nop dword` (30 sites); `stosq.rep` mnemonic; `notrack` dropped.
- Refusal reason leaks `OpLowering(lowering.rs:244)`; `pdih` on refused function prints no reason.

## Clean

No panics on 608 fuzzed files and 22 corrupted ls copies. pdd deterministic. 712 census
functions exit 0. All pddj/aflj valid JSON. Grep, `;`, `@`, wx/wcr invalidation correct.
x86-32, ARM, aarch64, RISC-V, Mach-O open. 149/150 O0 prototypes match DWARF.
r2s afl 2-3x faster than r2 aaa.
