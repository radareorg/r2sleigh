# Vendored crates

The Sleigh crates this engine is built on, owned and built from this tree.
Each is a copy of its 0verflowme fork's `main` (which carries every change
below as a merged pull request), keeping only the files its own `include`
list packages; a refresh copies the fork again and re-applies the trims.
`libsla-sys`'s Ghidra, the compiler `sleigh-compiler` builds against its
headers, and every `sleigh-config` specification sit on one Ghidra commit,
master `918acd744d` (2026-10-13): the engine resyncs whenever the
specifications do (ROADMAP D33). Each pin is in the table under Upstream pins.

| Processor | Ghidra | Carried on that text (below) |
|---|---|---|
| x86 | master `918acd744d` | AF; RDRAND r32's r/m register; SHR/SHRD OF at count 1; CVTTSD2SI/CVTTSS2SI's integer indefinite; VEX VPEXTRW 0F3A 15's r/m register; PREFETCHh and MPX decoded where the `0F 18`-`0F 1F` hint NOP took them; the Go cspec's RDX (fork #2) |
| ARM | master `918acd744d` | the hidden scratch marks; `ARM.cspec`'s `<returnaddress>` (fork #1) |
| AARCH64 | master `918acd744d` | the fork's #2 to #15; #16 and #17; `AtomicBegin`/`AtomicEnd` on the LSE atomics; `fcvtzu`'s full-width scale; CSSC's W forms; the hidden scratch marks; `AARCH64_apple.cspec`'s `<returnaddress>` x30, which Ghidra master omits (fork pull request owed) |
| MIPS | master `918acd744d` | none |
| RISCV | master `918acd744d` | none; `languages/old` (the deprecated variants) not vendored |

0verflowme/sleigh-config `ghidra-918-resync` (`028f390`, no pull request yet)
holds exactly the five processors' vendored text on top of the fork's `main`.
sleigh-config #4 had ported AArch64's fixed constructors, not its files; the
rest of 918acd744d's AArch64 text (GP-6448's CSSC, 611201b673's register
extend, the sha1h rotate, GP-5816, GP-3139's `AARCH64_apple.cspec`) came with
this resync. AppleSilicon's own compiler is now Apple's variadic convention,
so the lift runs its decoder under v8A's compilers and offers Apple's as `apple` for a Mach-O to choose (`disasm::selection`, r2engine's `assemble`).

| Crate | Fork `main` | Upstream | Carried by the fork | Vendoring trims |
|---|---|---|---|---|
| `libsla` 1.2.0 | 0verflowme/libsla `e97cd24d` | mnemonikr/libsla | user-operation names and the parser-cache reset (mnemonikr/libsla#18, #19); `GhidraSleigh` reads its address spaces once, a space's name is interned, and the p-code emit reads each varnode in place and its space from that list (ROADMAP PF1; #1); the specification's instruction alignment as `Sleigh::instruction_alignment` (audit W25; #3) | the fork's `[patch]` to the other forks; the workspace's `[patch.crates-io]` stands in |
| `libsla-sys` 0.1.5 | 0verflowme/libsla-sys `0919334f` (Ghidra 0verflowme/ghidra `6763e1ec`, `r2sleigh-sleigh-context` on 11.4's `aed1cf1c`); this tree vendors Ghidra 0verflowme/ghidra `ec9a9312`, `r2sleigh-sleigh-context-12`: PF0 and W2 on master `918acd744d` | mnemonikr/libsla-sys | the same two passthroughs (mnemonikr/libsla-sys#8, #9); `getVarnodeSpace` and `getVarnodeOffset`, which read a varnode where `getAddress` allocated an `Address` (#1); Ghidra's include directory stated as `DEP_SLA_INCLUDE` (#2); Ghidra: `SleighBase` keeps the context fields `buildXrefs` found, `Sleigh` records whether a decode committed context and can mark its cached parses stale, and `clearCache` rebuilds the context only after a commit (ROADMAP PF0; #3); `cc`'s `parallel` feature (audit B1; #4); `getAlignment` passed through as `getAlignmentProxy` (audit W25; #5) | Ghidra's decompiler C++ only, copied in place of the submodule, with `metatype.cc` built since `918acd744d` (`marshal.hh` includes it); built at `opt-level = 3` in dev and release by the root `Cargo.toml`, as the spec compiler's build dependency too (audit B2) |
| `sleigh-compiler` 2.0.2 | 0verflowme/sleigh-compiler `4e380af4` | mnemonikr/sleigh-compiler | compiles against `DEP_SLA_INCLUDE`, `libsla-sys`'s Ghidra headers, since it links that `libsla` and must see the same class layouts (#1); carried here, fork pull request owed: `slgh_compile.cc` re-ported onto `918acd744d`, the commit those headers are, and `largeTemporaryWarning` gone with GP-6316, which made a temporary over 256 bytes an error | no Ghidra copy of its own: `DEP_SLA_INCLUDE` is required; built at `opt-level = 3` as a build dependency (audit B2) |
| `sleigh-config` 1.0.1 | 0verflowme/sleigh-config `cd2c2111` | mnemonikr/sleigh-config | each processor's files by name with its `.ldefs` and `.dwarf` (#1); Ghidra's Go compiler specifications corrected to Go's `abi-internal.md` (ROADMAP LP1; #2); AArch64 `addv` zeroes the vector above its byte result (#3); resynced from Ghidra master (918acd744d): `ldpsw`, `ldapr Xt`, `ldar Wt`, `stlrb`/`stlrh`, scalar `fmadd`/`fmsub` and the reductions' zero-fill (#4), `eor3`/`bcax`/`rax1`/`xar` (GP-7313; #10); W-form sign-extending loads (#5, the shape of Ghidra #6471 and #6447); W/H/B atomics, CAS, `ldapr`, `ldlar` and `swp` write the whole register and min/max compare at the access size (#6, Ghidra #9893); `mrs`/`msr nzcv` and `crc32`'s polynomial (#7, Ghidra #9895, #9896); `stlxp` at +8 (#8, Ghidra #9894); scalar FP rounding (#9, Ghidra #9897); specifications and tables `static` (audit B3; #11); one `sla-<stem>` feature per `.slaspec` beside the processor features (audit B4; #12); AArch64 `casp` X form compares and stores Xs and Xt at `[Xn]` in either byte order (#13, Ghidra #9900); every AArch64 load-exclusive marks the monitor with `SetExclusiveMonitors` (audit M2; #14); every acquire and release stated on the side it orders (`LoadAcquire`, `LoadAcquirePC`, `StoreRelease`), where Ghidra marked only the LSE forms, with LDLAR's LORegion names and on the wrong side (#15) | only the x86, ARM, AARCH64, MIPS and RISCV processors (RISCV without `languages/old`), and only their `sla-<stem>` features (no processor feature), so the engine's 8 languages are the ones compiled (`ARM8_be` added for BE32 ARM, audit W26) |

Carried in this tree, not yet in the fork (sleigh-config #16 and #17): AArch64's unsigned scalar
`fcvt{a,m,n,p,z}u` into W and X and the scalar fixed-point `fcvtzu` into H, S
and D saturate as FPToFixed states (NaN and below 0 give 0, at or above 2^N all
ones), where #9's text wrapped (`fp_to_unsigned`, `fp_to_unsigned64`;
`AARCH64neon.sinc`). The scalar fixed-point `fcvtzu` into H and D reads its
fraction bits with `Imm_shr_imm16` and `Imm_shr_imm64`, as `fcvtzs` does, where
Ghidra read `Imm_shr_imm32`: `fcvtzu d0, d1, #8` decoded as `#-0x38` and
`fcvtzu h0, h1, #8` as `#0x28`. At the full width the scale stays exact: D takes
2^fbits as a product of two in-range powers (`1:8 << 64` is 0, and `1 << 63` reads
negative through `int2float`), and H scales in float32 (2^16 is past float16's
range): `fcvtzu d0, d1, #64` of 0.5 gives 0x8000000000000000, `fcvtzu h0, h1, #16`
0x8000.

The general-register fixed-point forms get the same: `fcvtzu` into W and X saturates
(`fcvtzu x0, d1, #64` of 0.5 gives 0x8000000000000000, of 1.0 all ones, `fcvtzu w0, d1, #32`
of 1.0 0xffffffff). `FBits64` and `FBits32` state 2^fbits, fbits 1 to 64, as the IEEE
constant (`AARCH64instructions.sinc`), where `1 << (64 - Scale)` is 0 at 64 and negative
through `int2float` at 63, so `fcvtzs`, `fcvtzu`, `scvtf` and `ucvtf` of an X register at
`#63` and `#64` were wrong. The H sources (`fcvtzs` and `fcvtzu` into W and X) are widened and
scaled in float32: Ghidra multiplied by `FBitsOp`, the fraction-bit count read as a float16 bit
pattern, in three of the four, and in float16, where 2^fbits is infinite from 16 bits, in the
fourth. 19 oracle cases (Apple M5) pin them (a sleigh-config pull request is owed, and a Ghidra
issue for the scale constants and the H operand). The fixed-point `fcvtzs` into W and X saturates as FPToFixed states (Arm ARM C7.2.91; NaN gives 0,
at or above 2^(N-1) the maximum, at or below -2^(N-1) the minimum), where it converted by a bare
`trunc` and so stopped in `r2il::eval` past the signed range; six oracle cases (Apple M5, D, S and H
sources into W and X) stop at the old text and agree now, and `fcvtzs_fix` left the list. The fixed-point
`scvtf` and `ucvtf` into H divided by `FBits16`, float16's 2^fbits, infinite from 16 bits; they convert
to a double, divide by `FBits64` (exact) and narrow once (Arm ARM C7.2.235, FixedToFP), an X source
folding the bits below 2^11 into a sticky bit once past 2^53 so the double's rounding cannot differ from
the half's (`ucvtf h0, x1, #64` of 0x8010000000000001 is 0x3801 on the CPU, one past the tie a bare
double would round to). `r2il::eval` narrows into binary16, ties to even, and four oracle cases
(Apple M5) pin them. `fmov` between H and W or X moves the bits (Arm ARM C7.2.131: `Wd =
ZeroExtend(Hn)`, `Hd = Wn<15:0>`), where Ghidra converted the value with `float2float` (four forms;
two oracle cases on an Apple M5 disagreed or stopped at the old text). `fcvta*`, `fcvtm*`, `fcvtn*` and
`fcvtp*` have no fixed-point form.

A 32-bit register destination zero-extends into its 64-bit register in 64-bit
mode (Intel SDM Vol. 1, 3.4.1.1): Ghidra's GP-7027 (`1735e73f4e`) states it
with `check_*_dest`, and 918acd744d's text is taken whole, MOVBE written byte by
byte, MASKMOVDQU's store and the VEX `pcmp?str?` results included
(`crates/r2sleigh-lift/tests/zero_extension.rs`). The lift inserts a piece
Sleigh writes into a live temporary (MOVBE's bytes, GP-6061's VPADD lanes),
where it refused one (`translate::whole_unique_reads`). Carried in this tree,
not yet in the fork or in Ghidra (sleigh-config pull requests and Ghidra issues
owed): `RDRAND r32` widens its r/m register, where GP-7027 widens the reg
field's (`rdrand ecx` cleared RSI); GP-6767's `shrflags` and `shrdflags`
write OF at a count of one and keep it at zero (SDM Vol. 2B, SAL/SAR/SHL/SHR
and SHRD), where its arms were swapped; CVTTSD2SI and CVTTSS2SI, legacy and
VEX, give the integer indefinite for NaN or a value out of range (SDM Vol. 2A),
where Ghidra wrote a bare `trunc`, and VEX's r32 forms zero-extend
(`crates/r2sleigh-lift/tests/truncating_conversion.rs`, the x86-64 oracle);
VEX `VPEXTRW reg, xmm, imm8` (0F3A 15) writes its ModRM r/m register, where
GP-7017 wrote the reg field's (`vpextrw ecx, xmm0, 1` wrote EAX); AArch64
CSSC's W forms (`abs`, `cnt`, `smax`, `smin`, `umax`, `umin`) write X
zero-extended, as GP-6448's own `ctz` does (the AArch64 oracle).

Carried in this tree, not yet in the fork or in Ghidra (a sleigh-config pull
request and a Ghidra issue owed; 918acd744d still decodes both as NOP): x86's catch-all
hint `NOP rm16`/`NOP rm32` (`0F 18` to `0F 1F`, `ia.sinc`) took `0F 18 /0-3` with a
memory operand (PREFETCHNTA, T0, T1, T2; `libc-2.31` 0x16868d) and every MPX
instruction (BNDMOV, BNDLDX, BNDSTX, BNDCL, BNDCU, BNDCN, BNDMK; `ld-2.31` 0x16b22),
because Sleigh orders two patterns that neither specialises by definition order and
the NOP's states `opsize` where theirs did not. They now state `opsize` as `ENDBR64`
does, and the MPX memory forms state `mod != 0b11`, so a register form of `0F 1A`/`0F 1B`
with no matching prefix is still the hint NOP, where they matched and then failed to
resolve their memory operand (Intel SDM Vol. 2, PREFETCHh and the MPX chapter;
`crates/r2sleigh-lift/tests/x86_hints.rs`). No oracle case: a prefetch changes no state,
and the recording CPU has no MPX, where `bndmov` would execute as a NOP.

Carried in this tree, not yet in the fork or in Ghidra (a sleigh-config pull
request and a Ghidra issue owed; 918acd744d still says `# AF not implemented`): x86's
arithmetic sets AF, the carry or borrow out of bit 3 (Intel SDM Vol. 1,
3.4.3.1), in `addflags`, `subflags`, `addCarryFlags`, `subCarryFlags`,
`negflags` and the new `incflags` and `decflags`, so ADD, ADC, SUB, SBB, CMP,
CMPS, SCAS, INC, DEC, NEG, XADD, CMPXCHG and GP-5780's CMPccXADD state it (`ia.sinc`,
`lockable.sinc`; `crates/r2sleigh-lift/tests/adjust_flag.rs`). It stays
unwritten where the SDM leaves it undefined: the logical operations, shifts and
rotates, multiplies, AAM and AAD.

Carried in this tree, not yet in the fork or in Ghidra (a sleigh-config pull
request owed; Ghidra master's ARM and AArch64 pspecs mark nothing hidden): the
ARM and AArch64 processor specs mark Sleigh's scratch registers
`hidden="true"`, as x86's marks `xmmTmp1`: ARM's `tmpNG`, `tmpZR`, `tmpCY`,
`tmpOV`, `shift_carry`, `mult_addr`, `mult_dat8` and `mult_dat16` in all six
ARM pspecs (918acd744d deletes `ISAModeSwitch` and writes TB directly), and AArch64's `shift_carry`, the four
`tmp` flags, `glob_mask32`/`glob_mask64`, `VecMemAddr`, `VectorSelem`,
`VecRegAddr`, `tmp_ldWn`/`tmp_ldXn`/`tmp_stWn`/`tmp_stXn` and `TMPZ1`..`TMPZ6`
with their Q, D and S views. None carries a value between instructions: once
a dead write to one is dropped, no instruction of 20,000 random words per
language reads one on entry (`crates/r2sleigh-lift/tests/scratch_registers.rs`).

Carried in this tree, not yet in the fork (sleigh-config pull request owed):
every AArch64 LSE read-modify-write (`ld<op>`, `st<op>`, `swp` at each size) and
every `cas` and `casp` brackets its load and store with `AtomicBegin()` and
`AtomicEnd()`, the Arm ARM's `MemAtomic`: one single-copy atomic access, inside
its release and acquire marks (`AARCH64base.sinc`, declared in
`AARCH64instructions.sinc`). Without it the p-code of `ldadd` was `ldr; add;
str`, and nothing told an atomic update from three plain accesses.

Carried in this tree, its Ghidra half on 0verflowme/ghidra
`r2sleigh-sleigh-context-12` (`ec9a9312`) and not yet in the forks' mains (fork
pull requests owed to 0verflowme/libsla-sys and 0verflowme/libsla; audit W2):
Ghidra's `ParserContext::applyCommits` writes only a commit aimed at the
instruction's fall-through into the context database. One aimed elsewhere
(a Thumb or ARM `blx`'s `globalset` of `TMode` at its target, MIPS `jalx`'s
`ISA_MODE`) goes to `Sleigh::contextTargets()` with the bits the database holds
there, so a continued run no longer decodes everything above a backward
target in the target's set, and `contextCommitted` no longer counts it
(`context.hh`, `context.cc`, `sleigh.hh`, `sleigh.cc`). Java's
`DisassemblerContextImpl` already keeps such a value for that address alone,
and the decompiler never commits, so this is a fork change, not a Ghidra one.
libsla-sys passes the record through as `context_targets` (`bridge.hh`,
`bridge.cc`, `sys.rs`), and libsla as `PcodeDisassembly::context_targets`
(`ContextTarget`, with `differs`).

Carried in this tree, fork pull requests owed to 0verflowme/libsla-sys and
0verflowme/libsla: GP-2493 renamed `CPUI_EXTRACT` to `CPUI_ZPULL` and added
`CPUI_SPULL` (74); `sys.rs` states both, and libsla maps them to
`AnalysisOp::Extract` and `AnalysisOp::SignedExtract`.

A parse deeper than Ghidra's parser holds is Ghidra's own refusal since GP-6554
(`5328fa2c6d`, in `918acd744d`): `ParserContext` grows its constructor states,
and `allocateOperand` and `pushOperand` throw `LowlevelError` past a 32-entry
operand path or a state's 20 operands, which libsla-sys returns as a decode
error. The `BadDataError` check this tree carried for 11.4 is gone; libflutter's
`vldm` at `0x7cd6ea9f` (a count of 159) still decodes as invalid
(`crates/r2sleigh-lift/tests/parse_depth.rs`), and no Ghidra pull request is
owed.

Licences: Apache-2.0 (each crate's `LICENSE`), with Ghidra's `NOTICE`,
`DISCLAIMER.md` and `licenses/` kept beside its sources.

## Upstream pins

`scripts/upstream_drift.py` reads this table. A row is the Ghidra commit the files it covers were
taken from, the fork's local changes aside: the base is `libsla-sys`'s decompiler C++ (the headers
`sleigh-compiler` builds against too), a processor is its `data/languages`. A resync changes the row.
`TESTBINS_REF` (`.github/workflows/ci.yml`) and the radare2 release (`scripts/diff_r2_judged.toml`)
are pinned where they are used.

| Pin | Commit |
|---|---|
| Ghidra base | `918acd744d` |
| AARCH64 | `918acd744d` |
| ARM | `918acd744d` |
| MIPS | `918acd744d` |
| RISCV | `918acd744d` |
| x86 | `918acd744d` |

## Drift budget

A pin's drift is the age in days of the oldest upstream change it lacks (for a Ghidra pin, a commit
that changes its paths; for `TESTBINS_REF` any commit; for radare2 a published release), 0 when it
lacks none. The weekly `upstream-drift` job fails once a pin passes its budget, or when a vendored
file is another upstream version than its row claims. The budget is a resync, not a waiver
(ROADMAP D33, D39); a pin over it stays red until it moves.

| Pin family | Days |
|---|---|
| ghidra | 90 |
| testbins | 180 |
| judged-release | 90 |
