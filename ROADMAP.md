r2sleigh Roadmap
================

This file lists the open work, the owner of each fact and the gate that checks it.
Design lives in the ADRs each row links, the why in [doc/engine-vision.md](doc/engine-vision.md),
and the working rules in [AGENTS.md](AGENTS.md). Where this file and an ADR disagree, this file wins.

A row states one open fact, its owner crate, its gate and its status. Built rows of the current
stack keep one line with their commit. Closed rows older than the stack left this file on
2026-11-15; [doc/roadmap-history.md](doc/roadmap-history.md) indexes them by number, and
`git show f011873c0:ROADMAP.md` holds every row's full text and measurements before the rewrite.

Rows cite the [end-to-end audit](doc/reviews/2026-10-end-to-end-audit.md) as `audit W1`
(correctness), `M` (missing), `D` (design), `P` (performance), `B` (build) and `T` (tests), always
with the word `audit`, since the same letters name items and rows. The
[2026-11 hand audit](doc/reviews/2026-11-hand-audit.md) is cited as `hand audit` and its section.
A bold id such as **P7** is a program item; `tests/equiv/gate.py` accepts only these ids as a
baseline record's owner.

What the engine is graded on
----------------------------

A benchmark score is never proof. Output is read by hand before a quality claim (D159).

| Gate | Question | Script or job | Blind spot |
|------|----------|---------------|------------|
| Equivalence | Does the C compute what the machine code computes? | `tests/equiv`, jobs `equivalence`, `equivalence-aarch64` | memory before a residual inside the body (audit T1); stripped builds only, so the DWARF route never runs (audit T5) |
| Census | Did any rendering move? A structural change is byte-identical or names each moved line | `tests/db`, `scripts/census.py`, job `census` | none |
| Certification | Does every rendering read only what it assigns, and never panic? | `scripts/certify_render.py` | invented arguments (audit T6) |
| Source-gold | Are signatures what the source declared, or marked? | `scripts/differential_truth.py`, `scripts/void_soundness.py`, `scripts/scratch_void.py`, job `source-gold` | `pddj` states no basis (D70); `frame_agree.py` in no gate (audit T21) |
| Coverage | How much of a binary renders; does any regress? | `tests/coverage` | stale baseline; clang other than 17 ungated (audit T19) |
| Differential | Where discovery, naming and decoding disagree with radare2, and who is right | `scripts/diff_r2.py`, job `diff-r2` | `ir iz iee i f` not compared (audit T4) |
| Dylints | Does the code keep the structural rules? | `tools/dylints`, job `dylint` | warn-level lints count only |
| Structure | Did nesting, length, arguments or clones rise? | `scripts/structure-report.sh` | none |
| Cost | Did instructions, allocations or work counts rise? | `census.py time`, `count`, `stats`; `scripts/scaling.py`, job `scaling` | the four shapes D404 names |
| Hostile input | Does any hostile file crash or hang a verb? | `scripts/hostile_sweep.py`, job `hostile-gate` | SIGBUS on a truncated open file (item **H**) |
| Specification | Does a vendored spec change bring an oracle case? | `scripts/spec_evidence.py`, job `spec-evidence` | none |
| Roadmap | Does every gap citation resolve and agree with its rows? | `scripts/roadmap_gaps.py` | none |

Standing rules
--------------

Each rule is enforced by the script or Dylint named beside it. "Review" means no tool enforces it.

| Row | Rule | Enforced by |
|-----|------|-------------|
| D1 | One item per branch replaces its owner and deletes the old path in that branch; the full bar runs once at the item's exit | review at the exit bar |
| D5 | Gates are blessed in CI, never on a laptop | CI artifacts |
| D6 | Equivalence runs on arm64 too | job `equivalence-aarch64` |
| D10 | DecBench is measured again only where PyPI is reachable | review |
| D11 | No iteration off `r2ssa::fixpoint` or a stated worklist, no silent cap, no entity-keyed map, no cache outside the query database | Dylints `ENTITY_KEYED_MAP`, `CACHE_OUTSIDE_QUERY_DATABASE`, `SCAN_IN_LOOP` |
| D17 | No new crates: a layer boundary inside a crate is a module boundary a Dylint enforces | review; item **L** adds its Dylint |
| D18 | Untrusted input is bounded: a read stops at the bytes the file holds, and every pass states its cost | job `hostile-gate` |
| D19 | Release time, peak RSS and allocation count are budgeted on named workloads | `census.py time` in job `census` |
| D22 | Every pass is an index with a stated bound, `O((V + E) h)`, or says at its definition why not ([next-pass](doc/adr-next-pass.md)) | `SCAN_IN_LOOP`, `scripts/scaling.py` |
| D26 | Allocation is budgeted: one arena per function, indexes sized at the seal, the allocator chosen by measurement | `census.py --alloc-budget 1.02` |
| D27 | On the `rebuild` integration branch, equivalence, certification and the census report and do not block until it merges; that branch merged as #142 | AGENTS.md Validation Bar (see Open questions) |
| D28 | A vendored spec defect is fixed in `vendor/` with an `r2il::eval` regression, listed in `vendor/README.md` and reported upstream | `scripts/spec_evidence.py` |
| D30 | A gate grades what it claims or it is red: a check that compares nothing, a lint at a deleted path and an unjudged disagreement are gate defects | item **GT** |
| D31 | Every layer has an executable oracle (container against radare2 and DWARF, lift against the CPU, rewrites against `r2il::eval`, C against the machine); a layer without one does not render | item **GT** |
| D32 | `pdd` renders an architecture only where an equivalence target grades it; elsewhere it refuses with that reason | `crates/r2engine/src/route.rs` |
| D33 | `libsla-sys`'s Ghidra, `sleigh-compiler` and `sleigh-config` sit on one Ghidra commit | `scripts/upstream_drift.py`, `upstream-drift.yml` |
| D41 | A property of an `R2ILOp` has one owner in r2il, an exhaustive list. Open: `obligation.rs`, `proved.rs` and `stack_bound.rs` still name the jump class, so its Dylint waits | Dylints `r2il_op_property_outside_r2il`, `SSA_CALL_CLASS_OUTSIDE_OP` |
| D159 | A hand audit runs at every stack exit and once per review period; each finding becomes an owner and gate row | review |
| D401 | An allocation rise past 1.02 stands only on a `scripts/cost_causes.txt` line | `census.py time --alloc-budget 1.02`, `test_census.py CountedBudget` |
| D402 | The timing job times analysed cases, and a missing binary fails | `census.py` `TIMED`, `test_census.py TimedCases` |
| D403 | Work counts (rebuilt, frames_built, table_seals) are held exactly. Open: count only release work, through an unmetered control | `census.py stats` against `scripts/stats_baseline.txt` |
| D404 | A cost quadratic in one dimension fails. Open: four fixes it misses at N = 64 need their own generator shape | `scripts/scaling.py`, job `scaling` |
| D405 | Every unknown input is crossed with every negative fact; `OPEN` is empty | `crates/r2engine/tests/engine/default_deny.rs` |
| D411 | Default-deny: a negative fact (unread, kept, void, never, bounded) holds only with its witness, and the unknown case takes the safe side | Dylint `UNPROVEN_NEGATIVE` (deny); `ReadBound`, `Cancelled`, `Transfers`. Open: the matrix rows "unknown placement" and "a CallUse with no call"; mutation of each minter |
| D416 | No pass scans a function-scale table once per item | Dylint `SCAN_IN_LOOP`, deny in r2ssa, r2types, r2dec, r2engine |
| D417 | Element visits are metered per call site | `work-meter` build, `scaling.py --meter` against 2.05 at N = 512 |
| D439 | Timing is read against the chain base: a rise past the budget names a cause line keyed by the base commit with a ratio ceiling | `scripts/cost_causes.txt`, `census.py --base-commit` |

Three rules hold without a row:

- Optimize by bound and algorithm. Derive the bound first, then pick the algorithm (SCC order, semi-naive fixpoint, sparse SSA). A cache or a cap that hides a slow pass is a defect (D11, D22).
- Each head's instruction counts compare with the stack's base commit. A rise over 2% needs a named cause before it merges (D439).
- Structure counts fall only at an item's exit. `scripts/structure-report.sh` fails a rise, and its baseline is blessed only downward.

r2image
-------

| Row | Fact or invariant | Gate | Status |
|-----|-------------------|------|--------|
| **H** Hostile input | A truncated open file kills the session with SIGBUS (audit W53): read through owned bytes or a guarded map | job `hostile-gate` | open |
| **I** Every container fact stated | Stubs no stub section holds are no function starts (ls-silent `call [abort]` thunks at 0x4038, 0x403e, 0x4056; libarm64's section-less `.plt` at 0x6c0, audit M4). PE: TLS callbacks (audit M8), `ir`, cited Windows API prototypes, the export directory inside the header and negative ordinals. ELF: an ET_REL import a record reads stated as an `ImportStub`; a preemptible definition read only under a named premise; AArch64, ARM and i386 PIC relocation field encoders; DWARF through an object's relocations; program headers when the section table is damaged (M4); one `DT_SYMTAB` reader (M6); `PT_DYNAMIC` init arrays (M7); the CIE `S` flag (W31). Mach-O: arm64e threaded binds (W34), the dSYM base (W39). COFF bits from the address size (W38). Raw bytes and fat-slice selection (M5); `is` omits an undefined weak symbol at 0; Mach-O and PE posture under their own headers; LSDA landing pads as statements. Cost: DWARF read on demand, each DIE decoded once (audit P12); one section-name index (P14); tables sized exactly (P28). Hand audit 3.9: PE `.pdata` starts as seeds (`afl` misses 140 of 346 hello_gs functions); `.gnu_debugdata` symbols (ls-toybox 363 against radare2's 1,192); the dynamic symbols of an ELF without section headers; the x86-64 stack placement of a declared argument, so entry0 renders `__libc_start_main` on a stripped glibc ELF. `diff_r2.py`'s `values` mode compares numbers, not names | `diff_r2.py` judged clean on elf, mach0 and pe; no corpus PE refuses at an entry radare2 maps; `ir` non-empty on every ET_REL object | open |
| **P8** Data objects and strings | `iz` reads Mach-O C-string sections and no pointer tables or debug sections (audit W32); an address constant passed as an argument names its object (M17); r2ssa's `source_string_literals`, a second string table, is deleted; string addresses print as integers in 178 DecBench functions (hand audit 3.9) | `iz` agrees with radare2, each disagreement judged | open |
| D152 | A call with a C++ landing pad carries a residual mark until pads are recovered: `safe_div`'s catch changes the result and the C shows none; 2,712 of 8,430 FDEs in 0pack carry an LSDA (hand audit 3.3). r2image states the pad, r2dec marks the call | an engine test where a catch changes the result; no LSDA function renders without the mark | open |
| D158 | `elf_stripped`, whose section header table lies past the file end, does not open; radare2 opens it (hand audit 3.9) | a golden `i` and `afl` | open |
| D259 | A static `__stack_chk_guard` guard row (gap G5) | canary elided only with a binding | open |

r2abi
-----

| Row | Fact or invariant | Gate | Status |
|-----|-------------------|------|--------|
| D78 | The noreturn rows fall short of what the C libraries declare (`pthread_exit`, `thrd_exit`, `longjmp`, `_longjmp`, `verr`, `verrx`), so an arm ending in one keeps its `else` and the walk falls through | an engine test per callee; census, corpus and equivalence read line by line | open |
| D205 | A function whose address flows only into `void (*)(...)` parameters is `Void { Declared, UbFreeSource }`. Open: the `twalk`, `tdestroy`, `pthread_once` and `_obstack_begin` rows, the `Dispute { kept: Calls, lost: Slot }` record, the slot on the proof line, the DecBench 4 | `scratch_void.py` `void-closed` +4, 0 false | open |
| D229 | `TerminateProcess` on the current-process handle and `int 0x29` end a path | an engine test per form | built 87d1419fe |
| D230 | `/GS` past x86-64 UCRT: i386 and live upper bytes built. Windows AArch64 (outlined helpers) is open | an engine test per form; testapp `0x140006138` elided | open |
| D237 | A termination function the container states is a way in whose call reads nothing (gap G11) | the 9 `_fini` print `void` | built 8a8b2bb65 |
| D239 | ELF fini array entries take D237's row; a PIE slot's `R_X86_64_RELATIVE` addend names the entry | `a_pie_fini_entry_named_by_a_relative_addend_is_unread` | built 420eaa7c8 |
| D240 | The loader's constructor call is a cited row per C library; nothing states what the loader passes | `an_unknown_library_constructor_escapes`, `a_musl_constructor_is_void` | built e9a6d36a7 |
| D242 | glibc's and POSIX's rows are read from the header. Open: `re_compile_pattern`, `re_search`, `re_match`, `re_set_syntax`, `gnu_dev_makedev` have no row; the 22 `_GNU_SOURCE` rows need a `LibraryId` for libintl; `qsort`, `bsearch`, `signal`, `atexit` lack a function-pointer spelling | `crates/r2abi/tests/cited_rows.rs` | built 7343a4ad8; open part |
| D243 | bionic states `mode_t` and its guard | `cited_rows.rs` | built 6eeae9da2 |
| D257 | An AArch64 canary is read from the C library's `__stack_chk_guard`, placed only by a stated binding | canary elided only with a binding (gap G5) | built fe1b0fc6b |
| D258 | Android's `tpidr_el0 + 0x28` guard row (gap G5) | canary elided only with a binding | open |
| D264 | `Tail::Flagged` counts only glibc's `open` with `__OPEN_NEEDS_MODE` cited; `prctl` is cited `...` and refuses | `only_glibc_counts_the_mode_open_reads`, `prctl_states_only_its_ellipsis` | built 13894db79 |
| D281 | Cited `msvcrt.dll` and `VCRUNTIME140.dll` tables declare those calls by their DLL's row | each call declared by its DLL's row | open |
| D332 | A mangled row's result in memory (`RSo`, Itanium C++ ABI 5.1.3) is refused by r2abi, so its lanes stay unstated; the parameter half is D263's | a template row returning a pointer states `Result` at `Declared` in RAX; 0pack `__ostream_insert` forwarders carry no `Returned` cause | open |
| D383 | A library summary binds through the row `Imports::bind` returns, never a normalised name | `crates/r2engine/src/library.rs` tests | built 330d2fad2 |
| D395 | An uncited row proves no `never`; it binds as a bound | `cited_rows.rs` | built 442f3a4fb |
| D406 | 33 of 38 uncited noreturn rows are cited. Open, no source found: `__cxa_call_unexpected`, glibc and darwin `xalloc_die`, `__longjmp_chk`, darwin `__stack_chk_fail` | per-table uncited caps fall | open |
| D428 | A call that may return twice keeps the frame | a red test | rejected: no failing program (rounds 6 and 7) |
| D431 | An import's call reads RAX at AL's width where no stated bound covers it (psABI Figure 3.4) | `an_import_call_reads_the_count_register_alone_of_its_register`; D211 81 to 36 | built e3ab01f5c |
| D448 | `__cxa_finalize` cites GCC 13 libstdc++'s `cxxabi.h` lines 134-135 and the Itanium C++ ABI 3.3.5.3: one fixed parameter, so a call reads RDI alone. Alone, 5 census records drop the stub from their floor line and keep the local callee's witness (frame_pointer_locals_clang_O0g 0x10e0, rv_O0g 0x1160, rv_O0g_stripped 0x1160, rv_O2 0x1320, two_units_O0g 0x1100); with D447 they equal master. Moves listed, not blessed | `call_boundary::a_cxa_finalize_call_reads_no_register_past_its_one_argument` | built (rd8-abi-cites) |
| D449 | The uncited rows a glibc 2.39 header states are cited: 49 rows (portable 41, glibc 8) move to `types-glibc.sdb.txt` with header and line, 30 of them the macOS SDK 27.0 states also to `types-darwin-cited.sdb.txt`; musl and bionic lose the 41 portable rows' uncited bound. D151's struct-pointer and function-pointer classes have rendered witnesses; the record-by-value class has none (`ldiv` renders `r2sleigh_word_u64` parameters and RDX as a residual), so `div`, `ldiv`, `lldiv`, `imaxdiv`, `inet_ntoa`, `setjmp`, `longjmp` stay uncited. DecBench: floors 873 to 837, loads 39,354 to 39,256, stores 24,059 to 23,950, refusals 2 to 0, `<< 32` 26/37; census 0 moved. Stopped on cost: bash `aa; pdd @ 0x2e630` +0.86% (Mac, same-tree, median of 3), over the ruling's +0.5% stop; the row opens one more callee to resolution there (`resolved` 2 to 3, `frames_built` 6 to 7, output identical); pumasim `aa` +0.45%, cause unnamed | `call_boundary::a_dcgettext_call_reads_exactly_its_three_arguments`, `audit_abi_rows.py --cc gcc` | open: stopped on cost (branch rd8-abi-cites-d449) |

r2il
----

| Row | Fact or invariant | Gate | Status |
|-----|-------------------|------|--------|
| **L** Layering | L5: r2ssa's IR and facts layers as modules with a Dylint boundary. L6: the trust types (`TrustedLiftedFunction`, `GenuineLiftedFunction`) move to r2il and a Dylint lets only r2sleigh-lift mint them, so r2ssa leaves the C++ chain (audit D9, B5; D17) | r2ssa builds without libsla-sys | open |

r2sleigh-lift
-------------

| Row | Fact or invariant | Gate | Status |
|-----|-------------------|------|--------|
| **LS** Lifted semantics are the machine's | The conditional store's success and a guarded load's value spelled beside their gaps; arm-thumb-movw-be.o's `f` and `g` stay 0-block functions (audit W26); a BE8 or aarch64_be jump table read in the machine's order (conditional); `AARCH64:BE:64:v8A` (deferred); BE ARM testbins in CI's differential; Thumb bytes past an ARM body (conditional); libverifyPass's PLT stubs once PLT0's literal decodes (W25); ARM's 4-byte alignment; `cmpxchg8b` and `cmpxchg16b` zero-extending on failure; the `AtomicBegin`/`AtomicEnd` fork pull request; `casp` and x86 `lock adc/sbb/not/neg` typed (conditional); multi-register `tbl` and NEON user operations. ARM32 refuses `pdd` until these and an ARM32 target land (D32) | no `Unimplemented` in place of a branch | open |
| **VC** The vendored core is right and cheap | The x86-64 oracle list is empty (0 of 385). Next: `AARCH64_apple.cspec` `<returnaddress>` as a fork pull request and Ghidra issue (audit B2); the `ghidra-918-resync` pull requests (AF, `rdrand`, SHR/SHRD OF, the CVTT indefinite, VEX `vpextrw`, CSSC's W forms) with Ghidra issues; SYSCALL's unpacked `rflags`; AArch64 fixed-point and saturating conversions (`fcvtzs`, `fcvtzu`, `scvtf`/`ucvtf` into H, signed scalar `fcvt*s`, vector `frint`/`fcvt`); fused `fmsub`/`fmla` round twice; `translate_pcode`'s 4 allocations per p-code op (P23); the fork pull requests ghidra#1, libsla-sys#6 and libsla#4 onto `r2sleigh-sleigh-context-12`; saturation limits as IEEE constants. Conditional on a RISC-V target: its CSRs named | the oracle lists only stops it names; every local change names its fork pull request | open |
| **M** One machine profile | RISC-V 64 as a qemu-user equivalence target and its 10 frame-base refusals (M6); one tuple-to-profile table, so AArch64 discovery and the trusted lift share one profile (audit D8); MIPS and RV32 profiles or a named refusal | one Sleigh parse per architecture per process | open |
| **LF** Lift once | `Lifted(address, mode)` for the walk and the trusted lift (inside **SM**); discovery translates operations it never reads (audit P18); block lifting copies the rest of the block per instruction (audit P24) | spec load under 20 ms; `afl` decode under 50% of its time | open |
| **LP** Language profiles ([language-profile](doc/adr-language-profile.md)) | LP1's boundary half (several results, two-register values, Rust scalar pairs); Go assembly declared `<ABIInternal>`; `runtime.(*moduledata).textAddr` refuses; LP2 Rust and C++ checks; LP3 pclntab `funcID`, Rust `core`, the C++ ABI, demangling; LP4 Rust, Go and C++ equivalence corpora on both arches | a Go or Rust function renders under its own convention or refuses with that reason | open |
| **AO** Per-instruction facts ([command-gap](doc/command-gap.md)) | A shift by an immediate reads the flags it overwrites under an unfolded `count == 0` select (x86 265, ARM 4; next, the instruction-local fold); ARM `bx<c> lr`, `ldm<c> sp!, {.., pc}` and `and<c> pc, ..` lift to UNIMPLEMENTED; `ldmia<c> sp!` and `cmpxchg.lock` spellings (conditional). radare2's side flips as each fix merges: radare2#26992, #27397 and #27398 (follow-ups to the merged #26984); #26987 closed unmerged | `diff_r2.py` compares size, bytes and register sets (met) | open |
| **P11** Names and listings ([listing-spelling](doc/adr-listing-spelling.md)) | x86-32 negative displacements signed (audit W27); ARM aliases (W28, conditional); `entry.initN` by array slot (W36); preemptible PLT stubs named; `main` named in stripped binaries; one spelling per function; symbol flags filtered as radare2 filters them; a section-less object's stubs; conditional: a section table past the file end, ET_REL listings, `e_entry` 0 in a static-pie; the unjudged rows (`px` 9, `pd` 8, `iS` 8, `is` 6, `ie` 3) | every disagreement judged on elf, mach0 and pe | open |
| D15 | One machine profile from the trusted Sleigh bundle; no architecture-name match below the lifter ([machine-profile](doc/adr-machine-profile.md)) | item **M**'s exit | open |
| D21 | The source language is a profile; the IR, facts and proof name no language | item **LP**'s exit | open |
| D24 | The lift is a query per address over a compact IL | item **LF**'s exit | open |
| D278 | The AArch64 `extension="zero"` override goes upstream (gap G16) | the pull request linked in `vendor/README.md` and both r2abi citations | open |
| D323 | `mov r32, imm32` lifts as a 32-bit write and its widening | census | built cd16feae0 |
| D352 | x86 `int3` and `int1` are traps | `a_call_to_a_function_that_executes_int3_ends_its_caller` | built 5b8062a23 |

r2ssa
-----

| Row | Fact or invariant | Gate | Status |
|-----|-------------------|------|--------|
| **K** One fixpoint driver | `address.rs` provenance onto the driver; the optimiser's round budget and address provenance keep a partial result only the trace shows (audit section 5.4): refuse or name it on the proof line; the depth-8 walks (`FOLD_DEPTH`, `frame_address`, induction); a Dylint for a `fixpoint::*` result matched to a default; the written-lane capture's `while` loop onto the driver | no budget keeps a partial result unnamed | open |
| **B** One byte relation | The forward lane relation reads a byte shift as data; residual traps in bytes the declared result never reads (`release_undemanded_bytes` by `of_returning`, audit W13); NEON and FP values in 256-bit z roots (audit D7); liveness over locations is F2.2's | none stated | open |
| **P5** Values as an index | The renderer reads the views for lane carriers; a call through an unresolved weak symbol (132 of 223 `call to fcn_0` sites over three static binaries) gains `WriteKind::Import { weak }` and an `UnresolvedWeak` class spelled as a comment; a reloaded bounded index as one value (`bomb` `phase_3`, audit M14); an `adrp`/`ldr` literal load captured on the restated preparation; `NEON_uaddlv`; `ax` lists call tables (a walk trigger, measured first) | a dynamic ELF fixture whose GOT word names a weak undefined symbol | open |
| **F2** One IR, indexed once | F2.1 `FunctionIndex` on `Sealed`; F2.2 one byte-granular liveness; F2.4 the builder with incremental def-use; F2.5 the machine projection and term arena as indexes | one representation of a function at the render peak | open |
| **LX** Linear per function | Undefined Ram values (23% of segments), exact sizing and one build (audit P6); P2's interval index; `Import::producers` dense (P3); one `ReachingStorage` per function (P19, deferred); `declarable_stack_object` once (P20); dense rename identities and block-indexed domtrees (P21); block facts by `BlockId` (audit D15); operand iterators (P22); 96-byte obligations (P25); O(1) refusal evidence (P29, P30). LX4 with F2.4 (P4). LX2: the decompiler reads T's and F2's dense indexes, and 65 entity-keyed map sites in 44 allowed items become dense | `census.py exponent` at most instructions^1.05 over 300+ instruction functions; peak RSS linear in instructions | open |
| **MM** Memory as a linear budget ([memory-model](doc/adr-memory-model.md)) | MM.6 a compile-time sealed type and `formal_*` maps keyed by `VarId`; MM.4 the fixed cost (loader writes, unwind frames, symbol layout); MM.7 obligation identities; MM.8 interned types and value geometries; MM.3 seal-only facts (conditional); `MachineBuilder` sized from a bound (audit P31) | `c` at most 600 B per operation, then 300 B | open |
| **P4** One frame model | `afv` and `pdd` disagree on every frame offset (`frame_agree.py` 0 of 582, audit T21); DWARF-declared slots refused promotion (audit D5: `-g` promotes 0 locals, stripped 22); a protector behind a trampoline (W48); a select of two frame addresses refuses the whole frame (`shape_byte_indexed_buffer`); the promotion predicate as a proof or mutation target | `frame_agree.py` gated | open |
| **P7** Call contracts ([call-boundary](doc/adr-call-boundary.md)) | The open call-boundary rows at their owners and the open gaps below. With no row yet: an indirect call's slot named in its gap; `result_ambiguous` stated as its cause; AArch64 `bl g; bl f` with g's x0; demangling as `AtLeast(explicit)` plus variadic; i386 stack parameters (audit W9); a message send's count from its type encoding (W10); cold float parameters (W11, D358); the parameter prefix past an unread slot (W12, 203 functions); a proven syscall named (M16); one case-preserving callee identity (audit D10); printf's stack tail on x86-64; a conditional tail jump as an exit; calls through structure fields (145 functions) and C++ virtual calls (0pack 3,667 sites) | no invented or dropped argument on certification's arity check; W7 to W11's repros render a refusal or the true prototype | open |
| **PE** Written-lane result widths | Its rest is item **B**'s | item **B** | held |
| D12 | One IR, indexed once ([one-ir](doc/adr-one-ir.md)) | item **F2**'s exit | open |
| D14 | One frame model ([frame-model](doc/adr-frame-model.md)) | item **P4**'s exit | open |
| D16 | One byte relation ([byte-relation](doc/adr-byte-relation.md)) | item **B** | open |
| D36 | A temporary is named by where it is defined | `stable_temporaries` | built 166ffa98e |
| D42 | A refusal is a property of the stage type | Dylint `EXHAUSTED_READ_THROUGH_SEALED_STAGE` (deny) | built 1dff1ba55 |
| D54 | A cap that keeps a partial result is an error: item **K** widens to the optimiser round budget, address provenance, the r2rewrite term budget, `COPIES = 8` and the lift's atomic `DEPTH`; the name interner is held per function; `Held` tables get a byte budget | D11's Dylints at deny with a shrinking allowlist | open |
| D157 | `UnsupportedInstruction` prints over ordinary code with no reason (testapp 209 sites, hello_gs 212, pumasim 256): each site names the instruction and why, or decodes (hand audit 3.11) | the three counts fall to named reasons | open |
| D171 | An indirect call through a DWARF member of function-pointer type is placed by the declaration's rule; its parameter roots by S32, the rest by D348 | `member_calls` golden | built 64a99401c |
| D211 | `residual_u64(n) << 32` in 26 of 2,621 DecBench functions, 37 sites, on rebuild-design-7's merged head (`s2count.py`; D440 took 10 RAX return roots, 0 new hits) | at most 5 | open |
| D226 | A cold `pdd` prepares a function once where an owner's statement moves its result; D286 to D288 built it, D289 the second recovery | `builds.rs` | built 033e1b76a |
| D231 | A result carried across an elided `/GS` call stays a residual: `op_ends_reaching_walk` ends the return walk at any call, so the return boundary and liveout learn the exemption together | `a_call_to_a_proven_check_of_the_load_config_cookie_is_elided` returns `r2sleigh_carrier_u64(7)`; hello_gs's 11 elisions hold | open |
| D232 | A Microsoft x64 variadic call with five or more arguments passes four (the Win64 target's 3 `ub` records, `shape_variadic` O0 to O2) | those 3 records leave `ub` | open |
| D241 | What caps the closed world's yield on class C is measured: 102 source-void functions over 35 DecBench builds (result-side ADR) | measured | built 94379e515 |
| D244 | Every executable byte has an owner, so the closed world can answer | result-side tests | built 94379e515 |
| D254 | An unproven machine return reads the registers reaching it; a merge of one frame object's address renders (gap G7) | `an_unproven_machine_return_reads_only_the_registers_reaching_it` | built 92c36d569 |
| D266 | A formal is read at the widest offset-0 lane an operation reads whole | `a_parameter_masked_to_one_bit_is_as_wide_as_the_and` | built 344174edc |
| D269 | `ParamClass::of` is the one classifier of a declared parameter's class | `param_class_of_answers_each_class_and_each_model_places_it` | built 7b0d77bca |
| D270 | A projected load of a member typed pointer to code is a member call | `a_member_whose_type_states_no_contract_stays_residual` | built 82faf0deb |
| D276 | Under `conventions: None` a call reads and clobbers every outermost register | `a_calling_body_without_a_model_clobbers_every_register_and_a_leaf_builds` | built a352026da |
| D282 | `CallReads` is the one owner of what a call reads | the replaced names gone | built 3b5568d3e |
| D283 | `CallUse` carries its register; `uncertified_call_reads` deleted (it raised D211 67 to 95; D431 and D433 answer the rise) | census unmoved | built 16148743f |
| D284 | Frame escape has one walk; moved to D290 | D290's | built a94cb0845 |
| D286 | Renaming reads and writes an identity in one lookup | output byte-identical | built cb89c7950 |
| D287 | Interface recovery derives the certificates it reads | output byte-identical | built cb89c7950 |
| D289 | A kept restatement's second recovery runs the dynamic phases only (`StaticPrefix`, Step A); Step B is D420 | `builds::a_kept_build_collects_its_static_phases_once` | built 3db753085 |
| D290 | `FrameReach` walks once, before promotion and the canary | `a_canary_inside_a_callee_write_ends_no_escape_run` | built 55be5c4cf |
| D260 | The frame extent apart from the protector call | none set | open |
| D306 | `void` is default-deny at the header (gap G2) | `void_soundness` x87 16 to 0 | built f57e1cb57 |
| D307 | A call no contract states leaves every killed result lane unstated | census | built f57e1cb57 |
| D318 | `RegisterEffects` keyed by (entry, thumb); `SiteFates` deposits before any deep read | `a_deposited_register_effect_renders_as_the_one_asked_directly` | built 4399ad678 |
| D319 | A read past a callee that keeps the lane is the earlier call's read | `a_read_past_a_callee_that_keeps_the_lane_is_the_earlier_calls_read` | built 4399ad678 |
| D320 | `RegisterEffect.kept` is the one owner of what a callee keeps | `a_callee_whose_register_effect_keeps_rsi_keeps_it_across_the_call` | built c172cd4dc |
| D321 | `SiteBoundary.written` and `written_before` deleted (gap G10) | census byte-identical | built b78e0a711 |
| D322 | A body's result states what lies above it (gap G1) | `a_body_result_zero_extended_on_every_path_states_zero_above` | built cd16feae0 |
| D324 | A body no return path leaves is never `void` | census | built cd16feae0 |
| D325 | A float result beside a written and read following lane is one group, from the cited `follows` row. Open: followers past the first (AAPCS64 q2, q3). Gap G19, gcc's scrub as `Undefined`, is refused | `a_float_result_beside_a_written_and_read_second_lane_is_no_double` | open |
| D326 | A call's arity is proven only by its callee's statement or a declaration | engine tests | built 8983fce86 |
| D327 | `SlotUse::Unread` is a proof | engine tests | built 999d63d09 |
| D328 | A floor whose only cause is `Homed` is exact only where no escaped address points at an argument slot | engine tests | built 999d63d09 |
| D329 | An argument-area read that crosses two slots or sits at an indexed place is no proof of arity | engine tests | built 999d63d09 |
| D333 | A newly rendered call exposed two effect-accounting defects; both fixed (gap G7) | census | built 5ad1db441 |
| D340 | A return whose result is `Unproven` reads no register | engine test | built a9ed15159 |
| D342 | `release_undemanded_bytes` keeps the INSERT bases of a `void` body: an empty return-storage list reads every return block unresolved | the pass reads `returns_no_register`; each moved census line read | open |
| D344 | The dead-arm select rule's cold cost (S25): 0pack +0.44%, pumasim +0.54% (`edge_fold`, `deadphi`, `obligation`) | both cold cases within 0.3%, output identical | open |
| D346 | The projection descends nested by-value members and states its member path | `a_read_inside_a_nested_struct_member_projects_its_member_path` | built 6b8fa01c6 |
| D348 | Member projection past parameter roots: frame, data-object and loaded-member roots | `layouts` engine tests; `member_calls` golden | built 92e4d507d |
| D351 | The stack pointer at each call has one reading | engine tests | built ddb5dd58d |
| D355 | `DynamicFrame` built for the MSVC CRT string helpers. Open: cpp_sample `0x1400026f0` (10 unaccounted, no dynamic frame) and a wrapper whose recovered arity omits what its tail jump hands on | both render or name each obligation | open |
| D356 | A shrink-wrapped AArch64 return has an exit stack pointer | engine test | built 3d7078c26 |
| D358 | A cold `pdd` of an arm64 float body prints `(void)` parameters (clang 18 -O2 `fadd`, `dmul`); `aa` prints the true prototypes. `BodyBoundary`'s float section must be stated cold | the cold prototypes name `s0`, `s1`, `w0`, `d0`, or a named residual | open |
| D362 | A frame struct array indexed by a value projects its member (`arr[i].third`). Open: a frame-pointer-based slot certificate | `layouts` tests | built 508bff4f0; open part |
| D363 | A call on a returning path keeps a register its callee keeps (transitive `kept`; D413's `Summary` closes cycles) | `builds::an_owner_that_moves_the_build_has_it_built_again` | built caf4bba7c |
| D364 | A call through a bound import's slot (`call [__imp_X]`) takes its import's site model through D390's one map | engine test | built 4f111b8c2 |
| D365 | A frame address handed to a direct callee escapes only upward, by `callee_reach_at` under the site's model | `builds::a_reach_that_moves_no_decision_keeps_the_build`; no engine test restates into a moved decision: gate open | built adaef5bf0 |
| D366 | A call argument is demanded at its callee's held lane | engine test | built c6dabf7da |
| D368 | An escape run is one frame object | engine test | built e676f3936 |
| D369 | Promotion keeps in memory a stack argument slot its call may rewrite | engine test | built 443eb0a4a |
| D370 | A guard's bound on an index value, on the WTO driver | `layouts::a_bounded_index_into_an_array_member_projects_its_element` | built 2856176a5 |
| D371 | An i386 call to a body that reads `ecx` states no `ecx` read, so `security_cookie::check_calls` takes `ecx`'s last definition in the block. The boundary states a walked callee's register reads, and the fallback goes | `gs::an_i386_check_of_the_cookie_in_ecx_is_compiler_inserted` states the read | open |
| D372 | A stated call reads RAX whole where it does not state it (`stat`, `ferror`): the recovered half is D413's, the stated fixed half is open | D211's 45 leave | open |
| D373 | A tail exit to a variadic, incomplete or unstated callee reads its count register beside its arguments | engine test | built c942ef737 |
| D374 | Every dispatch-table read pays a whole convention seal (`read_tables` about 11.0 of 74.7 G on pumasim `aa; pdd @ 0x3b6b20`); a read that needs only values pays none | that case falls, every table read identical over the D367 sweep | open |
| D377 | A stated callee's incoming stack writes are `CallReads::writes`, apart from its reads | `native::a_place_a_stated_callee_writes_above_its_arguments_stays_a_load` | built dc96ad6a8, 88d232c19 |
| D378 | A callee whose frame address escapes, or that indexes a frame object it may store through, bounds no incoming write (default-deny). D441 recovers `shape_recurse_mutual` and the three zig `main`s; shapes `main`, `shape_variadic_local` and aarch64 shapes `main` stay (kinds V, I, F). Kinds E and O were rejected in round 7 | those three records leave their cause | open |
| D381 | A tail transfer's writes count in its body's incoming writes | `default_deny.rs` | built 207460def |
| D389 | A promoted stack argument is found by entry offset in O(log n) | no test red on the parent: gate open | built 37bd70411 |
| D390 | One `SiteModels` for rename, the frame walk, `callee_write_spans` and `call_reads` | the `SiteModels` unit test; no engine test red on the parent: gate open | built af3b87473 |
| D392 | A `CallUse`'s call has one derivation | census | built 37bd70411 |
| D393 | `Reads.cancelled` names each cancelled register, at most two | a unit test only; no engine test: gate open | built 86cdcdad3 |
| D394 | A member base comes from the projection | census | built 94c3df0d8 |
| D397 | The frame walk's opaque points are an `IdMap<OpId, _>` with an O(1) `unplaced` flag | no test red on the parent: gate open | built 6e3250060 |
| D398 | The frame walk's other costs, each O(log n) or once per walk | no test red on the parent: gate open | built 6e3250060 |
| D409 | A counted printf bounds its stack writes; hashes clang-O1/O2 `main` are equal. values.c aarch64 clang-O0 `main` moves with D432 (was rd3-exit's D380) | `a_printf_whose_format_counts_its_tail_leaves_the_callers_slot_alone` | built e41227c90 |
| D412 | One condensation over `Csr` in `dense`; `resolved::Search` deleted | `one_condensation_answers_every_member_of_a_cycle` | built 595e941d1 |
| D415 | `Wto` and `wto_sparse`; ValueRanges on the driver. Open: an engine-level test, a fuzz differential, the census on both arches | `an_irreducible_loops_head_is_its_least_key_whatever_the_numbering` | built f473fc95b; gates open |
| D420 | D289 Step B: re-solve only the region of a kept build's second recovery its owners' changed sites reach. Entry: a typed read set per dynamic phase, a seed from differing site views, held facts with RSS, a measured boundary share | per RM-onerec change 8 | open |
| D421 | A printf format is folded twice (r2engine `formatted_sites`, r2ssa `bind_format_tails`). The literal's one owner is the machine context, which fates reads; D432 adds no third folder | one folder | open |
| D422 | A question about one frame object scans every structured access or return control (four sites, 3.9 to 4.0x per doubling at N = 512). One index by `ObjectId`, O(accesses + objects) | `scaling.py --meter`; closes `SCAN_OPEN` | open |
| D423 | clang x86-64 O1 `branchy.c` `_main` reads `xorps xmm0, xmm0`'s masked entry bits as a held residual where rd3 spelled `0U`; bisected to merge 500e93b46, cause unverified | the overwritten bits stated dead at their owner | open |
| D426 | Rescans R2 to R5 bounded; R4 virtual phis dropped (the R3 solver went with D427) | R3 against the path union on 200 random graphs; no D417 meter replay, and R3's and R4's counters pass on the parent too: gate open | built 5b39265a8 |
| D427 | `rewritten` kills at an exact whole-width store; every non-tail call writes `(i64::MIN, base)` | `a_place_stored_again_after_an_unstated_call_folds` | built a1d1be599 |
| D429 | `vfold`'s escaped incoming area bounds its writes (kind V) | a cost and a dry run | rejected: not costed (rounds 6 and 7) |
| D432 | A printf format reloaded from a clean frame place is its stored literal: one least fixpoint in D427's `fixpoint::sparse`. Open: shapes aarch64 clang-O0 `main` still keeps the slot through E, O and D callees (D378, D414) | aarch64 equal 748 to 749; `a_format_reloaded_from_a_clean_slot_is_its_stored_literal`; `reloaded <= reload_bound` | built efd0ae118; open part |
| D433 | A counted printf reads only its fixed parameters, counted operands and AL. Unverified: `counted_reads` checks no `Citation`, so an uncited printf-family row may reach it | `a_counted_printf_reads_only_its_placed_registers`; floors 940 to 873 | built 59ef32c49; open part |
| D434 | A slot the body reads is not `Unread` | `a_stack_slot_handed_to_a_call_nothing_bounds_is_not_unread` | built de1cef64d |
| D435 | Semi-naive descent from W' | Kani `meet(x,x)=x`, `refine(x,x)=x` | built bc0741289 |
| D436 | `CallReads` is a dense column per machine context | `a_context_builds_each_call_sites_reads_once`. Open, unruled: the demand pass runs twice per body | built ac851af97; open part |
| D437 | The format fold steps only blocks with a cited printf site | `a_body_with_no_format_site_folds_no_operation` | built 28ae1efd2 |
| D438 | Register-walk class lookup by one direct table and one CSR | `a_register_walk_allocates_its_written_classes_once` | built 700f64c8b |
| D443 | One seal of a body of n compare-and-return arms grows superlinearly (Scaling Bench `unproven_returns`): D422's four scans (`function/mod.rs:1824`, `:1967`, `semantic/certificates/returns.rs:131`, `semantic/certificates/mod.rs:533`) grow 4x per input doubling in `scripts/scaling.py`; callgrind at N = 64 and 128 adds `fuse_compare_chains_in_function` 3.99x, `collect_control_domain_facts` 4.21x, `FunctionLiveOut::collect_reaching` 3.79x, `recover_interface_inner` 2.99x, r2dec `CStmt::clone` 4.09x and `emit_stmt` 6.2x (an else-if chain nested n deep). Owner r2ssa optimize, control domains, liveout; r2dec render | `scaling.py` `unproven_returns` linear | open |

r2source
--------

| Row | Fact or invariant | Gate | Status |
|-----|-------------------|------|--------|
| **C** Provenance ([provenance](doc/adr-provenance.md)) | C1 r2dec reads the grade; C2 the convention, locals and syscalls as `Fact`s, JSON with confidence; C3 r2types on `Basis`; C4's Dylint | none stated | open |
| D4 | Provenance on every fact, as `Fact<T>` | item **C** | open |
| D261 | One parameter-type table keyed by `SlotId`, bases `Declared` and `DebugInfo`. Open: its `Option` | `a_slot_is_numbered_in_convention_order_whatever_the_formal_order` | open |
| D273 | `ConventionModel` answers every register question the views answered | `the_model_answers_every_register_question_its_views_answer`, deleted with the views in a352026da (D275) | built 70243d460 |
| D275 | Convention views and `callconv` strings deleted (gap G14, gap G15) | `git grep -w` of the deleted names finds 0 | built dcd716c75 |
| D386 | One call-site translation of the return-address spend | engine tests | built ac3e7d884 |
| D410 | `Never` has private fields, a `Citation` witness and one `proves`; `Placement::reads` bounds only a cited row | `compile_fail` doctest; D405's `uncited_row` | built 3926b190b |
| D425 | `SourceCallSiteInterface::new(.., complete: bool, ..)` lets any crate state completeness, and `CallReads::exact` mints arity from it: completeness carries no witness | completeness minted only by r2ssa recovery from an exact arity or by a cited declaration | open |
| D430 | Record the premise behind `StackWrites::arguments()`; options 2 and 3 print C that `native.rs:6708` and `:6770` contradict | none | rejected: option 1 moves no metric (rounds 6 and 7) |

r2types
-------

| Row | Fact or invariant | Gate | Status |
|-----|-------------------|------|--------|
| **T** Types as one monotone system | One parameter declaration fact for `afv`, `afi` and `pdd`, caller declarations equal to callee definitions (audit W46); an unproven return marked, the float carrier kept (W47); widths and float kinds from reads (W49); a narrow DWARF parameter's extension (W50); `named_blocks()` copies and name-keyed def maps deleted; `FunctionTypeFacts` and `FunctionRenderFacts` as dense indexes before LX2 | one declaration per function across verbs; source-gold soundness per gate run | open |
| **P9** Types over the graph ([aggregates](doc/adr-aggregates.md)) | Declared aggregates' members; callers' declarations of an inferred structure; arrays of structures; recursive and polymorphic types; conditional: one reach pass over `fixpoint::sparse` with a parameter mask | a struct pointer renders as its struct or refuses with the reason | open |
| D25 | Types are one monotone system: union-find, one meet per class, incremental | item **T**'s exit | open |
| D52 | Types and structure are the first measured quality gap on DecBench; the union levers are D65, D66 and D67 | D47's `improved` and `worse` columns | open |
| D71 | A value flowing into a declared pointer parameter, or defined by a declared pointer return, has that pointer type at `Basis::Declared` unless other evidence refuses it. A2 is D262's; A3 stays with **T** | the typed-values engine tests | open |
| D73 | A declared width is never narrower than a lane the body moved whole (`rotl(unsigned, int)` prints `uint8_t arg1`). W50 deferred | engine tests per width | held: conditional |
| D74 | `certified_parameter_pointers` is a second owner of what `gather_memory_widths` asserts: fold it into D71's meet or leave it to **P9** | one owner | held: conditional |
| D156 | Signedness reaches the declaration of locals: 0 of 286 `int` locals typed signed (hand audit 3.6, not remeasured). The parameter half is D265's (0c26c0184) | a DWARF-graded signedness count on bzip2 -O0 and gzip -O2 rises; equivalence | open (with **T**) |
| D206 | A write whose only reader is the return as Value evidence (Ghidra's `onlyOpUse`): ruled, pending the maintainer | a negative engine test: `h` is never declared with a value from its body alone | held: maintainer |
| D262 | A width-only parameter handed to a declared pointer slot is that pointer | `a_parameter_handed_to_a_declared_pointer_is_that_pointer` | built 0d7185ef8 |
| D265 | A parameter's sign is `Decoded` over every live sign-seeding use (hand audit 3.6) | `a_signed_division_declares_its_parameter_signed` | built 9232da795 |
| D345 | `ExternalTypeDb` and its name normalizers deleted | `two_tags_differing_in_case_keep_their_own_members` | built c513fefc8 |
| D347 | `parse_c_type_like` is test-only | Dylint `TYPE_SPELLING_REPARSED`, no allowlist | built f25f6a6de |
| D350 | One declaration per callee (gap G21): the join over calls is built (`DeclarationDisagrees`). Open: r2types states it upstream, and `decide_prototypes` (r2dec `render/values.rs:1934`) is deleted | `decide_prototypes` deleted | open |
| D353 | A pointee every access carries as a float is that float (gap G20) | rv_O2 `double avg(double* arg0, int32_t arg1)` | built 3f07e9965 |
| D382 | An argument handed to an unknown call keeps an empty `SummaryArgEffect`; r2types reads proven bits only. 8d183db39 held the upper bound apart in `assumed`; 97e57ed19 (D411) deleted the field | `a_handed_on_argument_is_no_pointer_or_out_param_evidence`; no engine-level trigger: gate open | built 8d183db39, superseded by 97e57ed19 |
| D387 | One aggregate table at the target's `ptr_bits` | r2types tests | built 4ca606ffc |
| D388 | `EvidenceTypes.slot_types` deleted | build | built af0a9854c |
| D391 | Handle tags (FILE, DIR) come from rows | r2abi data tests | built b908db75d |
| D396 | `apply_main_signature_override` deleted | `main_name_keeps_its_stated_signature`; engine test passes on the parent: gate open | built cd3c0874c |

r2rewrite
---------

No row names r2rewrite as its owner. Its rule proofs run as Kani harnesses in `scripts/quality-gate.sh`.

r2engine
--------

| Row | Fact or invariant | Gate | Status |
|-----|-------------------|------|--------|
| **Q** One query database | A no-op write re-runs nothing (audit P8): a `Newest` entry a retained reader read keeps its tombstone, so eviction counts retained readers (next); `aa` keys only result-ambiguous functions (P9); `afb` and `agf` from `Walked` (P10); lazy ARM32 modes (P11); one name table at open (P15); a text-only held rendering (P16); incremental discovery after a write (P17); the reference index from survey facts with one lift (audit P7); a walk continued past its tables (libc `lift_body` +25%); the name interner held per function; a relative number that folds to 0 is no address (ld `lea rdx, [0x0]`); `ValueUse::Consumes` and `Tests` have no reader outside r2il, pruned at their D41 owner; conditional on a cpuid render: `Unimplemented` states the write set of what it refused | first `axt` within 2x `afl`; a no-op write recomputes nothing | open |
| **FS** One owner for function starts and bodies | `LC_FUNCTION_STARTS` checked before seeding (audit W30); the `afb`/`afi` block-count drift (ls 0x4070: 300 against 298); one containing-function query for the verbs and the visual mode (W45, audit D2); overlapping instructions stated or refused typed (W6); entry refusals as D29 records; `aflj size` as radare2's; the dispatch's default edge as `case.default`; a dispatching body walked twice (6% of libc `afl`); a table's bound from relational value ranges (the libc `ssse3` string family: `__strncmp_ssse3` lacks 390 blocks); `Overlaps` as a D29 record `pdf` and `pdil` spell; `afi` for the blocks SCCP and switch fusion remove; the `Computes` fate rule judged against radare2; pumasim `0x204060` `SetDriver` unread; indexed table accesses as references (audit M12); IBT `endbr64` as a weaker start; the heap-pointer reload (`__spawni_child`); conditional: fragment frames no body holds, `__strptime_internal` and `parse_dollars` | the sweep (**W**) and `diff_r2.py` clean on function sets; `afl`, `afb`, `afi`, `axt` agree on every corpus function | open |
| **RF** Refusals are records | r2ssa's stack balance at every `ret`, so stack-pointer producers are elided or refused by name (audit W43: 65 of 866 static-glibc functions); `afi` on a sealing refusal and `agf` on a walk refusal as records; the sealing refusal's reason typed to `pddj`; D157 | no verb exits 1 on an analysis refusal; `pddj` emits JSON for every function | open |
| **SM** Summaries | A body resolved alone, then with its owners, sealed and collected once (pumasim `0x23fdf0`: 28 of 36 owned bodies resolve again, 89 of 95 under `aa`); one AArch64 preparation with literal addresses folded before recovery (64 of 281 gzdoom resolutions are a second); the summary-grade r2types run; an indirect call's arity from its table entries' common prototype; arity on a cold `pdd` (conditional on **LP**); compact rows that spell at display (bash's margin 0.05 G) | a sweep prepares each body once; callee reads under 10% of sort `0x3f50` `pdd` | open |
| **P6** One resolved body per function | Its remainder is item **SM**'s | item **SM** | held |
| D13 | One query database ([query-database](doc/adr-query-database.md)) | item **Q**'s exit | open |
| D23 | Summaries compose over the call graph: a body is prepared once per session and held, and no `pdd` pays a transitive closure. Its 2% cold budget grades D414 | item **SM**'s exit | open |
| D29 | Every refusal is a record: a typed reason the verbs print and `pddj` carries, exit status 0 | item **RF**'s exit | open |
| D49 | Every refusal and residual cause has a catalog row (symptom, closing fact, owner) that feeds `?` help | a test fails on a cause with no row | open |
| D50 | Batch decompilation is a deterministic pool (longest first, callee-first condensation, per-function budget, positional merge) | one worker and eight give byte-identical output | held: after the cost path |
| D53 | Discovery never returns a silent empty list: a mapped executable range with no seed yields a D29 refusal; r2image states a Cortex-M vector table as entries (libflutterapp 0 functions against radare2's 6,889) | `afl` prints the refusal | open |
| D55 | The listing answers from the walked body (`pdf`, `afb`, `afi` 4 to 5 times slower than radare2); D50's pool design is decided before D50; `ax` and gzdoom enter `TIMED` | the bench's RSS and decompile-all columns | open |
| D65 | A function is an import's stub only where the program says its address is one and its body is only the transfer. Open: `stub::import_stub` keeps its body proof as the second half | engine stub tests | open |
| D83 | `pddj` states the prototype typed, so `scripts/c_types.py`'s declarator reader goes | `test_differential_truth.py` reads the typed prototype | open |
| D213 | The closed world decides an entry-input result lane `void` when every call site leaves it `Dead` | `scripts/mutants_d213.py` | built 55c532e95 |
| D227 | A vector lane a body zeroes reaches its return through passing callees; the closed world names the lane a caller reads (Mach-O in Ga, ELF in S30) | equivalence moves of the class counted | built fb7e6e28f |
| D252 | One `Arc<ConventionModel>` per call site: a bound import takes the default model, a stated body its model, any other call `AnyCall` | `a_pe_stating_one_sysv_function_keeps_rsi_across_a_kernel32_call` | built 71cc05317 |
| D267 | `Exit::Lane` only if `sum_arr` prints `UntypedReturn`; it did not | the audit W47 trace | held: nothing to build |
| D271 | One call-site contract per member call, from the member's signature | `tests/db/cmd/member_calls` | built 82faf0deb |
| D274 | Go's arm64 call effect under Darwin (x18 reserved) | `every_native_model_and_join_builds_with_its_effect` | built cfe420e33 |
| D285 | 12 DecBench images refuse on `code no body holds`: (1) dispatch rounds built in Ge; (2) and (3) are open (gap G8) | the refused-image count at the exit bar | open |
| D288 | A cold `pdd` builds a callee once; its result owners' statements update that build | `builds.rs` | built a5652bbdb |
| D291 | The handed-back `Read(Integer)` arm is deleted; the number had no row before this rewrite | `an_argument_register_handed_back_untouched_stays_unproven_where_a_call_reads_it` | built 71afcd35d |
| D310 | The result side of the call boundary has one design ([result-side](doc/adr-result-side.md)); its slices S15 to S31b are rows. Open: the cost gate pumasim `0x3b6b20` `aa; pdd` at or under 64.38 G (gap G9) | `void_soundness.py` 0 false voids, `scratch_void.py` exit 0, both equivalence ratchets | open |
| D314 | The closed world's result decision is held (gap G9) | result-side tests | built a67e0f640 |
| D317 | The decision reads its supply from the seal that asks | result-side tests | built 5c2b0288f |
| D330 | An import whose row states parameters and no result keeps its signature (gap G3) | 0pack `declaration-disagrees` 1,221 to 353 | built 69e8525a4 |
| D331 | A declaration disputes its body and stays (gap G4) | `Dispute { kept: Declared, lost: Body }` test | built 69e8525a4 |
| D354 | `SiteFates` relifts after a callee ask (lazy variant: walks 375). Open: 30 of the 50 relifts cross roots (D424) | walks at or under 344 (gap G9) | built d6688a6fe; gate open on D424 |
| D361 | A data-object root for a member whose object start the body never references | `layouts` tests | built e65b14f36 |
| D367 | Dispatch rounds cost 8.6% of pumasim `aa; pdd @ 0x3b6b20`. Stage A is built; 1.74 G stays open, and the next lever is D374 | within 2% of 70.75 G; `a_later_round_in_a_loop_copies_its_region_once` | open |
| D375 | libc-2.32.so `0x160ad4`: round 1's table at `0x160bc7` sends an arm to `0x16e6bc` inside a decoded block, so capture refuses the body | the body captures, or the table refuses with its cause | open |
| D376 | A walked callee states its reads and incoming stack writes to every caller build. Tier 2 asks through `state_asked` and `callee_statement`; the writes come from D441 under `aa`. Open: cold builds ask nothing; entry is the cold write-blocking reach on pumasim `0x23fdf0` and 0pack `0x62ecf0` and a lift-grade write cost | `a_spilled_format_reloaded_in_another_block_reads_no_vector_register` | open (built in part dc96ad6a8) |
| D384 | One per-site `Never` carries its proof | `crates/r2dec/tests/architecture.rs` | built f78e5f11e |
| D385 | One held callee convention per callee | engine test | built a3c1ac812 |
| D399 | One restatement path, counted once | `builds.rs` | built 3af7b8489 |
| D400 | One held `OwnerTakes` per `(owner, thumb)` | no test red on the parent: gate open | built cb80a1d54 |
| D408 | A three-member forwarding cycle whose first member a cited slot reads decides `ForwardCycle` after the read joins (was rd3-exit's D379) | engine test; the `aa` census and equivalence moves are unread: gate open | built 49207be36 |
| D413 | Summary lift grade: `reads` and `kept` as a greatest fixpoint; `KeptAcross` deleted. Its open item C2, a walked lane read composed through calls, enters on a composed fixpoint dry run over at least 2 functions and 6 sites, cold within 2%. Also open: `reads` as a least fixpoint over callee reads | `a_read_past_a_recursive_callee_that_keeps_the_lane_is_the_earlier_calls_read` | built b5cbc65db; open part |
| D414 | Summary build grade (`writes`, `reach`, `tail`), one grade for cold and `aa`, would delete `state_asked`, `Stated.asks` and the two-round rule. Measured: 2,073 bodies, about +29 G cold | cold closure within D23's 2% | held: no-go on D23 |
| D418 | Statement firewall: structural equality of `CalleeReads`, `Resolved`, `Summarised`; `revision_identity` leaves `SourceFunctionInterface`; one frame per owner. Lands after D413 and the build key; V6 needs it | none set | deferred (foundation ruling 5) |
| D419 | `later_tables` decodes G(empty) again after `DispatchTables`; continuing round 1 needs a `Newest` or merged query, which the no-cache rule leaves open | G(empty) decoded once per body | open |
| D424 | Cross-root relifts: a deep read under one `ComponentForwarding` root lifts a body a later root's `DirectSites` asks (30 of D354's 50) | walks at or under 344 | open: needs a ruling on a multi-root seed |
| D440 | Where `ClosedWorld` holds, every way in is joined and the integer lane is `Dead` at every site, no instruction reads f's RAX after return; `returned_bytes` and r2dec's tail return read it. Open: callers of an undecided callee read weaker parameter types than its own signature (`closed_alone`); the four guard mutants were run by hand and are in no script | `a_result_whose_integer_lane_every_call_overwrites_reads_no_bits_above_a_narrow_callee`; D211 36 to 26 functions, 53 to 37 sites; equivalence held | built 6eed238f3; open part |
| D441 | A callee's incoming writes compose over its write-blocking calls: `WritesBound::solve` is the one composition, and the held `IncomingWrites` query solves each write-dependence component once, callee first, accepting a cycle only where every member computes its seed; `aa` only. Measured: DecBench loads 39,426 to 39,354, stores 24,107 to 24,059; pumasim `aa; pdd @ 0x23fdf0` +1.81% (81 bodies read alone to compose), outputs identical | `a_place_past_a_mutual_recursion_that_writes_nothing_folds`; `a_result_cycle_and_a_write_cycle_state_one_answer`; goldens differing from master 28 to 24, 0 away; floors 873 | built 41003ea2e |
| D442 | A body the closed world decides seals once: `Native::resolve` asks the decision before the first seal and captures under it. Open: `resolved_alone`, the build path asking callees (`native.rs:1476`), captures with nothing asked, so `finish` still seals a decided body twice under `aa` | `result_lanes::a_body_the_closed_world_decides_seals_once`; Scaling Bench `unproven_returns` | built 94bc163ec; open part |

r2dec
-----

| Row | Fact or invariant | Gate | Status |
|-----|-------------------|------|--------|
| **D** Decompiler rewrite | `uncompress2` and `deflateInit2_` read by hand; the rendered function named by its entry, not its loop header's `root()` (audit W44) | none stated | open |
| **SD** Structuring and readability ([structure-dominator-tree](doc/adr-structure-dominator-tree.md)) | Inverted empty thens, merges spliced into the parent, dead reloads proved; the exit edge's copies after a latch-only loop; irreducible entries; the assignment before a joined return folded; tails of 5 to 16 statements (133 gotos); jumps over a block no rule closes (588) | no more labels or nesting than today on the census, each moved line judged | open |
| D61 | A copy's place and text are read, and a copy may carry a residual. Next: bash `0x65bf0` and `0x48140` goldens read without the goto, and one engine test per guard; the rest waits for a producer | `structure/certify.rs` tests | open |
| D63 | A merge with one gapped and one rendered forward copy reads residual; relaxing it is sound only while the emitted trap and the certificate agree (426 `gapped-forward-copy` edges) | bash `0x2dd90` and `0x48140` read first | held: conditional |
| D64 | `Values` keeps interior mutability: the spelling pass as `&mut self`, `Values` immutable once spelled | no `RefCell` in `render::values` outside the pass | deferred |
| D68 | A named value is read as a variable only where its definition dominates the read. Open: a later member of the lane's class that dominates the call is not looked for (`low_lanes`); `canonical_source` names are unchecked | `scripts/mutants_d68.py` | built 390c17289; open part |
| D75 | The structurer respells only what a contract or the CFG licenses. Open: a literal shift count's overshift guard prints a ternary comparing two literals (480 of 2,668 DecBench functions); an exit block outside the body (GCC's `.cold` split, `noreturn_guards_gcc_x64_O2` `first_or_die`) or an arm entered past a shared join refuses as `EdgeMismatch` (r2dec `control.rs`); a role cut at seven or more arguments is tested only in r2dec's unit test; the select ADR is the maintainer's | `scripts/mutants_d75.py`; census read | open |
| D76 | A function of about 4,500 sequential checks overflows the stack (`chain4500`) where it should render or refuse by name | a generated 60,000-instruction function exits 0; `control::write` at 10,000 nested arms on a 256 KB stack | open |
| D79 | One failing guard reverts every guard of its function, since the stage is kept or reverted whole | a unit test where one of two guards fails and the sound one stays | held: until a binary shows a revert |
| D80 | The control certificate reads no order of plain statements, so a stage moving them across a test is held only by its own tests | the mutant dies with the guard's order tests removed | open |
| D233 | The proof line's unproven-return count counts every return the text shows (gap G12) | census names the residual | built e1ad8b33b |
| D234 | The closed-world premise is its own clause on the proof line (gap G13) | `a_closed_world_read_states_its_premise_and_a_cold_render_stays_unproven` | built e1ad8b33b |
| D263 | Unit declarations of declared types built. Open: the handle and `named_scalar` data table, the prelude's `typedef` of a named alias, `compile_check.py`'s binary step in CI | `a_cited_record_pointer_is_declared_and_passed` | open |
| D357 | The `__libc_start_main` call gap in the 17 census `_start` goldens names no argument; `CallGap` states the argument's index (S35 clause 1) | the census lines name the argument | open |
| D359 | r2dec spells a projected member (`cur->next`) | census | built e65b14f36 |
| D360 | An array member's element projects with its index (constant or guard-bounded). Open: r2types names no field and r2dec spells no `a[i]` (`member_indexed`) | `layouts::a_bounded_index_into_an_array_member_projects_its_element` | open (built in part eae6214be) |
| D379 | A bound ends no C: r2dec ends control only at a proven `Never` | `default_deny.rs` | built f78e5f11e |

r2s
---

| Row | Fact or invariant | Gate | Status |
|-----|-------------------|------|--------|
| **S1** Verb table, `?`, `e` | `j` on every verb from typed engine payloads (audit M9); `pi`, `p8`, `pD`, `pr` as flags of `pd` and `px`; `pdc` printing `pdd`; conditional, one commit each when a user asks: `ii`, `iI`, `iD`, `CL`, `ps`, `pv`, `ts`, `pf.name` | `diff_r2.py` covers the `j` forms | open |
| **S2** `@@`, search, pipes ([scripting-surface](doc/adr-scripting-surface.md)) | Address expressions, relative seek, `@@` (audit M10, W60); `/x`, `/`, `/w`, `/v` (M11) | none stated | open |
| **S3** Shell hygiene | `q <n>` exits `n`, `q!` (audit W61); `ax` and `axf` as radare2 has them, one error prefix (M20) | no exit status 101 on any hostile run | open |
| **CL** `r2sleigh-cli` | `compile` reads its input (audit W51); `test-arch` and `run --action dec` (M21); a spawn test (T13) | none stated | open |
| D56 | User facts (rename, retype, comment, save) as query-database inputs with a `Basis` (ADR first); `j` on every verb; an agent skill whose verbs a test checks; a thin MCP server; an agent-task bench of about 30 questions; an i386 equivalence target; cited Windows API rows; library identification by structural hashes; demangling as a `Symbol` hint | a date per item | open |
| D272 | Certification grades a call through a member | `pddj_states_a_member_calls_declared_arity` | built c25e29eb0 |
| D380 | `afi` says `noreturn: true` only for a proof and spells a bound as one | `crates/r2s/src/function.rs` tests | built f78e5f11e |
| D407 | `afi` on a body no walk finds returning has no `tests/db` golden for `noreturn: unproven (no return reached)` | a `ud2` fixture and its `afi` golden | open |

r2s-tui
-------

| Row | Fact or invariant | Gate | Status |
|-----|-------------------|------|--------|
| **V7** Visual state from engine facts | The panes ask **FS**'s containing-function and instruction-starts queries (audit W59, audit D2); a seek moves the decompiler pane (W56); pane switches keep the seek (W57); one screen at any typing speed (W58); re-entry and signals restore the terminal (W54, W55); `scr.color` (W62); the xrefs pane keeps axt's caveats (M19); requests cancel (P32) | a scripted key run settles to one screen across 5 speeds | open |
| **V1** to V6, E, A | V1's worker asks **Q**; V2 `eco` themes; V3 hints and palette; V4 linked cursors; V5 `agf`, `agc`, `agx` through one renderer off the UI thread; V6 annotation as user facts (after D418); E: `ae`, `ar`, `aer`, `aes` over `r2il::eval`, checked against host renderings; A: the agent surface with determinism tests | none stated | open |

Gates, CI and build
-------------------

| Row | Fact or invariant | Gate | Status |
|-----|-------------------|------|--------|
| **GT** Gates grade what they claim (D30, D31) | The full-corpus certification tier beside the per-push one; a pass-level differential (`r2il::eval` before and after each rewriting pass); memory before a residual inside the body, once `pddj` states each residual's position (audit T1); a DWARF route dimension (T5); `ir iz iee i f` in the differential (T4); a ratchet on calls graded beside invented and dropped; the x86-64 equivalence baseline counted once a runner counts (D343) | every confirmed audit row a gate could catch is caught by one | open |
| **G0** Gates real | A timing verdict where the base refuses and the head renders; tests on `[profile.ci]` (audit T15); a nextest timeout (T16); the Dylint lock committed and its tools pinned (T17); per-allocator feature sets in Clippy and tests (T9); `unittest discover` with named exclusions (T11, T18); rendered C in shard artifacts (T22) | none stated | open |
| **W** Real-binary sweep gate ([sweep](doc/reviews/2026-10-real-binary-sweep.md)) | coreutils and zlib with DWARF as a CI gate against radare2, objdump and DWARF; its discovery exits are **FS**'s | the sweep runs in CI | open |
| **BD** Build cost | An `iter` profile (audit B6); per-processor spec units (B8); thin LTO or `dist` in the README (B9); unused dependencies (B10) | clean release critical path under 4 minutes on a quiet machine | open |
| **PF** Performance foundation | The C++ heap reported beside the Rust heap peak (audit P27); one arena per function, with **F2** | none stated | open |
| **Hygiene** | `PreparedFunctionFacts::string_literal_for_value`, never filled, deleted; `samply_collapse.py` keeps the impl type (audit D16); README, BUILDING, `command-gap.md` and `tests/equiv/README.md` say what the code does (M22); a generated "where this stands" (D51); a file-length ratchet; pinned containers for gate results; macOS arm64 equivalence | none stated | open |
| D35 | x86-64 has a CPU oracle recorded on contabo and replayed on every host; CI fails a vendored spec change with no oracle case | `scripts/spec_evidence.py`, job `spec-evidence` | built 0126492c9 |
| D38 | The cost verdict counts retired user-space instructions; wall time is a hang guard. Open: the stack-exhaustion exemption graded through a sibling-call build; the x86 `Equivalence gcc-O2 a` shard's 8-minute timeout has 25 s of margin | `census.py --measure instructions` | open |
| D39 | A weekly job reports how far the Ghidra base, `TESTBINS_REF` and the judged radare2 release drift | `scripts/upstream_drift.py`, `upstream-drift.yml` | built f3985f01a |
| D43 | Every gate runs at a stack's tip, and every baseline source is in an equivalence shard | `scripts/check_shards.py`, `stack-tip.yml` | built 680e4855d |
| D44 | The oracle's breadth is ratcheted: each spec's mnemonics and constructors with an oracle case (x86-64 117 of 1,513, AArch64 489 of 783), the uncovered count only falling | `scripts/oracle_breadth.py`, not in the tree yet | open |
| D45 | A prover has a mutation target: `cargo mutants` over `tail_count`, `save_area`, the stack-guard scrub, `result_calls` and the cycle fixpoint | each survivor killed or listed with a reason | open |
| D46 | Moves are separated from noise by paired tests: a nightly pinned sample, McNemar and sign tests, Holm-adjusted; timing as an A/B in instructions ([measurement discipline](doc/adr-measurement-discipline.md)) | the nightly job | open |
| D47 | A type or layout change records `improved` and `worse` per project; `tests/decbench/mined_set.py` splits mining from held-out. Next: the PR gate and nightly that call it, the F1s, timing | `mined_set.py pair` | open |
| D48 | The census audits its own hunks: a classifier clears a hunk only where it checks equivalence, and a bless needs zero unclassified hunks | the classifier | open |
| D51 | Published numbers come from the gates: "where this stands" generated with a clean rate beside `rendered` | the generated table | open |
| D57 | The loop reaches the field: a cap of 8 open stacked PRs merged bottom first, a red nightly opens an issue within 24 hours, artifacts off contabo, a release binary per tag, a fuzz and sanitizer gate | review | open |
| D66 | A DecBench run that loses rows fails (exit 71), and the backend checkpoints by time. Next: a host run of bash with the 30 s backend | `tests/decbench/run_gate.py` | open (built in part 0d4c33d9c) |
| D67 | DecBench-ranked fixes after D65 and D66, each with its measured ceiling; large functions, switches, compound conditions and the type caps are deferred | D47's columns | open |
| D69 | A function a change moves is executed against its base on real binaries: a changed-function differential beside `tests/equiv` and an uninitialized-read sweep in `certify_render.py`, each with a control that must fail | both in CI | open |
| D70 | The soundness gate grades what the typed-values items change (built, `scripts/mutants_d70.py`). Open (a): `pddj` states no `Basis` for a parameter or return, so the gate cannot mark by grade (r2engine `json.rs`) | `marked_by.basis` counts on hashes -O0 | open |
| D82 | Source-gold places a parameter by DWARF's entry register; `ms_abi` and clang builds graded | `differential_truth.py` on `abi.gcc.O2` | held: on D71 |
| D84 | Source-gold counts a parameter the engine adds (`invented` beside `missing`) | grep's `insert` | held: on D71 |
| D85 | The equivalence gate and DecBench place functions with `Dwarf.placed(starts)`, so 39 split functions are placed | 1,656 call specs unmoved | held: conditional |
| D86 | A baseline holds no recovery floor and no refusal ceiling | the shim test with a floor | held: first change that lowers `functions_recovered` |
| D90 | A discontiguous function's entry is its first range, even when the cold part is a FUNC symbol listed first | a hand-built range list | held |
| D91 | Plain `char` graded by a rule, so `char*` stops being a silent `pointee` row | `test_differential_truth.py` `Buckets` | held: on D71 |
| D92 | The soundness number D71 and D73 gate on | one line of the D71 test | held: on D71 |
| D93 | One reader of the DWARF type graph for `Dwarf.type` and `c_types.from_dwarf` | `spec.py` and `c_types` read one graph | held |
| D94 | `_Atomic int *` and `va_list` graded | a `c_types` test each | held: on D91 |
| D95 | Source-gold grades a declared struct pointer by its tag and refuses builds it states no ABI for | a RISC-V build exits 2 | held: with D93 |
| D203 | The scratch-void gate | `scripts/scratch_void.py`, `scripts/mutants_d203.py` | built 0e06a22fb |
| D204 | r2abi's void rows are audited before any row decides a void | `scripts/audit_abi_rows.py` | built f80e5d42a |
| D207 | AArch64 scratch voids on an arm64 DWARF sample, where X0 is an input | D203 on the sample, 0 false voids | open |
| D216 | A Win64 equivalence target | Win64 shards in `tests/equiv` | built 092d17a85 |
| D245 | `scratch_void.py --target`: a build or baseline of another machine is exit 2 | `test_a_build_of_another_machine_is_exit_2` | built b2533fe19 |
| D246 | CI grades AArch64 scratch voids | job `source-gold-aarch64`; `mutants_d203.py --target aarch64` | built 016881692 |
| D247 | An arm64 DecBench sample for the scratch-void gate | D203 on the sample exit 0, 0 unnamed false voids | open |
| D248 | gcc's arm64 canary registers measured | counts in the scratch-result ADR | open |
| D277 | S35's gate clauses run base against head; a failing clause opens a row at its owner | `scripts/s35_clauses.py` | open |
| D280 | The result side's "Decided, pending" 1 to 5 answered by the maintainer, then the exit bar run once | recorded answers | open |
| D308 | `void_soundness.py` grades callers' externs | `scripts/void_soundness.py` | built ec94ec1bf |
| D338 | Peak RSS is a function of the input alone: one fixed hasher (`clippy.toml`), purging on a byte count | census RSS | built ce3ef4673 |
| D339 | A `slow` verdict is graded against the original's CPU time on the same runner | `test_equiv` fake-cost tests | built 829f467e0 |
| D341 | Under `time`, a `slow` is the processor's verdict | `test_equiv` | built 11b1d1ebd |
| D343 | Counted equivalence baselines: aarch64 counted under a plugin qemu (`rt/qemu_count.c`). Open: x86-64, on a host that counts | `CostTests` | open (aarch64 built 9f02ab662) |
| D349 | One gap table with one owner and state per gap | `scripts/roadmap_gaps.py` | built 531c6b798 |

Order
-----

### The current stack

| PR | Branch | Rows | State |
|----|--------|------|-------|
| #398 | `rebuild-design-3` on master | round 3: D370 to D378, D408, D409 | open |
| #399 | `rebuild-design-4` | the design-fit audit: D379 to D407 | open |
| #400 | `rebuild-design-5` | the foundation ranking and round 5: D410 to D426 | open |
| #401 | `rebuild-design-6` | round 6: D427, D431, D433 to D439 | open |
| #402 | `rd7-format` | D432 | closed: superseded by #403 |
| #403 | `rebuild-design-7` 94bc163ec | round 7: D432, D440, D441, D442, D443 | open |
| next | `roadmap-rewrite` | this rewrite: rows by owner, standing gates, history index | open |

Round 7's exit, on rebuild-design-7: D211 26 functions and 37 sites (gate 5); floor callees 873;
DecBench loads 39,354 and stores 24,059 over 2,621 functions; 25 golden records differ from
master; equivalence equal x86-64 745 and aarch64 749. The x86-64 745th is `review.c` clang-O2
`fact`, graded by time and not blessed.

### Next rounds, from the rulings

1. D211 to its gate of at most 5. After D440, 26 functions stay; D372's stated half is the next owner.
2. D413's item C2, then C3 (a tail callee that overwrites RAX). Entry: a composed fixpoint dry run over at least 2 functions and 6 sites, cold within 2%.
3. D376's cold ask. Entry: the cold write-blocking reach on pumasim `0x23fdf0` and 0pack `0x62ecf0`, and a lift-grade write cost.
4. D378's kinds V, I and F. V needs D429 costed; I needs a cited premise for indirect callees (psABI line 410 exempts local functions).
5. D414 stays held until a build grade fits D23's 2%.
6. Cost: D442's open part and D443 (with D422's index), then D367, D374, D419, D420, D344, D285's (2) and (3), D375. D424 needs a ruling before D354's gate can close.
7. Witnesses: D425, D433's citation check, D350's upstream declaration, D421's one folder.
8. D415's gates; D418 after D413 and the build key.
9. Then the open rows and items by owner above, the lift and container first.

### Hack ledger

| # | Hack | State | Rows |
|---|------|-------|------|
| 1 | `Placement::reads` passed `stated = true` with no citation check | closed by D410 (3926b190b) and D411 (97e57ed19, a00158681) | the same class stays open in D425; D433's `counted_reads` checks no `Citation` (unverified) |
| 2 | The two-round rule in `walk.rs` accepts a self call's writes only if round 2 equals round 1 | open | D414 holds its deletion and is no-go on D23. A write cycle has three owners: `own_rounds`, D441's seed check and `Assumed::writes`; `a_result_cycle_and_a_write_cycle_state_one_answer` holds the last two equal. Proposal, no row: a self call as a one-member `IncomingWrites` component, deleting `own_rounds` |
| 3 | 5 uncited noreturn rows stay bounds, so callers name no exit | open | D406 |
| 4 | The six default-deny violations of the call-boundary ruling, section 2 | closed | D276, D264 (twice), D265, D240, D252, each with its test |

### Rejected, no row

Rulings: RM-* the math designs, RF the foundation ranking, AWB the ABI write-bound judgement, R6 and R7 the round rulings (2026-11-14 to 15).

| Candidate | Missing measurement or reason | Ruling |
|---|---|---|
| Dispatch Stage B (incremental re-seal) | B, I, V, C per body; incremental-equals-cold proof; `ComesBack` cycle answer; RSS | RM-dispatch |
| Build-key rule 3 (held raw SSA) and the RSS fallback | a memo of an unpriced stage; a runtime cap | RM-buildkey |
| Relift heap worklist | 7 fewer walks against 28 required; the lazy variant is D354 | RM-relift |
| Build grade under `aa` alone | one key with two answers by session history breaks fresh-open identity (D153) | RF ruling 1 |
| early-cutoff as named | `db.rs` already cuts off; firewall deferred to D418 | RF ruling 5 |
| Write-bound rules E and N | no ABI words state the negative fact; contradicts gates `native.rs:6708`, `:6770` | AWB |
| `R6_RET` (own result read at 4 bytes, 18 functions) | no proof bounds what callers read | R6 section 3 |
| 13 return-expression functions, 7 unattributed sites | no mechanism | R6 section 3 |
| AL rule at indirect calls (2 functions) | psABI line 410 exempts local functions | R6 section 3 |
| `R6_CITE`: `dcgettext`, `getopt_long`, `fflush_unlocked`, `localtime`, `utimes` | 0 `<< 32` gain after D431; at most 10 floors | R6 section 3 |
| Reuse of 95 of 230 repeated range solves | input equality unverified | R6 section 1 |
| Unnamed +0.046 / +0.065 G (3f84dbe5f) | no design | R6 section 1 |
| 426 walked non-floor chain roots | unexplained | R6 rows |
| 15 functions with no fact | a fact | R7 section 6 |
| `R7_LANEDEAD2` | 0 gain | R7 section 2 |
| C1 with C2 (3 joint functions) | hand traces | R7 section 6 |
| C4 (cited libexpat handler slots) | a cited binding fact and an expat 2.4.0+ header; no number | R7 section 4 |

Renumbered rows
---------------

| Fact | Old | New | Where |
|------|-----|-----|-------|
| rd3-exit: a three-member forwarding cycle | D379 | D408 | 42778c52e; D379 is rd4-never's walk-only `noreturn` |
| rd3-exit: a variadic call's tail count bounds its stack writes | D380 | D409 | 42778c52e; D380 is rd4-never's `afi` spelling |
| D226's incremental builds | D282 to D285 | D286 to D289 | commits 3b5568d3e and a94cb0845 keep the old numbers |
| S25's cold cost | D285, then D340 | D344 | D340 is #378's unproven-return row |

No reference in `crates/`, `tests/`, `doc/` or `scripts/` uses an old number in its old meaning.

Gap rows
--------

The call-boundary rewrite's gaps, cited as "gap G7". Each row has one owner; its state follows its D-rows, and
`scripts/roadmap_gaps.py` (D349) fails a citation with no row or a state its D-rows contradict.

| Gap | Fact | Owner | Rows | Gate | State |
|-----|------|-------|------|------|-------|
| G1 | `SourceAbove::Zero` and `Sign` producers | r2ssa `lanes` | S24: D322 | `a_body_result_zero_extended_on_every_path_states_zero_above` | closed |
| G2 | 16 x87 header false voids | r2ssa `unheld_lane_written` | S36: D306 | `void_soundness` x87 16 to 0 | closed |
| G3 | an import with an unstated result keeps its signature | r2engine `declared` | S26: D330 | 0pack `declaration-disagrees` 1,221 to 353 | closed |
| G4 | a declaration disputes its body | r2engine decision | S26: D331 | `Dispute { kept: Declared, lost: Body }` test | closed |
| G5 | guard rows past `ThreadSlot` | r2abi `GuardRow` | S18: D243; S27: D257, D258, D259 | canary elided with a binding only | open |
| G6 | per-function `ConventionId` | r2engine `stated_convention` | S20: D249 | `an_ms_abi_function_in_an_elf_places_rcx_first` | closed |
| G7 | 14 effect-accounting refusals after a declared call | r2ssa effect accounting | S23: D254, D333 | the 14 render or name each obligation | closed |
| G8 | closed-world yield 4 of 102 | r2engine `reads` | S18: D241, D242, D243; S18b: D244; Ge: D285 | `void-closed` rises, 0 false voids | open |
| G9 | one seal; `CalleeEntry` cost | r2engine `fates` | S31a: D314 to D317; D226: D286, D287, D288; S31b: D318, D319, D320, D354 | pumasim `0x3b6b20` `aa; pdd` at or under S31b's parent; cold within 0.3% | open |
| G10 | `SiteBoundary.written` read by nothing | r2ssa `site_boundary` | S31b: D321 | `written` and `written_before` deleted, census byte-identical | closed |
| G11 | `_fini` void by a cited row | r2abi `loader_call` | S22: D237, D238, D239; Ga: D240 | the 9 `_fini` print `void` | closed |
| G12 | the proof line's unproven-return count | r2dec | S21: D233 | census names the residual | closed |
| G13 | the closed-world premise as its own clause | r2dec | S21: D234 | `a_closed_world_read_states_its_premise_and_a_cold_render_stays_unproven` | closed |
| G14 | convention views, `callconv` strings, `AdvisoryCallPrototype` | r2source contracts | S34: D273, D274, D275, D276 | the convention-view lint's allowlist at 0 | closed |
| G15 | `reg_type_hints`, `merge_type_hint` | r2engine | S34: D275 | both deleted | closed |
| G16 | AArch64 `extension` override sent upstream | vendor | S35: D278 | the PR linked in `vendor/README.md` | open |
| G17 | stale text (P7, T, four call-boundary rows, ADR status lines) | docs | S35: D279 | none left | closed |
| G18 | cspec `<rule>` elements, Apple `PackedStack` | r2ssa `place` | none | a conformance test per rule | not sliced |
| G19 | gcc's `xor eax, eax` scrub as `Undefined` | r2ssa `stack_protector` | S24: D325 | `a_guard_scrub_a_return_reads_is_the_returned_zero` | refused |
| G20 | S16 exit-bar findings 1, 2 and 4 | r2engine `fates` | S16: D212; S36: D307; S31b ruling: D353 | rv_O2 `0x1430` prints `double avg(...)` | closed |
| G21 | `decide_prototypes` picks the first call by address | r2types | D350 | `decide_prototypes` deleted | open |

Built rows the gap table names and no owner table holds:

| Row | Fact or invariant | Gate | Status |
|-----|-------------------|------|--------|
| D212 | Per-lane pass-through at a call | result-side tests | built 0d051bc4f |
| D238 | `SourceLoaderRole` deleted | build | built 2038a953e |
| D249 | A function's convention is what its debug information states | `an_ms_abi_function_in_an_elf_places_rcx_first` | built 9b1494a16 |
| D279 | Gap G17's stale text corrected | none left | built 865a4bfe6 |
| D315 | Forwarding is solved per strongly connected component on `r2ssa::fixpoint` | result-side tests | built a67e0f640 |
| D316 | The closed world's coverage of loader writes is positive | result-side tests | built c832fafd6 |

Audit rows by item
------------------

Every row of the [audit](doc/reviews/2026-10-end-to-end-audit.md) has one owning item.

| Item | Audit rows |
|------|------------|
| H | W53 |
| I | W1, W5, W31, W33, W34, W35, W37, W38, W39, M1, M4, M5, M6, M7, M8, M18, P12, P14, P28 |
| VC | W15, W16, W17, W18, W19, W21, M15, T7, B1, B2, B3, B4, P13, P23 |
| LS | W2, W3, W20, W22, W23, W25, W26, M2, M13 |
| M | audit D8 |
| LF | P18, P24 |
| L | audit D9, B5 |
| K | audit section 5.4's budgets |
| B | W13, audit D7 |
| P5 | M14 |
| LX | P2, P3, P4, P5, P6, P19, P20, P21, P22, P25, P29, P30, audit D11, audit D15 |
| MM | P31 |
| Q | P7, P8, P9, P10, P11, P15, P16, P17 |
| FS | W4, W6, W29, W30, W40, W41, W42, W45, audit D1, audit D2, audit D6, M12 |
| D | W44 |
| RF | W43, W63, audit D4, audit D14 |
| SM | P1 |
| P7 | W7, W8, W9, W10, W11, W12, W14, W24, M3, M16, audit D3, audit D10 |
| P4 | W48, audit D5 |
| T | W46, W47, W49, W50 |
| P8 | W32, M17 |
| P11 | W27, W28, W36 |
| SD | audit D13 |
| S1 | M9 |
| S2 | W60, M10, M11 |
| S3 | W52, W61, M20 |
| V7 | W54, W55, W56, W57, W58, W59, W62, M19, P32 |
| CL | W51, M21, T13 |
| GT | T1, T2, T3, T4, T5, T6, T8, T10, T12, T14, T19, T20, T21, T23 |
| G0 | T9, T11, T15, T16, T17, T18, T22 |
| BD | B6, B7, B8, B9, B10 |
| PF | P26, P27 |
| Hygiene | M22, audit D12, audit D16 |

Upstream radare2
----------------

radare2 is the differential target ([radare2-function-walk](doc/adr-radare2-function-walk.md)). Each fix is its own pull request, measured alone.
Open pull requests: no pointer for an ARM pc load indexed by a register (#27397), the address an ARM pc-relative `pld` prefetches (#27398).
Merged 2026-10-15: #26965, #26970, #26984, #26985, #26986, #26988, #26991, #26995, #26996, #26997.
Closed unmerged: `aea` on unmapped memory (#26987), arm64 `mrs`/`msr` `tpidr_el0` (#26994). Issue #26983 (BE8 code byte order) is closed.
Open issue: #26992 (`aea` under a failing ARM condition).
Edge-labelled path state needs a design first.

After the program, each only once its consumers exist: binary diffing over callee summaries, exception-handler
recovery (D152 marks the calls until then), the #65 techniques (switch prover, SAILR idioms as r2rewrite rules,
library identification, Retypd after **P9**), static rewriting, deobfuscation, trace recording.

Not taken, each against a rule (command-gap sections 2 and 3): shell escapes and file-system verbs (`!`, `rm`, `o`, `prj`);
analysis triggers and hand-made functions (`aa`, `af+`; discovery owns them); zignatures (`z`; a name-owned summary);
`tk` (a stringly store); hints (`ah`; a second owner for a derived fact); the assembler (`pa`, `wa`); custom graphs (`agg`);
`ab` (a flag on `afb`); `as` (debugger work, [debugger](doc/debugger.md)).

Standing debt
-------------

Each item has an owner and no row yet.

- A reload certified as the stored value binds as a copy of the stored temporary in three census functions (item **D**).
- Partition-first's conservatism (read closure, `CallRestore`, return carrier, call-use reads) and the semantic-kernel ADR's rewrite fold into D's ADR (item **D**).
- Listing claims follow the demand release, valid only for the function's meaning; annotations must read the index before it (**F2**).
- `def_use_graph` seals a raw function to answer a listing (F2.1, in **LX**).
- `seal_body_proven_interface` rewrites the format parameter after the build (**C**, C1).
- Entry condition flags cannot be booleans until the specification carries a flag fact (**LS**).
- `StackObjectRefusal::ParameterHomeWidthMismatch` is shown genuine or deleted (**P4**).
- Address-proven formals change no test or census function: **P7** proves their use or deletes them.
- x87 80-bit floats refuse ([floating-point](doc/adr-floating-point.md)).

Issues
------

| Issue | State | Owner |
|-------|-------|-------|
| #47, #50 | one liveness model in r2ssa; consumers remain | **F2** |
| #58 | widths fixed; pointee types open | **P9** |
| #61 | 85 of 98 traps | **P4**, **P7** |
| #63 | fixed on CI | close after review |
| #65 | slice library and switch prover landed | after the program |

Open questions
--------------

- AGENTS.md's Validation Bar still names the `rebuild` exemption (D27), which ended when `rebuild` merged as #142.
- Item rows' open clauses (I, P4, P7, SD, T) and unknown-shaped clauses (D158 `elf_stripped`, D76 chain4500) are not yet checked against code.

Next free row: D444. Unused: D292 to D304 and D334 to D337. D291 was minted in this rewrite for 71afcd35d.
