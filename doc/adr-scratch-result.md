# ADR: the scratch result

Status: S0 (D204), S1 (D200), S2 (D201), S3 (D202, in call-boundary S7) and S4 (D203) built; S5 (D205) deferred; D206 waits for its own ADR; D207 is S19, D245 to D248 (ROADMAP P7 and T; decisions D200 to D208; hand audit 3.5.1, D72 remainder 2)

## Problem

A function is declared with a value when its body leaves a scratch value in the result register.

- Hand audit 3.5.1 measured this on 541 of 670 source-void DecBench functions (81%), 49 of 59 in bzip2 -O0 and 25 of 34 in gzip -O2.
  - `to_upper` returns the last char it loaded.
  - toybox `dlist_add_nomalloc` returns `*arg0 + 8`.
- This ADR measured a second set: 35 gcc 13.3 x86-64 debug builds.
  - The builds are DecBench O2 and O2-noinline of bzip2, diffutils, findutils, grep, gzip, libexpat and zlib, plus the audit's bzip2 -O0.
  - They hold 1,383 source-void functions that return and 4,039 source-value functions.
  - In 1,317 of the 1,383 void functions the body writes RAX or XMM0 on some path to a return.
- Master's rendering invents C. Stripped bzip2 O2 `compress` (`0x49d0`) prints `uint64_t fcn_49d0(uint64_t arg0)` with 5 `return 0;`.
  - The 0 is the stack-protector check `mov rax, [rsp+X]; sub rax, fs:[0x28]`, which the frame model already elides.
  - No C expression of the source defines that 0, so printing it breaks AGENTS rule 8.
- The call-boundary ADR changes a written carrier alone to `Unproven`. Today `Unproven` renders `return r2sleigh_residual_u64(n)`, which traps.
  - That change hides the value at every return of up to 1,317 source-void functions. It also stops equivalence from comparing their output.
- The closed world proves that no caller reads a result. It does not prove the result is void.
  - Among source-value functions with a written carrier, 87 have every call site `Dead` (72 after removing `.isra` clones). Examples: bzip2 `BZ2_bzDecompressEnd`, cmp `c_stack_action`, find `explain_how_to_report_bugs`, diff `set_char_quoting`.
  - This is the "3 more silently wrong" of D72 remainder 2, measured at scale.

## Decision

A result lane is a carrier only when some return path leaves in it a byte that some C expression of the function defines. A byte on a path is `Fill::Undefined` (the same variant the call-boundary S2 adds) in three cases:

1. **Entry byte of a non-input.** The byte is the entry byte of a location that the convention says is not an input, and the body does not read it as one. On SysV x86-64 this is RAX in a body that does not read AL on entry. It never applies to AArch64 X0, SysV RDX or XMM0, which are input locations.
2. **Left by a call that states no result there.** The callee states no result in that lane and overwrites the lane on every path.
   - An import overwrites every `killedbycall` register of the cspec, and its r2abi row declares the result.
   - For a function of the image, the result comes from its `CallBoundary` (`Void`, or a `Value` in other lanes). The overwrite comes from d72's `EntrySummary::overwrites`.
   - If the callee may leave the lane untouched, the pre-call bytes flow through.
3. **Written by a compiler-inserted operation.** Today this means the stack-protector check (`stack_protector.rs`, `record_compiler_inserted`). The check is elided under `Premise::UbFreeSource`, so this void carries that premise.

Rules:

- **Void at `Decoded`.** When every byte of every result lane is `Undefined` on every return path, r2engine's `CallBoundary` states `Void { basis: Decoded, premise }`. The premise is `UbFreeSource` when case 3 applies, else none.
  - The source either is void or falls off its end on every path. C11 6.9.1p12 makes a caller's read of that undefined, so `void` is exact for every defined execution.
- **Mixed lanes.** `Undefined` joined with `Data` is `Data`. A lane that holds a defined byte on any path stays a carrier.
- **Composition.** Lanes that are `Undefined` count as unwritten. The remaining lanes follow the call-boundary ADR's rules unchanged.
  - An XMM0 lane that holds its entry byte stays `Unproven` in the open world. Under the closed world it is `Void` when every site is `Dead`.
- **Closed world on a written lane.** When a written lane holds a defined byte and every site is `Dead`, the result is `Unproven { cause: Unread }`, never `Void`.
  - This amends the call-boundary rule "When a path writes the result, the world is closed and every site is `Dead`, the result is `Void { Solved, ClosedWorld }`". The rule now holds only when every written lane is `Undefined`.
- **Value.** It stays as the call-boundary ADR states: DWARF, a declaration, or a closed-world `Read`. This ADR adds no Value source.
- **Declared callbacks (deferred, D205).** An address that flows only into parameters declared `void (*)(...)` is `Void { Declared, UbFreeSource }`. Example slots: `atexit`, `on_exit`, `__cxa_atexit`, `signal`'s handler, `twalk`, `tdestroy`, `pthread_once`, `_obstack_begin`'s freefun.

Owners:

| Fact | Owner | Readers |
|---|---|---|
| Result bytes, `Fill::Undefined` | r2ssa `lanes` (one record, `BodyBoundary.results`) | r2engine join |
| Compiler-inserted operations | r2ssa `stack_protector` (frame model) | `lanes` |
| An import's declared result, killed registers | r2abi rows, r2sleigh-lift `ProtoModel` | `SourceCallResult` on the snapshot |
| Void, Unproven cause | r2engine `CallBoundary` | r2types projection, r2dec, `afi` |

Invariant: `Void` only when no C expression of the function defines any result byte that any return leaves. No name, no call-site count and no use pattern decides it.

Complexity:

- The lanes pass is unchanged at O(ops × W). `Undefined` is one more way, inside the `MOST_WAYS` bound.
- A call output reads the callee's `SourceCallResult` in O(1).
- `CallBoundary` stays one held query per callee. A cycle yields `Unproven`, which is the least fixpoint.
- Under `aa`, each result moves up at most once, from `Unproven` to `Void`. This adds 1 to the arity height H in the call-boundary bound O(k + (s + H)·E).

## Evidence

Method:

- A standalone x86-64 dataflow over `llvm-objdump` read every function: RAX reaching definitions per return, XMM0 per return, x87 loads, and per-call-site RAX fates.
- The approximate closed world counts direct calls, tail jumps, `lea` and immediate address takes, relocation addends, exports and the entry point.
- Truth is the debug build's DWARF return type, with `DW_AT_abstract_origin` resolved.
- Base is master's engine (the audit binary, cold `pdd`) on stripped copies.

| Class | Source void | Source value | Base renders void |
|---|---|---|---|
| A. Every lane `Undefined`, open world, `Void` at `Decoded` | 196 | 0 | 65 (127 new) |
| C. RAX `Undefined`, XMM0 entry lane, every site `Dead` (closed world, call-boundary rule) | 102 | 2 | 25 (77 new) |
| B. RAX `Undefined`, XMM0 entry lane, a site not `Dead`: `Unproven` | 91 | 0 | 52 |
| A defined value on some path: `Unproven` | 994 | 4,037 | not measured |

- **Class A by evidence:** canary residue 125, tail call to a void import 55, call to a void import 6, `pop rax` 4, mixed 6.
  - Examples: bzip2 O2 `compress`, bzip2recover `bsClose`, gzip `progerror`, zlib `test_inflate`, `zcfree`.
- **Class C's 2 values:** find `visit_open_fds.constprop.0.isra.0` in the O2 and O2-noinline builds.
  - GCC's IPA-SRA removed the return of this clone, and the machine code returns nothing.
  - DWARF names the origin's `int`. The C renders the binary correctly.
- **Why the rest stays `Unproven`:**
  - 441 return a written value (loop temporary, pointer, flag word): `to_upper`, `dlist_add_nomalloc`.
  - 233 return a declared value import's result (`redundant` returns `fprintf`).
  - 200 return the result of an unproven function of the image.
  - 98 write XMM0 or x87.
  - 22 read AL on entry or call indirectly.
- **Programs named by the audit:**
  - bzip2 -O0: A 2, C 12, B 2, rest 33 (49 void).
  - gzip -O2: A 1, C 2, B 3, rest 28 (34 void).
- **Value-side cross-check (input to D206):** a write whose only reader is the return marks 3,011 of 4,039 source values. It also marks 4 source voids, and all 4 are `or al, cl; jne` flag reads the measurement does not model.

## Rejected candidates

The population is written carriers: 1,317 source void, 4,039 source value. A false void is a source value rendered `void`. The parenthesis counts the false voids that are not `.isra`, `.constprop` or `.part` clones.

| Candidate | True voids | False voids | Why it fails |
|---|---|---|---|
| Closed world, every site `Dead` | 790 | 87 (72) | An unread result is still a result: `BZ2_bzDecompressEnd`, `c_stack_action`, `run_in_dir`, `set_cloexec_flag` |
| Closed world with tail forwarders | 867 | 103 (83) | A void forwarder's `jmp g` discards g's value. It does not make g void |
| Closed world `Dead` and no sole-use write | 727 | 23 (9) | `return printf(...)` (`explain_how_to_report_bugs`) and gzip `deflate`'s tail call are values nobody reads |
| The returned write has another use (loop temporary, store address) | 216 | 20 (20) | `set_char_quoting` returns the old bit it also stores. diff3 `skipwhite` and `reverse_diff3_blocklist` return a pointer they also walk. bzip2 `uInt64_qrm10` |
| Ghidra's negative: another use or a call's output means no output | 1,217 | 1,011 (989) | `mkCell`-style `p = malloc(); p->x = 0; return p;`, plus every `xmalloc` |
| Some return path holds no defined value | 562 | 11 (2) | find `safe_atoi` returns a value on one path and falls through after `error(1, ...)` on another. C allows falling off the end |
| Declared void callback slot only | 4 | 0 | Sound, kept as D205. The yield is 4 (find `close_stdout`, grep `clean_up_stdout`) |

Byte-identical counterexamples rule out every body-local use pattern:

- `void f(char *s){ while (*s) ...; }` and `char f(char *s){ char c; while ((c = *s)) ...; return c; }` compile to the same code.
- `void f(){ g(); }` and `int f(){ return g(); }` compile to the same code.

Only bytes that no C expression defines separate void from value without a declaration.

## Ghidra

- **Output side.**
  - `ActionReturnRecovery::apply` (coreaction.cc:1908) marks an output trial active when `AncestorRealistic::execute` (funcdata_varnode.cc:2188) accepts its ancestry and `ancestorOpUse`/`onlyOpUse` finds the return is the value's only use. `ParamListStandardOut::fillinMap` (fspec.cc:1698) then picks the entry.
  - Sound part:
    - `enterNode` fails a trial whose value is an unaffected input, a non-parameter input (`!isDirectWrite`) or a flow through a call that kills the register (`isKilledByCall`). It fails and kills one whose value is an indirect creation that cannot be a call output (`isIndirectZero`).
    - These checks are this ADR's cases 1 and 2.
  - Unsound part:
    - `onlyOpUse` treats a LOAD, STORE or BRANCH use as evidence of no output.
    - `ancestorOpUse` returns false for a CALL-defined value ("A call is never a good indication of a single op use").
    - Measured above at 1,011 false voids.
  - The positive (a solid write used only by the return) is a strong Value hint, and it goes to D206.
- **`likelytrash`.**
  - It is input-side only. `ActionLikelyTrash` (coreaction.cc:2140, `traceTrash` :2047) drops the entry value of a listed register when the value flows only into INDIRECT, SUBPIECE, PIECE or a high-byte mask.
  - Only the 32-bit x86 cspecs list a register (EAX in x86gcc, x86win, x86borland, x86delphi, x86-32-golang). x86-64-gcc.cspec lists none.
  - The sound part is the convention's statement that a register's entry value is not an argument. r2s reads that fact from `<input>` and the convention row's `al`, which gives case 1. The use-pattern trace is a guess and is not adopted.

## Rendering of Unproven

- The header spells the carrier through a prelude typedef: `r2sleigh_result_u64 fcn_57b8(uint64_t arg0)`, with `typedef uint64_t r2sleigh_result_u64;`.
  - It states where the machine leaves a value and claims no C type.
- A return whose carrier value D2 spelled renders `return r2sleigh_carrier_u64(x);`.
  - The helper is the identity. It never traps, and `tests/equiv` defines it, so the output is still compared.
  - The residual ledger counts it as an `unproven-return` obligation.
- A return with no spelled value keeps today's trapping `r2sleigh_residual_u64(n)`.
- The proof line names the cause:
  - `Written`: a defined value reaches a return, and no declaration and no reading caller decide it.
  - `EntryInput`.
  - `Unread`: no call reads the result (assuming closed world).
  - `ForwardCycle`.
- `afi` prints `result: unproven (rax)` with the same cause.
- Callers declare the extern with the carrier typedef. A `Dead` site stays a call statement.
- Rejected renderings:
  - `return x;` with a value type claims a result.
  - `void` with a `/* rax = x */` comment claims no result and drops the output from equivalence.

## Slices

| Slice | What | Owner | Gate |
|---|---|---|---|
| S0 (D204) | Audit r2abi's void rows. `signal` is `func.signal.ret=void` in types.sdb.txt, but it returns a handler, so under S1 it makes a false void. Fix the row and send the radare2 fix upstream | r2abi | `audit_abi_rows.py` covers every void row; diff `sigsegv_deinstall_handler` is no longer void by that row |
| S1 (D200) | `Fill::Undefined` from cases 1 to 3. `SourceCallResult` states per lane none, pass-through or result. `CallBoundary` gives `Void { Decoded }` | r2ssa, r2engine | Engine tests that fail first: bzip2 O2 `compress` is `void`, where it now has 5 `return 0;`. A canary function whose result is kept in RBX stays non-void. A function with a `safe_atoi` path stays `Unproven`. A variadic body with entry RAX is never `void`. `jmp free` is `void`. Census lines named. d72 `void_soundness` exit 0 |
| S2 (D201) | The Unproven rendering: typedef, identity marker, cause, `afi` | r2types, r2dec, tests/equiv | Certification invents 0. Equivalence does not move. DWARF-graded count of value-typed returns in source-void functions falls by A plus C |
| S3 (D202) | Closed world on a written defined lane gives `Unread` | r2engine | The 72 plain false voids above render non-void |
| S4 (D203) | `scripts/scratch_void.py`: debug-build DWARF against r2s on the stripped copy, counts per class, fails on any `void` source value outside a named clone list. Mutants: entry-input check, a void row, inserted-operation write, the some-path join | GT | x86-64 open-world `void` at least 196 and closed world at least 298 on the 35 builds, 0 false voids |
| S5 (D205) | Declared void callback slots | r2abi, r2ssa, r2engine | 4 true, 0 false |

## Decided (2026-11-10, by the maintainer)

1. **XMM0 entry lane:** the call-boundary rule stays. An XMM0 entry byte with RAX `Undefined` is `Unproven`, because `double f(double x){ g(); return x; }` under `-fipa-ra` has the same bytes. The 52 base voids it moves are recorded in D208; the closed world decides those whose every site is `Dead` (D202).
   - Measured at #355 (x86-64 equivalence): 14 records go from `equal` to `residual-trap`, each void in the source with RAX and XMM0 as the caller left them: `and_chain_effect` clang and gcc O1, O2; `inverted_void` gcc O1, O2; `shape_stash` clang and gcc O1, O2; `total_add` clang and gcc O1, O2. Base's `equal` was luck: no fact proved the void.
   - 8 records that already trapped now trap first at a held-from-entry residual (`and_chain_effect` clang and gcc O0, `inverted_void` clang O0 to O2 and gcc O0, `crc32_init` clang and gcc O0).
   - Coverage: `_fini` and `_dl_relocate_static_pie` gain 2 gapped obligations on each of the three pinned gcc cells, and `_and_chain_effect` gains 2 on clang 17 O1 and O2. The gcc-O2 `a` equivalence shard ran 1.5 to 2 times slower per source and timed out once at 8 minutes.
   - D213 is the closed-world rule that renders these `void`.
2. **The base-void floor:** the 17 base voids that move to `Unproven` are named in S4's known list until their owner proves them. A base `void` that rests on a rejected fact is a lower bound used as an upper bound (call-boundary ADR, "Lower bounds and upper bounds").
3. **Rows:** a library row decides `void` only when D204's audit has cited it. An uncited row's result stays as base.
4. **`.isra` clones:** named only by the gate. The engine reads no names.
5. **D206 and D207:** D206 waits for its own ADR on the Value side. D207 is measured with D203 on an arm64 DWARF sample before S1 claims AArch64.

## S1 and S2 as built (2026-11-10)

What the code said that this ADR did not, and the owner chosen:

- This base has no r2engine `CallBoundary` query. Result presence stays in r2ssa `recover_interface`, its one owner today. r2types projects Written and EntryInput into `ReturnTypeFact`, and r2dec spells it.
- Case 1 is `entry_defines_nothing`: the result slot is no convention argument, and `read_on_entry` finds no use of its entry value past copies, merges, zero extensions and subpieces, other than a call's or a return's boundary read. A path that leaves the slot untouched then leaves no result. A body that reads AL, or stores entry RAX, keeps the base rule: Unproven.
- Case 2 needed no new code. `returned_by_call` already counts a complete void boundary, or a register outside the stated result, as no value. An image callee that leaves the register untouched on every path is `preserved_by_target`, so its call defines nothing and the pre-call bytes flow on. A callee that leaves it untouched on some paths only still defines it at the call. d72's `EntrySummary::overwrites` is not on this base.
- Case 3: `lanes` marks every operation in `compiler_inserted()`, and each decided check's difference, `Fill::Undefined`. `stack_protector::decide` records the differences (`checked_differences`). gcc's `xor eax, eax` scrub after storing the guard is not recorded and stays data.
- `lanes::defines_nothing` judges a returned value. Its bytes are Undefined, Zero, Sign or, under case 1, the slot's own entry bytes: the path leaves nothing. Otherwise undefined joined with data is data.
- A void tail beside direct returns joins them (`direct_returns_beside_void_tails`). `direct_return_result` answers an unproven tail only where a direct return defines a byte.
- XMM0: a written float lane that no reading call decides `Float` is `Unproven` (Written). D208: where RAX defines nothing, an XMM0 entry byte at a direct return, unwritten on a path or a merge's arm, is `Unproven` (`HandedBack`, spelled EntryInput).
- Demand was off in every void function: `FunctionLiveOut` over no storage leaves each return unresolved. `semantic::demanded` now reads no register at a void return. A written result's return that still holds the caller's RAX carries no value (boundaries `left_undefined`), renders a residual, and is left out of demand.
- D201: `ReturnTypeFact::Unproven { carrier, cause }` with `UnprovenCause` Written, EntryInput, Unread or ForwardCycle. r2types decides Written for a recovered integer `Register` result that no declaration states and no reading call chose; `SourceFunctionInterface::result_read_by_callers` marks a float, a pair or a handed-back argument the reads chose. Of r2ssa's causes, `HandedBack` alone is EntryInput, `NoReturn` names none, and any other is Written. Unread (D202) and ForwardCycle are named and not produced.
- The carrier is `r2sleigh_result_uN` at the result's observed width, not always u64: a u64 header over a 32-bit value would claim 4 upper bytes. The typedef sits in the unit's prelude, so the definition `pdd` shows starts at the header. `r2sleigh_carrier_uN` is a static inline identity among the prelude's helpers, so `tests/equiv` needs no definition of its own. A value spelled as a residual is not wrapped.
- The proof line ends `; the result is unproven (CAUSE): N unproven-return carried`. `afi` prints `result: unproven (rax, CAUSE)`.
- Under `aa` a closed-world call that reads the integer register makes a written result a value (`result_read_by_callers`): 685 source values and 7 source voids. The value claim records no `ClosedWorld` premise on the proof line yet.
- An argument register a merge hands back (AArch64 x0 = `arg0` on one path) is a spelled value: the result stays a register, its cause EntryInput (`result_holds_input`), and each return carries its value. Treating it as untouched made aarch64 `inverted_void`, `classify` and `avg` (#355) traps, and `avg`'s callers lost its float lane. A reading call decides it a value, as for one handed back.
- Left: a caller's extern keeps the callee interface's integer type (`uint32_t f(void);`), the typedef's target. A callee D208 leaves Unproven forwards that through every call or tail that returns its value; per-lane pass-through is D212.

Measured, release r2s on the 35 builds (`decbench_baseline.json`), base then head:

| Class | Source void | Source value |
|---|---|---|
| `void-open` | 230 to 272 | 6 to 2 |
| `unproven:Written` | 0 to 964 | 0 to 3,273 |
| `unproven:EntryInput` | 0 to 144 | 0 to 3 |
| `unproven:unstated` | 1,157 to 7 | 3,952 to 685 |
| `refused` | 36 to 36 | 96 to 91 |

- 169 new voids, 127 base voids moved, each named `moves` in `known.txt`: 91 XMM0 entry bytes (D208), 26 a callee's value or a written XMM0 at a return (D200), 10 a call or tail to a callee D208 left Unproven (D212).
- The 2 false voids are the named clones `insert_primary.part.0` and `add_count.part.0`. The 3 XMM0 defects are Written: `constrain_rate`, `file_sparseness.isra.0`, and `estimate_timestamp_success_rate` through its tail to `constrain_rate`. `huft_free.isra.0` and both `visit_open_fds` clones are no longer void.
- bzip2 O2 `compress` (`0x49d0`) is `void`, its 5 `return 0;` now `return;`.
- CI's shapes: `canary_void` and `tail_free` void; `sum_args` (reads AL), `identity` and `some_path` not; `bump` and `exported_void` move by D208. The mutants `entry-byte` and `inserted-write-unread` replace their base forms.
- Certification on radare2's ELF bins (24 binaries, 8 functions): 0 invented, 0 undefined reads.
- Census and goldens: 18 files, 215 headers move to the carrier typedef and their spelled returns to `r2sleigh_carrier_uN`. 13 void leaves (`_fini`, `_dl_relocate_static_pie`, `entry_fini0`) move to EntryInput with a residual return. `__do_global_dtors_aux` falls from 4 residuals to 2 in 3 builds and rises from 7 to 9 in 4 PIE builds, where its return reads a call the renderer leaves a gap.

