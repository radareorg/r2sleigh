# ADR: one owner of the call boundary

Status: accepted and built in slices, each in its "as built" section below; what is left is ROADMAP's open P7 rows and "Gap rows" (ROADMAP P7, with P4 and T slices; decisions D160 to D172 and D209; hand audit 3.2, 3.5 to 3.8; amended 2026-11-10 after round 6 of the typed-values tracks)

## Problem

No owner states, as typed data, what the ABI says at a function or call boundary. Six places each decide part of it:

- r2ssa `recover_interface` treats register parameters as a prefix of the integer registers. The cause is the `map_while` at `recover_interface.rs:1639-1655`. It never reads `float_argument_slots`. It admits the argument area only when all six integer slots are parameters (`every_register`, `:1706`). That guard is right and stays, generalized per section.
- r2engine `declared::Placement` places DWARF and library prototypes all or nothing. It stops at the first parameter that has no register (`declared/mod.rs:149-191`). `restatement` then drops the whole declaration (`:306`).
- r2ssa formal facts drop stack parameters (`semantic/boundaries.rs:1823`, `register_storage()?`). So the `pdd` header (r2types `prepare.rs:44`) and `afv`/`afi` (r2engine `program/info.rs:233`) count different lists.
- Result presence is decided per call site, from reads that stop at the first branch (`caller_reads.rs:31`). The call fact carries no callee width (`SourceCallResult`, `contracts.rs:2351`). The callee's width exists already: `recover_interface.rs:1085` narrows its result storage through `lanes::written_width`.
- The convention has two halves. Hand-written `r2abi::CallingConvention` rows hold one (`platform.rs:159`). The cspec subset that `LanguageProfile` reads holds the other (`profile.rs:63`). `native.rs:2453-2715` joins them by hand. The cspec's `localrange`, `paramrange` and `likelytrash` are dropped when the cspec is parsed.
- Library rows are radare2's sdb text, keyed by radare2's names (`assert_fail`). Bindings are bare names: r2image reads no `.gnu.version` or `.gnu.version_r`. Types reach r2types by two routes. The declared route converts an r2abi `TypeGraph` twice, to `SourceTypeGraph` (`declared/graph.rs`) and to `CTypeLike` (`declared/c_type.rs`), with no string. Every other route parses C strings: 54 `parse_c_type_like` references in 14 caller files, among them `ExternalTypeDb` member strings (`structs.rs:85`, `arrays.rs:82,133`), `data_object.rs:159`, `evidence.rs:650` and `source_spelled_type` (r2engine `lib.rs:783`).

The audit counts below were rerun on master b99f00ee0 unless marked.

| Finding | Count |
|---|---|
| 3.6.1 (W12): an unread first parameter drops the rest | 203 DecBench functions. libz (O2-noinline-libz) `0xe160` prints `uint64_t fcn_e160(void)` |
| 3.6.3 (W11): float parameters are lost without DWARF | 0 of 8 builds. fp `0x1000003c0` prints `float fcn(void)` |
| Arity above 6 shows as 6 | bzip2 `0x1bc6d`: `afi args: 7`, `pdd` 6. pigz has 9 functions above 6 |
| 3.5.1: a source-void function is declared with a value | 541 of 670 DecBench functions (81%) |
| 3.5.2: `callee() \| residual(n) << 32` | DecBench 149, `ls` 14, zlib 9 |
| 3.5.3: `int` returns are declared `uint64_t` | bzip2 -O0 15 of 17, ls-toybox 698 of 814 (not rerun) |
| 3.2.1: a linked glibc name has no row | 426 DecBench functions. pigz has 99 asserts |
| 3.2.2: `FILE` turns a prototype into `uint64_t` | `__fprintf_chk` 28 declarations over a-user. bomb `fopen`. Closes in S8 (d71 A1's rows) |
| 3.2.3: `error` has no ellipsis | 84 sites in 52 functions. Closes in S8 (`Tail::Format { index: 2 }`) |
| 3.2.4: libz.so has platform `Unknown` | 22 `__stack_chk_fail` calls are undeclared |
| 3.2.5 to 3.2.7: bionic, libstdc++, KERNEL32 | ls-toybox 703 residuals; 0pack 7,621 sites in 1,153 functions, pumasim 4,942 in 357; hello_gs 98 sites, testapp 96 |
| 3.8.1: Win64 home stores are residuals | hello_gs 71 of 246, testapp 51 of 174 |
| 3.8.2: an MSVC variadic gets 4 fixed parameters | hello_gs `main`'s only call is refused |
| 3.8.3: `/GS` is never elided | 21 functions (not rerun) |
| 3.8.4: the gcc canary entry load stays a residual | bzip2 -O0 16 of 27, bash 59, 0pack 218 |
| 3.8.5: `mov rbx,[rbp-8]; leave` | bzip2 `mapSuffix` |
| 3.8.6: AArch64 d8 to d15 saves are residuals | toybox 5 of 5 |
| W46: a caller's declaration differs from the callee's definition | 41 of 234 |

Two audit claims do not hold:

- 3.6.2 says `_exit()` drops `exit`'s status. On switch-hello-world the C is right. `__libnx_exit` calls `__libc_fini_array`, `__appExit` and `envGetExitFuncPtr` (`afi args: 0` each), so its entry x0 is dead after the caller-saved clobber at `0x8728`. It then writes `mov w0, 0x0` at `0x8738` before `__nx_exit`. `Exact(0)` matches the bytes.
- D74 says "`argument_area` stays empty". On bzip2 `0x1bc6d` this is refuted. Recovery finds the stack slot and mints 7 parameters (`recover_interface.rs:2304`). Two readers downstream then lose the seventh.

## Decision

Each fact at the boundary has one owner, and the owners form a chain:

1. r2sleigh-lift reads the cspec into `ProtoModel`.
2. r2abi states only what no cspec states, and each row carries a citation.
3. r2engine joins the two into one `ConventionModel` per `ConventionId`. The query is held.
4. r2ssa states the evidence on each side of the boundary (`BodyBoundary`, `SiteBoundary`). It mints the function's one parameter list from that evidence, from the declared prototype and from the resolved callee statements that r2engine passes in. The list r2ssa mints is the arity. No other field restates it.
5. r2engine joins the program-wide facts into one held `CallBoundary` per callee and world: result presence and width per callee, and disputes.
6. r2types projects `CallBoundary` into C types once per callee. The definition's header, `afv`, `afi` and every caller's extern declaration read that one projection. r2dec reads it and decides nothing.

Ghidra's `ParamListStandard` (`fspec.cc`) is the prior art for sections and holes. This design keeps its sections and drops four of its mechanisms, because each one invents a fact (AGENTS rule 8):

- the `maxchain=2` cap (`fspec.cc:1291`), which silently drops a real argument after 3 unread slots;
- `unref` trials passed as call arguments (`:5682`);
- the scored choice of convention (`:2706`);
- a leftover RAX from an unknown call counted as a result.

### Lower bounds and upper bounds

A fact used as an upper bound ("reads only these", "holds no code", "is signed") must come from an owner that states it complete. Otherwise the fact is a lower bound, and it may only move output toward refusal or toward base output. Round 6 of the typed-values tracks (2026-11-10) found one blocker per track, and each used a lower bound as an upper bound:

| Fact | Used as | What its owner states |
|---|---|---|
| A library row's fixed parameters | every register the import reads (d72 `import_takes`) | the reads at least. glibc `error` is variadic, and AAPCS64 has no count register, so a call may read x0 to x7 and v0 to v7 |
| `char` is `Signed` (`spelling.rs` `integer_specifiers`) | the sign on every target (d71) | the sign on SysV x86-64 only. AAPCS64 makes plain `char` and `wchar_t` unsigned |
| A section's `X` flag | the only place code lies (d70 gate) | where the linker marked code; `section(".x,\"aw\"")` puts code in a `WA` section |
| 920 drawn arguments | proof that `never_returns` ignores arguments (d75) | 920 cases. The signature `never_returns(&CStmt)` can read any argument |

The rule closes each case at its owner:

- An import whose row is not cited complete reads every argument location of its convention. A `Tail::None` row is complete only when its citation states a fixed prototype. Rows parsed from radare2's sdb are `Tail::Unstated` until cited (S8).
- The sign and width of `char` and `wchar_t` come from the target's C data model (below). A target the model does not list leaves the sign unstated, and the pointee spells as base did.
- Code lies in the file bytes a loaded segment maps past the headers (the d70 gate's D70 row).
- A predicate that depends only on the callee takes only the callee, so a mutant that reads an argument does not compile (D75 row).

### What the cspec states (r2sleigh-lift)

`Prototype` (`profile.rs:63`) becomes `ProtoModel`. It already reads `outputs`, `extension`, `position` and `<varargs>` (`profile.rs:46-80`). S1 adds `localrange`, `paramrange` and `likelytrash`, and types `extension`:

```rust
pub struct ProtoModel {
    pub id: ConventionId,
    pub input: Box<[ParamEntry]>,          // pentry order
    pub output: Box<[ParamEntry]>,         // x86-64-gcc: XMM0_Qa, XMM1_Qa, RAX, RDX; AARCH64: x0, x1, q0 to q3
    pub unaffected: Box<[SpecStorage]>,
    pub killed_by_call: Box<[SpecStorage]>,
    pub likely_trash: Box<[SpecStorage]>,
    pub local_range: Box<[StackRange]>,    // Win64 8..39 (x86-64-win.cspec:129-132)
    pub param_range: Box<[StackRange]>,
    pub stack_shift: u32,
    pub extrapop: ExtraPop,
    pub variadic_on_stack: bool,           // <varargs first="0">, AARCH64_apple
}
pub struct ParamEntry {
    pub class: SlotClass, pub at: SpecStorage, pub size: RangeInclusive<u8>,
    pub align: u8, pub extension: Extension, pub group: u16,
}
pub enum SlotClass { Integer, Float, Stack }
pub enum Extension { Zero, Sign, IntType, Unspecified }
```

Every cspec element is either read into a field or refused by name. The every-element test runs over each cspec a `ConventionId` selects: `x86-64-gcc`, `x86-64-win`, `AARCH64` and `AARCH64_apple`. The other ten vendored cspecs (`AARCH64_win`, `_ilp32`, `_golang`, `x86-64-golang`, `x86-16`, `x86-32-golang`, `x86borland`, `x86delphi`, `x86gcc`, `x86win`) are refused by name until a `ConventionId` selects one. The `<rule>` elements `join_dual_class`, `hidden_return`, `convert_to_ptr` and `join_per_primitive` (AARCH64 `<output>`) are refused by name until a slice reads them.

### What only the ABI states (r2abi)

```rust
pub enum ConventionId { SysVAmd64, Win64, Aapcs64, AppleArm64, I386Cdecl, /* ... */ }
impl ConventionId { pub fn radare2_name(self) -> &'static str }  // "amd64", "ms" for afi
pub struct ConventionRow {
    pub id: ConventionId,
    pub cspec: (&'static str, &'static str),  // file and prototype name; was `prototype`
    pub frame_pointer: Option<RegName>,       // read by native.rs:2493, declared/frame.rs:67
    pub red_zone: u32,
    pub count_register: Option<RegName>,      // SysV al
    pub save_area: Option<RegisterSaveArea>,  // SysV reg_save_area, AAPCS64 __gr_top
    pub home_va_list: Option<HomeVaList>,     // Win64: va_list = &home[first unnamed]
    pub entry_stack: Option<EntryStack>,
    pub refused: Option<&'static str>,        // read by native.rs:1223
    pub overrides: &'static [SpecOverride],   // a cspec claim the ABI contradicts or omits
    pub citation: &'static str,
}
pub enum SpecOverride {
    Results { lanes: &'static [RegName], citation: &'static str },   // SysV 3.2.3: xmm0, xmm1, st0, st1
    Extension { class: SlotClass, extension: Extension, citation: &'static str },
}
pub enum CLibrary { Glibc, Bionic, Musl, LibSystem, Ucrt, Unknown }
pub enum Kernel { Linux, Darwin, Windows, Unknown }
pub enum GuardRow {                              // was CallingConvention.stack_bound, keyed by CLibrary
    ThreadSlot { base: RegName, offset: u32 },  // glibc x86-64 fs:0x28
    LinkedGlobal { symbol: &'static str },      // matched only to a binding the container states
    LoadConfigCookie,                           // PE load config SecurityCookie
}
pub struct LibraryRow {
    pub library: LibraryId, pub linked_name: Box<str>,
    pub prototype: PrototypeId, pub tail: Tail, pub noreturn: bool, pub citation: Box<str>,
}
pub enum Tail {
    None,                                     // the citation states a fixed prototype
    Unstated,                                 // no citation yet: reads every argument location
    Variadic,                                 // `...` with no format or va_list parameter
    Format { index: u8, kind: FormatKind },   // glibc __attribute__((format(printf|scanf, i, j)))
    VaList { index: u8 },                     // vprintf, __stdio_common_vfprintf
}
pub enum LibraryId { Iso, Posix, Glibc, Bionic, LibSystem, Ucrt, Dll(Box<str>) }
```

- `RegName` is resolved once, when the model is built. A name that does not resolve fails the conformance test. This replaces the `&str` lookups at `native.rs:2633`.
- `variadic_on_stack` lives in `ProtoModel` only. The cspec states it.
- d72's `result_registers` (`xmm0`, `xmm1`, `st0`, `st1`) become the `SpecOverride::Results` row cited from SysV 3.2.3. The cspec's `<output>` has no ST0 and no ST1, and d72's `ld.c` and `ldb.c` void-soundness golds depend on them.
- Library rows stay data files in `crates/r2abi/data/`. They are parsed once into `LibraryRow`, and d71's `cited_rows.rs` grades them. `Tail` replaces the format test by parameter name and `contains("char")` (`declared/mod.rs:425-446`).
- A row from Itanium mangling states parameters only. A non-template mangled name encodes no return type, so its result is `Unproven`.
- Handle types are data rows. ISO C 7.21.1 states that `FILE` is an object type. d71 A1 adds the `FILE` and `DIR` handle rows beside `named_scalar`. S8 moves any tag still in code (`spelling.rs:285`) into those rows.
- `Platform`'s two meanings split by retyping `platform()` (`program/mod.rs:570`) into `CLibrary` and keeping `kernel()` (`:603`) as `Kernel`. `CLibrary` picks the library and guard rows. `Kernel` picks the syscalls and the psABI. `stack_guard` is keyed on `kernel()` today (`native.rs:2701`) while it cites glibc. Under the split it is keyed on `CLibrary`.
- An import reads its row's fixed locations. Under `Unstated`, `Variadic`, `Format` or `VaList` it also reads every later argument location of the convention, bounded only by a count register the convention states (SysV `al` bounds the vector registers). AAPCS64 and Win64 state none, so all of x0 to x7 and v0 to v7, or all four shared positions, are read. Apple arm64 passes the tail on the stack (`variadic_on_stack`), so only the fixed registers are read there.
- glibc evidence for an ELF with no `PT_INTERP` is `DT_NEEDED libc.so.6` together with a `.gnu.version_r` need of `GLIBC_*` on that library. r2image reads the version needs and per-symbol versions into `Container` (a `VersionNeed` and a symbol `version`). Today `Container` has `libraries` and no versions (r2image `lib.rs:998-1016`).

### The C data model (r2abi)

A C type spelled in a row or in DWARF has a sign and a width only on a target. `Width::Long` and `Width::Pointer` already resolve per target (`spelling.rs`). The sign of plain `char` and the sign and width of `wchar_t` do not: `integer_specifiers` makes `char` `Signed` everywhere, and `named_scalar` makes `wchar_t` signed 32-bit on Linux.

```rust
pub struct CDataModel {                 // one row per (arch, CLibrary), cited
    pub plain_char: ScalarKind,         // SysV x86-64 Signed; AAPCS64 Unsigned; Apple arm64 Signed
    pub wchar: (ScalarKind, Width),     // glibc x86-64 (Signed, 32); glibc aarch64 (Unsigned, 32); Win64 (Unsigned, 16)
    pub long: Width, pub pointer: Width,
    pub citation: &'static str,
}
```

- `ScalarKind` gains `PlainChar`, resolved by the model as `Width::Long` is. `signed char` and `unsigned char` keep their stated sign.
- A target the model does not list resolves `PlainChar` to no sign. The type then spells as base spelled it, and the proof line names the missing row.
- The conformance test compiles an empty file with each listed target's compiler and reads `__CHAR_UNSIGNED__`, `__WCHAR_TYPE__`, `__SIZEOF_LONG__` and `__SIZEOF_POINTER__` from `-dM -E`. A row that disagrees fails the test.
- One model serves row types, DWARF base types without `DW_ATE_signed_char`/`DW_ATE_unsigned_char`, and the r2types projection. No second table states a sign.

### The joined model (r2source type, r2engine query)

```rust
pub struct ConventionModel {                // query keyed (target, ConventionId), Held
    pub id: ConventionId,
    pub sections: Box<[Section]>,       // SysV, AAPCS64: [Integer, Float, Stack]; Win64: [Shared, Stack]
    pub results: Box<[ResultLane]>,     // cspec <output> plus SpecOverride::Results
    pub owned: Box<[OwnedRange]>,       // who owns each entry-relative stack range
    pub preserved: Box<[LaneSet]>,      // d8 is v8 bytes 0..8
    pub killed: Box<[LaneSet]>,
    pub likely_trash: Box<[LaneSet]>,
    pub forms: BoundaryForms,           // save area, home va_list, count register, entry stack, guard
}
pub struct Section { pub class: SectionClass, pub locations: Box<[Location]> }
pub enum SectionClass { Integer, Float, Shared, Stack { first: i64, step: u32 } }
pub enum Location {
    Register { storage: CanonicalStorageId, bytes: u8 },
    Stack { offset: i64, bytes: u32 },
}
pub enum OwnedRange {
    Callee(Range<i64>), Home { position: u8, at: Range<i64> },
    Arguments(Range<i64>), ReturnAddress(Range<i64>),
}
pub struct LaneSet { pub storage: CanonicalStorageId, pub bytes: Range<u8> }
```

- A function's `ConventionId` comes from container or DWARF facts: PE gives `Win64`, Mach-O arm64 gives `AppleArm64`, `DW_AT_calling_convention` and `ms_abi`/`sysv_abi` attributes give theirs. The target default applies otherwise. No score chooses it.
- The stack is a section of its own. Under SysV, a MEMORY-class argument and the ninth float reach the stack while integer registers are still free. Under AAPCS64, an HFA overflow does the same. So a stack read proves nothing about registers, and rule 4 below admits a stack parameter only behind a full section.
- `ConventionModel` replaces seven holders of the same facts:
  - `SourceConventionSlots` (`contracts.rs:4115`);
  - the convention half of `SourceCallEffect` (`:3862`);
  - the envelope of `SourceStackAllocationContract` (`:520`);
  - the argument and return registers of r2ssa `MachineAbiModel` (`machine_context.rs:54`);
  - `r2ssa::abi::AbiProfile`, read also by `interproc/mod.rs` and `interproc/dependence.rs`;
  - r2types `RegisterIdentity::argument_registers` (`register_identity.rs:24`);
  - d72's `CallingConvention.result_registers`.
- During the item, the old contracts are read-only views of the model. `slot_promotion.rs:93`, `frame_reach.rs:146`, r2dec `values.rs:2672` and the two `interproc` readers keep compiling. The views are deleted at the item's exit (S34). Until then the Dylint `convention_view_read` (D309) denies a production reader outside its allowlist, 136 `(file, item)` pairs at D309, and the list only falls.
- `ConventionModel::owner(offset)` is the one rule for the caller's region. It replaces three rules: `contracts.rs:562`, `function/mod.rs:1527` (`caller_frame_offset`, read also at `info.rs:357` and `caller_stack_slots.rs:37`) and `slot_promotion.rs:677`.

### Evidence (r2ssa)

```rust
pub struct BodyBoundary {                       // in PreparedFunctionFacts, one per body
    pub slots: IdVec<SlotId, SlotUse>,          // every location of every section
    pub floor: Option<SourceArityFloor>,        // D37, type unchanged
}
pub enum SlotUse {                              // total order, lowest first, for the fixpoint
    Unread,                                     // includes a read that folds to a constant
    Homed { loaded: bool, escapes: bool },      // the entry value stored to its home
    SaveArea,                                   // read only by the variadic save area
    HandedOn { bytes: ByteMask, to: SmallVec<[CallSiteId; 2]> },
    Read { bytes: ByteMask },                   // the entry value is used
    Unknown(SourceFloorCause),
}

pub struct SiteBoundary {                       // one per call site; d72's SiteFate
    pub written: IdVec<SlotId, ByteMask>,       // evidence only, never arity proof
    pub fates: IdVec<LaneId, LaneFate>,
}
pub enum LaneFate { Dead, Read(ByteMask), Returned(ByteMask), Unknown }
```

- Result bytes reuse `lanes::Byte` (`lanes.rs:63`: `Data`, `Widened`, `Filled{Zero, Sign, Entry}`). No second byte lattice exists. S2 adds one `Fill::Undefined` for the bytes a callee's declaration leaves undefined above its width.
- Saves are not part of `BodyBoundary`. They are the frame model's `SavedRegister` role (doc/adr-frame-model.md), which reads `ConventionModel::preserved` and `owned`.

### The function's parameters (r2ssa mints them, r2engine supplies the inputs)

`SourceAbiParameterSpec` (`contracts.rs:246`) gains the fields it lacks. It stays a serialized cross-function contract in r2source, which depends only on r2il, so it carries no `ValueId` or `ObjectId`:

```rust
pub struct SourceAbiParameterSpec {
    index: u32,
    location: SourceParameterLocation,  // Register or Stack, unchanged
    class: SlotClass,
    bytes: u8,
    basis: Basis,                       // DebugInfo | Declared | Decoded | Solved | Convention
}
pub struct DeclaredPrototype {          // r2engine builds it; r2ssa places it
    parameters: Box<[DeclaredParameter]>, // class from the declared type, or why none
    arrivals: Box<[Option<Arrival>]>,   // DWARF location at the first instruction
    nocall: bool,                       // DW_CC_nocall
    result: Option<DeclaredResult>,
    tail: Tail,
    basis: Basis,                       // DebugInfo or Declared
}
```

`FormalHome::Register(ValueId) | Frame(ObjectId)` lives in r2ssa formal facts (`PreparedFunctionFacts.boundaries.parameters`), indexed by the spec's `index`.

One placement rule, `place(&ConventionModel, &[ParamClass]) -> Placement`, lives in r2ssa and serves the declared route, the recovered route and bodiless imports. It counts each class on its own, or by position where positions are shared. It places stack locations past the registers. Where a class has no location (`long double`, a record passed by value), it returns the placed prefix plus a typed floor. It keeps today's arrival check (`arrivals_hold`, `declared/mod.rs:233-256`): a DWARF arrival that disagrees with the placed location refuses the declaration for this body (`.isra`, `.constprop`). `DW_CC_nocall` refuses convention placement; r2image reads `DW_AT_calling_convention` for it. The step from a type to its class is r2ssa `ParamClass::of`, over the declaration's interned `SourceTypeGraph` node (S32a as built).

r2ssa applies the parameter rule to each section, reading `BodyBoundary.slots`:

1. A `Read` at position k makes positions 0..k of that register section parameters.
   - A `HandedOn` slot counts as a read when the resolved callee statement reads that slot. r2engine passes those statements in from today's `aa` fixpoint (`resolved.rs:345`). The slot takes `Basis::Solved`. `Basis::Handed` keeps its own meaning (`confidence.rs:71`: a function address handed to a function-typed parameter).
   - A slot handed to an unproven call is a D37 floor. The floor names only the calls that the slot reaches.
2. A slot below k with no use is a parameter at `Basis::Convention`, with `ty: None`. It spells as the residual type of its section's class and width, so recompiled C places it in the same register. The rule has no cap.
3. A read counts for rule 1 only when it is attributable to the entry value:
   - A read that folds to a constant (`xor edx, edx`, `x - x`, `x & 0`) is `Unread`.
   - A homing store with no load and no escape is `Homed`, not a read. A `Homed` slot above the read prefix adds a floor cause `Homed`, because -O0 homes declared parameters the body never uses.
   - A read that only the variadic save area reaches is `SaveArea`.
   - Any other read of an unproven kind is `Unknown(cause)`. The section above the last proven slot then stays `AtLeast(k)` with that cause.
4. The stack section runs alone, with one guard. The highest stack offset read makes the stack slots below it parameters only when a register section it can overflow from is full: every integer location is a parameter (integer class, today's `every_register`), or every float location is (float class). Otherwise the arity is a floor with cause `ArgumentAreaRead` (D37), and the stack reads stay residuals. A declaration that states a MEMORY class places the slot through `place`. An argument-area address that escapes in a function with a proven save area (`overflow_arg_area`) is `SaveArea` for the stack section and gives no fixed stack slot.
5. Across sections, parameters render in convention order: integer, float, stack.
   - Under rule 4 every stack parameter follows a full register section. So recompiled C places each argument where the body reads it (SysV 3.2.3, AAPCS64 6.8.2).
   - The rule never claims the source order. The proof line says "convention order" and names the `Convention` basis.
6. Win64 shares positions, so it has one `Shared` section.
   - A hole in a shared position has no class. Position alone places it, so it spells as the integer residual.
   - A home whose address escapes starts a variadic tail only when the pointer reaches a `Tail::VaList` parameter of a declared callee (UCRT `__stdio_common_vfprintf`). Any other escape (`/Od` `g(&b)`) homes a fixed parameter, and the count past the last read is a floor with cause `Homed`.

The per-slot `Basis` records where each parameter came from:

- `DebugInfo` for DWARF whose arrivals hold;
- `Declared` for a library row;
- `Decoded` for a read of the entry value;
- `Solved` for a slot that a resolved callee statement reads;
- `Convention` for a hole.

D73 and D71 A2 read this basis.

Formal facts keep stack parameters. `boundaries.rs:1823` mints a `FormalHome::Frame` for each one. So `[rbp+0x10]` is a parameter, and `CertifiedEntity::Parameter` covers it.

r2ssa mints the final list. The `aa` fixpoint's last preparation, with the callee statements it settled on, is the artifact `pdd`, `afv` and `afi` read. Formal facts and parameter certificates read the list where it is minted, so no second prepare pass feeds a list back in.

### The callee's boundary (r2engine)

```rust
pub enum CalleeKey { Entry(u64), Import(ImportId) }
pub enum World { Open, Closed }                 // Closed only under aa
pub struct CallBoundary {                       // query keyed (CalleeKey, World), Held
    pub convention: ConventionId,
    pub interface: Arc<SourceFunctionInterface>, // r2ssa's mint, or place() over an import's row
    pub result: BoundaryResult,
    pub disputes: Box<[Dispute]>,
}
pub enum BoundaryResult {
    Void { basis: Basis, premise: Option<Premise> },
    Value { lanes: Box<[ResultLaneFact]>, basis: Basis },
    Unproven(SourceUnprovenResult),
}
pub struct ResultLaneFact { pub lane: LaneId, pub width: SourceResultWidth }
pub struct SourceResultWidth { pub logical: u8, pub above: SourceAbove }  // r2source
pub enum SourceAbove { Zero, Sign, Undefined }
```

The arity is `interface.arity`. `CallBoundary` holds no second count.

The authority order is the same for each slot and for the result:

1. DWARF for this function, when its arrivals hold and it is not `DW_CC_nocall`.
2. The body's proof.
3. A library row, applied through an import binding.
4. The convention.

A source that loses becomes a `Dispute` and leaves refusal evidence. Caller writes never raise the arity of any callee. A register written before a call may be scratch reuse, so the write proves no read. No owner computes them: S31b deleted `SiteBoundary.written` (D321), which had no reader.

Result presence follows six rules:

- A declaration states the result.
- When no path writes a result lane and no lane holds an entry byte of an input location, the result is `Void` at `Decoded`.
- A lane that holds an entry byte of an input location (`Fill::Entry`: arm64 x0, SysV rdx and xmm0) is `Unproven`. `long keep(long x, long y){sink=y; return x;}` and `void f(long x, long y){sink=y;}` have the same bytes, so neither `Void` nor `Value` is proven.
- `Value` needs DWARF, a declaration, or a site fate of `Read` under the closed world (`Solved`, premise `UbFreeSource`). A `Returned` fate forwards to the caller's `CallBoundary` (d72 `forwarded`, `reads.rs:123-155`). A cycle of forwarders is `Unproven` with cause `ForwardCycle`. An open world, or `Unknown`, with a written carrier stays `Unproven`. `Unproven` renders as today (`returns.rs:94`), at the seed's width.
- When a path writes the result, the world is closed and every site is `Dead`, the result is `Void { Solved, ClosedWorld }`. Today this applies to `Unproven` results only (d72). A written lane that holds a defined byte is `Unproven { cause: Unread }` under the closed world, never `Void` ([scratch-result](adr-scratch-result.md), D202).
- A pair or a single register is decided per callee (D62). A site that does not read the high half reads the low half, and nothing is invented.

Result width follows five rules:

- `logical` is one past the highest `Data` or `Widened` byte of the joined bytes. This is `lanes::written_width` today (`lanes.rs:427`).
- `above` states the bytes above `logical`: `Zero` or `Sign` where every byte is that fill on every path, `Undefined` otherwise. A body's implicit zero above a 32-bit write (`Fill::Zero`) is the machine's, so a caller read above renders that proven extension.
- A returned `CallDefine` reads the callee's width. S2 copies the callee interface's observed size into `SourceCallResult.width` in `mint_recovered_call_site_interface` (`:2441`). `lanes` reads it as `logical` Data bytes and `Fill::Undefined` above. Today `lanes.rs:406-412` reads it as `Rule::Whole`. r2dec reads the width and stops rebuilding it from a parsed return type (`calls.rs:189`).
- Bytes a caller reads above an `Undefined` byte stay a residual. No zero or sign extension is invented, and r2dec's `a_declared_result_read_wider_holds_a_residual_above_it` keeps this.
- `ReturnTypeFact::unproven` (`returns.rs:94-102`) reads `SourceResultSeed.bits`, not the carrier width.

A cold `pdd` runs at `World::Open` and joins no sites. A caller's extern then reads the callee's r2ssa interface at `Decoded`. An undeclared import has `Unknown` arity, and its written slots render as residual evidence, never as `foo()`.

### Types on the wire

`SourceTypeGraph` with `TypeId` is the one carrier of types from r2abi rows and DWARF into r2types:

- r2engine converts an r2abi `TypeGraph` once (`declared/graph.rs`). `declared/c_type.rs`, the second converter from the same graph, goes.
- One converter in r2types builds `CTypeLike` from `SourceTypeGraph`. `CTypeLike` stays as r2types' internal model.
- `source_spelled_type` (`lib.rs:783`), the `ExternalTypeDb` member strings and every other production caller of `parse_c_type_like` go. A Dylint holds the references at the definition in `convert.rs` alone, with an allowlist that only falls.

### Owners and readers

| Fact | Owner | Readers |
|---|---|---|
| Locations, output, unaffected, killed, local and parameter ranges, `variadic_on_stack` | r2sleigh-lift `ProtoModel` | r2engine model build |
| cspec choice, frame pointer, red zone, `al`, save area, home `va_list`, entry stack, refusal, overrides | r2abi `ConventionRow` | r2engine model build |
| Guard | r2abi `GuardRow`, keyed by `CLibrary` | r2engine model build |
| Library prototypes and tails by linked name | r2abi `LibraryRow` | r2engine `Declared::import` |
| Sign of plain `char`, sign and width of `wchar_t`, `long`, pointer | r2abi `CDataModel` | row and DWARF type conversion, r2types projection |
| Registers an import reads | r2ssa `place` over the row and its `Tail` | `CallBoundary`, d72's site fates |
| Version needs, symbol versions, `DW_AT_calling_convention` | r2image `Container` | r2engine binding and convention choice |
| C library and kernel | r2engine, from `Container` | row selection |
| `ConventionModel` | r2engine query, Held, per `ConventionId` | r2ssa recovery, placement, promotion, frame reach, frame model |
| Slot use, floor | r2ssa `BodyBoundary` | r2ssa minting, r2engine join |
| Bytes written before a call, result fates | r2ssa `SiteBoundary` | r2engine join |
| Placement | r2ssa `place` | r2ssa minting, r2engine imports |
| Parameter list, arity, per-slot basis | r2ssa `SourceFunctionInterface` | formal facts, certificates, `CallBoundary` |
| Formal homes | r2ssa formal facts | certificates, promotion, r2dec |
| Result presence and width, disputes | r2engine `CallBoundary` | r2types projection, `afv`, `afi`, call sites |
| C types of parameters and result | r2types projection of `CallBoundary` | header, `afi`, caller externs, r2dec |
| Parameter class at render | `SourceAbiParameterSpec.class` | r2dec |
| Parameter names | r2engine `declared_parameter_names` | r2s spells them; r2types reads them |
| Saved registers | r2ssa frame model `SavedRegister` | promotion, certificates, `afv` |

## How each audit finding closes

| Finding | Closes by | Owner | Slice |
|---|---|---|---|
| 3.2.1 linked names | Rows keyed `(LibraryId, linked_name)`, bound through the import's version. The radare2 keys `assert_fail`, `errno_location`, `libc_start_main`, `cxa_throw`, `libc_init` and `uClibc_main` are deleted | r2image, r2abi | S8 |
| 3.2.2 `FILE` | d71 A1's handle rows and `TagScope::opaque`, moved into S8 with the rest: an `Unknown` parameter type no longer drops the prototype (`declared/mod.rs:276`, `function_type`'s `?`) | r2abi, r2engine | S8 |
| 3.2.3 `error` | The row cites `error(3)`: `(int, int, const char *, ...)`; glibc's `format(printf, 3, 4)` makes it `Tail::Format { index: 2 }` | r2abi | S8 |
| 3.2.4 libz.so | `DT_NEEDED libc.so.6` together with a `GLIBC_*` version need selects glibc | r2image, r2engine | S8 |
| 3.2.5 to 3.2.7 | bionic rows, libstdc++ parameters from Itanium mangling with `Unproven` results, KERNEL32 keyed by `Dll` plus name | r2abi | S13 |
| 3.5.1 to_upper | Under `aa`, every site is `Dead` and the callee does not escape, so `Void { Solved, ClosedWorld }`. The scratch case follows [scratch-result](adr-scratch-result.md) (D200, D202). A cold `pdd` keeps the written carrier as `Unproven` | r2engine | S7 |
| 3.5.2 `\| residual << 32` | The callee's width on the `CallDefine` means a tail into `strcmp` writes 4 Data bytes and `Undefined` above. The header is 32-bit and its sign is D156's | r2ssa, r2engine | S2 |
| 3.5.3 `int` as `uint64_t` | The call-defined part closes with S2. The lift's `COPY:8` of a `mov eax, imm` constant makes 8 Data bytes, so it stays D74's | r2ssa | S2, D74 |
| gzclose `uint64_t` for `-2` | `unproven` reads the seed's bits | r2types | S2 |
| 3.5.4 vector reductions | Not a boundary fact (T, W47) | T | none |
| 3.6.1 W12 | Section rule 2. libz (O2-noinline-libz) `0xe160` becomes `(arg0, arg1, arg2)`, with arg0 at `Convention`. The caller's argument for arg0 is a typed "slot the callee ignores" residual | r2ssa | S6 |
| 3.6.2 `_exit` | No change. libnx is `Exact(0)` by its bytes. A glibc `_exit` import gets the row `void _exit(int)` | none | S8 |
| 3.6.3 W11 | The float section runs the same rule. fadd becomes `float fcn(float, float)` | r2ssa | S6 |
| Arity above 6, stripped | Stack formals as `FormalHome::Frame`. `afi`, the header and the `cmp eax, arg6` read one list | r2ssa | S5 |
| Arity above 6, DWARF | `place` puts the seventh at `Stack{8,4}`, so the declaration and its names survive | r2ssa | S4 |
| 3.6.4 signedness | D156 writes into the one list's `ty` | T | D156 |
| 3.6.5 pointers | D71 A2 and D74 read the per-slot `Basis` | r2types | S6 |
| 3.6.6, W46 `afv`/`pdd` | One list and one name owner | r2engine | S5 |
| W46 caller declaration ≠ callee definition | The caller's extern reads the callee's projection, and `CalleeFacts::derive` (`lib.rs:1157`) projects under the root's context. The carrier-width extern (`input.rs:166`) goes | r2types, r2dec | S7 |
| 3.7.1 struct-field calls | A DWARF member of function-pointer type is placed by `place` at the call. Stripped builds stay residual | r2ssa, r2engine, r2image | S32 |
| 3.7.2 C++ virtual calls | Stay residual until vtables are recovered (P9, LP) | none | none |
| 3.7.3 tail jumps | `return callee(args)` once `CallBoundary(callee)` is stated. 267 of 376 follow 3.2 (205 after a residual call, 62 after `error`). The other 109 have no closer in this ADR and stay residual | r2engine | S8 |
| 3.8.1 Win64 home | `localrange` 8..39 becomes `OwnedRange::Home`. The homing store is a callee-owned save and the reload is no stack parameter | r2sleigh-lift, r2ssa | S10 |
| 3.8.2 MSVC variadic | A home whose address reaches `__stdio_common_vfprintf`'s `Tail::VaList` starts the tail. UCRT printf becomes `(fmt, ...)` | r2abi, r2ssa | S10 |
| 3.8.3 `/GS` | r2image reads the load-config `SecurityCookie`. The check callee is proven by its body, and its name decides nothing | r2image, r2ssa | S10 |
| 3.8.4 canary entry load | The decided check's `reload - guard` is 0 where it is defined (`stack_protector.rs`, `decide`), so a returned carrier holding it does not observe the load. This does not depend on D72 | r2ssa | S11 |
| 3.8.5 `rbp`-relative restore | One `SavedRegister` role resolves `rbp`-relative reloads through the frame base. An lldb session first decides whether the reload is not reached or removed as dead | r2ssa | S11 |
| 3.8.6 d8 to d15 | `preserved` holds `LaneSet { v8, 0..8 }`, cited from AAPCS64 6.1.2. A `d8` store is a lane save | r2ssa | S11 |

## What is deleted

- Parameter logic:
  - the `in_order`/`map_while` prefix (`recover_interface.rs:1639-1655`); `every_register` (`:1706`) becomes rule 4's full-section test;
  - the `HandedOn` list of every unproven call (`:1734`).
- Placement:
  - `declared::placed_prefix`, `placed` and the all-or-nothing `restatement` (`declared/mod.rs:149-191`, `:306`); `arrivals_hold` moves into `place`;
  - r2dec `carrier_class` (`values.rs:2656`).
- Argument-register copies: the argument and return halves of `MachineAbiModel`, `r2ssa::abi::AbiProfile`, and `RegisterIdentity::argument_registers: Vec<String>`.
- The formal-facts filter on stack parameters (`boundaries.rs:1823`).
- Parameter lists and names: the argument rebuild in `info.rs:233`, and the second numbering in r2s `function.rs:125`.
- Results (S7 re-cites the lines; the shelved d72 branch removes `direct_reads` and most of `reads_after`, and S7 takes that code):
  - `body_proven_return` and `with_body_proven_return` (`lib.rs:1120`, `:1163`);
  - the per-site Pair or Register choice in `mint_recovered_call_site_interface`;
  - the tie-break by address in `decide_prototypes`;
  - the `result_ambiguous` bool (`machine_context.rs:474`);
  - the remaining per-body `reads_after`.
- Callee signatures, once `CalleeKey::Import` exists:
  - `known_function_signatures: HashMap<String, _>` (`native.rs:1300-1328`), filled from `Declared::import`;
  - r2types `CalleeIdentityContext.by_name` (`callee.rs:114`);
  - `PointerParameters::body_summary` (`pointers.rs:121`).
- Strings:
  - `calling_convention: String` in `SourceFunctionInterface`, `SourceCallSiteInterface` and `SourceConventionSlots`;
  - `CalleeFact.signature_callconv`;
  - `param_type`/`ret_type: String` and `ExternalTypeDb`'s member strings;
  - every production caller of `parse_c_type_like`, plus `declared/c_type.rs` and `source_spelled_type`;
  - the format-name and `contains("char")` test (`declared/mod.rs:425-446`) and `is_function == "func"` (`prototypes.rs:167`).
- ABI duplicates:
  - the r2abi fields the cspec states;
  - d72's `result_registers`, now a cited override row;
  - `StackGuard.register: &str`;
  - any `handle_tag` code left after d71;
  - the radare2 unprefixed keys.
- Frame duplicates:
  - three caller-region rules become one;
  - `slot_promotion::saves` and `structural_save` fold into `SavedRegister`.

## Cost

- **`ConventionModel`:** O(L) to build, with L ≤ 60 locations. Built once per `ConventionId` and held. Each lookup is O(1).
- **`BodyBoundary`:**
  - It is the current recovery pass, O(values + uses).
  - Float slots and the stack slots a function reads join the same scan: at most 8 float slots plus the stack slots read.
  - The section rule is O(L).
  - The constant-fold check reads the existing fold, O(1) per read.
- **`SiteBoundary`:** d72's backward worklist, O((B + E) × lanes). A visit budget gives `Unknown`.
- **The `aa` fixpoint:** today `resolved.rs:356-357` states O(k + (s + 6)·E) preparations, 6 being the arity height. Assumptions now rise along `SlotUse`'s total order and `lanes::Byte`'s join, whose height is `MOST_WAYS + 2` = 6 per byte; `written_width` rounds to powers of two, so a lane's width rises at most 5 times. The height is H = Σ register locations (6 + 8 on SysV) + S + 5·R, where S is the stack slots read (fixed per body) and R the result lanes. The bound is O(k + (s + H)·E). Expected in practice: arity and width each rise once or twice per cycle, as today; S3 measures it.
- **`CallBoundary` join:**
  - O(sites of the callee), read from a held reverse call index, and O(call sites) per program under `aa`. Forwarding through `Returned` reads the caller's held entry, O(1) each.
  - A cold `pdd` is `World::Open` and joins nothing.
- **Measured before S3:**
  - bash `0x2e630`: `aa; pdd` is 19.43 G instructions, `aa` 7.38 G and a cold `pdd` 0.66 G.
  - The extra cost is the first `ReferenceIndex` build (`requests.rs:781`), not `Walked`'s retention. "S3 as built" has the split.
- **Held index:** the index lifts each body once and is held. The lifted blocks are not held. "S3 as built" has the numbers.
- **Callee preparation:** already 47 to 84% of a cold `pdd`. This design adds none on the cold path. Under `aa` it adds the preparations the H bound allows.
- **Gates:**
  - release `pdd` and `aa; pdd` on 0pack `0x62ecf0` and pumasim `0x23fdf0` within 2%;
  - peak RSS within 5% for a cold `pdd` and within 10% after `aa`;
  - D153: `aa; pdd` within twice `aa` plus a cold `pdd`, and `aa; pdd` output byte-identical before and after S3. Cold and `aa` output differ by design since D72.

## Slices

Slice 0 is Order step 7: d70-gate and d75's follow-up land, each after its one structural fix. The d71 and d72 branches are shelved (see Fate). S2, S3, S8 and S14 touch other crates and stack beside S1. Each slice deletes its old path in its own PR.

| # | Slice | Owner | Gate | Deletes |
|---|---|---|---|---|
| S1 | `ProtoModel` parses `localrange`, `paramrange` and `likelytrash`, and types `extension`. `ConventionRow` with each field's home, `SpecOverride::Results`, `ConventionId`, `ConventionModel` query per id, the function's id from container and DWARF. Old contracts become views | r2sleigh-lift, r2abi, r2engine | Census and goldens byte-identical. Equivalence unmoved on x86-64 and aarch64. A conformance test per selected cspec. The every-element test over four cspecs. d72's `ld.c` and `ldb.c` void golds unmoved. `afi` names unchanged | r2abi fields the cspec states, d72 `result_registers`, convention `String`s |
| S2 | `SourceCallResult.width`, copied from the callee interface's observed size at `:2441`. `Fill::Undefined`. Lanes read a `CallDefine` as `logical` Data bytes plus `Undefined`. `unproven` reads the seed | r2ssa, r2engine, r2types | DecBench `residual_u64(n) << 32` from 149 to ≤ 5, each with a cause. diff `0x9e70` prints `return strcmp(...)`. r2dec's read-high-half test kept. `native.rs:5188` | r2dec width rebuild at `calls.rs:189` |
| S3 | pumasim profiled first. Then compact index rows and fates held from `aa`'s walk (D153's design) | r2engine | D153 on bash, pumasim and 0pack. `aa; pdd` byte-identical before and after. dhat RSS bound | Second walk of `ReferenceIndex` |
| S4 | One `place` for the declared, body and import routes, with stack placement, the arrival check and `DW_CC_nocall` (r2image reads `DW_AT_calling_convention`). Partial DWARF keeps its placed prefix plus a typed floor. D105: the boundary names the low lane of an entry carrier as the argument where the callee holds only that lane | r2image, r2ssa, r2engine | bzip2 -g `0x1bc6d` has 7 parameters with DWARF names. `__libc_start_main`'s seventh places. 32 `arity.rs` tests. `.isra`/`.constprop` refusals unmoved. D105's `a_declared_integer_is_read_at_its_width_not_the_registers` un-ignored, its five corpus functions `uint32_t`, 0 pointers turned into integers on bash, ls-toybox and pigz | `placed_prefix`, `placed`, all-or-nothing `restatement`, `carrier_class` |
| S5 | `FormalHome::Frame` stack formals in r2ssa formal facts. One list for `pdd`, `afv` and `afi`. One name owner | r2ssa, r2engine, r2s | bzip2 stripped `0x1bc6d`: `afi args: 7`, header 7, `cmp eax, arg6`. `frame_agree.py` does not fall | `boundaries.rs:1823` filter, `info.rs:233` rebuild, `function.rs:125` numbering |
| S6 | `BodyBoundary` section rule with the read refusals, rule 4's full-section guard, the argument-area save area. Per-slot `Basis`. `HandedOn` limited to the calls reached. Hole arguments as typed residuals. D100's floor carried to the header's proof line | r2ssa | libz (O2-noinline-libz) `0xe160` 3 parameters. fp fadd, dmul and dcmp true prototypes. Certification: 0 invented arguments (W7), hole arguments counted apart, 0 invented variadic parameters (W14). D37's engine test that refuses `f(stack0)` kept. D100's `fcntl` test. Equivalence. d70 soundness floor (43%, 21%) holds or rises | `map_while`, `MachineAbiModel` argument half, `AbiProfile`. The prefix test at `:3006` becomes its negative test |
| S7 | `CallBoundary` keyed `(CalleeKey, World)`: result presence per callee (D62), d72 fates with byte masks and forwarding, entry-lane `Unproven`, caller externs from the callee's projection, `CalleeFacts::derive` under the root's context, cold externs at `Decoded` | r2engine, r2types, r2dec | bash `0x61520` D62 gate. pumasim `png_free`. `shape_mutual_even` and `shape_mutual_odd` equal. An arm64 engine test: `keep` never `void`. d72 round 7's aarch64 `e1.c`, `e2.c` and `d.c` print base's declarations. `void_soundness`, `mutants_d72.py`, `result_reads.rs`. W46 caller mismatches from 41 of 234 to 0 or each named | `body_proven_return`, remaining `reads_after`, `known_function_signatures`, `by_name`, `body_summary`, `result_ambiguous`, `input.rs:166` |
| S8 | r2image version needs and symbol versions. Library rows by linked name with `Tail`. `CLibrary` and `Kernel` as the retyped `platform()` and `kernel()`. `GuardRow`. An `Unknown` parameter keeps the prototype (D151) | r2image, r2abi, r2engine | pigz `__assert_fail` declared and its 99 asserts end control. libz.so `__stack_chk_fail` declared. printf-family tails from `Tail::Format`. `error` is `Tail::Variadic`, every sdb row `Unstated` until cited. `cited_rows.rs`. `library_named_type` falls | radare2 keys, d71 duplicate rows, `Platform`'s two meanings, the format-name test |
| S9 | `SourceTypeGraph` into r2types through one converter | r2types, r2engine | Production `parse_c_type_like` references from 54 in 14 caller files to the definition alone, under a Dylint with a falling allowlist. Census judged | `c_type.rs`, `source_spelled_type`, `param_type`/`ret_type` and `ExternalTypeDb` strings |
| S10 | Win64 forms: `OwnedRange::Home`, the `va_list` escape tail, `printf.rs` and `tail_count` on the `Shared` section and `HomeVaList`, `/GS` through the load config (D154) | r2sleigh-lift, r2abi, r2image, r2ssa | hello_gs `main` prints printf with 2 arguments, given a cited `__stdio_common_vfprintf` row. Home residuals from 71 to 0. Cookie reads elided where the check body is proven. A Win64 equivalence target | `MICROSOFT_X64` fields `localrange` states |
| S11 | ELF forms: edge-conditioned canary observation, `SavedRegister` aware of lanes and the frame base (D155) | r2ssa | One engine test per form. bzip2 -O0 `FS_OFFSET` residuals from 16 to 0. `mapSuffix` clean. toybox d8 to d15 5 of 5 clean. `frame_agree.py` rises | `slot_promotion::saves`, `structural_save` |
| S12 | Indirect calls through a DWARF function-pointer member of a pointer parameter, placed by `place` (built by S32; members past parameter roots are D348) | r2ssa, r2engine, r2image | zlib `inflateEnd` renders both `ZFREE` calls. Certification invented arguments stay 0 | none |
| S13 | Data rows: bionic, libstdc++ parameters from mangling with `Unproven` results, KERNEL32 once cited rows exist | r2abi | ls-toybox: 0 residuals at `__errno`, `__strchr_chk`, `__open_2`, `getline`, `_exit`, `dup2` (of 703). 0pack (7,621 sites) and pumasim (4,942): every mangled callee states its parameter count. hello_gs (98) and testapp (96): each cited KERNEL32 row's sites declared | none |

| S14 | `CDataModel` per `(arch, CLibrary)` with citations; `ScalarKind::PlainChar`; `wchar_t` from the model | r2abi | The `-dM -E` conformance test per listed target. d71 round-7 probes: aarch64 `mkdir`, `strnlen`, `unlinkat`, `regexec`, `error_at_line` and `wcsdup` parameters never `int8_t*` or `int32_t*`. x86-64 output unmoved | the fixed `Signed` default for `char`, `named_scalar`'s `wchar_t` |
| S34 | Delete the views: `SourceConventionSlots`, `SourceCallEffect` with `SourceBoundaryReads`, `RegisterIdentity::argument_registers`, the `callconv` and `calling_convention` strings (to `ConventionId`), `CalleeFact.signature_callconv`, `AdvisoryCallPrototype`, `reg_type_hints` | r2source, r2ssa, r2types, r2engine | `convention_view_read`'s allowlist empty; the lint goes with the views. Until S34, the lint (D309) holds the readers to 136 `(file, item)` pairs at most | the views and strings |

S4 to S7 are P7's single signature item. S10 and S11 are P4 slices.

## Fate of rows and branches

- **D37:** kept. `ArgumentAreaRead` stays as rule 4's floor cause (readers at `resolved.rs:108,680`, `arity.rs:592`). Its engine test stays: a stack read with an unfull register section is no parameter. `RegisterRead` now means a read whose kind is unproven (rule 3). `HandedOn` lists only the calls a slot reaches.
- **D62:** absorbed by S7. The join moves to r2engine, because it is a program query. r2types projects it. The row text is amended.
- **D71 (`d71-prototypes`, shelved at 856416c26 on 2026-11-10):** seven review rounds each found a new blocker in row typing. Round 7 found aarch64 `const char *` parameters printed `int8_t*` where base printed `uint64_t`. The branch is the code source for three slices:
  - A1's handle rows (`FILE`, `DIR`) and the compile gate move to S8. 3.2.2 and 3.2.3 close there, with `error` as `Tail::Format { index: 2 }` (S8 as built).
  - A2, pointer types from a declared row, moves after S6 and S14. It reads the per-slot `Basis` and the model's `char` sign.
  - A3 stays with T.
- **D100:** fix (b), the floor in the header, lands in S6. Fix (a) is not taken: shown tail registers are caller writes, which never prove arity.
- **D105:** moves to S4. Its fix is a placement and narrowing rule. Its test stays ignored until S4.
- **D106:** independent of this ADR (r2dec's ledger). It keeps its row and timing.
- **D72 (`d72-return-fates`, shelved at f40057e78 on 2026-11-10):**
  - Six review rounds found 1 to 7 blockers each in per-instruction lane rules. The round-6 strict core kept only site fates and the closed-world void. Round 7 found 13 false voids on aarch64 plus 3 in the gate's own `d.c`: `error`'s row has no ellipsis, so `import_takes` read only x0 to x2 and the caller's d0 became `Dead`.
  - S7 builds `SiteBoundary` from the branch's `site_fates`, with byte masks and forwarding. Import reads come from `place` under the bounds rule above.
  - S1 turns its `result_registers` into the cited `SpecOverride::Results` row.
  - S7's gate adds round 7's repros (`e1.c`, `e2.c`, `d.c` built for aarch64): every one prints base's declaration.
  - Its "Return storage" invariant and its closed-world ADR stay in doc/adr-resolved-bodies.md.
- **D73:** B1 reads `SlotUse::Read { bytes }` and the per-slot `Basis` that D165 mints. The row text is amended. It stays with T after S6.
- **D74:**
  - The stack-argument item closes in S4 and S5. Its premise ("`argument_area` stays empty") is refuted.
  - The `COPY:8` constant item stays D74's.
  - The dereferenced-pointer item stays D74's.
  - The silent `void` item stays D74's.
- **D151, D153, D154 and D155:** each keeps its row and gate, D153's restated. Their designs are D167, D162, D169 and D170.
- **d70-gate:** lands first, after its floor counts every DWARF function whose entry lies in file bytes a `PT_LOAD` maps, less the ELF and program headers (a PIE's first load starts at 0, where `--gc-sections` leaves its tombstone). Section flags decide nothing. It grades S4, S6 and S9.
- **d75-noreturn-guard:** lands after `never_returns` takes the callee alone. S8 carries `noreturn` on `LibraryRow`.
- **The "`_exit` is `AtLeast(1)`" gate** (hand audit section 6, item 9): dropped. A glibc static `_exit` probe replaces it.

## Refusals

- **An unread slot below a read one:** declared at `Convention` with `ty: None`, spelled as its class's residual type. It is never typed `uint64_t` or `double`. A Win64 shared-position hole has no class.
- **A hole's argument at a call site:** a typed "slot the callee ignores" residual with no dataflow. The caller's reaching value is not shown, because `jmp second` after `a*7` leaves the entry `a` in rdi. Certification counts these apart from W7.
- **A read not attributable to the entry value:** a floor `AtLeast(k)` with a typed cause. It never fills a hole.
- **A homing store with no load:** a floor cause `Homed`. It is no parameter and no hole.
- **A stack read:** fills only the stack slots below it, and only behind a full register section. Otherwise `ArgumentAreaRead`. It claims no register.
- **A stack read past 64 unread slots:** the slots up to the 64th hole stand and the arity is a floor with cause `ArgumentAreaPastBudget`, so one load at `[rsp + 0x40000000]` costs `O(reads + 64)`, never a record per slot.
- **Caller writes:** evidence only. They are never arity proof, for a callee with a body or without one.
- **Indirect calls with no stated type:** residual. Virtual calls stay residual too.
- **A library row:** applies only through an import binding. A versioned import binds to the library its version names. An unversioned import binds at `Declared` only where the container's `DT_NEEDED` names one C library. A PE import binds the DLL its directory names and a Mach-O import the dylib its two-level namespace ordinal names; a library no table states binds nothing (S20). A name match on a static body applies nothing (AGENTS rule 6).
- **DWARF whose arrivals disagree with placement, or `DW_CC_nocall`:** no declaration for this body; a `Dispute` with refusal evidence.
- **A `DW_AT_calling_convention` code no model has:** the function is refused; it is never placed under the default (S20).
- **Void:** only with no written lane and no entry byte on a result lane, or under a proven closed world with every site `Dead`. Exports, taken addresses, variadic callees, unresolved branches, budget `Unknown` and forwarding cycles keep the carrier as `Unproven`. The scratch-result case follows [scratch-result](adr-scratch-result.md).
- **Value:** only from DWARF, a declaration, or a closed-world `Read` fate. A written carrier alone is `Unproven`.
- **Bytes read above an `Undefined` result byte:** stay a residual.
- **`mov eax, imm`:** compilers emit it for a small 64-bit constant (B8+r, 5 bytes). The lift's `COPY:8` makes all 8 bytes Data, so the width stays 8 until D74.
- **An unplaceable declared class** (`long double`, a record by value): the placed prefix plus a floor that names the class.
- **A Win64 home escape that reaches no `Tail::VaList` parameter:** no variadic tail; the count past the last read is a floor.
- **`/GS`:**
  - Without a load-config cookie, the check stays a residual.
  - Without a proven check body, the check stays a residual.
  - `__security_check_cookie` decides nothing.
- **An AArch64 `__stack_chk_guard` read** with no binding the container states stays a residual.
- **A returned canary carrier** with no passing edge that proves it is 0 keeps its residual (ADR P4.4).
- **cspec against ABI:**
  - AArch64 `extension="zero"` contradicts AAPCS64, which leaves the upper bits unspecified. Apple arm64 extends arguments narrower than 32 bits to 32 bits.
  - The width above `logical` stays `Undefined` there until a `SpecOverride` row or an upstream fix settles it.
  - Every override is listed and tested.
- **`libc.so` with no `GLIBC_*` need:** stays `Unknown`, because musl and bionic both use that soname.
- **A mangled libstdc++ row:** parameters only; the result is `Unproven`. Where the name encodes no result, or names a base-object structor, it places nothing on a convention whose first argument register could hold a hidden result pointer or a VTT (S13 as built, PR #349 review).

## Rejected objections

- Soundness 1 asks for `Value` on an entry-filled result lane. `keep` and `void f(long x,long y){sink=y;}` have the same bytes, so the lane is `Unproven`. The negative test (never `Void`) is kept.
- Coverage 6 asks that only a declaration narrow body width. `written_width` already narrows on implicit zeros (`lanes.rs:427`, `recover_interface.rs:1085`). The zeros are the machine's, so the narrowed C stays value-equivalent, and `above: Zero` states the fact.
- Coverage 2 asks that a forwarding cycle give `Value`. A cycle proves no read, so it is `Unproven`, which renders the same carrier.
- Coverage 1 asks to invert D37's test. `ArgumentAreaRead` stays, so the existing test already refuses `f(stack0)`.
- Coverage 8 asks to name a closer for 109 tail jumps. No owner in this ADR closes them; they stay residual and listed.

## Decided (2026-11-09, by the maintainer)

- **Name base:** `arg0`. The one name owner numbers from `arg0`, as `pdd` does; `afv` and `afi` change to match, and the census does not move.
- **Unversioned imports:** an unversioned ELF import binds at `Declared` where the container's `DT_NEEDED` names exactly one C library. The binding rests on that container fact, never on the name alone.
- **Static library bodies:** no row applies to a statically linked body by its name (AGENTS rule 6). Such a body is typed only from its own evidence.
- **Scratch-result void:** its rule-8 ADR is written now, beside S1 ([scratch-result](adr-scratch-result.md), D200 to D208).
- **Slots against C parameters:** the proof line counts a hole run as slots, not C parameters, so a by-value record or an `__int128` spanning `rsi:rdx` states what is proven and names no C type.
- **AArch64 and Apple `extension`:** cited `SpecOverride` rows now; the vendored Ghidra spec fix goes upstream as its own pull request, and the override is deleted when the vendored core moves to it.
- **KERNEL32 and UCRT rows:** a row cites the Microsoft API reference page for the function (header and minimum version). Until a row exists the import stays residual.
- **Held-index RSS:** peak RSS after `aa` within 10% of today's, measured with dhat before S3 lands.
- **musl:** `CLibrary::Musl` reads only the ISO and POSIX rows until a cited musl table exists.
- **D105 timing:** D105 moves to S4 (D163). d71 merges with the five known `uint64_t` headers (bash 4, pumasim 1) recorded in its row.

## Decided (2026-11-10, by the maintainer)

- **Design before branches:** the d71 and d72 branches stop taking review rounds. Their blockers belong to owners this ADR defines, so the slices rebuild them: d71 into S8, S14 and after S6; d72 into S7. d70 and d75 each take one structural fix and land.
- **Bounds:** the "Lower bounds and upper bounds" rule above applies to every slice's review.
- **C data model:** S14 (D209) adds `CDataModel` to r2abi beside S1.

## S1 as built (2026-11-10)

What the code said that this ADR did not, and the owner chosen:

- None of the four graded cspecs states `paramrange` or `likelytrash`. x86-64-gcc states `localrange` only in a non-default prototype. `likelytrash` appears in x86gcc, x86win and three ungraded i386 cspecs. `ProtoModel` reads all three anyway.
- A cspec's prototypes are not conventions: x86-64-gcc's `__thiscall` and `syscall` have no `ConventionId`. So `ProtoModel` carries the cspec's `name`, and the id lives in `ConventionRow` and `ConventionModel`.
- `ParamEntry.size` is `RangeInclusive<u32>`: the stack entry's `maxsize` is 500. `align` is `Option<u32>`.
- `SlotClass` gains `HiddenReturn` (AARCH64 `x8`, `storage="hiddenret"`). `Extension` gains `Float` (13 vendored `extension="float"` entries).
- `ConventionModel` lives in r2source and holds r2abi's `ConventionId`, so r2source and r2sleigh-lift gain an r2abi edge. r2abi stays the leaf; it gains serde for `ConventionId`.
- `ConventionRow.cspec` names a toolchain (an `.ldefs` compiler id, or the container's) and a prototype, never a file: the language picks the file (AppleSilicon or v8A). A PE under cdecl, AAPCS32 or AAPCS64 reads x86win, ARM_win or AARCH64_win, as before.
- Five of the "other ten" cspecs are selected today: x86gcc (`I386Cdecl`), x86win and AARCH64_win (a PE), x86-64-golang and AARCH64_golang (Go). Refusing them would move i386, PE and Go output. The every-element test grades all nine selected cspecs and names the five no id selects.
- Ids beyond the sketch: `Aapcs32`, `RiscVLp64`, and arch-specific Go ids (`GoAmd64`, `GoArm64`, their `Abi0`, and `Unstated`, which refuses).
- `SpecOverride::Results` states a class (SysV 3.2.3's SSE and X87 lanes are float). `SpecOverride::Extension` states a side: AAPCS64 C.16 covers arguments and, by 6.9, results; Apple's 32-bit extension covers arguments only.
- `MachineAbiModel`'s argument and return registers, and `AbiProfile` built from them, read the function's interface parameters (`machine_context.rs:94-118`), not the convention. They are no convention holders; they go with the one parameter list (S5, S6). `RegisterIdentity::argument_registers` reads `SourceConventionSlots` (`machine_context.rs:1029`), so it is a view once the slots are.
- The model adds `hidden_return`, `reserved` (platform rows), `link` and `refused`. `BoundaryForms` adds the frame pointer, red zone, `variadic_on_stack` and Go's stack bound. `Location::Register` adds class, position and extension. `ResultLane` says whether the cspec or an override states it, and the call effect reads the cspec's lanes only, as before.
- The query is keyed by `ConventionId` alone: a program fixes the target, and ARM and Thumb share one register file.
- d72's `result_registers` and its `ld.c`/`ldb.c` golds are on the shelved branch, not this base. The override row has no reader until S7.
- `home_va_list` waits for S10 and `GuardRow` for S8. `StackGuard.register` is a `RegName` now.
- Left for later: `AdvisoryCallPrototype` has no producer and is typed, not removed; `SourceSignaturePresentation`'s convention is always `None`; r2types `callconv` strings are spelled from `radare2_name()` until `CalleeFact.signature_callconv` goes.

## S8 as built (2026-11-10)

What the code said that this ADR did not, and the owner chosen:

- `LibraryRows` (r2abi `library.rs`) parses each table once per program's `CLibrary` into `LibraryRow`s keyed `(LibraryId, linked_name)`. `Prototypes` and `Platform` are deleted.
- `LibraryId` is `Portable`, `Glibc`, `Bionic`, `LibSystem` or `CxxRuntime`. The sketch's `Iso` and `Posix` fold into `Portable`: a lookup never tells them apart, and the citation names the standard. `Ucrt` and `Dll` wait for S13's rows.
- `Tail::VaList` carries the format its citation names: `vfprintf` is GCC's `format(printf, 2, 0)`. `FormatKind` adds `WidePrintf` and `WideScanf`. The engine counts only narrow formats, because no format reader here reads a wide literal.
- `error` is `Tail::Format { index: 2 }`, not `Variadic`. glibc's `error.h` declares it `format(printf, 3, 4)`. On d72 round 7's aarch64 `e1.c` and `e2.c`, base printed `error(0, 0, "%f")` and dropped d0 at 8 sites. S8 leaves each site a residual (`floating_variadic_argument`): no argument invented, none dropped. `Variadic` gives the same residual there and loses the count where the tail is integer.
- The printf and scanf families, `err`, `syslog`, the fortified `__*printf_chk` and the twenty `va_list` functions moved into the cited tables to state their tails. radare2's other rows are `Unstated`.
- The format test by name is deleted for DWARF bodies too. A wrapper's format now comes from its body: r2ssa binds a callee's body-proven format at each call (`recover_interface.rs`), and the body proves it through a cited `va_list` row. pigz `try_throw_` forwards `fmt` to `__vsnprintf_chk`, so its 91 calls still count their tails. Base rendered 93: the 2 more were a duplicated tail behind an `__assert_fail` base thought returned.
- `va_list` spells as a typedef over a pointer to an opaque state. Every graded convention passes it as a pointer: SysV's one-element array decays, AAPCS64's 32-byte struct goes by reference, and Microsoft's and Apple's are `char *`. Without this, the twenty rows stayed unplaced.
- Binding lives in r2engine `imports::Imports`:
  - `GLIBC_*` binds glibc's rows.
  - bionic's `LIBC` and `LIBC_*` on its `libc.so`, `libm.so` or `libdl.so` bind bionic's.
  - `GLIBCXX_*`, `CXXABI_*` and `GCC_*` bind the C++ runtime's rows only. Any other version binds none.
  - An unversioned ELF import binds at `Declared` where `DT_NEEDED` names exactly one of `libc.so.6`, `libc.so` or `libc.musl-*.so.1`.
  - Mach-O and PE imports bind as before, because the format names libSystem or Microsoft's runtime. S13 keys a PE import by its DLL.
  - A versioned binding is also `Declared`.
- Two readers typed a body by its name: `hands_a_function` and `handed_functions` called `name_at`. They read `import_at` now. A program's own `atexit` body hands nothing.
- glibc from `DT_NEEDED libc.so.6` and a `GLIBC_*` need applies wherever no evidence names a library, not only without `PT_INTERP`.
- `GuardRow` has `ThreadSlot` only: glibc and musl x86-64 (`fs:0x28`), glibc i386 (`gs:0x14`). `LinkedGlobal` and `LoadConfigCookie` wait for S11 and S10. A bionic or unknown-library ELF loses `fs:0x28`, because no row cites it.
- `CDataModel`, `spelling.rs`'s type names and the handle rows are keyed by `CLibrary`. Syscalls, `platform_registers`, `ConventionId::default_for` and Go's first systems are keyed by `Kernel`.
- D151's `Unknown` parameter: `function_type` keeps the prototype with that slot `Unknown`, and r2types' width check accepts it. An `Unknown` result still states nothing.
- The registers an import reads are `Placement::reads`. SysV reads all 14 argument registers and `al` under a tail. AAPCS64 reads 16, Microsoft x64 reads 8, and Apple arm64 reads the fixed ones under a cited `...`. No reader exists until S7.
- d71's `TagScope::opaque` and r2dec's handle typedefs are not taken. Without A2, no call or definition here spells `FILE *`; calls keep their carriers as d71's D109 did. `c_type.rs` keeps the handle's name over its tag.
- d71's compile gate (`scripts/compile_check.py`) and its unit test run in CI. The binary step waits: pigz fails one unit at base and head (`int-conversion` into `struct Node *`), which is A2's.
- r2ssa's second format-by-name test (`function/mod.rs`, `parameter_names_a_format_string`) is on the snapshot path. The native capture passes no callee signatures, so it decides nothing. It goes with S9's strings.

## S13 as built (2026-11-10)

What the code said that this ADR did not, and the owner chosen:

- `LibraryId` gains `Dll(Dll)`, where `Dll` is `Kernel32` or `Ucrt`, not `Dll(Box<str>)`. `LibraryId` stays `Copy`, and a DLL no cited table states has no id. `Dll::of` matches a module name ignoring case. `Ucrt` covers `ucrtbase.dll` and every `api-ms-win-crt-*` set.
- A PE import binds by the DLL `Symbol::library` names (r2engine `imports::Linkage`). KERNEL32 reads only its own table. A UCRT DLL reads its table, then the C++ and portable rows as before. Any other DLL binds as before S13.
- bionic's rows are a cited table, `types-bionic.sdb.txt` (136 rows), each read from bionic's `libc/include` header. They sit beside radare2's `types-android.sdb.txt`, not in the portable table: a POSIX function there would claim glibc and libSystem declare it alike, which was not checked (libSystem's `getgrouplist` takes `int *`, bionic's `gid_t *`).
- bionic's `FILE` is `struct __sFILE` and `DIR` is `struct DIR` (`stdio.h`, `dirent.h`). `dev_t` is `long`'s width, `clockid_t` 32-bit signed, and `nfds_t` and `speed_t` 32-bit unsigned. `mode_t` stays opaque: 16 bits on 32-bit ARM and x86, 32 on the 64-bit targets. So `mknod`, `mkdirat`, `fchmodat`, `mknodat` and `__umask_chk` are `import-unplaced`.
- KERNEL32's 53 rows cite their `learn.microsoft.com` page on `.cite=` with the minimum supported client. Spellings use Microsoft's type names, which `spelling.rs` reads for `CLibrary::Ucrt` as "Windows Data Types" defines them. `LARGE_INTEGER` reads as `long long`: Microsoft x64 passes an 8-byte union as that integer. `ExitProcess` is noreturn because its page says it ends the calling process.
- `__stdio_common_vfprintf` has no Microsoft reference page. Its row cites the Windows 10 SDK's `corecrt_stdio.h`, with tail `va_list(4,printf,2)`.
- r2abi `mangled` reads an Itanium name's parameters, including templates, whose first type is the result (5.1.3). No demangler was in the tree. A reference is its pointer. A class or enum by value stays opaque and unplaced, because the name does not say whether it is trivially copyable. `Dp`, `J`, `X`, vendor types and local names refuse the whole name.
- The mangling states `this` only for a constructor, a destructor, a conversion, a cv- or ref-qualified member, and an operator other than new, delete, `()` and `[]` of a scope the name proves a class. Any other nested name can be a namespace function, a static member or a non-static one: `std::_V2::generic_category` is the first, `ios_base::xalloc` the second. `data/cxx-objects.txt` states those 52 from the declaring header (libstdc++ 13.3, OpenCV 4.x). A name it does not list gets no row: pumasim's 5 NEWMAT callees (9 sites).
- Mangled rows are built once per program from the container's imports (`LibraryRows::read_mangled`, O(imports x name length)) under `LibraryId::CxxRuntime`. They apply to any C++ import, libstdc++'s or another library's: the name is the ABI's statement, and a body's name still binds nothing. The return type is refused, so the result is `Unproven` and `function_type` states no signature.
- PR #349 review: a row that does not state its result must not place arguments where a result returned in memory passes a hidden pointer in an argument register (Itanium C++ ABI 3.1.3; SysV x86-64 `rdi`, Microsoft x64 `rcx`). `LibraryRow::passing` (`r2abi::Passing`) records it:
  - `Stated`: a template or conversion whose encoded result is `void`, a builtin, a pointer or a reference; a complete-object constructor (C1) or destructor (D0, D1), which return nothing.
  - `HiddenResultUnstated`: every other name, such as `Big foo(int)` mangled `_Z3fooi`, and a template returning a class by value. r2engine `Placement::placed_prefix` places nothing unless the convention's `hidden_return` is outside its argument registers (AAPCS64 x8), and `reads` treats the tail as `Unstated`.
  - `VttUnstated`: a base-object constructor or destructor (C2, D2), which takes a VTT after `this` for a class with virtual bases (2.6.2), and C3, D4 and D5. It places nothing on any convention. No cited row states a class has no virtual base yet.
  - The call stays an `import-unplaced` residual with its parameter count in the refusal evidence.
- With no declared signature, r2dec derives each call's extern from its own arguments. Calls to one callee that disagree are `declaration-disagrees`: 0pack's mangled callees 374 to 1,222, pumasim's 630 to 690. A signature with an `Unproven` result is S7's per-callee result presence.
- Gates (release, `aa` then `pddj` of every `afl` function, base `e616a0b87`):
  - ls-toybox: `__errno` 81, `__strchr_chk` 62, `__open_2` 26, `_exit` 12, `dup2` 11 and `getline` 0 fall to 0. Import-call residuals fall from 666 to 195; all residuals from 5,823 to 4,019.
  - 0pack: undeclared mangled sites fall from 7,621 (118 callees) to 0. About 3,088 render; 3,634 are `import-unplaced` (a result or VTT the name does not state on x86-64, or an enum or class by value) and 860 `declaration-disagrees`.
  - pumasim: 4,942 (50 callees) fall to 9, all at NEWMAT. About 2,852 render; 2,016 are `import-unplaced` and 60 `declaration-disagrees`.
  - hello_gs: 98 KERNEL32 residuals fall to 26; testapp: 96 to 28. Every one of the 53 rows binds. 16 and 18 are `import-unplaced`: a row with more than four parameters needs Win64 stack placement (S4). 10 and 10 are `argument-operand`, a frame address passed.
- 5 functions newly refuse and 1 renders, all on unaccounted effect obligations (`live-value-producer`, `volatile-or-unknown` at a register phi) once a call is declared: ls-toybox 2, hello_gs 1, testapp 2. 0pack's 5 went with the review fix. The owner is r2ssa's effect accounting, not the rows.


## S2 as built (2026-11-10)

What the code said that this ADR did not, and the owner chosen:

- `SourceCallResult::Register` carries `width: SourceResultWidth`. `Pair` carries none: both of its registers are the value. `SourceCallResult::register(storage)` is the whole register, which is base behaviour.
- The width is `SourceFunctionInterface::result_width()`: the low bytes of the stated integer logical value (signed, unsigned or plain `char`). A body's value is its observed size joined over every return path; a declaration's is its declared integer. A float, a pointer or no logical value leaves the register whole. `mint_recovered_call_site_interface`, `with_exact_callee_interface` and `CalleeStatement` copy it; an unproven callee's carrier stays whole.
- Every producer states `above: Undefined`. `Zero` and `Sign` exist, and r2dec renders them as the extension, but no producer states them until `BodyBoundary` (S6, S7). So a body's implicit zero above a 32-bit write is still no fact a caller reads; native.rs `a_staged_call_to_a_carried_callee_is_declared_at_its_carriers_widths` and `bits_above_a_declared_narrower_result_are_never_zero` hold that.
- `lanes` reads the width when the record is captured, before any rewrite: `CallResults` holds each narrower call by the instruction it was lifted from, built once from the machine context and searched in O(log calls). The `CallDefine` of the stated register is `logical` Data bytes and `Fill::Undefined` above. Every other register the call clobbers stays Data; the scratch-result ADR's case 2 (D200) owns those.
- A tail transfer is no `CallDefine`. `TailResult::Exact` narrows the observed size to the tail callee's width, and tails into one register join (the widest value, a fill both state).
- r2dec reads `CallPlan.width`. The declared C type only spells the value. A declaration narrower than the width keeps the bytes above it a residual, since C computes no bit past its type. `from_declared` stays for declared globals and reads the same rule at the global's width.
- `ReturnTypeFact::unproven` reads the seed's bits. Every return of an unproven result renders a residual, so a narrower header hides no value.
- The `native.rs:5188` gate is `crates/r2engine/tests/engine/native.rs` `a_call_through_a_halting_slot_has_no_edge_to_the_join_after_it`. The stripped tail is `a_tail_transfer_to_a_declared_int_returns_the_callees_width`.
- The header is `uint32_t` (its sign is D156's), so the tail renders `return (uint32_t)strcmp(...)`: C's own conversion at the return, spelled.
- Demand names a tail-transfer exit (`demand::exits_are_named_beside`): where every tail transfer's boundary is complete, has fixed arguments and states a narrower width, the exit reads each argument and the result lane's `logical` bytes. A tail callee whose width is whole or unknown leaves the body unnamed, as base.
- Gate, DecBench O2 and O2-noinline, non-bash (2,621 functions): `residual_u64(n) << 32` in 142 functions on base, 158 on S2 (O2 68 to 67, O2-noinline 74 to 91). Read by hand: diff `0x9e70` prints `return (uint32_t)strcmp(...)`; `compare_names`, `rpl_fseeko` (`fileno`), `BZ2_bzclose` (`ferror`) and zlib `test_gzio` (two `strcmp`) lose the residual, each value read only in its low four bytes.
- What remains is no width fact. In 28 hits read: a call that does not come back ends the body outside the walk (the `Call` block's fallthrough is no block), an unresolved jump table (`IndirectBranch`), a return the live-out walk cannot resolve, a tail callee of whole width (`fputs`, `FILE` unknown, S8), and 64-bit returns on another path (D74). Naming the call that does not come back clears 41 more (to 117) but makes five getopt `main`s refuse (`live-value-producer` at the switch's table load unaccounted by r2dec's ledger), so it waits for its own row.


## S3 as built (2026-11-10)

What the profile said that this ADR did not, and the design taken from it:

- Holding `Walked` saves nothing. On pumasim, 67 of 15,365 walks repeat (0.4%).
- The extra cost of `pdd` after `aa` is the first build of `ReferenceIndex`. `ResultReads`' closed-world check asks for it, and a cold `ax` costs the same as `aa; pdd`.
- Base split of pumasim `aa; pdd` (147.9 G instructions): the survey 63.7 G and the index 84 G. The index spent 30.0 G lifting each body through `Walked`, 34.5 G decoding it again for the listing (19.7 G of lift, 13.1 G of spelling), 8.9 G annotating, 7.7 G on pointer parameters and 3.2 G indexing.
- Rows built in `aa`'s walk are not taken. The discovery trace keeps no lift, so the rows would need every body's lift held until the survey ends. They would also move about 33 G of annotation and pointer-parameter work into every `aa` on pumasim.
- The index stays a held query built on first demand, and lifts each body once. `body::listed_body` keeps each instruction's lift, decode window and decoder context. `query::decode::walked_listing` annotates those decodes, so nothing is decoded again.
- A body whose dispatch tables the survey holds is walked once, through them. Others walk first and read their tables only where the walk stops at a dispatch, as `Walked` does.
- A line is spelled only where a claim or a computed number reads its operands (`Disassembler::spell`). A line with no claim never reaches the index.
- A lazily spelled line starts from a fresh decoder context. Inside a Thumb `it` block its text can differ from `pdf`'s; x86-64 and AArch64 keep no such context.
- The index still holds each claiming line whole, for `ax`'s text. Compact rows that spell at display wait for a reader that needs the memory.

Measured, release, instructions retired, base then S3. The bound is twice `aa` plus a cold `pdd`.

| | `aa` | cold `pdd` | `aa; pdd` base | `aa; pdd` S3 | bound | peak after `aa; pdd` |
|---|---|---|---|---|---|---|
| pumasim `0x1fad00` | 63.82 G | 1.24 G | 147.92 G | 116.17 G | 128.88 G | 443.6 to 428.7 MB |
| 0pack `0x475520` | 56.57 G | 1.04 G | 104.21 G | 84.30 G | 114.18 G | 278.4 to 274.7 MB |
| bash `0x2e630` | 7.36 G | 0.71 G | 19.31 G | 15.38 G | 15.43 G | 110.6 to 110.0 MB |

- `aa; pdd` and `aa; ax` output is byte-identical to base on all three.
- Cold release `pdd`: pumasim `0x23fdf0` 19.77 to 19.80 G (+0.1%), 0pack `0x62ecf0` 15.36 to 15.40 G (+0.3%).
- Peak after `aa`: pumasim 205.6 to 206.9 MB, 0pack 150.4 to 158.4 MB, bash 61.8 to 61.7 MB. Peak footprint varies about 4% run to run on the same binary.
- bash passes by 0.05 G. What remains of its index is about 2.5 G of walk, 1.4 G of pointer parameters (callee preparations) and 0.7 G of spelling.


## S4 as built (2026-11-10)

What the code said that this ADR did not, and the owner chosen:

- `place` is r2ssa `place.rs`. `ParamClass` is `Integer(bytes)`, `Float(bytes)` or `Unplaced(SourceUnplacedClass)`, and r2ssa `ParamClass::of` maps a type graph node to it (S32a; r2engine's `declared/mod.rs` `class` until then). `SourceUnplacedClass` names `Float(bits)`, `WideInteger(bits)`, `Aggregate`, `Unsized` and `PackedStack`; the floor is `SourceFloorCause::Unplaced`.
- The cspec's stack section counts from the call (`offset - stackshift`). `place` adds the `OwnedRange::ReturnAddress` the call pushes, so bzip2 `0x1bc6d`'s seventh is `Stack { 8, 4 }` from the entry.
- Apple arm64 packs stack arguments by size. `place` refuses a stack class narrower than the step there (`PackedStack`) until a cited row places it.
- `place_declared` keeps the arrival check and `DW_CC_nocall`; r2image reads `DW_AT_calling_convention` into `Prototype::nocall`. `arrivals_hold`, `placed_prefix`, `placed` and the `break` are deleted.
- The recovered route mints only where `place` puts each recovered parameter at the slot the body read. The native snapshot carries the `ConventionModel` (`OwnedFunctionSnapshot::convention`) for it; a wire snapshot has none and is not checked.
- r2dec `carrier_class` is deleted. The class of a register is `SourceConventionSlots::class_of`, the view of the model's sections; r2dec maps class and width to `MachineType`. `SourceAbiParameterSpec.class` waits for S6, which mints classes per slot.
- A placed stack parameter is a `SourceStackSlotSpec::new_parameter` at the stack pointer, as recovery mints one; its DWARF home is that slot and gets no second spec. The `pdd` header still drops it until S5's `FormalHome::Frame`: bzip2 -g `0x1bc6d` shows 7 in `afi` and `afv` (`alphaSize` last) and 6 in the header.
- D105 is not closed. Narrowing an entry carrier's argument to the lane the callee holds makes bash's `sh_unset_nodelay_mode` shape `uint32_t`, and then a call reached through `test edi, edi` renders `err((int32_t)rdi_1)` with `rdi_1 = residual << 32 | arg0`, the withdrawn second build's failure. Both D105 tests stay ignored until the formal's lane binds the call argument.


## S9 as built (2026-11-10)

What the code said that this ADR did not, and the owner chosen:

- `SourceTypeGraph` carried no qualifier and no name: r2engine's `Interned` peeled both, and the presentation's spellings put them back. Two facts moved into the graph (schema 4). `SourceTypeKind::Pointer` gains `const_target`, the pointee's `const`, the one qualifier a prototype keeps. A typedef name, or a scalar's own name that is no C keyword (`size_t`, `wchar_t`), is a `SourceTypeAlias` on a copy of its structure's node, so `unsigned long` stays unnamed beside it. A `<stdint.h>` name its structure already spells (`uint64_t`) is none: as an alias it made `return (uint64_t)(uint64_t)x`. A record carries its first name itself, because its aggregate row names one node. A named copy of a pointer still being placed is resynced at `finish`.
- `Interned` (`declared/graph.rs`) is the one conversion of an r2abi `TypeGraph`. It now also states an unprototyped code signature (`prototyped: false`), which `c_type.rs` alone spelled. `Placement::function_type` interns its prototype and converts through r2types, and `declared::object_types` does the same for data objects.
- r2types' one converter is `convert::source_type_like` (moved from `analysis`, with `requalify` deleted). A pointer to code it cannot spell is `Pointer(Unknown)`, as `c_type.rs` gave.
- The presentation is names only: `SourceSignatureParameter` lost `type_spelling`, `SourceSignaturePresentation` its return spelling, `SourceStackSlotName` its spelling (no reader), and `FunctionPresentation.callee_signatures` (empty in both constructors). r2engine's `trusted_source_signature` reads the declared interface's graph. r2ssa's format test by parameter name went with the callee signatures.
- `SourceDataObject` carries a `type_id` into the image's `data_types` graph. A named data object type is placeable where its structure is.
- `ExternalField.ty` and `FieldAccessCertificate.field_type` are `CTypeLike`. A member's type is the converter's, an array where its width repeats its element, so a pointer member keeps its pointee where it was `void *`. `ExternalTypeDb.typedefs`, `ExternalTypedef` and `insert_typedef` are deleted: no production path filled them.
- r2types' inferred signature (`InferredSignatureParam.ty`, `InferredSignature.ret_type: Option<CTypeLike>`) holds types. It stores each as the rendered spelling read back, materialized with an unstated sign signed, so the classifiers see what they saw. `type_name_is_generic` still classifies the rendered text; it reads no type back.
- A typedef whose target is `Unknown` still resolves where C, `<stddef.h>` or `<stdint.h>` defines its name (`convert::standard_type`). Plain `char` is not one: its sign is the model's.
- The one text type left is an operator's `TypeHint` assumption. Nothing in production builds one, so `convert::operator_type_hint` parses it beside the definition. When an operator verb lands, the hint carries a graph and `parse_c_type_like` becomes a test fixture.
- A declared return reaches the return-type decision from the declared interface's graph, where `exact_source_return_type` needs a coherent ABI model and a callee prepared alone has none. One the interface leaves unplaced (a struct by value) no longer reaches it.
- A rendered unit declares no typedef, so r2dec spells a name over an arithmetic type (`size_t`, `pid_t`) as its target at emission, as `calls::spellable` already did for call declarations; plain `char` stays. Without it rv `copy_name` returned `size_t` and 7 rv units failed `-std=c11`. Handles (`FILE`, `va_list`) keep their names, as `c_type.rs` gave them.
- Census: 1 function moved, rv_O0g `main`'s `extern const int8_t* g_msg` to `const char*` (DWARF's `char`, now `Char` in the graph where the spelling read `int8_t`). radare2's arg, back1, bomb and bashbot x86-64: byte-identical.
- radare2's row gives `sigprocmask` a `pid_t` result (`types.sdb.txt:2996`); POSIX states `int`. The graph carries it; emission spells `int32_t` either way.
- The Dylint `type_spelling_reparsed` (deny) flags a path to `parse_c_type_like` outside its defining module in production code. Its allowlist, `TYPE_SPELLING_REPARSE_ALLOWLIST`, is empty.


## S11 as built (2026-11-10)

What the code said that this ADR did not, and the owner chosen:

- Base `s8-library-rows` leaves 3 bzip2 -O0 functions with `FS_OFFSET_0`, not 16: the audit ran on master 14d384c3b. Two have a decided check, one has none.
- The decided check's difference: `decide` already rewrote each reread as a copy of the first read, but the observation closure still walked the sub to the canary load. `decide` now records the difference and its passing block, where that edge alone enters it (`passing_differences`). `unobserved_compiler_inserted` drops a returned value that is the difference only at a return the passing block dominates, as the row says. A value computed from the difference before the branch still reads the guard. The first cut wrote the difference as 0 at its definition; it was replaced before landing.
- gcc emits no check in a function that never returns (bzip2 `cleanUpAndFail`): the guard is stored and never read. `stack_protector::unchecked` takes it only in a body with no return, conditional exit, indirect branch or open exit. There every guard read must reach only copies, lanes, `x ^ x` or `x - x` (gcc's `xor eax, eax` reads `eax`, a lane of the guard in `rax`, and computes 0), and stores to frame slots no affine load reads. One other reader keeps them all, and so does a slot whose address escapes: a walk from the entry stack pointer through exact address arithmetic and merges records each frame address put anywhere but a load's or store's address, and an address no offset places denies every slot (PR 354). The frame round trip admits a save no load reads (`push rbp`, never popped).
- `mapSuffix`, decided with lldb on the `debugger` build: the reload `mov rbx, [rbp-8]` is reached and live. The callee-allocation proof read no stack pointer at it: `leave` redefines `rsp`, so the merge before the reload keeps no `rsp` phi, and `ReachingStorage::join` gave `Conflict`. The slot was refused as a callee allocation, so no round trip formed. `ReachingStorage::arriving` hands the proof each edge's state where no write in the block precedes the access, and the proof takes the offset every edge agrees on. The frame base is not read: the edges place the stack pointer exactly.
- `saved_register.rs` is the `SavedRegister` role: a store of a preserved lane's entry value, whole or a `Subpiece` of an entry root. `slot_promotion::saves`, `structural_save` (now `frame_slot`) and the round trip's two copy-chain walks read it; `exact_copy_chain_to_storage` is deleted. A restore of a lane is the insert into its root at the lane's bits, then inserts that leave those bits alone (`ldr d8` zeroes `z8` bytes 8..32).
- `preserved` names each cspec register as bytes of the widest register holding it: `d8` is `z8` bytes 0..8 (AARCH64.sla names no `v8`). `killed` and `likely_trash` are placed the same way, and the call effect reads every list narrowed, so the effect is unchanged.
- toybox: 6 functions save d8 to d15, 4 render, and their 8 residual stores fall to 0. The other 2 refuse at a switch dispatch (hand audit 3.1) at base and head. `0x501c8` moves 36 obligations from rendered to `assumed`: base filed the `str d8, [sp, -0x70]!` save as the top 8 bytes of a 1,144-byte object at entry-1240, and that object fenced the escaped run below it as a barrier. With the save its own slot at entry-112, nothing compiler-owned lies between entry-1392 and entry-112, so FrameReach merges the run and labels its accesses `assumed`. The fence was a mis-filed save; the label is the honest one.
- `frame_agree.py` over the census: agree stays 0 (of 423, then 419), and afv-only falls 389 to 385. Four zig aarch64 census goldens move: each elides its d8 lane save and restore (+2 obligations, `elided`), and `0x10105e4` loses its `StoreNotSpelled` residual.
- Cost: release `pdd` on 0pack `0x62ecf0`, 0pack `0x58e3d0` and pumasim `0x23fdf0` retires the same instructions within 0.3%. `aa` plus `pdd` over all 1,148 ls-toybox functions retires 211.0 G at base and 212.1 G at head (+0.5%).


## S7 as built (2026-11-10)

What the code said that this ADR did not, and the owner chosen:

- r2ssa `site_boundary.rs` takes d72's backward byte liveness (f40057e78). `SiteBoundary { written, fates }` holds `written: Box<[ByteMask]>` per argument register (no reader: caller writes prove no arity) and `fates: [Option<LaneFate>; LANES]` indexed by `LaneId`: the typed three (`INTEGER`, `FLOAT`, `SECOND`), then up to four lanes of the convention model's `results` that overlap none of them. `LaneFate` is `Dead`, `Read(ByteMask)`, `Returned(ByteMask)` or `Unknown`. A fixed array replaces the sketch's `IdVec`.
- A `Read` is a read of byte 0 before any call that may leave the lane, any write that may not run, or any operation with unstated effects; a read past one of those is `Unknown`. d72 instead made a read `Unknown` wherever a later call might take the lane, which lost `cvttsd2si eax, xmm0` after rv `fcn_12ef`. A tail transfer is `Unknown`: the code it reaches is not read here, so only a `ret` is `Returned`.
- Entry summaries (`CalleeEntry`) read no other summary. Reading them recursively walks most of the program on the first `aa; pdd`.
- r2engine `program/fates.rs`: `World { Open, Closed }` replaces `Callers`, `CalleeKey { Entry(u64), Import(ImportId) }`, `ImportId(u64)` (the address calls reach). The `CallBoundary` query keyed `(CalleeKey, World)` holds the evidence half: `Sites { lanes: [JoinedLane; LANES], calls, exhaustive }` for a function under `Closed` (now `unread` and `forwarders`, every-way-in asked lazily: "The result side as built"), `Import { reads }` (S8's `Placement::reads`) for an import. `Open` joins nothing.
- `JoinedLane.held` marks the lanes a body may leave a result in: the typed three and each lane that is an argument location (SysV xmm1, AAPCS64 q1 to q3). x87 `st0`/`st1` are not held: the x87 stack is empty on entry (SysV 3.2.1), so a body writes them before they hold its value. A `Void` or `Unread` decision needs every held lane `Dead` at every call, and the calls must be every way in (`only_called`).
- A `Returned` lane forwards to `CallBoundary(caller, Closed)`: `Read` there is a read, `Dead` with the caller exhaustive is dead, a database cycle is `ForwardCycle`. Forwarding is asked only where its answer can move the decision (a lane no call reads while every held lane is dead or returned, or a typed lane), so `aa; pdd @ bash 0x2e630` joins 111 boundaries, not 253.
- Presence is decided by `fates::decide(open interface, CallBoundary)` at seal time, not held in the query: a declared interface is left alone; `Read` gives `SourceClosedResult::Read(Integer | Float { bytes } | Pair)`; every held lane dead gives `Void` where the body's causes are only `HandedBack` or `NoReturn`, else `Unread` (D202); a cycle gives `ForwardCycle`. r2ssa applies it in the function's second seal (`FunctionIdentity.closed_result` replaces `result_reads`) and records it on the interface (`SourceFunctionInterface::closed_result`, which replaces the `result_read_by_callers` bool). `Unread` and `ForwardCycle` on a written register only name the cause: the carrier and its returns render as before.
- The closed-world premise: every applied decision puts `Premise::ClosedWorld` on the function and in the response premises (PR #355 review). The proof line says "a call reads the result", "no call reads the result" or "a call returns the result on through a cycle", each "(assuming closed-world)".
- Under `aa` a callee is read in the closed world too: `Resolved` at `Demand::Arity` reseals a callee where its boundary decides (`closed_alone`), so its callers' externs and its own header agree. Members of a cycle (`least_fixpoint`) keep their open results: the fixpoint moves the results it tracks.
- D62, per callee: `mint_recovered_call_site_interface` takes no caller reads. A pair is the callee's at every call; an unproven result with one carrier is that register at every call; with two carriers the call states no result, as base's cold path did. The per-body `reads_after` and `direct_reads` are deleted.
- W46: `SourceOwnedCalleeSignature` carries the header's unproven carrier bits. r2dec's extern for a body-recovered callee is `Prototype::of_projection`: the header's own types, `r2sleigh_result_uN` for an unproven result, refused where the call defines a result and the header is `void`. `of_widths` and `callee_carrier_signature` are deleted. The prelude declares every carrier typedef the unit spells. An assignment from the typedef to its integer takes no cast.
- `CalleeFacts::derive` still projects under the callee's own context: base had no case where the root's context changes a callee's projection, so the move waits for one. No `Dispute` is minted: a declared interface skips the decision, so DWARF and the body never meet here (since minted as evidence: "The result side as built"). r2dec `decide_prototypes` stays for callees with no projection.
- Deleted: r2ssa `caller_reads.rs` (`reads_after_call`), `reads_after`, `direct_reads`, `result_ambiguous` (r2ssa and the engine's reseal trigger), `body_proven_return`, `with_body_proven_return`, `known_function_signatures` (dead in production since `with_trusted_ssa` replaced the context), `CalleeResolutionFacts.by_name` with `identity_for_name` and `identity_for_name_in_context`, the free function `body_summary` (now the held `CalleeSummary` query, read after a held `CalleeReads`), `Prototype::of_widths`, `callee_carrier_signature`, `SourceResultReads`, `SourceFloatReadWidth`, `ResultReads`.
- Not built: D212's per-lane pass-through at a call.
- A forwarder of a callee's stated float result is never void (1b0ad7395, picked from c70b688f2): `ReturnedByCall::Stated` names a value a callee's complete boundary states it returns in that register, and where the integer register holds nothing the body computed, that float lane counts as written. f3.gcc.O1's `p_f3_chain_a`, `_c` and `_arm` were `void` with callers reading XMM0. An argument handed back beside a written float names both carriers, so AArch64 review.c `avg` stays `double` where its one call reads d0.
- AArch64 equivalence (CI run 42855337203 at 38a675dad; base `bf3e9d8ce` and head read by hand on the same host): 15 source-void records leave `equal` for `residual-trap`, each `unproven (EntryInput)`: D208's class, decided in scratch-result Decided 1. Base's void read x0 alone; head needs every held lane dead, and q0 to q3 survive to `main`'s `printf`, which AAPCS64 lets take every vector argument register (D218). Nine also forward through `shape_call_chain`-like callers whose result is read, whose boundary never asks `only_called` (D219). A test build that makes `printf` take no vector register decides the six D218 records `void`; the nine stay unproven. D213 decides them once D218 and D219 make those lanes `Dead`.

Gates, release, base `6129d1797`:

- d72 round 7, `aa` then `pddj` of every `afl` function: aarch64 `e1.c` and `e2.c` at O0 to O3 (224 functions) print base's declarations. `d.c` built for aarch64 (`da`, O1 to O3, 174 functions) moves 9: `c_d_compute_arm`, `c_d_forward_arm` and `c_d_chain_arm` go from `void` to unproven in each build. After their call, `main` calls `c_d_forward_store`, which reaches `hook_d`, an untyped function pointer that may take q0. Base's `void` rested on a read of the call's own block.
- An aarch64 engine test (`call_boundary.rs`): `keep` is not `void` cold or under `aa`. The premise test: under `aa` a read result is `uint64_t f(` with the premise; cold it is `r2sleigh_result_u64 f(` with none. The D202 test: every held lane dead gives `unproven (Unread)`, never `void`.
- bash `0x61520`: base and head, cold and `aa`, print the same `ignore_signal`: 2 residual obligations, 1 site (the high half of `arg0`), `set_signal_handler(uint32_t, uint64_t)` at every call.
- pumasim `0x3b6b20` (`png_decompress_chunk`): `png_free` stays `void`, 23 residual sites, 121 residual obligations, as base.
- `shape_mutual_even` and `shape_mutual_odd` both print `uint64_t ...(uint64_t arg0, uint64_t arg1)`, and each one's extern of the other is that header.
- W46, every caller's extern of a callee the same run renders, `aa` then `pddj` over the 23 census binaries: 135 of 200 differ at base, 25 at head.
  - 18 callees have no projection for callers: r2types refuses their signature (no certified parameter entity, or no render-authorized signature), so the extern is built from the call's own classes (`uint64_t register_tm_clones()` beside `r2sleigh_result_u64`; rv `avg`, `fill`).
  - 4 headers name a struct the caller's unit does not define (`rec_spread`, `mixed_touch`, `_out_param_parse` twice).
  - 1 is a cycle member (rv_O0g_stripped `fcn_1362`), which keeps its open result where its header is closed.
  - 2 are the measurement's own: two static `helper`s in two units, and a function-pointer parameter split at its comma.
  - The ADR's 41 of 234 came from a corpus the audit did not record.
- `scripts/scratch_void.py` over the 35 DecBench builds: exit 0 at base and head, so no false void beyond the 2 named clones. Source values a closed-world read decides (`unstated`) go from 685 to 1,864, and written source values from 3,273 to 2,092. 12 source voids and 2 source values are `ForwardCycle`. `void-open` stays 272 void and 2 value. Closed-world voids are 0 at base and head, and no `Unread` is decided: at some call, some lane a body may hold is never dead (RDX, XMM1, or a lane its caller returns on). D213 makes them 4 ("The result side as built"). Source voids rendered with a value fall from 7 to 6.
- The CI source-gold steps (hashes, returns, the CI scratch-void corpus and the 10 shapes) exit as at base, and their reports match base line for line.
- Census: 10 goldens and 436 lines move. A written result a closed-world call reads goes from `r2sleigh_result_uN` to its integer, and its proof line names the premise. Residual obligations in the moved proof lines are 56 at base and 56 at head.
- Cost, instructions retired:
  - Cold `pdd`: pumasim `0x23fdf0` 19.78 to 19.73 G, 0pack `0x62ecf0` 15.38 to 15.34 G; RSS unchanged.
  - `aa; pdd`: pumasim `0x1fad00` 115.9 to 65.9 G and 0pack `0x475520` 84.3 to 56.6 G. Base built the reference index there; head decides without it.
  - bash `0x2e630`: 15.4 to 22.2 G before "S7 cost" below, over D153's bound of 15.43 G; 14.32 G after it.
  - pumasim `0x3b6b20` after `aa`: peak RSS 221 to 438 MB before "S7 cost" below, which removes the reference index it built.

S7 cost (2026-11-10):

- The profile (samply, bash `aa; pdd @ 0x2e630`, 6,782 samples) split the 22.24 G:
  - 32.7% built the reference index for `Escapes`, which then refused at `0x1e887` (code no body holds). pumasim `0x3b6b20`: 43%, refused at `0x1c5102`.
  - 17.5% was `CalleeEntry` (878 callees of callers lifted and summarised), 17.6% `SiteFates` (450 callers lifted, 4.5% its pass). 1,331 walks of 1,018 bodies.
  - The second seal was under 1%: 2 functions decided in bash, 4 in pumasim `0x3b6b20`.
- `Escapes` refuses on code no body holds before it asks for the index. The index is built only where the closed world can still hold, as for `ax`. A test (`code_no_body_holds_refuses_the_closed_world_before_the_reference_index`) counts no index built (`AnalysisStats::references`).
- Not taken here: deciding inside one seal (r2ssa `site_boundary::decide`) rests on S6's `BodyBoundary` seal and lands above S6. `CalleeEntry` still lifts each callee of a caller: those 878 callees are two calls from the root, and preparing one costs more than its lift and pass.
- Release, instructions retired and peak footprint; base and before as measured on `s7-cost` (base `bf3e9d8ce`, before at S6), after the median of three on S7:

| | base | before | after |
|---|---|---|---|
| bash `0x2e630` `aa; pdd` | 15.42 G, 104.3 MB | 22.24 G, 104.4 MB | 14.32 G, 65.1 MB |
| pumasim `0x3b6b20` `aa; pdd` | 64.42 G, 196.4 MB | 118.47 G, 411.0 MB | 66.29 G, 206.3 MB |

  - bash is under D153's 15.43 G. Output: each `aa; pdd` prints the bytes it printed before, and the census goldens do not move.

### The result side as built (D213, Dispute, W46; 2026-11-10)

What the code said that this ADR did not, and the owner chosen:

- D213: `fates::decide` needs dead at every call only the lanes a body may hand back. r2ssa states on the carriers that no return defines a byte of the integer register (`SourceResultCarriers::integer_undefined`, scratch-result case 1 to 3). That register, and the second one, which holds a result only beside it (SysV psABI 3.2.3, AAPCS64), are then no result: a call reading them after the call reads its own bytes (`-fipa-ra` keeps RAX and RDX live across a callee that leaves them alone).
- Every-way-in is asked lazily, by the decision that rests on it (`fates::every_way_in`). A lane a caller returns on, dead at every call to that caller, is `DeadIfEveryWayIn`: the caller joins `Sites::forwarders`, and its own calls must be every way in too. Each function is answered once per question (`every_way_in_from`), so the walk ends; the database cuts a cycle of boundaries first, and no fixture builds a ring of forwarders.
- A function nothing calls is `Sites { calls: 0 }`. It is decided only where it hands back an input (void); a written result nothing calls is not asked, since its `Unread` moves no C and asking builds the reference index.
- Escapes reads `hlt` (a direct branch to itself) and a multi-byte `nop` (a temporary only) as padding. Before, the `hlt` after `_start`'s call, or the `nop` after a canary's `__stack_chk_fail`, refused the closed world in each of the 12 binaries probed (`branchy.c`, `shapes.c`, `atomics.c`, gcc and clang, O1 and O2). "S7 cost" refuses on such code before the index; with padding read, the index is built there, at the cost measured below.
- An import with an uncited row reads every argument location, so a canary's `__stack_chk_fail` kept XMM0 open in every caller with a stack protector. `exit` and `abort` (ISO C17, `types-posix`), `_exit` (POSIX, `types-glibc`) and `__stack_chk_fail` (LSB 5.0 Core, binary-only: its section on `.cite=`, admitted by `tests/cited_rows.rs` for an LSB row whose comment says so) are cited, `Tail::None`.
- `Dispute { lane, kept, lost }`, `Authority { Declared, Body, Calls }`: a callee stated void by its declaration or body, and a call reading a lane the callee overwrites on every path (its entry summary), is a dispute the calls lose. It leaves `call-boundary-dispute` evidence and decides nothing. A lane the callee leaves alone disputes nothing.
- `CalleeFacts::derive` still projects under the callee's own context: none of the 24 W46 pairs below differs by context.
- D212 is not built. `testf` (bzip2 O2-noinline `0x4c20`) has one cause: its tail to `setExit` (`0x3290`), a callee with two carriers, gets no call-site contract, so "a tail transfer to a target without a complete prototype owns the result boundary". The narrow fix: a callee whose only cause is `HandedBack`, with `integer_undefined`, states its call no result, and the caller keeps that tail's block in the direct-return and float checks (today `without(&tails)` drops it), so the bytes the caller left there stay its result. Owner r2ssa `recover_interface`.

Gates, release, base `1e4a74a1a`:

- The 14 x86-64 equivalence functions D208 moved (gcc and clang O1 and O2 of `and_chain_effect`, `shape_stash`, `total_add`, gcc's `inverted_void`) print `void` under `aa` with the premise. clang's `inverted_void` writes EAX on one path: `Unread`, as D202 says. S31a's one-call minimum takes back the uncalled ones (`and_chain_effect` gcc-O1/O2, `total_add` clang and gcc -O1/O2 on x86-64, 7 on aarch64): nothing in the program calls them (doc/adr-result-side.md, "S31a as built").
- Engine tests (`call_boundary.rs`): void through a caller that reads RAX and RDX, through a caller whose own caller kills the lane, and with nothing calling it; never void where a call reads XMM0, where a pointer enters, or where a written float lane is unread; an x87 read after the call is no evidence; two functions that forward to each other end.
- `scripts/mutants_d213.py`: 19 mutants of the decision, the carrier fact, the padding and the byte liveness, each killed by a baseline-green test.
- `scripts/void_soundness.py` (from d72, 332 builds): 1,858 read results, 23 rendered void at base and head. 20 are x87 st0 results recovery holds no lane for, named in `known.json`. 3 `f3.gcc.O1` forwarders base `1e4a74a1a` voids under `aa` (`20c1f7832` did not) are false voids, left out of `known.json` so the gate stays red until they are traced. 8 premised voids. 66 s compiling the builds on Linux.
- `scripts/scratch_void.py` over the 35 DecBench builds: exit 0. `void-closed` 0 at base to 4 (cmp and sdiff O2-noinline), 0 false; `void-open` stays 272 void and 2 value. Most of the 140 `EntryInput` voids stay open: a lane they hand back reaches a call whose callee is uncited or unread (bzip2's `setExit` reaches `main`, where every lane is open).
- W46 over the 23 census binaries, base and head: 24 of 200 differ, the same pairs. 18 calls carry no exact callee interface, so r2types projects nothing and the extern comes from the call's own classes: `uint64_t f()` beside a `r2sleigh_result_u64` header (17) or `void` where the call reads nothing (`_table_dispatch`). In the two traced (`callee-signature` evidence, `site=None`), main's call to `crc32_init` gets none because r2ssa mints no contract for a callee with two unproven carriers (the refusal D212 lifts), and `frame_dummy` reaches `register_tm_clones` by a tail transfer. Owner: r2ssa call-site minting (`mint_recovered_call_site_interface`). 4 headers name a struct the caller's unit does not define (`rec_spread`, `mixed_touch`, `_out_param_parse` twice; owner r2dec's unit prelude). rv_O0g_stripped `fcn_1362` is a cycle member that keeps its open result (owner `least_fixpoint`). rv_O0g `dispatch` is the measurement's own: a function-pointer parameter split at its comma.
- Cold `pdd` byte identical: 0pack `0x62ecf0` 15.35 to 15.31 G, `0x58e3d0` 18.70 to 18.72 G, pumasim `0x23fdf0` 19.75 to 19.73 G instructions.
- `aa; pdd` byte identical, peak RSS within 2%: bash `0x2e630` 14.32 to 14.34 G instructions, pumasim `0x3b6b20` 66.27 to 66.30 G, pumasim `0x1fad00` 65.06 to 65.56 G, 0pack `0x475520` 56.71 to 56.70 G. Before "S7 cost" the lazy question alone took bash from 22.36 to 14.34 G; on this base it holds the cost.
- Equivalence, x86-64 (828 records, 744 equal): exactly the 14 move, `residual-trap` to `equal`, and are blessed; no other record moves. AArch64 (828 records): `and_chain_effect` gcc-O1/O2 and `total_add` at five cells go to `equal`, and are blessed. Contabo's run also shows 18 records leaving `equal` (`inverted_void`, `shape_stash`, `mixed_touch`, `crc32_init`, `indirect_store`, `avg`, `fill`), the same at base; CI's aarch64 ratchet passes at base, so they are the host's toolchain, not the engine, and stay unblessed for CI to grade.
- Census: 4 goldens, 19 lines. `_dl_relocate_static_pie` (and stripped `fcn_401270`) is `void`: nothing enters it, glibc declares it `void`. Seven proof lines of written results nothing reads now name the closed-world premise. Coverage: 560 of 562 rendered, no regression; the three pinned `_dl_relocate_static_pie` go from 2 gapped obligations to 0.
- Source-gold CI steps (hashes, returns, the CI scratch-void corpus, the 10 shapes): exit codes and reports equal base's. `comment_runs` adds no run; structure counts equal the baseline; Dylint 8 warnings, the baseline. The 24 W46 pairs read the same at `1e4a74a1a`.

On S6 (`31a8371bb`, 2026-11-11), release r2s on one x86-64 host (gcc 13.3, clang 18.1; aarch64 under qemu-user):

- S7's arm for an argument handed back beside a written float states `integer_undefined: false`: the integer register holds an input's entry byte, which the field excludes.
- Equivalence: x86-64 731 to 745 equal of 828, exactly the 14 above; aarch64 736 to 743, exactly the 7 above. No other record departs from S6's baseline on either target, so the 18 aarch64 records the run at `1e4a74a1a` showed leaving `equal` do not recur. The 21 are blessed.
- `void_soundness.py`: 1,858 read results, 16 rendered void, all 16 x87 results named in `known.json`, at S6 and here. S7's `ReturnedByCall::Stated` ended the 3 `f3.gcc.O1` false voids and clang's `p_ldb_chain_b` at O1, O2, O2.avx2 and O3; those 4 stale entries are deleted, and the gate exits 0.
- `mutants_d213.py --check`: 19 of 19 mutants apply. Touched crates 1,590 tests pass; census 444 goldens, 0 moved; Dylint 8; structure counts equal the baseline; coverage 560 of 562 rendered, no regression.

## S5 as built (2026-11-10)

What the code said that this ADR did not, and the owner chosen:

- `FormalHome` carries its storages: `Register { abi_storage, graph_storage, value }` or `Frame { object, offset, bytes }`. `SourceFormalParameterFact` is `{ index, logical_value, home }`, with `value()`, `register()`, `object()` and `bytes()`. The r2source spec stays id-free.
- The object model mints an argument-area object (`StackSlot` at the entry offset) for each stack parameter of the interface, read or not, after every other object, so no other object's id moves. `ObjectModel::argument_object(offset)` finds it.
- A stack formal is `bytes` wide: the low lane its logical value states where memory is little-endian, else the slot. bzip2 stripped `0x1bc6d`'s seventh is an 8-byte slot holding a 4-byte lane.
- Preparation reads only register formals (`collect_source_formal_parameter_facts` with no object model). The published boundary facts read both, after the object model.
- A read of a stack formal is `CallerSlotSupply::Formal(index)` in the caller-slot certificate: the object at the formal's offset, read whole and written nowhere. A read that overlaps a formal any other way gives the object no certificate. r2dec declares the formal and spells that read as its name.
- One list: `afv` and `afi` list `boundaries.parameters`, and the `pdd` header declares the same list. The entity-and-interface rebuild in `info.rs` is deleted, with r2types `interface_parameter_widths`, `declared_parameter_width_bytes` and `parameter_home_width_bytes`, which only it read.
- One name: r2types `FunctionFacts::parameter_name(slot)` (the certified signature's name, else the source's, else `r2source::positional_parameter_name`, `arg{slot}`). r2dec, `afv` and `afi` read it; r2types' recovered signature starts from the positional name, since a display spelling decides nothing there (Dylint). r2s `argument_name` (`arg{slot + 1}`) is deleted, and the other positional spellings in r2types and r2engine call the one function.
- D105 is closed by four pieces in r2ssa, all reading `callee_held_lane` (`semantic/shared.rs`): the low lane of an argument register that the callee's interface states as a narrower logical value (`int fd` in `rdi` is `edi`).
  - The boundary narrows the argument to that lane (`narrowed_argument` at the held width). Where no lane value is named and the carrier is the entry register handed on whole, the argument is this function's own formal of that lane, if one exists (`is_entry_lane_of`).
  - The call-argument certificate checks a lane at the value's own width, so either proof holds.
  - Recovery reads an entry carrier handed on whole at the held lane (`passed_through_entry_storages`).
- No projection is minted for a held lane, and no entry value is materialized for one: a lane that is no formal binds nothing, and the argument stays the carrier.
- S4's declared interface bound a stacked return address (`stacked_return`) without the carriers' names, so the trusted lift dropped the return-address and stack-pointer carriers and refused the body: bzip2 -g `0x1bc6d` refused at base `e7a294146`. `Placement::carriers` now copies the machine's role names onto the interface, as the recovered route does.
- D105 narrows by default-deny (`held_lane_admitted`). A held lane narrows a carrier only when the lane is already this function's formal, or the carrier's entry value is read only within the lane: a lane read, or a `CallUse` whose callee holds that register at no wider a lane. A whole copy, arithmetic, a wider store or a merge keeps the full width. Census aarch64 `_main` (`mov x20, x0`) keeps base's `uint64_t arg0`.
- Gates, release, base `c3978b896`:
  - bzip2 O0 stripped `0x1bc6d`: `afi args: 7`, header `fcn_1bc6d(..., uint32_t arg6)`, and the body reads `tmp_1bce1_8_1 = arg6` for `cmp eax, [rbp + 0x10]` (base: header 6, the read a residual). bzip2 -g: 7 with `alphaSize` read by name.
  - `frame_agree.py`: 0 of 423 offsets agree at base and head, afv-only 389, pdd-only 34, 85 functions refused; unmoved.
  - Source-gold exit codes match base on all 13 builds. `seven.c`'s `seven` goes from 7 parameters marked wrong (6 in the header) to 7 placed, each a silent sign error `int32_t` against `uint32_t`, the cause `add1` already records: no byte states the sign (D156). `returns.c` and `odd.c`'s `int` parameters fall from `uint64_t` to `uint32_t` (D105), the sign still D156's.

## S6 as built (2026-11-10)

What the code said that this ADR did not, and the owner chosen:

- `BodyBoundary { slots, locations, floor }` is r2ssa `body_boundary.rs`, minted by recovery and carried on `PreparedFunctionFacts::body_boundary` of the sealed artifact. `SlotId` numbers the integer section, the float section (or Win64's one `Shared` section), then the stack slots read. `locations` gives each slot its section, position and location.
- The sketch's `results` (each typed lane's bytes joined over every return) is not built. It had no reader, and S7's decision cannot use it: `decide` reads the open interface's return kind, carriers and causes, which joined bytes do not state (an `Ambiguous` pair, a `Returned` cause). Its three live-out walks per body went with it.
- `SlotUse` derives its order: `Unread < Homed < SaveArea < HandedOn < Read < Unknown`. `HandedOn.to` holds the `CallSiteId`s whose boundary passes the entry value to an argument the callee does not leave a hole. A slot `HandedOn` mints at `Basis::Solved`, a `Read` at `Decoded`, a hole at `Convention`.
- Rule 3 as built:
  - The preliminary build has already dropped a dead frame store, so -O0's homing store is invisible. `Homed` is an entry value whose only uses end in a copy nothing reads. A lane projection nothing reads is the build's own and counts as no home (`xor ecx, ecx` folds the lane it read).
  - A read that folds to a constant (`x ^ x`, `x - x`, `x & 0`) is `Unread`, as is a call's read that its certified boundary does not pass.
  - `Unknown` is an entry value that reaches a call of unproven arity, through any computation. A slot below the reads with that use is a parameter at `Decoded`, never a hole: the call may read it, so a caller passes its value. Every other unobserved use is `Unread`, since nothing observable reads it. `RegisterRead` is no longer minted.
- Only the first slot past a section's parameters names the calls of unproven arity it reaches, as D37's probe did. A later slot handed on stays `Unknown` in `BodyBoundary` with no floor cause: on the census, such floors made callers refuse while the `aa` fixpoint still held the callee unstated (`shape_pointer_to_pointer`).
- Floats: a float section nothing reads probes no call, as recovery before S6 did. Under a proven register save area every float slot is `SaveArea`: the prologue saves every vector register under `al`, and the area records no float save apart from a named float's read.
- A recovered float parameter is placed in its register's low lane at the width read (4 or 8 bytes), as `place` puts a declared one; a float hole is 8 bytes. An integer hole keeps its slot's width.
- An exact interface states every logical value, so a hole carries a `CarrierWidth` logical value at its slot's width. `ty: None` is its `Basis::Convention`: r2types' `parameter_declaration_fact` projects it as `r2sleigh_unread_uN` or `r2sleigh_unread_fN` (`r2types::unread_slot`), so the `pdd` header, `afv` and `afi` agree, and r2dec's prelude declares the typedef, which claims no C type.
- `SourceAbiParameterSpec` gains an optional `(SlotClass, Basis)`; recovery states it for every parameter. The declared route states none yet.
- A hole's argument at a call: `SourceCallBoundaryFact::ignored` lists the positions the callee's exact interface leaves holes. The value reaching one seeds no producer obligation, is no observation root and no live read, so the caller's `a*7` before `jmp` is dead. r2dec passes `(r2sleigh_unread_uN)0`, and `pddj`'s `calls[].ignored` counts these apart from invented arguments.
- D100: r2dec's proof line names a floor, `the parameters are a floor: at least N (causes)`. The glibc static `_exit` probe (D172) prints `void _exit(void)` with `at least 0 (a supervisor entry)`.
- Deleted: the `map_while` prefix; `MachineAbiModel`'s argument and return registers with `MachineAbiRegisterSlot` (the return registers read the interface's `return_kind`); `AbiProfile`. The interprocedural summaries read the interface through `abi::Formals`, a borrowed view that holds no second list.
- The argument area holds at most 64 holes below its highest read (`HOLE_BUDGET`, r2ssa `recover_interface.rs`). Past them the list stops as a floor, cause `ArgumentAreaPastBudget` (Codex review of #358: one hostile load built ~134 million records). Two engine tests in `arity.rs`.

Gates, debug build, base `20c1f7832`:

- libz (O2-noinline-libz) `0xe160`: `fcn_e160(r2sleigh_unread_u64 arg0, uint32_t arg1, uint32_t arg2)` (base `(void)`), `malloc(arg1 * arg2)` with no residual.
- fp x86-64 (clang -O2, stripped): fadd `float (float arg0, float arg1)`, dmul `double (uint32_t arg0, double arg1)` in convention order, dcmp `uint32_t (double arg0, double arg1)` (base `float (void)`, `double (uint32_t)`, `uint32_t (void)`). On arm64 the three stay `(void)`: their result is unproven (`EntryInput` on x0), so no float read is observed. That is S7's.
- Certification, radare2 `test/bins/elf --limit 24 --functions 8`: base and head print the same 50 rendered, 30 refused, 0 invented, 0 dropped. Over the 13 DecBench O2 builds at 40 functions each: 518 rendered and 2 refused at base and head; calls graded rise from 109 to 117, with 0 invented, 0 dropped and 0 hole arguments.
- D37's `an_argument_area_read_past_the_prefix_is_a_floor_of_that_cause` (`f(stack0)`) passes unchanged. D100's `a_floor_of_parameters_is_named_on_the_proof_line` runs the clang -O0 `fcntl` wrapper.
- Source-gold over 15 gcc builds: aggregate soundness 0.6065 to 0.6079, with missing facts 13 to 9, marked 196 to 199 and silent 157 to 158. `scratch` rises 0.2222 to 0.2857. `odd` falls 0.1935 to 0.1875: `set_handler`'s function-pointer parameter, missing before, is now present and typed `uint64_t` (D71 A2). The grader reads `r2sleigh_unread_*` as marked, as it reads `r2sleigh_result_*`.
- Census: 15 goldens move. Nine `_start`s gain `rdx`, handed to `__libc_start_main`, behind two holes. -O0 `zero_of` homes its unused `x`: its own arity is a floor (`Homed`), and a call to it passes no argument, since a floor of homes nothing loads reads no slot past the parameters (`SourceArityFloor::reads_past`; Equivalence ratchet of #358). Proof lines name the floors they rest on.
- Cost, release, instructions retired, base then head: cold `pdd` on 0pack `0x62ecf0` 15.32 to 15.34 G (+0.2%), 0pack `0x58e3d0` 18.69 to 18.72 G (+0.2%), pumasim `0x23fdf0` 19.75 to 19.83 G (+0.4%); bash `0x2e630` `aa; pdd` 22.20 to 22.22 G (+0.1%), output identical. Peak RSS moves within run-to-run noise (0pack `0x58e3d0` 242 to 245 MB over two runs each). The entry values are indexed by register once per body, and `results` adds the float and second lanes' live-out walks.
- pumasim `Gui::Gui(QWidget *, const char *, unsigned)` goes from `(void *arg0)` to three parameters, and its call to `QWidget::QWidget` passes four arguments. 0pack `0x62ecf0`'s proof line names its floor of two and the four calls it rests on.
- Dylint: 8 warnings, the baseline; no `entity_keyed_map`. Structure counts match base finding for finding; `long_comments` falls from 2,498 to 2,493.
- Equivalence, on one x86-64 host (gcc 13.3, clang 18.1; aarch64 under qemu-user), S7's head then S6's: x86-64 730 to 731 equal of 828. `manual_limits.c` clang-O1 `table_walk` and `code_pointer_table.c` clang-O2 `main` become equal; `manual_limits.c` clang-O1 `main` leaves equal, since S6 counts `table_walk`'s entry ECX, read by a `cmove` only on paths where its condition rejects it, and `main` never writes RCX (D214 owns the proof). aarch64 holds 736: `code_pointer_table.c` gcc-O1 `table_dispatch` and `main` trap for another reason. gcc -O0 `pure_zero_guard` stays equal on both, by the `Homed` floor rule above.

## S10 as built (2026-11-10)

What the code said that this ADR did not, and the owner chosen:

- The row states only what the cspec does not. `MICROSOFT_X64` gains `home: Some(HomeArea { step: 8 })`, cited from Microsoft x64 "Stack allocation" and the Windows SDK `vadefs.h`. The cspec's `localrange` 8..39 says where the area lies. The model splits a `localrange` that starts at the return address's end, and holds one home per shared position, into four `OwnedRange::Home`. x86-64-win's negative `localrange` stays `Callee`. The sketch's `HomeVaList` needs no field: `va_list` is `&home[first unnamed]`.
- `ConventionModel::owner(offset)` returns `StackOwner { Callee, Home { position }, ReturnAddress, Caller }`. Without a model the rule is the old one, below the entry stack pointer. The machine context holds the snapshot's `Arc<ConventionModel>`. Five readers take it:
  - `SsaArtifact::caller_frame_offset`, now a method;
  - slot promotion's caller gate;
  - the stack geometry's `names_own_object`;
  - `CalleeStackAllocationCertificate`, which treats a home as the callee's at every access whatever the stack pointer, because a callee's home lies below the pointer it is called with;
  - r2dec `Frame::lay_out`, whose array reaches past the return address to a home.
- `SourceStackAllocationContract` (`contracts.rs:562`) is unchanged. It states what a stack-pointer move allocates, and a home is no move.
- Recovery's argument area starts at the stack section's first offset past the return address: entry+40 under Microsoft x64, unchanged where the section starts at 0. A home reload was read as stack slot 0, so `place` refused the interface. That refusal left hello_gs's UCRT `printf` with no parameters.
- Rule 3 under Microsoft x64 (`homed_in_its_home`): an entry value read only by stores to its own home is `Homed`, where no load reads that home and its address does not escape (`FrameReach::escapes_directly`). Above the read prefix it is floor cause `Homed`.
- Rule 6: `SourceFunctionInterface::va_list_parameter` states the parameter `Tail::VaList { index }` names, set by r2engine `formatted`. `save_area::home_va_list` proves a tail at position k where:
  - `&home[k]` is the argument at that index of a call whose exact callee interface states it;
  - each later position's entry value is read only by its home.
  - It reuses `SaveArea { named: k }`, so the body mints `(fixed..., ...)`. Its format comes from S8's body-proven forwarding.
- A promoted home leaves a copy and no store. The proof therefore reads the entry values, and does not search for the stores.
- Not built:
  - `printf.rs` on the `Shared` section. A variadic callee homes and reads the integer register. A floating operand's C value is in the float register. The argument is that value only where SSA proves the two registers equal, as `movq r8, xmm2` does. The first cut read `xmm2` alone and was withdrawn. `a_floating_variadic_operand_whose_registers_differ_is_no_argument` keeps it a residual (D220).
  - `tail_count` over a home `va_list`. Its row is SysV's `RegisterSaveArea` (D220).
  - `/GS`. r2image reads `IMAGE_LOAD_CONFIG_DIRECTORY`'s `SecurityCookie` into `Container::security_cookie`: hello_gs `0x14001d040`, testapp `0x140016108`. `GuardRow::LoadConfigCookie` and the check proven from its body are D215, the field's reader. 29 hello_gs and 27 testapp functions read the cookie. 21 and 20 keep the read or the check as a residual or a literal at base, 16 and 17 at head. None is elided.
  - A Win64 equivalence target. No PE in the corpus imports UCRT, and the equivalence harness compiles for ELF hosts (D216).
- The gate "hello_gs `main` prints printf with 2 arguments, given a cited row" cannot hold. hello_gs links UCRT statically: it imports 67 KERNEL32 functions and nothing else. `__stdio_common_vfprintf` is the body at `0x140004448`, and no row binds a body by its name. Only the engine test `a_home_handed_on_as_a_cited_va_list_is_a_variadic_tail` exercises the cited-row path. Its import comes from `api-ms-win-crt-stdio-l1-1-0.dll`; it prints `print_line(uint64_t arg0, ...)`, and its caller prints `print_line(0x10a0, (uint64_t)7U)`.
  - On hello_gs, head prints `fcn_140001090(uint64_t arg0, uint64_t arg1)` with "at least 2 (a register past them is only homed)". `main` prints `fcn_140001090((uint64_t)0x14001d008U, rax_1)`. That comes from the floor and the two registers the call writes, not from a tail.
- Found: slot promotion promotes a frame address held in an outgoing stack-argument slot. The callee reads that slot, and promotion does not count the address as escaped. In the `va_list` fixture, `&home[1]` at `[rsp+0x20]` let all four homes promote. The defect predates S10 for locals: it hits SysV from the seventh argument and Microsoft x64 from the fifth. S10 extends it to home slots, which base never promoted (D217).

Gates, release r2s, base `b2f9b4758`:

- Home stores rendered as residuals, by function: hello_gs 74 of 89 homing functions to 3, testapp 61 of 70 to 3. The three are `__isa_available_init`, where `push rdi` is a residual too around `cpuid`, and two functions whose every operation is `UnsupportedUnknown` at base and head.
- Residual obligations over every `afl` function: hello_gs 30,639 to 12,482, testapp 16,050 to 7,694.
- Refusals: hello_gs 28 to 20 (6 new, 14 gone), testapp 12 to 12 (3 new, 3 gone). Each new one is an unaccounted `live-value-producer` or `volatile-or-unknown` effect obligation. S13 recorded the same cause once a call is declared and named r2ssa's effect accounting its owner.
- Signatures: 13 move and are listed. Three bodies were read:
  - `0x140001040` (`_vfprintf_l`) gets 4 parameters, its 4 homes reloaded.
  - `0x140008258` gets 6: `arg4` and `arg5` are the slots at entry+40 and +48 that the body reads.
  - `0x140010000` gets `(void *, void *)`. It hands its entry `rcx` and `rdx` to `0x1400115d0`, which hands them to `0x1400115f0`. `0x1400115f0`'s arity is a floor of 3. A register handed to a call that may read it is a parameter (S6 rule 3). At base, `0x1400115f0`'s interface was refused because its home read at entry+16 counted as stack slot 1.
- Four rendered functions gain residual obligations. Each was read:
  - hello_gs `0x1400105b8`, 6 to 13. `stmxcsr [rsp+8]` stores MXCSR into home 0 and reloads it. The home promotes, so the entry MXCSR is read where the reload stood. That is a held-from-entry residual at each of 13 uses. Base had one residual temporary and a false "argument area read" floor.
  - hello_gs `0x140010000`, 102 to 119. Its two new parameters bring 28 obligations into reach: 11 render and 17 stay residual, with 7 more `TermNotSpelled` markers.
  - testapp `0x14000a364`, 79 to 80. Its saves go through `mov rax, rsp; mov [rax+8], rbx`. The promoted homes read `RBX_0`, `RBP_0` and `RSI_0` as held-from-entry residuals, and the text holds 24 residual sites at base and head.
  - testapp `0x140001368` (`entry0`), 146 to 148, has the same proof line at base and head.
- Census: 444 golden tests pass and 0 lines move. The 23 census binaries are ELF and Mach-O, where `owner` is the old rule and the stack section starts at 0.
- Touched crates' tests: 1,908 pass (r2engine, r2dec, r2ssa, r2source, r2abi, r2image).
- Cost, release, instructions retired, median of three, base then head: cold `pdd` on 0pack `0x62ecf0` 15.40 to 15.42 G (+0.1%), pumasim `0x23fdf0` 19.85 to 19.84 G (−0.04%). Peak footprint 0pack 216 to 216 MB, pumasim 212 to 214 MB. `owner` scans at most six ranges, and `homed_in_its_home` runs once per shared position: O(objects + accesses).
- Dylint: 8 warnings, the baseline, none in a touched file. Structure counts match base; `long_comments` stays 2,493. One nesting finding the first cut added in `names_own_object` was flattened.
- Certification, radare2 `test/bins/elf --limit 24 --functions 8`: base and head print 50 rendered, 30 refused, 0 invented, 0 dropped.
- Not run:
  - Equivalence. The x86-64 and aarch64 runs need the Linux build host, which this slice did not use, and no corpus PE has a target (D216).
  - The full workspace suite. Only the touched crates' suites and the census goldens ran.

On S7b (`60208afbd`, 2026-11-11):

- Equivalence, release, on one x86-64 host (gcc 13.3, clang 18.1; aarch64 under qemu-user): x86-64 and aarch64 each hold all 828 records of S7b's baselines (745 and 743 equal). The ELF targets take the old owner rule, so no record moves.
- Touched crates' tests: 1,941 pass (r2abi, r2dec, r2engine, r2image, r2source, r2ssa). Census 444 goldens pass, 0 moved. Dylint 8, the baseline. Structure counts equal the baseline; `long_comments` is 2,491.
- hello_gs `0x140001010` prints `fcn_140001090((uint64_t)0x14001d008U, rax_1)` and `0x140001090` the floor "at least 2 (a register past them is only homed)", as above.
- Row numbers: S6 took D214, so this slice's Win64 float varargs row is D220; D215 to D217 keep their numbers.

## D217 as built (2026-11-11)

Slot promotion carried a frame address stored into an outgoing stack-argument slot to that slot's loads, as if only this function read it. The callee reads the slot, so the address escapes. The rule listed escapes and allowed the rest, so each new way out (a stack argument here, a `StoreConditional` or `BlockTransfer` operand before) was a silent promotion. The fix inverts it.

The predicate, owned by `r2ssa` slot promotion (`Classifier::read`): a frame object is promoted only where every use of its address is proven local. A use is local when it is one of these:

- a load or store through the address;
- a value operation (`SSAOp::value_use` is not `Consumes`): copies and address arithmetic carry the point, a test yields a flag that carries nothing, and anything else makes a number whose own uses decide;
- the condition of a branch;
- the stored value of a store into a promoted place that no call's argument area holds.

Every other use escapes the address and keeps the object in memory:

- a register handed to a call (`CallUse`), unless the callee is proven to reach only upward;
- a store into a place a call may read;
- a return, a transfer target, an intrinsic;
- any operation the list does not name: atomics, guarded or linked accesses, block transfers.

The stack a call may read is one fact with one owner, `SourceMachineContext::call_argument_area`. `FrameReach` reads it as well.

- The area is the space the convention reserves for the callee, plus the slots a complete, non-variadic call-site interface places.
- Without such an interface, the call may read every place from its stack pointer up to the entry pointer. Its arguments lie in this frame, below the return address. `FrameReach` reads the same `None` as `Whole`.
- Above the entry pointer, this function's own homes and stack parameters are no call's arguments. testapp `0x140007ff4` stores a `sete` byte into home 1, and RAX held `rsp` before the byte was inserted. The store made a number from a frame address, in a place no call reads.
- The coordinates are the boundary's: from the pointer a `CallRestore` records, else the reaching pointer past what the transfer spends. One dominator-tree walk carries the pointer to each call, `O(B + ops)`. Each classification round tests the stored places against each call's area, `O(calls x stored places)`.
- A call at a pointer no offset places may read any place.
- A place holding an address a call may read keeps its store, so `FrameReach` still sees the address leave. A place holding only a value still promotes, and the boundary reads its version.

Tests:

- `a_local_passed_as_the_fifth_argument_stays_in_memory` (Microsoft x64) and `a_local_passed_as_the_seventh_argument_stays_in_memory` (SysV) store 5 into a local and pass its address only through the stack slot. Every argument register holds 0. Each reads the local after the call. At base both print `return r2sleigh_carrier_u32(5)`, where the callee writes 9. At head the store stands before the call and the load after it.
- The `va_list` fixture keeps all four homes and the outgoing slot in memory. `print_line` stores `arg0` into home 0 and reloads it for the format. The three tail homes are the save area of `...`, so the proof elides them. The call stays a residual, since `&home[1]` has no C spelling. `a_home_handed_on_as_a_cited_va_list_is_a_variadic_tail` now asserts the home-0 store.

Gates, release r2s, base `505319748`:

- Census: 444 goldens pass, 0 lines move. A 445th, `tests/db/cmd/stated_convention`, holds `diff` and `twice` above.
- Win64 equivalence was not run: no CI job runs it and the build host held no xwin sysroot. Its corpus calls `memcpy` with constant sizes of 4 and 8 only. Touched crates' tests: 1,488 pass (r2ssa, r2engine).
- hello_gs 0 of 259 and testapp 0 of 181 functions move in `aa; pdd`. hello_gs `0x140001040` passes `arg3` as its fifth argument through `[rsp+0x20]`. That is a value, so its rendering is unchanged.
- Certification, radare2 `test/bins/elf --limit 24 --functions 8`: base and head print 50 rendered, 30 refused, 0 invented, 0 dropped. Coverage: 560 of 562 rendered, no regressions.
- Cost, instructions retired, median of three, base then head: cold `pdd` on pumasim `0x23fdf0` 19.87 to 19.92 G (+0.2%), 0pack `0x62ecf0` 15.38 to 15.43 G (+0.4%), output identical. Peak footprint is flat on the Mac: 0pack 228 to 232 MB at S7b `60208afbd`, S10 and head, over 7 runs each.
- #360's Timing vs Base read 0pack `0x62ecf0` RSS 250 to 281 MB and 257 to 284 MB. On one Linux host, CI's own `r2s` artifacts give these numbers:
  - Over 30 interleaved runs each, S7b reads 219 to 231 MB (median 225) and head 218 to 231 MB (median 226).
  - The counting builds' heap peak is 131.4 MB on every run of both.
  - No thread is spawned. RSS varies by up to 30 MB from run to run at one heap peak, and the gate takes the largest of 5 runs. No retained allocation was found.
- Dylint: 8 warnings, the baseline. Structure counts do not rise.

## S21 as built (2026-11-11)

The proof line now counts what the text shows (D233, D234). Both changes are in r2dec's proof line, and no C moves.

- D233: "the result is unproven (CAUSE): N unproven-return carried" counted only returns wrapped in `r2sleigh_carrier_uN`. A return whose value holds a residual is never wrapped (`carry`), so `_fini`'s `return r2sleigh_residual_u64(1)` stood beside "0 unproven-return carried". `prelude::unproven_returns` now counts each `return` statement of the body once: carried, where the value is the carrier call; residual, where the value holds a residual of any cause. The clause adds ", M unproven-return residual" where M is not zero. The fact is the returned expression itself, the one the text prints. The statement walk is one pass, `O(statements)`. `count_gaps` reads the same walker.
- D234: the closed-world premise left the obligation list. "a call reads the result", "no call reads the result" and "a call returns the result on through a cycle", each "(assuming closed-world)", is now a `;` clause after the parameter floor and before the result's own clauses. It is printed wherever the ledger holds `Premise::ClosedWorld`. The old line printed it only beside a non-empty obligation list; no census line gains the clause.

Gates, debug r2s on `s10-win64` `505319748`, census rerun on `d8487d42d` and `052de86bc` (`f26030869` drops one trace):

- Census: 14 goldens, 157 line pairs, proof lines only. 130 move the premise clause (119 "a call reads", 11 "no call reads"). 29 gain "1 unproven-return residual" (23) or "2 unproven-return residual" (6). Two lines take both. A script applied both transforms to the base goldens and matched the re-record in every line. Each residual count equals the `return ... r2sleigh_residual_uN(...)` lines below it, counting the casted `(uint64_t)r2sleigh_residual_u64(4)` in `__do_global_dtors_aux`. The one line left at "0 unproven-return carried" is rv_O2 `dispatch`, "no return reached", which holds no return.
- Engine: `a_closed_world_read_states_its_premise_and_a_cold_render_stays_unproven` asserts "; a call reads the result (assuming closed-world)" and no "refused, a call". `an_aarch64_keep_is_never_void` asserts "0 unproven-return carried, 1 unproven-return residual" beside `return r2sleigh_residual_u64(1);`. Both fail on the old line.
- Not run here: equivalence and certification. No C changes, so CI's runs grade them.

## S15 as built (2026-11-11)

D218 and D219, the 15 aarch64 equivalence records S7 left `residual-trap` (`unproven (EntryInput)`).

Invariant: a call takes a vector register of a variadic tail unless its own format proves no floating operand; a lane is `void` only where every lane a body may hand back is dead at every call, the calls are every way in, and each forwarder's calls are too. A format the walk cannot fold, a refused parse, a `VaList`, scanf or wide kind keeps today's takes, so an unproven call never decides a lane.

What the code said that this ADR did not, and the owner chosen:

- D219 was already built. "The result side as built" asks every-way-in lazily (`Forwarded::DeadIfEveryWayIn`, `Sites::forwarders`), per lane, whatever the forwarder's own integer lane does. The row described S7's `exhaustive`, which D213 deleted. A probe build whose imports took no vector register decided all 15 `void`, the nine D219 records with them. S15 adds the test: `a_lane_forwarded_through_a_caller_whose_result_is_read_is_decided_per_lane`.
- D218's owners, one each:
  - r2abi states the tail (`Tail::Format { index, kind: Printf }`).
  - r2engine `Placement::reads` states `ImportReads::format`: the format parameter's register and the tail's vector registers, only for a printf format placed whole where the convention has no count register. SysV keeps `al` (`Counted`).
  - The site walk (`fates.rs` `Reading::formatted_sites`) folds the format register at each call with r2ssa `BlockOrigins::step_under` and the convention's `SourceCallEffect`, reads the text with `immutable_text_at` (`text_at` over bytes mapped read-only that the loader does not write, `TableBytes::ReadOnly`), and parses it with r2ssa `printf.rs`, now public. A format with no floating conversion takes no tail vector register (`Effects::by_site`).
- A call keeps a preserved register's constant: clang -O1 and -O2 build the format once in x21 and pass it to 15 `printf`s across other calls. The SSA format reader rests on the same convention fact: a probe whose callee writes x19 without restoring it prints the literal cold and decides `void` under `aa`. A body that breaks AAPCS64's callee-saved set is outside both readers' premise.
- `strlen` and `memcpy` move from radare2's table to the cited ISO C17 table (7.24.6.3, 7.24.2.1), `Tail::None`. Uncited, each read every argument location, so review.c clang -O1 `fill`'s q0 reached `copy_name`'s `strlen` and stayed open.
- Cost: one forward pass per block over a body that calls a printf-format import, O(ops); none otherwise.

Not built:

- shapes.c clang -O0 `shape_stash` and `mixed_touch`: `main` spills the format to `[sp, #8]` and reloads it before each `printf`. `BlockOrigins` tracks no frame slot, so the call takes q0 to q7 and both stay `residual-trap`. Proving the reload needs the frame slot unescaped across the calls between (D221).

Gates, release r2s, base `505319748`; the branch was then restacked on D217's default deny and the result-side ADR (`9ad72ecd2`), where CI's full run passes:

- The 15 records' `aa; pdd` on stripped aarch64 builds, read by hand: 13 print `void` with "no call reads the result (assuming closed-world)" and a bare `return;` (base: `r2sleigh_result_u64` and `return r2sleigh_residual_u64(1);`). Bodies are byte-identical. clang -O2 `inverted_void` stores 8 bytes at `0x420040`: clang merged `g_note` and `g_sink`.
- Engine tests (`call_boundary.rs`, aarch64): `%d` is `void`, `%f` never, a format held in caller-saved x9 across a call never; the D219 forwarder above.
- `mutants_d213.py`: 22 of 22 killed in the full run. Three D218 mutants join the 19: the per-site effect ignored, a float format read as float-free, a call keeping every register. A 23rd, a writable format trusted, came with the Codex review of #363: a format in writable data may change before the call, so only read-only bytes bound the call; `an_aarch64_printf_whose_format_the_program_may_write_reads_every_vector_register` kills it.
- Certification, radare2 `test/bins/elf --limit 24 --functions 8`: 50 rendered, 30 refused, 0 invented, 0 dropped, at base and head.
- Census: 2 goldens, 2 lines. x86-64 `fill` in `rv_O2` (`0x14c0`) and `rv_O0g_stripped` (`0x1391`) go from `unproven (Written)` to `unproven (Unread)`, "no call reads the result (assuming closed-world)": the cited `strlen` no longer takes RAX in `copy_name`. The C does not move.
- Cost, release, instructions retired, median of three, base then head; output byte-identical: cold `pdd` 0pack `0x62ecf0` 15.37 to 15.37 G, pumasim `0x23fdf0` 19.86 to 19.85 G; bash `0x2e630` `aa; pdd` 14.30 to 14.33 G (+0.2%), under D153's 15.43 G. Peak footprint within run-to-run noise.
- Dylint 8 warnings, the baseline. `comment_runs` adds no run. Structure counts equal the baseline.
- On D217 (`d8487d42d`): the 15 records print as above and the census holds 444 goldens.
- Equivalence, CI on #363: x86-64 holds every record. AArch64 moves 21 records from `residual-trap` to `equal`: the 13 above, and 8 more whose void body's lanes reached the same `printf` or `strlen` (`and_chain_effect` clang O0 to O2, `crc32_init` clang O2, `fill` clang O0 and O2, `indirect_store` clang O1, `mixed_touch` gcc O1). Each of the 8 was read by hand, base then head: `unproven (EntryInput)` with `return r2sleigh_residual_u64(1);`, then `void` with `return;`; bodies unchanged. All 21 are blessed. The two clang -O0 records keep `residual-trap` with cause D221.

## S22 as built (2026-11-11)

The loader's call to a termination function is a way in whose read a cited row states (D237 to D240).

- The brief said the gABI states `DT_INIT` and `DT_FINI` as `void (*)(void)`. It does not: chapter 5 gives no function type. It says termination functions "are executed with the atexit(BA_OS) mechanism", and that the dynamic linker may register "the executable file's termination function with atexit(BA_OS)". ISO C17 7.22.4.2 types atexit's handler `void (*)(void)`. That chain is the row's citation.
- Owner: r2abi `loader_call(format, kind) -> Option<&LoaderCall>`, `LoaderCall { arguments, reads_result, citation }`, keyed by `(Format::Elf, FiniHook | Fini)` from r2image's entries, never by a name. r2engine `Escapes` drops an entry whose row passes and reads nothing, and skips the word starting in the pointer-wide slot r2image states it at (`Entry::stated_at`): `O(log slots)` per matched word. Every other word, reference, export or call still escapes.
- Route: the closed world, not a declaration. The result-side ADR's constructor row planned `SourceLoaderRole` at basis `Declared`; that row now names this owner. A declaration outranks the closed world (`decide` returns `None` on declared types), so a synthesised `void(void)` would outrank a call in the image that reads the result. Through `Escapes`, a reading call still makes the result a value, and a cold `pdd` keeps the residual. The proof line names closed-world only; the row's citation is in the `closed-world` refusal evidence.
- D213's rule then decides a handed-back result void with no call. A termination function that writes RAX (`xor eax, eax`) and has no caller stays `unproven (Written)`: D202 decides Unread only over at least one call.
- Constructors had no row (D240): glibc's `elf/dl-init.c` passes `argc, argv, envp`, musl passes nothing, and the gABI states no type. Ga keyed them by C library ("Ga as built"). Mach-O terminators have none.
- `SourceLoaderRole` was deleted (D238). It was `None` at every capture since #66, and its r2ssa rule made a hook void whatever another caller read.

Gates, debug r2s on S15 (`dbe66a333`; `40dd51372` changes only docs and the aarch64 baseline):

- The 9 exit-bar functions print `void _fini(void)` (`fcn_401ba0` and `fcn_17cc` stripped) with "no call reads the result (assuming closed-world)": branchy O0, frame_pointer_locals clang O0g, hashes O2 and stripped, rv_O0g and stripped, rv_O2, shapes O0, two_units O0g. Each body is `sub rsp, 8; add rsp, 8; ret`. Residual obligations 2 to 0 each.
- Census: 9 goldens, 31 lines, and nothing else. 27 are the 9 `_fini`. 4 are `deregister_tm_clones` in 4 of those goldens (hashes O2 and stripped, branchy O0, shapes O0): "unproven (Written)" becomes "no call reads the result (assuming closed-world); the result is unproven (Unread)". Its one caller `__do_global_dtors_aux` returns its result on and is a non-PIE `.fini_array` entry. In PIE fixtures the slot's `R_X86_64_RELATIVE` addend is one more word naming it (rv_O0g file offset `0x618` names `0x1160`), so nothing moves there (D239).
- Engine: `a_termination_function_the_loader_alone_calls_is_void` (`void f(void)` under `aa`; a cold render and an `InitHook` keep the residual) and `a_termination_function_another_way_reaches_keeps_its_result` (a second data word keeps the residual; a call reading the RAX `f` writes makes it `uint64_t f(void)` with "a call reads the result").

## S17 as built (2026-11-11)

S17 is the rest of Win64 after S10: `/GS` (D215), a Win64 equivalence target (D216), and floating varargs with a home `va_list`'s count (D220). Branch `s17-win64-rest`.

### `/GS` (D215)

What the code said that this ADR did not, and the owner chosen:

- `GuardRow::LoadConfigCookie` is the row for `(x86, 64, Ucrt)`. The row says the C library checks a load-config cookie. The container says where: `convention_model` takes `Container::security_cookie` beside the kernel and the library, and `forms` sets `BoundaryForms::security_cookie` only where both state it. r2ssa reads `SourceSecurityCookie { address, width }` off the machine context's `ConventionModel::forms`, and the first integer argument and the result registers off the model: D309 admits no new reader of `SourceCallEffect` or `SourceConventionSlots`. D220's new readers (`home_cursor`, `homed_tail`, `floating_tail_placed`, `shared_float_slot`) read the model too. A PE is `Ucrt` by its format, so both radare2 test PEs take the row.
- The callee is proven in r2ssa (`security_cookie::proves_check`), during interface recovery, and minted as `SourceFunctionInterface::security_check`. The proof:
  - one block's branch compares the entry value of the first integer argument register with a load of the cookie's address and width;
  - that block dominates every return;
  - every block reached from the failing edge goes on inside the function or ends at a call that does not return, and none returns;
  - no block a return is reached from stores, calls, enters the machine or branches indirectly.
  - every other branch a return is reached from is decided by register operations over the argument, the cookie and constants alone (`derived_only_from`), so a matching argument decides that the call returns with no effect; a callee that also tests another argument is no check (`a_cookie_compare_that_also_tests_another_argument_is_no_check`, a Codex review finding).
  - The name decides nothing: `a_cookie_compare_that_comes_back_is_no_check_whatever_its_name` names a body `__security_check_cookie` whose failing arm returns.
  - MSVC's check also tests the cookie's top 16 bits on the passing edge (`rol rcx, 16; test cx, cx`). That arm reaches the same failure. The proof does not need the second test: a returning path writes no memory (`inert`), and `preserved_call_carriers` states which registers it leaves, so eliding the call claims only that a call that returns did nothing a caller reads.
- A UCRT check's failure is `__report_gsfailure`: `__fastfail` (`int 0x29`) where `IsProcessorFeaturePresent(23)` holds, then `__raise_securityfailure`, which tail-jumps to `TerminateProcess(GetCurrentProcess(), 0xc0000409)`. Without a fact for that jump, the failure returned and no check was proven on hello_gs or testapp. Two cited KERNEL32 keys supply it (`data/README.md`):
  - `func.GetCurrentProcess.yields=current-process`: "The return value is a pseudo handle to the current process."
  - `func.TerminateProcess.halts_on=0,current-process`: "When a process terminates itself, TerminateProcess stops execution of the calling thread and does not return."
  - `LibraryRow::{yields, halts_on}` type them as `Handle::CurrentProcess`; the handle's value (`(HANDLE)-1`, "currently") decides nothing.
- Discovery owns whether control comes back. The body walk follows handles through one straight run: a call through a sealed import slot whose row yields a handle leaves it in the convention's integer result register, a copy hands it on, any other write or call ends it (`body::Handles`, `O(ops × held)`). A tail jump through a sealed slot halts where the import never returns (`ExitProcess`), or where its `halts_on` register holds that handle. A branch later found into the proven run puts the jump's stop back (`Walk::transfer`; `a_branch_past_the_handle_s_copy_may_return`). The walk tracks handles only in a PE (`Program::binds_handles`), whose KERNEL32 rows alone state them. hello_gs `0x140011cb0` (`__raise_securityfailure`) is now `noreturn`; `terminating_the_current_process_does_not_return` and `terminating_another_handle_may_return` are the engine tests.
- `preserved_call_carriers` now counts writes only in blocks a return is reached from. A write on a path that never returns is unseen by a caller. The check's failure path writes `rax`; its passing path writes `rcx` and flags. So callers read `rax`, `rdx` and `r8` to `r11` past the check as their own.
- The caller (`security_cookie::decide`, after `stack_protector::decide`, under `Premise::UbFreeSource`):
  - each direct call to a proven check is handed `saved ^ sp`, where `saved` is the prologue's `[cookie] ^ sp'` itself (a promoted slot) or the reload of a slot whose one writer stored it before the reload, and no other load reads that slot;
  - `sp` and `sp'` are the entry stack pointer at one offset;
  - the cookie load, both xors, the save and reload, the call instruction's operations, and the flags nothing reads are recorded compiler-inserted, as `stack_protector` records the canary's;
  - the call stays in the SSA, recorded compiler-inserted, and the boundary pass gives it no C boundary. A clobber of the call that something reads refuses the elision.
  - A value carried across the elided call in a result carrier stays a residual: the return-value walk (`reaching_rules::op_ends_reaching_walk`) ends at any call. Exempting an inserted call there turned 9 of hello_gs's 11 elisions into refusals on the return boundary's taint, so it was withdrawn (D231). hello_gs `0x140003178` returned `(uint64_t)rax_11` at base, the check call's `rax` read as the function's result, a value the check never computes; head returns `r2sleigh_residual_u64(3)`. The machine returns `ebx`.
  - A save that reaches a return in a result carrier refuses the elision: testapp `0x140009a10` returns the save in `rax` on its `jb` path, and that C is what the machine computes.
- Two readers learned of compiler-inserted operations: obligation liveness does not propagate through one (`SeedingFacts::inserted`), and a read by one leaves a value inside the stack geometry (`StackGeometryContext::inserted`). Without them the stack pointer the xor read stayed a live producer nothing rendered, and testapp `0x1400051a4` and `0x140009a10` refused.
- Found: a `/GS` function's other readers of the cookie keep their reads. Of the 36 readers radare2 `axt` names in each PE, 16 in hello_gs and 20 in testapp call no check: UCRT's pointer encoding (`mov rax, [cookie]; xor; ror`), `__security_init_cookie` (the writer), and the check itself.

### Floating varargs and a home `va_list`'s count (D220)

- `printf_consumed_arguments` states each operand's class. A positional operand read as two classes refuses (`ConflictingOperandClass`); merged formats whose floating operands differ refuse.
- A floating operand at shared position p < 4 is the argument where `r_p` and `xmm_p`'s low 8 bytes reach one root or one constant through copies, low pieces and zero extensions (`same_bits`). The argument names the float register `SourceConventionSlots::float_argument_slots()[p]`, read from the convention. Otherwise `FloatingVariadicArgument` stays.
- The double prints as `r2sleigh_float_from_bits_64(rax_1)` with `rax_1 = 0x4004000000000000`; r2dec folds no bit pattern to a literal.
- `save_area::home_cursor` starts a tail at the lowest home whose address the body keeps; the area stands only where `tail_count` proves a count over it, and the prover now runs with no base or offset cell. clang -O0 does not home `rcx`: it stores `n` to a local, read through that local's cell. A cursor value a call reads implicitly (`CallUse`) still counts as harmless, as on SysV. The clang -O1 shape (cursor in a register, `dec ecx; jne`) is untested.

### A Win64 equivalence target (D216)

- Design: the PE is mapped at its own image base inside an empty non-PIE Linux host, so `LD_PRELOAD`, `fork` per run and the trap guard work unchanged (`rt/pe_win64.c`). Imports from UCRT, KERNEL32 and VCRUNTIME bind to Microsoft x64 shims over glibc; one with no shim binds to `abort`. `rt/call_win64.S` enters with `rcx`, `rdx`, `r8`, `r9`, `xmm0` to `xmm3` and stack words past the home. Renderings build with `gcc -mabi=ms -fno-builtin -U_FORTIFY_SOURCE`; `rt/ms_support.c` forwards libc, libgcc and libubsan helpers to their System V versions. Object links go through the dynamic loader, as on AArch64.
- Rejected: wine. A Win32 process has no `fork` or `LD_PRELOAD`, so it meant a rewrite of the runtime.
- Population: `tests/corpus` and `tests/gold` by clang-cl `/MD /GS /Od|/O1|/O2` with DWARF, linked by lld-link-18 against an xwin 0.10.0 sysroot. `llvm-strip` keeps section addresses; `readelf` reads DWARF from an `objcopy -O elf64-x86-64` copy. Every corpus PE imports `__stdio_common_vfprintf` and carries a load-config cookie, so it also grades D215 and D220.
- Baseline from the S17 base (`9f924f196`), 483 records: 365 equal, 72 residual-trap (34 held-from-entry, 25 `CallNotRendered`), 15 refused (unaccounted effect obligations), 28 unsupported, 3 `ub`. The 3 `ub` are `shape_variadic` at O0, O1 and O2: the rendering writes a 5th-or-later variadic argument into its frame array and passes 4 registers (D232).
- The inline UCRT `printf` is recovered as `fcn_X(uint64_t, ...)` and its callers pass the format and arguments; the printf body refuses in all 10 records.
- Found: `pddj` links a call through `call [__imp_X]` with kind `function` at the IAT slot's address; the harness jumps through slots the import table names. The link's owner should state kind `import`.
- A result that rests on Windows' own library behaviour is graded against glibc's; `tests/equiv/README.md` states the limit.
- Run: `EQUIV_XWIN=<xwin> bash tests/equiv/run_win64.sh <r2s>` on an x86-64 Linux host, about 510 s with `--jobs 2`. No CI job: the runners hold no xwin sysroot. 46 self-tests pass on win64, x86-64 and aarch64; 156 harness tests pass.

### Gates

- Touched crates' tests (r2abi, r2source, r2ssa, r2engine): all pass; r2engine engine 583, r2ssa 746. Clippy `-D warnings` clean with `--tests`. Dylint 8, the baseline.
- Census: 444 goldens pass after 14 move. Each moved line is a proof line only: an ELF canary function owes 3 fewer obligations (5 to 3 compiler-inserted, one fewer elided), since liveness no longer runs through the canary's inserted operations into their inputs. The rendered C is unchanged.
- x86-64 and aarch64 equivalence: graded by CI's `full-ci` ratchets on the pull request (the shared build host was held by another run).
- Hand-read, release r2s, hello_gs: `main` prints `fcn_140001090((uint64_t)0x14001d008U, rax_1); return 0;` as at base. `0x140003178`, `0x14000fc3c` and `0x1400095d4` render with no cookie load and no check call; `0x1400095d4` and 8 others refused at base. `0x140005f80` renders where base had 22 `UnsupportedInstruction` gaps, since `0x140006050` is now `noreturn`; its own cookie read is UCRT's pointer decode, kept.

## S20 as built (2026-11-11)

The container picks each function's convention and each import's library (D249 to D252). No score and no name decides either.

The convention:

- r2image reads `DW_AT_calling_convention` whole into `Prototype.convention` (`r2abi::StatedConvention`), replacing the `nocall` flag. It chooses nothing. `Normal`, `Program` and `NoCall` are DWARF 5's codes (3.3.1.1). `LlvmWin64` (0xc1) and `LlvmX8664SysV` (0xc2) are clang's `ms_abi` and `sysv_abi`, from `llvm/BinaryFormat/Dwarf.def`. Any other code is `Other(u8)`.
- A producer that writes no attribute for `ms_abi` (gcc probably; not checked, no gcc on the build host) leaves the function under the target's default, as before. No fact in the container says otherwise.
- r2engine chooses (`program::stated_convention`): on x86-64, `LlvmWin64` is `ConventionId::Win64` and `LlvmX8664SysV` is `ConventionId::SysVAmd64`. `Normal` keeps the target's default: a PE's Win64, a Mach-O arm64's AppleArm64, the kernel's otherwise. `Program` and `NoCall` keep it too, and `place` refuses their parameters (`PlacementRefusal::NoCall`).
- Any other code refuses the whole function (`Unassembled::StatedConvention`), where `NoCall` refuses only the declaration. A `vectorcall` or `regcall` body read under the default would place its parameters in registers it does not use.
- `Machines.stated` holds one `Assembled` per other convention a declaration states, built in one O(functions) pass at open. `assembled_at` is O(log functions). The imports and the data model moved from `Assembled` to `Machines`: one program has one of each.
- `SYSTEM_V_AMD64` now names gcc's cspec outright. It read "the container's usual", which in a PE is Windows' and has no SysV prototype.
- An import is placed under the program's convention, which its library runs under (`NativeTarget::importing`): `puts` called from an `ms_abi` function in an ELF still takes rdi.
- `Declarations::same_interface` compares the stated convention, so two units stating one function under two conventions disagree.

The call effect:

- No call site states its callee's convention. In a program where a declaration states a second convention, a call may run under either. `ConventionModel::either` joins two models: reads, kills and likely-trash are the union, preserved is the intersection, `results_complete` is `None`. Only the call effect reads the join; nothing is placed in it.
- `AnyCall(ConventionId)` holds the join of a convention with every other the program states, one per convention, O(conventions x registers). `NativeTarget.call` carries it and `machine`, `SiteFates`, `CalleeEntry` and the reference index read its effect. With nothing stated it is the convention's own `Arc`.
- The join is per program, not per site (D252). A direct call to a body the engine reads takes that body's effect: a `sysv_abi` callee that writes rsi kills it, and one that does not leaves it. A call to an import, to an unread body or through a pointer takes the join. In a PE that states one `sysv_abi` function, such a call loses rsi, rdi and xmm6 to xmm15. The precise form reads the program's convention at an import and the join at an indirect site. It needs a per-site effect in `NativeMachine`, which holds one per function.
- A direct call's arguments were already the callee's: its boundary places them.

The import binding (design review finding 6):

- `Linkage` holds one `Binding` per import name, built once: O(imports x (log imports + needed libraries)), then O(log imports) per lookup. `Scope(tables)`, `Versioned(CLibrary)`, `CLibrary` or `Unstated(why)`. `Unstated` binds no row, so the call reads every location.
- PE: the DLL the import directory names. `KERNEL32.dll` reads its table. A UCRT DLL reads its table, then the C++ and portable rows. Any other DLL is `Unstated`; before S20 it read the portable rows by name. An import by ordinal states no name a row is keyed by.
- Mach-O: r2image reads the two-level namespace library ordinal from `n_desc` (`GET_LIBRARY_ORDINAL`, `<mach-o/nlist.h>`) into `Symbol::library`, the install name of load command `ordinal - 1`. Ordinals 0, 0xfe and 0xff, and a flat namespace (`MH_TWOLEVEL` clear), name none. `/usr/lib/libSystem.B.dylib` reads libSystem's scope, `/usr/lib/libc++.1.dylib` and `/usr/lib/libc++abi.dylib` the C++ runtime's, `/usr/lib/libobjc.A.dylib` objc4's. The whole install name is matched: another path's `libSystem.B.dylib` is another library.
- objc4's 7 rows moved from `types-darwin.sdb.txt` to `types-objc.sdb.txt` under `LibraryId::Objc`. A libobjc import reads only them, and a libSystem import reads none of them.
- ELF: a version need binds only where `DT_NEEDED` names its file. `GLIBC_*` is glibc, `LIBC` and `LIBC_*` on `libc.so`, `libm.so` or `libdl.so` bionic, `GLIBCXX_*`, `CXXABI_*` and `GCC_*` the C++ runtime. An unversioned import binds only where `DT_NEEDED` names one library and it is a C library. Only `.dynsym` imports count; `.symtab` repeats them unversioned.
- Two imports of one name that bind two libraries are `Unstated`.
- A mangled name's row moved to `LibraryId::Itanium`. It applies whatever library defines the import, because the mangling is the ABI's statement of the parameters. A table's row for the same name wins where the import binds that table.
- `Symbol::library` now names a Mach-O dylib too. r2s `is` and `ii` print it only for a PE directory entry (`origin.directory`), as radare2 does.
- `ucrtbased.dll`, the debug build of the UCRT, is `Dll::Ucrt` (Microsoft, "C runtime (CRT) and C++ standard library (STL) lib files").
- `msvcrt.dll` and `VCRUNTIME140.dll` have no cited table, so their imports bind nothing. D281 owns their rows.

Gates, release r2s, base `f961bfdaa` (S31a; `62a564fb9` changes only a doc and the coverage baseline):

- `crates/r2image/tests/data/dwarf_ms_abi.elf` (clang, `diff` stated `DW_CC_LLVM_Win64`), `aa; pdd`, read by hand. `diff` is `mov rax, rcx; sub rax, rdx; ret`. Base prints `uint64_t diff(r2sleigh_unread_u64 arg0, r2sleigh_unread_u64 arg1, uint64_t arg2, uint64_t arg3)` returning `arg3 - arg2`, and `twice` calls `diff(0, 0, b, a)`. Head prints `int64_t diff(int64_t a, int64_t b)` returning `a - b`, and `twice` calls `diff(a, b)`.
- Engine tests (`stated_convention.rs`): an `ms_abi` function in an ELF takes rcx and rdx, and rdi and rsi with nothing stated; its SysV caller passes `diff(arg1, arg0)`; `DW_CC_LLVM_vectorcall` refuses the function and not its neighbour; `puts` called from it still takes rdi; in a PE stating a `sysv_abi` function, `add rax, rsi` past a call through r8 reads a residual, never `arg0`, and reads `arg0` with nothing stated; a direct call to a `sysv_abi` body that writes rsi reads a residual too, cold and under `aa`.
- hello_gs and testapp, `aa; pdd` of every `afl` function: 0 of 259 and 0 of 181 functions move (26,076 and 14,155 lines). Callee prototypes supplied by the source: 103 and 103, 97 and 97.
- `an_import_from_a_dll_no_table_states_stays_undeclared`: `printf` from `msvcrt.dll` in a PE is "the import has no declaration to state its arguments".
- radare2 `test/bins/pe`, eleven more x86-64 PEs, each moved line read (lines removed plus lines added):
  - `cobalt.exe` and `hex_search.exe` (mingw, msvcrt.dll): 237 and 263 lines. The thunks of `malloc`, `memcpy`, `fwrite`, `vfprintf` and the rest lose the portable row a bare name gave them, so each call to one is `CallNotRendered` with "its arity is only at least 0".
  - `seh_x64.exe`, `testx64.exe`, `rarg_detection.dll` (4 lines each) and `plscrackme.exe` (12): the `VCRUNTIME140.dll` thunks of `memset`, `memcpy` and `memcmp` go from three parameters to `(void)` with a floor.
  - `cpp_sample.exe`, 21 lines: `ucrtbased.dll`'s `__stdio_common_vfprintf` binds UCRT's cited row. Its caller goes from "the import has no declaration" to a rendered five-argument call, 20 residual obligations to 2.
  - `WindowsUI-App.exe`, `exceptions.exe`, `normal64.exe` and `tls64.exe`: 0 lines.
- radare2 `test/bins/mach0`, eight binaries, 3,377 functions (`cat-macos-arm64`, `hello-objc-osx`, `hello-objc`, `hello-macos-arm64-chained`, `ClassCpp.out`, `a.out`, `hello-osx-i386`, `dlang-hello` with 3,194 functions): 0 lines move. Each imports through a two-level namespace from libSystem, libc++ or libobjc. `macho_two_level` binds `puts` and leaves libz's `zlibVersion` undeclared.
- ELF: ls-toybox `aa; pdd` of every function, 101,266 lines, 0 move. A 300-function sample of 0pack and of pumasim: 0 move.
- Census: 444 goldens pass, 0 lines move. A 445th, `tests/db/cmd/stated_convention`, holds `diff` and `twice` above.
- Win64 equivalence was not run: no CI job runs it and the build host held no xwin sysroot. Its corpus calls `memcpy` with constant sizes of 4 and 8 only.
- Cost, release, instructions retired, one run each, base then head; output byte-identical: cold `pdd` 0pack `0x58e3d0` 18.85 to 18.81 G, `0x62ecf0` 15.46 to 15.48 G; pumasim `0x23fdf0` 24.45 to 24.42 G, `0x4baf30` 14.92 to 14.93 G; bash `0x2e630` `aa; pdd` 14.34 to 14.36 G. Peak footprint within 3%.
- Touched crates' tests (r2abi, r2image, r2source, r2ssa, r2types, r2engine, r2s): 2,615 pass, 0 fail. Clippy `-D warnings` clean with `--tests`. Dylint 8, the baseline. `comment_runs` adds no run. Structure: no count rises; `long_comments` 2,484 to 2,483, blessed.
- x86-64 and aarch64 equivalence: graded by CI's `full-ci` ratchets on the pull request.

## S16 as built (2026-11-11)

D212 and W46, reworked to the result-side design (the lattice `None`, `PassThrough`, `Result`, `Unproven` per lane; default deny). What the code said, and the owner chosen:

- One decision per call to a callee whose result is unproven: r2ssa `recover_interface::call_lanes(callee, passes, results)`. The lane set is `ConventionModel.results`; `passes` is the callee's existing preserved set (`preserved_call_carriers`, an every-path fact: no operation writes the lane, every exit a return, every inner call passes it). A lane is `PassThrough` where that set covers it, `None` for the integer register with `integer_undefined` and the second register beside it, `Unproven` otherwise.
- Call-site minting reads it. Every lane `PassThrough` or `None`: the call states `Void`; one `Unproven` lane, or no lane set, refuses `Void`. One carrier left: `Register`, as D62 mints a single carrier. Two written carriers: `SourceCallResult::Unproven { integer, float }`, one group, no lane picked; the extern spells the callee's header (its integer carrier typedef, D201). A second register beside an integer that does not pass still refuses.
- `SourceCallBoundaryFact::unproven_lanes` holds the call's `Unproven` lanes. `returned_by_call` reads one, or either lane of a group, as `Undecided`: a forwarder of it is never void, and a float lane `Undecided` beside a written integer is `Ambiguous`. A call with no stated result at all stays `Unstated` and leaves a written integer its register (`call g; mov eax, 7; ret`).
- `PassThrough` is read only from the preserved set, for a direct target, never from a missing `CallDefine`. The reaching walk (`reaching_rules::op_ends_reaching_walk`) goes past a call whose callee passes the storage. A tail to a callee passing every result lane is a return in `liveout` (`passing_tail`); per lane, a tail block leaves the checks only where its callee does not pass that lane (`owned_tail_blocks`). A tail whose float lane is `Unproven`, or a group, states no exact tail result (`stated_result`).
- The float lane of a function whose integer register holds nothing: a lane an unstated call or an `Undecided` lane leaves at a return is a carrier, so the function is `Unproven`, not `void`. ldb `p_ldb_forward_b` (`push rax; call rax; pop rax; ret`, the struct's double in XMM0) was this: its 4 `known.json` entries named an x87 cause the fixture does not have. clang O1, O2, O2.avx2 and O3 now print `r2sleigh_result_u64` cold and `double` under `aa`.
- Closed-world demand is unchanged. A read past a call that passes the lane is still `Unknown`: reading each callee's preserved set from its open read inside `SiteFates` prepared every callee of every surveyed caller, bash `aa; pdd @ 0x2e630` 14.31 to 26.28 G, over D153's 15.43 G. S31's held register effect (`kept`) supplies it. The hand-off `Read` for a cited fixed parameter is not built: at S16's base no cited row had a float parameter (S18 cites the math rows), and on an integer lane (AArch64 `free(x0)`) it reads an argument a callee may leave alone (D228).
- W46, one owner per header fact: r2types projects a callee's body-read integer parameters unsigned, as its own header declares them (D156: no byte states the sign), so the extern and the header agree (`setExit(int32_t)` against `uint32_t`). A call that takes no lane of an unproven result declares the header's carrier word. r2dec declares a tag a callee's projection names behind a pointer (`struct fcn_401472_arg0;`) where the unit defines no tag of that name, so the extern spells the header's struct pointer.

Per D212 record, bzip2 O2-noinline stripped, release, cold and `aa`:

- `testf` (`0x4c20`): `void`. It is the only header of the binary that moves to or from `void` under `aa` (`pddj` of every function, base and head). Its tail to `setExit` passes RAX and XMM0, and on every path XMM0 is a void import's clobber (`None`) and RAX the canary residue.
- `uncompress` (`0x44a0`): `Unproven(EntryInput)`: XMM0's entry byte reaches a return through passing calls (D208); void only where the closed world finds it dead at every call.
- `compress` (`0x5400`): `Unproven`: XMM0 at a return is left by a call whose callee mints no contract (a floor of parameters, D225).
- The tails of `compress` (`0x58ea`) and `flush_RL` (`0x5cb9`, `0x5cc0`) still render `TailTransferNotRendered` ("r2ssa states no call site here"), as at base, though each block is now a return.
- `flush_RL` (`0x5cb0`): `Unproven`, `r2sleigh_result_u32`: it forwards `add_pair_to_block`'s written RAX through its tail to `init_RL`.
- `setExit`, `init_RL`: `Unproven(EntryInput)`, as at base.

Gates, release r2s, base `d8487d42d`:

- Engine tests (`result_lanes.rs`): `a_call_that_passes_the_lane_keeps_the_callers_bytes` (`mov eax, 7; call pass; ret` returns the 7; base a residual), `a_callee_that_leaves_the_lane_on_some_paths_only_defines_it`, `an_indirect_target_never_passes`, `an_entry_lane_across_a_passing_tail_is_entry_input`, `a_float_written_before_a_passing_tail_is_never_void`, `a_float_an_unstated_call_leaves_is_never_void` (base `void`), `a_callee_with_two_written_lanes_mints_a_call_and_its_float_forwarder_is_not_void` (base `void`, extern `void both(void)`), `an_aarch64_argument_passed_through_a_call_is_never_void`. Unit test: `a_call_states_void_only_where_every_lane_passes_or_is_none` (r2ssa `recover_interface`).
- W46, `scripts/extern_agree.py` over the 23 census binaries: 24 of 200 differ at base, 16 at head. 14 are calls to callees whose parameters are a floor (`register_tm_clones` 7, `deregister_tm_clones` 3 and stripped `fcn_401280`, syscalls `fcn_401030`, `_table_dispatch`, rv_O0g_stripped `fcn_1521`): no exact interface, so the extern comes from the call (D225). rv_O0g_stripped `fcn_1362` is a cycle member (`least_fixpoint`); two_units `helper` is two static functions of one name. The measurement's own function-pointer artifact (`dispatch`) is gone: names are dropped inside `(*fn)`.
- rv_O2 `avg` (`0x1430`) stays `r2sleigh_result_u64` with residual returns: `main` reads XMM0 after `call fact`, a callee that passes it, so the read is a `Read` only once closed-world demand reads past a passing callee (S31). With that read taken from the preserved set, `avg` printed `double avg(uint64_t* arg0, uint32_t arg1)` with its `addsd` loop and `divsd` return.
- Census: 7 goldens, 35 lines added and 74 removed. Externs from projections: `rec_spread`, `_out_param_parse` twice, `mixed_touch` with forward-declared tags, `crc32_init` and stripped `fcn_401580` as `r2sleigh_result_u64`, rv_O2 `fill(uint32_t)` and `avg(int64_t*, uint32_t)`. manual_limits_O0 `_main` (AArch64): Unproven(`Ambiguous`) where base printed `return r2sleigh_carrier_u64(...)`: q0, zeroed by `movi` for a local struct, now reaches the return through callees that pass it, a written float lane beside the integer one (D227). Its calls to `uint32_t` callees spelled their upper halves as residuals, though no store reads them: an `Unproven` interface named no return storage, so demand was refused for the body (D340 fixes it).
- The handed-back `Read(Integer)` arm is deleted (result-side ADR open question 2, decided): a closed-world read of an argument register a body leaves alone made that argument the result, and under `-fipa-ra` a `void` callee that leaves x0 alone has the same bytes. With it disabled the census moves 0 lines. The two engine tests that asserted it (`result_reads.rs`) now assert the sound rule: `an_argument_register_handed_back_untouched_stays_unproven_where_a_call_reads_it` and `an_argument_handed_back_beside_a_written_float_stays_unproven_where_a_call_reads_it` (AArch64 `ret` and `fmov d0, #1.0; ret`: `unproven (EntryInput)`, no `return (uint64_t)arg0;`). CI's equivalence ratchets grade the records it moves.
- pumasim `0x23fdf0` (`Gui::Gui`, a constructor) goes from `void` to `r2sleigh_result_u64`: at its return XMM0 is left by a call whose callee mints no contract (a floor of parameters, D225), so no lane proves void. Base's `void` rested on reading that lane as no value.
- Cost, release, instructions retired, median of three, base then head (Mac): bash `aa; pdd @ 0x2e630` 14.31 to 14.33 G; pumasim `aa; pdd @ 0x3b6b20` 66.46 to 66.48 G; 0pack `pdd @ 0x62ecf0` 15.42 to 15.65 G (+1.5%); pumasim `pdd @ 0x23fdf0` 19.96 to 24.61 G (+23%). Peak footprint within 2%. The pumasim cold rise is `outside_resolved` (17 to 241 of the profile's samples): 31 functions at base and 38 at head are resolved again because a callee now states a result or an exact arity. 36 of the 38 second reads change the interface (most `Unproven` to `Register`, 5 to `Void`), so the second preparation carries statements; only a decision held per component and applied at one seal avoids it (S31a, D226).
- Not run here: the DecBench `scratch_void.py` and the Linux `void_soundness.py` builds (the build host was held by another job); CI's full tier grades `void_soundness.py` and both equivalence ratchets.

On S31a, S20 and S18 (rebased onto `f301c8646`, 2026-11-11; tests, goldens, Dylint and structure rerun there, every golden as on S20):

- D317: `CallBoundary` is keyed `(CalleeKey, World)` and reads its supply from the open read (`CalleeReads`); `View::closed_result` takes no interface. The open read prepares a body against no callee, so a forwarder names its carriers from the lanes its calls leave at its returns: the float lane an unstated or `Undecided` call leaves, the second register every return takes from a call (`left_by_calls`). An unproven supply with the second register held decides `Read(Pair)` where a call reads it, as a register supply does. `a_forwarder_of_a_stated_float_result_its_caller_reads_is_never_void`, `a_forwarding_cycle_decides_the_same_whichever_function_is_asked_first` and `a_pair_a_callee_returns_on_is_its_callers_pair` hold.
- The helpers that take the result lanes read `r2source::convention::TypedResults`, not `SourceConventionSlots` (D309's Dylint).
- W46 on S20: 23 of 200 differ at base, 15 at head: 13 floor callees (D225), the cycle member and the two `helper`s; `_table_dispatch` matched at base already.
- Census against S20: 9 goldens, 37 lines added and 76 removed: the moves above, and two proof lines (code_pointer_table_O0, rv_O0g_stripped) that now name the second register open, one with "no call reads the result (assuming closed-world)".
- Cost, release, median of three, S20 then head: pumasim `pdd @ 0x23fdf0` 24.45 to 24.69 G (+1.0%), 0pack `pdd @ 0x62ecf0` 15.48 to 15.67 G (+1.2%), bash `aa; pdd @ 0x2e630` 14.36 to 14.41 G, pumasim `aa; pdd @ 0x3b6b20` 66.36 to 66.73 G (+0.6%). The cold pumasim 24.45 G is the chain's own (S31a measured 24.38 G on S17); d8487d42d's 19.96 G predates S12 to S36.
- D226's one-preparation design was tried. Predicting owners from the raw walk's site fates (`Returned` or `Unknown` on a typed lane, plus tail targets) took cold pumasim to 134.5 G: `Unknown` names nearly every callee, and each owner is resolved with its own closure. `Returned` only took it to 31.8 G with output that differs, since stating owners the read does not name moves call contracts the old resolution left alone, and each prediction pays a `SiteFates` pass and a `CalleeEntry` per callee. Neither is kept; D226 stays a failing timing note.
- Coverage (CI, Apple clang 17): four AArch64 cells gap more, each the deleted handed-back `Read(Integer)` arm: `branchy_arm64_O1` and `_O2` `narrow64` (2 each; a bare `ret` hands back x0, which `main` reads), `branchy_arm64_O2` `inverted_goto` (4; one path returns the argument it stored) and `hashes_arm64_O2` `main` (3, its reads of such a result). No x86-64 cell moves: RAX is no input. They are recorded in `coverage-baseline.json`.

## S34 step 4 as built (2026-11-12)

`ConventionModel` answers every register question the two views answer (D273). No reader moved; steps 5 to 8 move them and delete the views.

- r2engine resolves a `ConventionParts`. `ConventionModel::new` checks it and builds a private index once: O(L log L) in its locations and lanes (L about 60), once per held `ConventionId` and per `AnyCall` join. The parts read through `Deref`, with no `DerefMut`, so no field changes under the index. Every literal builds through `new`.
- The checks are the views' own, written without the view types (`ModelRefusal`). A location that is no register, an integer argument register named twice or a second result pairing no first refuses the model, as the slots' check did. A reserved lane also preserved or clobbered, or a stack guard or bound on a base no call keeps, refuses only the effect (`effect_refused`), as `call_effect`'s `Err` did. Under a refused effect every storage is clobbered and `clobbered`, `call_reads` and `result_reads` are `None`, so `Arch` answers as for no model.
- Go's arm64 specification under Darwin refuses its effect: its `unaffected` names x18, which Darwin reserves. The test names its 6 builds; only the GoArm64 rows are reachable (D274). `stack_guard` and `stack_bound` are `None` under a refused effect, as the view had none.
- Answers: `argument` O(1); `arguments`, `clobbered`, `preserved_registers`, `system_reserved`, `call_reads` and `result_reads` are sorted slices, O(1); `class_of` is a binary search to the registers starting at or before the storage, then a scan of those; `effect_on` is the views' cover sweep, O(L).
- `either` builds through `new`. The join of Microsoft x64 and SysV named rcx, rdx, r8 and r9 twice and failed the slots' check, which nothing read. It now keeps each register in its first position. Its effect is unchanged: the views read the locations as a set.
- A call under no model (ruling 2.1): r2ssa `Arch::{call_reads, call_clobbered, call_effect_on}` take `Option<&ConventionModel>`. Under `None` or a refused effect every outermost register is read and clobbered, and none is preserved or reserved. `SourceMachineContext::result_slot`'s fallback to `Arch::result_slot` stays until step 8.
- `native::convention_model` reads no view, so D309's allowlist falls from 131 to 130 (134 to 133 before S25 removed three readers).

## S34 as built (2026-11-13)

The views and strings are gone; one `ConventionModel` pair is the carrier (D275, D276), each stated call site holds its own model (D252), and what a callee keeps has one owner (D320). Built in the rebuild mode: carriers first, the compiler as the worklist, no allowlist stepping.

- `r2source::Conventions { own, calls }`: `own` places the function's arguments and result, `calls` (the `AnyCall` join) says what a call reads, keeps and clobbers. `NativeMachine.conventions`, `OwnedFunctionSnapshot::conventions`, `EngineSourceSnapshot::conventions` and `SourceMachineContext::conventions` hold two `Arc`s and no copies. The context's `convention()` is `own`, `calls()` is `calls`; `DefinedWhole` now reads `calls`, where it read `own`.
- `ConventionModel` holds `TypedResults` in its index (`results()`, `result()`), so `result_slot` reads it in O(1). `ConventionParts::argument_registers` is private; every reader takes `arguments(class)` or `argument(class, n)` off the index.
- No model (RULING 2.1): a call reads and clobbers every outermost register, a return reads none, no lane is kept (`saved_register::preserved`, `follow_copies`), no register is a result. A calling body builds; `SsaPrepareError::NoCallEffect` is gone. A body with no call keeps an inert boundary config, so leaf tests are unmoved.
- `afi` prints `callconv:` from the interface's `ConventionId` (`radare2_name()`), as radare2 does (`canal.c`).
- Test models: `r2source::convention::testing::model(id)` builds through `ConventionModel::new` (feature `testing`, dev-dependencies only). The step 4 equivalence test went with the views; `every_native_model_and_join_builds_and_only_d274_refuses_its_effect` keeps its build and refusal half.
- Per-site model (D252): `Program::site_convention_at` (the program layer) keys a callee address to the program's default model where the container binds the import, to the stated model where the callee's declaration states one, and to nothing else; r2ssa `CalleeBoundary::keeps` skips a `CallDefine` of what that model keeps, unless the callee's interface returns it. The models join `BuildKey`. Slot calls are D364.
- D320: the artifact no longer states `preserved_call_carriers`. r2engine asks the callee's held `RegisterEffects` row (`Program::kept_at`), so a wrapper whose returning path calls keeps nothing (D363) and a body ending in a tail or `syscall` keeps nothing, where the old set kept them on no proof.

## S27 as built (2026-11-12)

`GuardRow::LinkedGlobal` (D257). AArch64 reads its canary from a global, and only a binding the container states places it.

- r2abi: `GuardRow::LinkedGlobal(LinkedGuard { symbol, width, citation })` for `(arm, 64)` under glibc, musl and bionic, all `__stack_chk_guard`, 8 bytes. glibc defines it in ld.so (`elf/rtld.c`, exported at `GLIBC_2.17`) because the AArch64 thread control block keeps no guard. GCC reads the global by default (`-mstack-protector-guard=global`). The x86 bionic rows stay `ThreadSlot`, as LLVM reads the TLS slot there.
- r2engine `stated::linked_guard` reads the binding from the container once per convention model, O(W + R):
  - a word the loader writes the import's address into (`WriteKind::Import`, `Encoding::Word`, pointer wide, never `Writable`), the predicate `sealed_import` uses for a call;
  - the one `R_*_COPY` record naming the symbol, at the copy's own address. Two copies state no place.
  - A defined symbol of that name binds nothing (`a_defined_symbol_named_like_the_guard_binds_nothing`). A static link keeps only that symbol, so its canary stays a residual (D259).
- `ContainerGuards { cookie, linked }` carries both container facts into `convention_model`. `forms` places each only where the row names its kind, as S17 did for the cookie. r2source `BoundaryForms::linked_guard: Option<SourceLinkedGuard { copy, slots, slot_width, width }>`.
- r2ssa `stack_protector::decide` reads the guard off the model's forms: `Guard::Slot` (`forms.guard`, which base read through `SourceCallEffect::stack_guard`) or `Guard::Linked`. `decide` reads no view now, and its entry leaves D309's allowlist. One proof decides both: `Guard::read` takes a load at the copy's address, or a load at offset 0 from a load of one bound word. Every load of a sealed word holds one address, so clang's second GOT load reaches the same guard. The `Affine` equality between the two sides is gone; both sides are reads of the one stated guard.
- The rereads in the checking block now match by `Guard::read`, width included. Before they matched by address alone.
- A word load is recorded compiler-inserted only when every reader is an inserted operation (`unread_words`, after the address temporaries are taken). A word another reader sees stays a load. A rewritten reread's address temporaries are walked as well (`inserted_addresses`'s `from`). Without that, clang's second GOT load rendered as `(void)r2sleigh_load_u64(0x1080)`.
- `unchecked` (a body that never returns) takes the linked guard through the same `Guard::read`.

Found:

- LLVM reads Android AArch64's canary at `tpidr_el0 + 0x28` (AArch64ISelLowering `getIRStackGuard`, bionic `TLS_SLOT_STACK_GUARD`). Bionic's row here is GCC's global. A second, TLS row for bionic is D258. radare2's `ls-toybox` (bionic, LLVM) has no stack protector at all.
- The CI equivalence corpora do carry canaries: Ubuntu's `aarch64-linux-gnu-gcc` enables `-fstack-protector-strong` by its specs (72 `__stack_chk` references in shapes.c at O1), and `-no-pie` links the guard by `R_AARCH64_COPY`. The local corpus copies had none.
- Eliding a check removes the only call in a leaf, and with it the `__stack_chk_fail` call that reached the whole frame. That exposed a frame-model defect master has on the same code built `-fno-stack-protector`. gcc -O2 `shape_struct_array` reads its table through `x2 = phi(sp, x2 + 8)`. The object model places that address in the unknown object. `FrameReach` counted any placed address as placed, so the loop's read named no frame object, and `dead_frame_stores` elided the `st2` lane store at `frame + 0`. The equivalence record went from equal to `uninit`. `FrameReach` now treats a load or store at a frame address placed in the unknown object as an escape of the objects that flow into it (`Placement::Unknown`). The frame model's extent rule (`close_upward`, decided 2026-10-07) then escapes the run between compiler-owned slots, up and down. A walk from an escaped object stays in that run under `Premise::UbFreeSource`: a C object's address indexes only within the object, and the frame model places no C object across a saved register or a canary. A merge of two frame bases escapes both origins. `a_frame_walk_stepping_down_keeps_the_store_below_it` steps down from `sp + 8` to `sp`; master elides both stores there. Reaching the whole frame instead was tried: 0pack `0x62ecf0` went from 888 to 1,099 residuals with 147 `assumed`, a cost no record needed (`a_frame_read_through_an_unplaced_walk_keeps_the_stores_it_may_read`, which fails before the fix).
- The escape moves other renderings. x86-64 gcc -O2 `shape_byte_indexed_buffer` (`native.rs`, `EDGE_COPY_GAP`) walks its frame in a vector loop through an address in the unknown object. The frame now escapes as one array, and the loop's entry edge carries `frame + 16`, where base left a `ValuesNotRendered` gap. That test now asserts the carried address. The x86-64 equivalence records gcc-O1, gcc-O2 and clang-O1 `shape_byte_indexed_buffer` stay residual-trap with another first gap. Base stopped at `StoreNotSpelled` on the first loop's byte store. Head spells that store and stops at the read-back `TermNotSpelled`. Residuals fall from 51 to 15 at gcc-O1, 56 to 14 at gcc-O2 and 45 to 15 at clang-O1. The new reasons are blessed under P4. ls-toybox moves 1 proof line (one more obligation elided), and 0pack `0x62ecf0` and pumasim `0x23fdf0` do not move.
- A decided canary is a compiler slot that ends an escaped run (`compiler_slots`). gcc's AArch64 canary at `sp + 0x48` has no object of its own: the model places its store inside the object at `sp + 0x10`, and the whole object became a barrier. The run then stopped short of the pointer table, and aarch64 gcc-O1 and gcc-O2 `shape_pointer_to_pointer` showed `StoreNotSpelled`. A canary store is now a barrier only at its object's own base (`interior_offset`); the run reaches the save of `x29`. `a_canary_inside_a_frame_object_does_not_end_its_escape` (the gcc-O2 function itself) fails without that rule. Both records are `equal` again, and x86-64 gcc-O1 `shape_pointer_to_pointer` goes from residual-trap to `equal`. The census golden branchy_gcc_x64_O0 `0x401764` re-bases one frame object: its x86 canary sat inside the object at `frame + 48`, the run now merges it, and every access names the same address (`frame + 80` is `frame + 48 + 32`).
- aarch64 gcc-O2 `shape_byte_indexed_buffer` goes from equal to residual-trap at the read-back `TermNotSpelled`, and master renders that residual when built `-fno-stack-protector`. Its equal rested on the guard call reaching the whole frame. It is blessed `residual-trap` under P4 (maintainer's decision, 2026-11-13): a visible residual beats an equal that rested on the guard's call. aarch64 clang-O1 `shape_byte_indexed_buffer` (no canary) moves as the x86-64 records do: base held `SP_0`, head spells the buffer store (26 to 10 residuals) and traps at the read-back term.

Gates, release r2s, base `ca413c45c` (master):

- Engine tests (`linked_guard.rs`, an in-memory AArch64 glibc ELF): clang -O2's check through a sealed GOT slot bound to `__stack_chk_guard` is elided, and the proof line has no residual or unaccounted obligation. The `-fno-pic` check at an `R_AARCH64_COPY` of it is elided too. A defined symbol of that name at the word, a writable slot, and an ELF that names no C library each keep the reads and the call.
- radare2 `test/bins/elf/gnome-extensions` (glibc AArch64 PIE, `R_AARCH64_GLOB_DAT __stack_chk_guard` at `0x1fff0` in the RELRO `.got`), `aa; pdd` of every `afl` function: 9 functions move, 1,046 lines. Each elides its check: 4 to 9 obligations `compiler-inserted (assuming ub-free)`, and the `__stack_chk_fail` call and its extern are gone. Read by hand:
  - `fcn_57a4` returned `r2sleigh_carrier_u64(x0_6)` at base, where `x0_6` is the GOT load: the guard's address read as the result. Head returns `r2sleigh_residual_u64(32)`, 207 to 209 residuals: the compiler-inserted write defines no result byte (D200 case 3).
  - `fcn_3b40` drops 10 residuals (1,535 to 1,525): the callee-saved restores (`x25`, `x26`) no longer merge through the check's block, so a path returns `x21` directly.
  - gcc keeps the slot's load in `x5` across the body of `fcn_6ea0`, and calls with open arity read `x5`. That load stays (`x5_2 = r2sleigh_load_u64(0x1fff0)`); only its guard reads are the compiler's.
- ls-toybox: 150 functions, 10,415 lines, 0 move (no stack protector). Census: 445 goldens pass, 0 lines move (no AArch64 golden has a canary).
- Certification, base then head: radare2 elf (24 binaries, 8 functions each) 9 calls graded, 0 invented, 0 dropped, both. gnome-extensions 74 to 76 calls graded, 0 invented, 0 dropped.
- Cost, release, instructions retired (`perf stat -e instructions:u`, Linux build host), median of three, master `ca413c45c` then head with the `FrameReach` fix: cold pumasim `0x23fdf0` 25.03 to 25.14 G (+0.4%), cold 0pack `0x62ecf0` 16.04 to 16.11 G (+0.5%), bash `aa; pdd @ 0x2e630` 14.53 to 14.53 G, pumasim `aa; pdd @ 0x3b6b20` 65.53 to 65.44 G. No x86 path reads a word: `guard_words` returns at once for `Guard::Slot`.
- Touched crates' tests (r2abi, r2source, r2ssa, r2engine, r2s, all features): pass, 0 fail. Clippy `-D warnings` clean. Structure: no count rises. `comment_runs` adds no run. Dylint did not build on the Linux host (`dylint_driver` clones a `master` that no longer exists); CI's Dylint step grades it.
- Equivalence, aarch64 gcc O1 and O2 shapes on the Linux host (qemu) and in CI: `shape_struct_array` is equal at O1 and O2 with the `FrameReach` fix. The two residual-trap records above are blessed. CI's `full-ci` ratchets grade the rest.

## S32a as built (2026-11-12)

r2ssa `ParamClass::of(&SourceTypeGraph, id, pointer_bits)` is the one classifier of a declared type (RULING 1.2). S28 reads it for each declared slot, and S32 reads it for a member's subroutine type.

- `of` reads one node: an integer, `char` or pointer no wider than `pointer_bits` is `Integer`, a 32- or 64-bit float is `Float`, any other float is `Float(bits)`, a wider integer `WideInteger`, a struct, union or array `Aggregate`, and `void`, code, an opaque tag or a missing node `Unsized`. O(1).
- It takes the pointer width because the graph states none. S32's sketch `of(&SourceTypeGraph, u32)` cannot tell `Integer(8)` from `WideInteger(64)` on an ILP32 target.
- `of_type` classifies a node of a graph still being interned; its kind and size are final once `Interned::node` returns.
- r2engine's `Placement::class` over the r2abi graph is deleted. `Interned::class` interns the type and asks `of_type`, so no reader of it remains for S32. Each declaration interns its types apart from the interface's graph, so classifying moves none of that graph's nodes.
- Where the interning states less, only the unplaced cause can change, never a location: an untagged record (a `Void` node), an array of an unsized element and a record with no layout (an opaque tag) are `Unsized` where they were `Aggregate`. The proof prints every `Unplaced` cause as one line.
- A `_BitInt` of a width the graph refuses (not 8, 16, 32, 64 or 128) is `Unsized` where it was `Integer`.
- Measured: old against new over every class the census asked (repo corpus, DecBench `-g` and stripped, 15 aarch64 builds, 8 PE builds under Microsoft x64, i386 and Windows arm64), 6,895,613 agree and 0 differ; no case above occurred.
- Gate: `param_class_of_answers_each_class_and_each_model_places_it` pins 19 nodes and their places on SysV, Microsoft x64 and AAPCS64.

## S32 as built (2026-11-13)

A call through a function-pointer member of a declared pointer parameter takes the member's type as its contract (D171, D270, D271). D171's owners are r2ssa (the evidence), r2engine (the contract and the second seal) and r2image (the subroutine type's convention); "after P9's field types" is struck for parameter-rooted members, because `AggregateAccessProjection` already names the member. Members past a parameter root are D348.

- r2ssa `MemberCalls` on `SsaArtifact`, derived beside the projections at the seal and in `with_assumptions`: one row per `CallSiteId`. `Ok(MemberCall { identity, access, signature_id })` where the site is an indirect call (not a tail call) with a raw identity, its target is the `Read { result }` of one projection of this revision, and the member is `Pointer` to `Code`. Otherwise `NoTypeGraph`, `TargetNotProjected` (a copy, phi, reload, or a load through a loaded pointer such as a vtable slot), `MemberNotCode`, or `Stated` (a table or slot contract). O(sites x log projections). `Stated` is checked last and excludes a site whose contract a member minted, so seal 2 proves the rows seal 1 did.
- r2image reads `DW_AT_calling_convention` on a subroutine type into `r2abi::Signature.convention`. r2engine interns code under any convention but `Normal` as `void`, so its member refuses `MemberNotCode`.
- r2engine `Placement::member_call` (`declared/member.rs`) mints the contract: the signature is prototyped and not variadic, the caller runs under the program's own convention (an `ms_abi` caller refuses), each parameter classed by `ParamClass::of` on the interface's graph and placed by `place`. A floor keeps the placed prefix with `complete = false`. The result is `Void` for a `void` node or the register its class takes; a record refuses. The contract carries an exact callee interface built through the declared route's `Placement::typed`, so D105's held lane applies (`int n` passes as `(uint32_t)n`) and its width rule is `result_width`'s. O(parameters + graph), the graph cloned once per minted site.
- `Native::finish` mints from the first seal of any body that has one and seals again where a contract was minted, through `Restatement.member_calls`, `NativeFunction.member_calls` and `OwnedFunctionSnapshot::member_calls` (validated: this revision, an instruction of the body, one per site). r2ssa's correlation adds each where no advisory call states the site. If seal 2's rows differ from seal 1's, the contracts are a defect (`member-calls-defect` evidence; `Native` holds no query database, so no counter rises) and rows compare on site, signature and refusal (`MemberCalls::agrees`; `access` is seal-local) and the body seals once more without them. At most three seals, the third only on that defect.
- Measured (release, against S32a 8421c99f7): census byte-identical on the repo corpus (the new fixtures aside), DecBench stripped (9 builds), 15 aarch64 builds and 8 PE builds. DecBench `-g`: 31 functions move, every one a member call newly rendered with the member's arguments (gnulib `hash.c` `hasher`, `comparator` and `data_freer` in diff, find and grep; bzip2's `bzalloc` and `bzfree`; bash's `assign_func`; find's `pred_func` and `exec_callback`); residuals in the 6 builds that move 3,941 to 3,782, and no function gains one. libz O2 `-g`: 9 of 183 move, residuals 419 to 280. Certification on the radare2 corpus, libz, bzip2 and the fixtures: 0 undefined reads and 0 invented arguments among the direct calls it grades, as the parent; it counts a member call as a pointer call and judges none (libz 0 to 24, bzip2 0 to 15), so each moved call was read against its source by hand (D272 grades them). Traced over every function of libz and bzip2: the bodies sealed again are exactly the moved ones (9 and 3), 0 `member-calls-defect`, and the calls left residual refuse `TargetNotProjected` (5 and 22; `inflateInit2_`'s and `BZ2_bzCompressInit`'s first allocation call a target that merges the member with the default allocator). Release `pdd` against S32a b27d7074a: the four timed cases are byte-identical and none is a `-g` build, so none seals twice; three are within 0.04%, cold 0pack is +0.5% (14.77 to 14.85 G, repeated three times, unattributed: before the rebase onto S23 the same change measured +0.02%); libz `aa; pdd` of `inflateEnd` 1.416 to 1.436 G and of `inflateCopy` 1.547 to 1.608 G (+4%, the second seal of a body with four member calls).
- The member's classes are read off the interface graph's nodes, where a typedef name binds once, so two typedefs of one spelling share a node. `Interned::code` states a signature only where each part's node stands for its own structure (`faithful`: the node is the structure or a named copy of it); one through a merged name is no code, and its member refuses `MemberNotCode` (gate `a_signature_through_a_merged_typedef_name_is_not_code`). O(log copies) per part.
- The snapshot validates each member contract's instruction against one sorted index of the body's block spans, O(B log B + C log B) (`BlockSpans`).
- Not built: a tail call through a member (`jmp [rdi+8]` is no call site), the target's spelling as `o->release` (r2dec renders a cast of the load; no field certificate reaches a declared pointer parameter's load), and every root but a parameter (D348).

## S28 as built (2026-11-13)

A declared slot's type reaches the projection, and a declaration's counted tail reaches the call (D261 to D264; RULING 1.1, 1.2, 2.2, 2.3, 3).

- Slots (D261). `SourceAbiParameterSpec` carries `SourceSlot { id, class, basis }`. r2ssa `place` numbers each placed location as the body boundary numbers a body's slots: integer registers, float registers (Microsoft x64's shared positions are one run), then the stack. The declared route and member calls state `declared.basis` per slot. Recovery states each parameter at the boundary slot of its location. r2types `ParameterTypes` holds one row per `SlotId` (`basis`, `refused`) and replaces `parameter_bases`; S29 widens the row to `SlotType`. `Basis::states_type` is true for `DebugInfo` and `Declared` only. r2dec `declared_parameter` reads the slot's row, so a slot a declaration types is spelled with `Tags::names` whatever the interface's own basis. The spec's `Option` stays for 71 test constructors.
- Declared pointers (D262, D71 A2). The solver records each callee slot bound with the basis `FunctionType.bases` states for it. A pointer bound counts only where the argument is the parameter's entry value on every path: itself, a copy, or a merge whose every input is it (`entry_identity`); a constant, a load or another definition refuses, since gcc hands on a register it reused (find's `check_option_combinations` passes its loop's null `p` as `dcgettext`'s domain). A type-bearing integer bound anywhere in the class refuses. All pointers give that pointer at the weakest of their bases; `void *` refines to the other pointee; two other pointees meet at `void *`; any type-bearing integer slot refuses `IntegerBound`; a carrier narrower than a pointer refuses `NotPointerWide`. A width-only slot takes the declared pointer before a certified one, except that a declared `void *` yields to the pointee a certified access reads. A body's projection bounds no caller's slot, DWARF or not: `CalleeFacts::derive` reads its body against its imports' declarations (`declared_callees`, O(call sites)) and against none of its own callees, so a slot typed through an internal callee would disagree with that callee's extern. With it, pigz's caller externs differ from their callee's header in 2 of 219 (parent 2) and stripped pigz in 69 of 261 (parent 73). O(callee slots + parameters) per function, inside the one solve.
- D74. On the DWARF route #383 fixed the r2dec spelling. Stripped, the four r2types points of the trace do not fire: r2types states `Pointer(Struct fcn_403da0_arg0)`. The tag was undefined because member `f_8` was solved `Pointer(Int { 64, Unknown })`, which C cannot spell. `aggregates::field_type` now refuses a solved type of no stated sign, and the field takes its width's unsolved spelling. `tag-undefined` evidence names a laid-out tag the unit cannot define (0 lines over stripped pigz).
- Unit declarations (D263). A pointer may name a tag any graph of the unit states, a callee's included, because the callee's extern already declares it. POSIX `stat`, `lstat` and `fstat` are cited at `struct stat *`. A declared pointer whose pointee is an opaque name (a mangled row's `this`) passes as `void *` with `pointee-unspelled` evidence; an unnamed tag or an unspelled scalar pointee keeps its class.
- Counted tails (D264). r2abi `Tail::Flagged { index, test, then }`. `FlagTest::OpenNeedsMode` is glibc 2.39's `__OPEN_NEEDS_MODE` (`<fcntl.h>`: `O_CREAT`, or every bit of `__O_TMPFILE`), read in `open64.c` and `openat64.c` before `va_arg`. Its bits are per architecture (`__O_DIRECTORY` 0200000 on x86-64, 040000 on aarch64) and resolved through `Imports::on(arch, bits)`; another target states none, so its call stays `...`. r2source `SourceTailCount` carries `SourceTailRule::{Trips, Flagged}`; r2ssa counts a constant flag and refuses `FlagNotConstant` otherwise. A call's reads stay `Variadic`'s, so no caller gains a parameter. `prctl` is glibc's cited `...` and refuses. bionic and musl state `...` from their `<fcntl.h>`; musl gains `types-musl.sdb.txt`. Darwin keeps radare2's two rows in its own table.
- Measured (release, against S32 0b4e9a489): repo census 5 functions move (`copy_name`'s `src` is `const char*` in two fixtures, as `review.c:59` declares it, and `main`'s externs follow; member_call `ops_virtual`'s structure is defined, `opaque` at 0, `vt` at 0x40, `count` at 0x48 as `member_call.c` lays it out). DecBench stripped: 356 headers gain 357 pointer parameters; paired by address with the `-g` build, 296 name DWARF's pointee, 22 say `void *` for a typed one, 10 name a pointee where DWARF says `void *`, and 1 says `void *` where DWARF says `uintptr_t addr` (gnulib `is_mapped` hands `addr` unchanged to `mincore`'s `void *`, which the binary cannot tell from a `void *` parameter). gnulib's `open_safer` and `openat_safer` (flag not constant) refuse `flag_not_constant` (+6 residuals in find, grep, gzip); every `open` with `O_CREAT` passes its mode (bzip2 `open(name, 193, 0x180)`). 15 aarch64 builds byte-identical. bash `-g`: 5 headers whose DWARF parameter points to a function typedef (`add_unwind_protect`'s `sh_uwfunc_t *cleanup`) spell `void*`, as every caller's extern does; so do 9 stripped DecBench and 2 PE parameters that take an opaque `mbstate_t *`, `va_list` or UCRT `FILE *`. Source-gold (gzip and bzip2 O2 against `-g`): soundness 0.2907 to 0.4943 and 0.3953 to 0.4902, recovery 0.0903 to 0.1552 and 0.0955 to 0.1404, silently wrong 61 to 44 and 26 to 26. Certification 0 undefined reads and 0 invented on the radare2 elf sweep, pigz, stripped pigz, bzip2 and gzip. `compile_check.py`: pigz 117 compiled, conversion 0; DecBench `-g` 405 and stripped 422 compiled, conversion 0, as the parent. Extern agreement: pigz 2 of 219 as the parent, stripped pigz 73 to 69, `hello_gs_x64.exe` 58 to 52, gzip stripped 4 and `-g` 0 as the parent. Release `pdd` against 7f7484a6b: the four timed cases within 0.09%.
- Not built: the spec's `Option`; the handle and `named_scalar` data table; the prelude's `typedef` of a named alias (D168); `compile_check.py`'s binary step in CI (the image's clang 18 binds no `return-mismatch`); ordered unsigned compares on a pointer class; folding `certified_parameter_pointers` into the solver.

## S29 as built (2026-11-13)

A slot's type is one `SlotType` row; its sign is what the body's live operations state, its width the lane an operation reads whole (D265, D266, D268, D353; RULING 1.1, 1.3, 1.7, 2.4, 3).

- Row (D265, RULING 1.1). r2types `ParameterTypes` holds `ParameterType { ty: SlotType, refused }` per `SlotId`. `SlotType` is `Declared(ty, basis)` (basis `DebugInfo` or `Declared`), `Integer(IntegerDecl { bits, width, sign })`, `Float { bits, basis }`, `Pointer(ty, basis)` or `Carrier(ty, basis)` (a width-only bit vector, so `Declared` never holds a body reading); a hole stays `unread_slot`'s typedef, read before the row, where the design had a `Hole` variant. `apply_exact_source_signature` builds the row and the signature's type from it, so `pdd`, `pddj`, `afi` and a caller's extern (`source_owned_callee_signature`, whose forced `Unsigned` is deleted) spell one value.
- Sign (D265, RULING 2.4). `SignFact` is `Signed(Decoded)` or `Unsigned(Decoded)` where every seed on the formal's entry value and its offset-0 SUBPIECE at the slot's width agrees, `Conflict` where two disagree, `Unstated` where none seeds. `Conflict` and `Unstated` spell `r2sleigh_word_uN`, a prelude typedef over `uintN_t`, so wraparound stays defined and the grader marks it. Seeds are `SDIV`, `SREM`, `SRIGHT`, `SEXT`, `DIV`, `REM`, a stated `ZEXT`, and an ordered compare a branch reads; `IntRight` seeds nothing. Measured both ways on gzip and bzip2 -O2: silent sign 0 and 0 with or without it, so the tie drops it (RULING 3). A seed counts only where its operation is live: it reaches a store, branch, call, return or returned value (`live_values`, O(operations + merges)). x86's three-operand `imul` sign-extends its factors only for OF; that dead seed made fnv1a32 `int32_t`.
- Pointee and result. A certified pointee takes the same map over its loads (`pointee_signs`); a `movzx` load seeds `Unsigned`, so `hashes` keeps `uint8_t*`. A carrier result is signed by the seeds on every returned value at its width (`ReturnTypeFact::signed_by`). r2ssa `RecoveredResult.signed`, `SourceResultSeed.signed` and `lanes::signed` are deleted (RULING 1.7): the recovered graph's integers are unsigned nodes, `state_result` reuses any integer node of the width, and r2ssa's fill states no C sign.
- Float pointee (D353). r2il `R2ILOp::float_op` states which side of each P-code float operation is IEEE 754 bits (`FloatOp`: arithmetic and `FLOAT2FLOAT` read and write floats, `INT2FLOAT` writes one, `FLOAT2INT`, `TRUNC` and the tests read one); r2ssa `SSAOp::float_op` mirrors it. `pointee_floats` takes a pointee as a float where every certified access at a width is a load whose uses, through copies and merges, read a float, or a store of a result that is one. rv_O2 `avg` is `double avg(double* arg0, int32_t arg1)`, as the source declares.
- Width (D266). `ReadLanes` in `observed_entry_read_storages`: a formal is read at the widest offset-0 lane an operation reads whole. A merge, a copy and an offset-0 SUBPIECE pass the question on; an `and`, `or` or `xor` with a constant reads its output's observed bytes; any other operation reads the demand it already has. gzip `discard_input_bytes` `flags` and branchy `mask_probe` `q` are 32 bits (both `unsigned int`). `resolve_evidence_driven_signature_type`, its scores and `bool_like` are deleted.
- r2dec. `declare` admits every r2types declaration, a word as its own typedef (`spellable` and `pointee_spelling` keep it). The symbol table, returns and call conversions read the word as its integer (`terms::word_free`), so the body casts nothing it did not cast before. A parameter r2types declares nothing for, and an extern argument no prototype types, spell their class's word (`unstated_class`). The prelude declares each word a header, extern or cast spells (`typedefs_within`). A 128-bit pair keeps `__uint128_t`.
- Text (D268, RULING 1.3). `InferredSignature` keeps `function_name`, `ret_type` and typed `params`; `AssumptionValue::TypeHint`, `analysis/assumptions.rs`, `operator_type_hint`, `SignatureCertificateSource::TypeAssumption`, `RegisterIdentity` and `argument_register_names` are deleted; `parse_c_type_like` is test-only. D309's allowlist falls from 128 to 121.
- D267. The W47 trace prints no `UntypedReturn` for `sum_arr` under `aa`, so nothing is built (RULING 3).
- Not built: width rule 2 (a handed lane no wider than the callee's declared slot); a declared callee slot's sign as a bound; locals' signs (D156's other half); a mangled row's `int` for an import's extern.
- Measured (release, against S31b 5efcfde38). Source-gold silent errors fall or hold in every build: gzip -O2 44 to 21 (soundness 0.4943 to 0.6182), bzip2 -O2 26 to 13 (0.4902 to 0.6829), branchy 39 to 5, odd 26 to 15, returns 10 to 1, review 12 to 5, seven 1 to 0. The word is marked only where the source has an integer of its width at the same pointer depth; elsewhere it is graded as the `uintN_t` it claims, so a pointer it misses stays silent. The silent `sign` bucket is 0 everywhere but review's `classify` (an unsigned range compare of a signed `int`, 7 to 1). `correct` falls where an unsigned guess was right (gzip 43 to 34, hashes 19 to 11); hashes' soundness rate falls 0.5758 to 0.4783 though its silent errors fall 14 to 12, all `const` qualifiers or pointers. `returns_baseline.json` holds. Census moved lines: repo 394, DecBench `-g` 326, stripped 4,975, aarch64 28, PE 3,597; outside the sign's spelling 42, 77, 742, 0 and 124, sampled by class and not each read: the D266 lane (`mask_probe`, `fts_stat`, PE masks), grep's structure a signed field lays out, rv_O2 `avg`, and no proven pointer is lost (a header's `void*` checked parameter by parameter against the parent). Two fixes keep them: every evidence merge reads the word as its integer (`word_free`), so an interprocedural summary's pointer still replaces it (hello_gs_x64 `fcn_140008620` `arg3`); and a body-proven pointer whose pointee the unit cannot spell is `void*` in the header and in a callee projection's extern (`analysed_pointer`; grep `fcn_17830`, find `fcn_18580`). hashes keeps 12 silent errors, none a sign or width: 8 `const` qualifiers, 2 `void*` pointees and 2 pointers spelled as integers. Its 8 lost corrects (`murmur3_32`'s `len` and `seed`, `rotl32`'s `x`, `siphash24`'s `k0`, `k1` and `len`, `xxhash32`'s `seed`, `combined`'s `len`) now spell the word: their only unsigned-looking uses are logical shifts and rotates, the `IntRight` seed RULING 3 drops, so they stay refused. shapes `shape_signed_divmod`'s `arg1` is `int64_t` where the source declares `uint64_t b`: its only sign-seeding use is the signed division of `(int64_t)b`, which RULING 2.4 counts. Certification 0 undefined, 0 invented on the radare2 elf sweep, pigz, stripped pigz, bzip2 and gzip. Extern agreement: pigz 2 of 219 as the parent, stripped pigz 69 to 68. `compile_check.py`: pigz 117 compiled; stripped DecBench and stripped pigz 2,124 compiled, conversion 0, as the parent. Extern pairs, parent against head: stripped pigz loses one and gains none, stripped gzip 4 and pigz 2 unchanged, `hello_gs_x64.exe` 52 to 53: `fcn_140011c90`'s header takes a summary-proven `void*` its callers' derived projection does not read (D262: a body's facts read none of its own callees). Release `pdd` (G instructions, median of 3): pumasim cold 21.036 to 21.049 (+0.06%), 0pack cold 14.876 to 14.905 (+0.19%), bash `aa` 13.471 to 13.464 (-0.05%), pumasim `aa` 70.954 to 70.917 (-0.05%).

## Gb as built (2026-11-13, `rd-frame`)

D221: a format spilled to the frame and reloaded in another block is still the call's format. `Reading::formatted_sites` folds the format in the block first; where that leaves it unknown, it asks r2engine `ConventionSeal(caller, thumb)` once per body. The query seals the caller against the convention and its imports' rows, with no image callee read (`native::convention_seal_of`), and its retention is `Newest` (RULING 1.8). r2ssa `TrustedSeal::folded_before_call` folds the format register at the call's instruction through `value_reaching` and the prepared constants.

- The reload equals the spill only through a promoted slot. Promotion reads D290's escape walk, so a slot whose address a call receives stays in memory and its reload folds to nothing: the call takes every vector register.
- The seal reads no other row's facts, so a `RegisterEffects` row depends on it as on `Walked`.
- `dispatch_reads` is not folded into this query: Ge (D285) owns the dispatch rounds and their seal.
- Integrated with Ge: the seal reads the whole walked body through the tables its walk followed, as Ge's whole-body seal does; both Gb tests and Ge's pass.
- Tests: `a_spilled_format_reloaded_in_another_block_reads_no_vector_register` (fails without the seal) and `a_spilled_format_whose_slot_a_call_receives_keeps_q0_taken`.
- Open for the Exit bar: shapes.c clang -O0 `shape_stash` and `mixed_touch` under `aa` on aarch64 equivalence, and bash `aa` within 0.3%.

## D228 as built (2026-11-13, `rd-frame`)

A cited fixed float parameter is a read at its call: `sqrt(avg())` decides `avg`'s `double`. r2ssa `CallEffect.reads` holds the bytes a callee certainly reads, and the site walk marks them read at the call, beside `takes`, which only keeps bytes open. r2engine `Reading::import_takes` fills it for an import whose `CallReads` is `stated`, has no count register and no format, from the registers that overlap the convention's float argument slots. An integer argument a callee may leave alone stays `takes` only. An image callee, an unstated row and a variadic or printf row read nothing for certain.

- A callee that leaves XMM0 as found passes the caller's bytes to the parameter: the read past it is the earlier call's (`kept`), so no `double` is decided for it.
- Open for the Exit bar: census and equivalence moves from rows the corpus cites with float parameters.

## ExtTypeDb as built (2026-11-13)

`ExternalTypeDb` and its name-keyed strings are deleted (D345 to D348, D272, D266 rule 2). One fact has one owner: r2ssa's projection names members, `SourceTypeGraph` states layouts, r2types reads both by type id.

- D346. `AggregateAccessProjection` descends by-value struct members to the scalar leaf the access covers exactly: `path` (member ids) and `member_name` (`top_left.x`). A union, an array, a bit-field or two containing members refuse. An anonymous struct member adds no name. O(depth x m), depth below the graph's aggregate count.
- D345. Field certificates come from the parameter-rooted projections alone. A parameter's aggregate stride is its pointee's `size_bits / 8` read through `parameter_logical_value(i).type_id()`, so a typedef strides by its target. A data object places from the image graph by type id (`ProgramDataObjectTypeFacts::from_source(graph, (address, type_id))`). A `Typedef { name, Unknown }` resolves only by a standard name (`typedef_resolves`). `preserving_c_typedefs` matches the `CTypeLike` itself. Deleted: `external.rs`, `ExternalTypeDb`, `ExternalStruct`, `ExternalField`, `ExternalUnion`, `ExternalEnum`, `normalize_external_type_name`, both `aggregate_lookup_keys`, `StructDeclSource`, `StructDeclCandidate`, `build_struct_decl`, `external_aggregate_size`, `external_layout_field_access_for_offset`, `normalize_field_certificates_from_external_layout`, `trusted_external_type_db` and `external_struct_fields`.
- D347. radare2's spelling normalizer is a `#[cfg(test)]` module beside `parse_c_type_like`. The `type_spelling_reparsed` Dylint flags any production reference outside the definition's own body; its allowlist is deleted.
- D348. `AggregateRoot` is `Parameter(slot)`, `FrameSlot(object)` (a slot declared a struct by value, constant offset), `DataObject { address }` (a constant address inside a struct-typed data object; the machine context binds the image's `DataStructs`, O(log n) per lookup) or `Member(access)` (the result of a projected load of a `Pointer { target: Struct }` member plus a constant). `GraphOf` (r2ssa) says which graph the ids name; the design's r2source `TypeRef` is not built, since only projections carry an id across graphs. A worklist over projected loads roots the waiting accesses; each access enters once, O(accesses x log). `MemberCall.graph` picks the graph r2engine places the contract in. r2types' declared-slot and field-certificate member render passes, `MemberAccessRenderFact` and `MemberAccessSource` are deleted: a loop carrier's loaded type is its projection's member type.
- D272. r2dec's rendered call carries its instruction; the engine's `Rendering.member_arities` holds each proven member call's exact-callee parameter count; `pddj` states it as `declared`; `certify_render.py` grades a pointer call against it.
- D266 rule 2. `ProvenProgramObservations` roots a call-argument obligation at the lane the callee's exact interface holds (`callee_held_lane`), declared or recovered from the callee's body as D105 reads it; a call no exact callee states reads the whole register, and a value two calls take is read at the union. `int i_call(int x){return isalpha(x)+1;}` through `rbx` declares `x` 32 bits; `CalleeNamedLikeAParameter`'s `arg0` is its recovered callee's 32-bit lane, so one projection precedes the calls (gap ordinals 4, 14 to 5, 15).
- A data object or a parameter pointee places and strides only as a `Struct`: no reader defines a union's tag there, and the deleted table had no union writer.
- Unmeasured until the exit bar: `pdd` timing of the projection collector and of `recover_interface`'s narrowed roots (both run per function), census, equivalence, gate 7's goldens (`member_call.c` x86-64 and aarch64, O0 and O2) and the certifier run on the member-call fixtures.
- Not built: r2dec spells no projected member (`cur->next` renders as address arithmetic; D359); an array member's element (`a[i]` inside a struct) projects nothing (D360); a data-object root needs the body to reference the object's start, since r2engine's `referenced` names only exact addresses (D361); a frame struct array indexed by a value projects nothing, where the deleted declared-slot pass typed its member (D362).
- Gates: `two_tags_differing_in_case_keep_their_own_members`, `a_typedef_strides_by_its_target_never_by_a_tag_sharing_its_name`, `a_global_struct_places_from_the_image_graph`, `a_read_inside_a_nested_struct_member_projects_its_member_path`, the `layouts` engine tests (parameter, loaded member, frame, data object, stripped, and `a_root_no_projection_proves_projects_nothing`: a merged base, a narrow read, a load through `void *`), `pddj_states_a_member_calls_declared_arity`, `a_value_handed_to_a_declared_int_is_as_wide_as_the_int`, `a_value_also_handed_whole_keeps_its_register_width`.

## Ga as built (2026-11-13)

The loader's calls are rows keyed by the container's entry kind and the C library it names; each states what the loader reads (D240, D239's rest, D227's Mach-O half; RULING 2.5).

- Contract. r2abi `loader_call(format, library, kind) -> Option<&LoaderCall>`, `LoaderCall { reads_result: ResultRead, citation }`, `ResultRead::{Nothing, Integer { bytes }}`. The note's `LoaderPasses` is not built (RULING 2.5: no reader); `arguments` and `adds_no_read` are deleted. `reads_result` names a lane, as the G-rows note asks, where it was a bool.
- Rows. ELF termination functions as S22, any library. glibc `Init`, `InitHook`, `Preinit`: `elf/dl-init.c` `call_init` and `_dl_init`, `csu/libc-start.c` `call_init` (2.34 on, static and shared), 2.33's `csu/elf-init.c` `__libc_csu_init`; each call a statement whose value is dropped. musl `Init`, `InitHook`: `ldso/dynlink.c` `do_init_fini`, `src/env/__libc_start_main.c` `libc_start_init`; musl reads no preinit array, so `Preinit` has no row. Mach-O `CMain` under libSystem: dyld's `dyld/dyldMain.cpp` `start` hands `appMain`'s `int` to `libSystemHelpers.exit`, `Integer { bytes: 4 }`. Bionic, an unnamed library and a Mach-O initialiser have none, so their entries escape. r2image types init and fini entries only by `SHT_INIT_ARRAY`, `SHT_FINI_ARRAY`, `SHT_PREINIT_ARRAY` and the Mach-O flags, so crtstuff's `.ctors`, which an in-image `__do_global_ctors_aux` calls, is never a row's.
- What the loader passes is no row's: no parameter decision reads `only_called`, so a constructor storing RDI is `void f(r2sleigh_word_u64 arg0)`.
- Owner of the read. r2engine `Escapes` drops every entry with a row (the loader's call is a call); `DirectSites::loader_reads` counts it and joins `Integer { bytes }` as a `LaneFate::Read` of those bytes on the integer lane, `O(entries)` per callee. The decision is unchanged: an integer read with no float read is `Read(Integer)`, premise `ClosedWorld`.
- PIE slot (D239). r2image states `Relocation::addend_at`, a `RELA` entry's `r_addend` word with its mapped address (an object's tables map none); `REL`, `RELR`, packed streams and Mach-O state none. The note put it on `LoaderWrite.record`; a composed write holds several records, and the record owns its addend, so it is the record's. `Escapes` skips that word for a relative record at a dropped slot whose addend is the slot's entry, and skips the reference index's own claim from that slot (a PIE's slot is a loader write the index reads). Any other addend, word or reference still escapes. Cost: a search of the dropped slots per reference and per record, `O(R log L)`.
- Not moved, by S22's rule. `frame_dummy` tail-jumps to `register_tm_clones` and `_init` loads `__gmon_start__` into RAX: both are `Written`, and a written result asks every way in only over one program call or more (S7 cost), so a loader call alone decides neither.
- The integer result's width is the body's write (S24): `SourceReadLanes::Integer` carries no bytes for any call, so AArch64 `_main`, whose `cset w0` writes X0, spells `r2sleigh_word_u64`.

## S30 as built (2026-11-13)

A function whose address every take hands only into cited `void (*)(...)` slots, and that every direct call leaves dead, returns nothing under the closed world (D205; RULING 1.4, 1.5).

- r2abi. A row spells a slot `R (*)(P, ...)`; `spelling::read` makes it a pointer to `Code`. radare2's `func` is `Code { returns: Refused }`, never `void`. `Parameter::code_returns(graph)` replaces `is_function`'s text compare, which is deleted. Cited rows: `atexit`, `at_quick_exit` (C17 7.22.4.2, 7.22.4.3), `signal` (C17 7.14.1.1) in `types-posix`; `on_exit` in `types-glibc`; `__cxa_atexit` (Itanium C++ ABI 3.3.5.3) in the new cited `types-cxx-cited`. `uncited-rows.txt` loses `atexit`, `signal`, `at_quick_exit`. A row's parameter name follows the last comma outside parentheses.
- r2ssa `site_boundary`. `CallerFlow::fate_after` and `fate_from_entry` walk one register forward: `Dead`, `Handed(handoffs)` or `Other`. A non-transfer read (an instruction cancelling the register against itself reads none), a branch out the walk does not resolve, an open end, or any return is `Other`. A transfer that may read it is a handoff; the walk goes past a call unless the call overwrites the register (an import by the convention's clobbers; a body never, since `RegisterEffect.overwrites` covers result lanes only). `CallReadsAt` states the transfer's target, its reads and its overwrites. `O(B + E)` per walk.
- r2engine. `Escapes` is `WaysIn { escaped, takes }`: a `Role::Value` claim from an owned instruction is a `Take`, still a way in for `only_called`. `DeclaredSlot(f)` holds when `f` escapes no other way and every take's instruction writes one register whose fate hands it only into a cited import's `void`-returning parameter (`native::void_slot`, placed by the import's convention) or a body's `SlotParameter`. `SlotParameter(body, thumb, register)` is the same walk from the body's entry; a cycle reads as no slot, the least answer (test `wrappers_forwarding_to_each_other_prove_no_slot`) (the component fixpoint of S30.md is not built: yield, not soundness). `CallBoundary` decides `DeclaredVoid(SourceSlotOrigin)` where no held lane is read, taken, lost or cycled, no forwarder returns one on, and every call the index claims was read; premises `ClosedWorld` and `UbFreeSource` (C17 6.3.2.3p8). r2ssa recovery applies it as `Void` over a written lane, since the slot's type is the way every caller calls.
- Tests: `a_handler_only_atexit_takes_is_void_under_the_closed_world`, `a_handler_a_wrapper_hands_to_cxa_atexit_is_void_under_the_closed_world` (find's `0x278e0` shape), `a_take_into_no_void_slot_keeps_the_result` (`qsort`, `call rdi`, a direct call reading EAX), r2ssa `a_register_handed_to_a_tail_transfer_or_a_call_is_handed`, `a_register_read_returned_or_stored_is_other`, r2abi `a_cited_callback_slot_returns_void_and_func_states_no_return`.
- Not built: `twalk`, `tdestroy`, `pthread_once`, `_obstack_begin` rows; the `Dispute { kept: Calls, lost: Slot }` record; `afi` and the proof line naming the slot; the aarch64 twin test; the DecBench 4 and timing (exit bar). D227's ELF half stays open: `__libc_start_main`'s `main` is `func`, which states no return.
