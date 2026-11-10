# ADR: one owner of the call boundary

Status: proposed (ROADMAP P7, with P4 and T slices; decisions D160 to D172 and D209; hand audit 3.2, 3.5 to 3.8; amended 2026-11-10 after round 6 of the typed-values tracks)

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
| 3.2.3: `error` has no ellipsis | 84 sites in 52 functions. Closes in S8 (`Tail::Variadic`) |
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
- Code lies wherever a loaded segment has bytes (the d70 gate's D70 row).
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
    Variadic,                                 // `...` with no format or va_list parameter: error(3)
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
- During the item, the old contracts are read-only views of the model. `slot_promotion.rs:93`, `frame_reach.rs:146`, r2dec `values.rs:2672` and the two `interproc` readers keep compiling. The views are deleted at the item's exit.
- `ConventionModel::owner(offset)` is the one rule for the caller's region. It replaces three rules: `contracts.rs:562`, `function/mod.rs:1527` (`caller_frame_offset`, read also at `info.rs:357` and `caller_stack_slots.rs:37`) and `slot_promotion.rs:677`.

### Evidence (r2ssa)

```rust
pub struct BodyBoundary {                       // in PreparedFunctionFacts, one per body
    pub slots: IdVec<SlotId, SlotUse>,          // every location of every section
    pub results: IdVec<LaneId, lanes::Bytes>,   // lanes::Byte, joined over every return path
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

One placement rule, `place(&ConventionModel, &[ParamClass]) -> Placement`, lives in r2ssa and serves the declared route, the recovered route and bodiless imports. It counts each class on its own, or by position where positions are shared. It places stack locations past the registers. Where a class has no location (`long double`, a record passed by value), it returns the placed prefix plus a typed floor. It keeps today's arrival check (`arrivals_hold`, `declared/mod.rs:233-256`): a DWARF arrival that disagrees with the placed location refuses the declaration for this body (`.isra`, `.constprop`). `DW_CC_nocall` refuses convention placement; r2image reads `DW_AT_calling_convention` for it. r2engine keeps only the step from a type to its class (`declared/mod.rs:107`), because r2engine holds the type graph.

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

A source that loses becomes a `Dispute` and leaves refusal evidence. Caller writes (`SiteBoundary.written`) never raise the arity of any callee. A register written before a call may be scratch reuse, so the write proves no read.

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
| Slot use, result bytes, floor | r2ssa `BodyBoundary` | r2ssa minting, r2engine join |
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
| 3.2.3 `error` | The row cites `error(3)`: `(int, int, const char *, ...)`, `Tail::Variadic` | r2abi | S8 |
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
| 3.7.1 struct-field calls | A DWARF member of function-pointer type is placed by `place` at the call. Stripped builds stay residual | r2types, r2ssa | S12 |
| 3.7.2 C++ virtual calls | Stay residual until vtables are recovered (P9, LP) | none | none |
| 3.7.3 tail jumps | `return callee(args)` once `CallBoundary(callee)` is stated. 267 of 376 follow 3.2 (205 after a residual call, 62 after `error`). The other 109 have no closer in this ADR and stay residual | r2engine | S8 |
| 3.8.1 Win64 home | `localrange` 8..39 becomes `OwnedRange::Home`. The homing store is a callee-owned save and the reload is no stack parameter | r2sleigh-lift, r2ssa | S10 |
| 3.8.2 MSVC variadic | A home whose address reaches `__stdio_common_vfprintf`'s `Tail::VaList` starts the tail. UCRT printf becomes `(fmt, ...)` | r2abi, r2ssa | S10 |
| 3.8.3 `/GS` | r2image reads the load-config `SecurityCookie`. The check callee is proven by its body, and its name decides nothing | r2image, r2ssa | S10 |
| 3.8.4 canary entry load | `unobserved_compiler_inserted` (`certificates/mod.rs:1515`) reads the returned value on the guard branch's passing edge. There the difference is 0, so the return does not observe the load. This does not depend on D72 | r2ssa | S11 |
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
- **Measured today:**
  - bash `0x2e630`: `aa; pdd` is 19.43 G instructions, `aa` 7.38 G and a cold `pdd` 0.66 G.
  - About 12 G of that is `ReferenceIndex` (`requests.rs:781`) walking every body again, because `Walked` is `Retention::Newest` (`program/analysis.rs:126`).
  - pumasim `0x1fad00` is 148.9 G against 64 G for `aa`. Its split is not profiled. D153 requires that profile before S3's design.
- **Held index:** compact index rows and site fates built inside `aa`'s walk and held. The lifted blocks are not held. Estimates: bash about 8.2 G, pumasim unknown until profiled. Peak RSS grows by bytes per call site. dhat measures it before landing, against pumasim's 434 MB.
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
| S12 | Indirect calls through a DWARF function-pointer member, placed by `place` (after P9's field types) | r2types, r2ssa | zlib `inflateEnd` renders both `ZFREE` calls. Certification invented arguments stay 0 | none |
| S13 | Data rows: bionic, libstdc++ parameters from mangling with `Unproven` results, KERNEL32 once cited rows exist | r2abi | ls-toybox: 0 residuals at `__errno`, `__strchr_chk`, `__open_2`, `getline`, `_exit`, `dup2` (of 703). 0pack (7,621 sites) and pumasim (4,942): every mangled callee states its parameter count. hello_gs (98) and testapp (96): each cited KERNEL32 row's sites declared | none |

| S14 | `CDataModel` per `(arch, CLibrary)` with citations; `ScalarKind::PlainChar`; `wchar_t` from the model | r2abi | The `-dM -E` conformance test per listed target. d71 round-7 probes: aarch64 `mkdir`, `strnlen`, `unlinkat`, `regexec`, `error_at_line` and `wcsdup` parameters never `int8_t*` or `int32_t*`. x86-64 output unmoved | the fixed `Signed` default for `char`, `named_scalar`'s `wchar_t` |

S4 to S7 are P7's single signature item. S10 and S11 are P4 slices.

## Fate of rows and branches

- **D37:** kept. `ArgumentAreaRead` stays as rule 4's floor cause (readers at `resolved.rs:108,680`, `arity.rs:592`). Its engine test stays: a stack read with an unfull register section is no parameter. `RegisterRead` now means a read whose kind is unproven (rule 3). `HandedOn` lists only the calls a slot reaches.
- **D62:** absorbed by S7. The join moves to r2engine, because it is a program query. r2types projects it. The row text is amended.
- **D71 (`d71-prototypes`, shelved at 856416c26 on 2026-11-10):** seven review rounds each found a new blocker in row typing. Round 7 found aarch64 `const char *` parameters printed `int8_t*` where base printed `uint64_t`. The branch is the code source for three slices:
  - A1's handle rows (`FILE`, `DIR`) and the compile gate move to S8. 3.2.2 and 3.2.3 close there, with `error` as `Tail::Variadic`.
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
- **d70-gate:** lands first, after its floor counts every DWARF function whose entry lies in a loaded segment (`PT_LOAD` with file bytes). Section flags decide nothing. It grades S4, S6 and S9.
- **d75-noreturn-guard:** lands after `never_returns` takes the callee alone. S8 carries `noreturn` on `LibraryRow`.
- **The "`_exit` is `AtLeast(1)`" gate** (hand audit section 6, item 9): dropped. A glibc static `_exit` probe replaces it.

## Refusals

- **An unread slot below a read one:** declared at `Convention` with `ty: None`, spelled as its class's residual type. It is never typed `uint64_t` or `double`. A Win64 shared-position hole has no class.
- **A hole's argument at a call site:** a typed "slot the callee ignores" residual with no dataflow. The caller's reaching value is not shown, because `jmp second` after `a*7` leaves the entry `a` in rdi. Certification counts these apart from W7.
- **A read not attributable to the entry value:** a floor `AtLeast(k)` with a typed cause. It never fills a hole.
- **A homing store with no load:** a floor cause `Homed`. It is no parameter and no hole.
- **A stack read:** fills only the stack slots below it, and only behind a full register section. Otherwise `ArgumentAreaRead`. It claims no register.
- **Caller writes:** evidence only. They are never arity proof, for a callee with a body or without one.
- **Indirect calls with no stated type:** residual. Virtual calls stay residual too.
- **A library row:** applies only through an import binding. A versioned import binds to the library its version names. An unversioned import binds at `Declared` only where the container's `DT_NEEDED` names one C library. A name match on a static body applies nothing (AGENTS rule 6).
- **DWARF whose arrivals disagree with placement, or `DW_CC_nocall`:** no declaration for this body; a `Dispute` with refusal evidence.
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
- **A mangled libstdc++ row:** parameters only; the result is `Unproven`.

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
