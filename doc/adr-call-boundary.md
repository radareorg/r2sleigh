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
| 3.7.1 struct-field calls | A DWARF member of function-pointer type is placed by `place` at the call. Stripped builds stay residual | r2types, r2ssa | S12 |
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
| S12 | Indirect calls through a DWARF function-pointer member, placed by `place` (after P9's field types) | r2types, r2ssa | zlib `inflateEnd` renders both `ZFREE` calls. Certification invented arguments stay 0 | none |
| S13 | Data rows: bionic, libstdc++ parameters from mangling with `Unproven` results, KERNEL32 once cited rows exist | r2abi | ls-toybox: 0 residuals at `__errno`, `__strchr_chk`, `__open_2`, `getline`, `_exit`, `dup2` (of 703). 0pack (7,621 sites) and pumasim (4,942): every mangled callee states its parameter count. hello_gs (98) and testapp (96): each cited KERNEL32 row's sites declared | none |

| S14 | `CDataModel` per `(arch, CLibrary)` with citations; `ScalarKind::PlainChar`; `wchar_t` from the model | r2abi | The `-dM -E` conformance test per listed target. d71 round-7 probes: aarch64 `mkdir`, `strnlen`, `unlinkat`, `regexec`, `error_at_line` and `wcsdup` parameters never `int8_t*` or `int32_t*`. x86-64 output unmoved | the fixed `Signed` default for `char`, `named_scalar`'s `wchar_t` |

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

- `place` is r2ssa `place.rs`. `ParamClass` is `Integer(bytes)`, `Float(bytes)` or `Unplaced(SourceUnplacedClass)`, and r2engine maps a type to it (`declared/mod.rs` `class`). `SourceUnplacedClass` names `Float(bits)`, `WideInteger(bits)`, `Aggregate`, `Unsized` and `PackedStack`; the floor is `SourceFloorCause::Unplaced`.
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
- r2engine `program/fates.rs`: `World { Open, Closed }` replaces `Callers`, `CalleeKey { Entry(u64), Import(ImportId) }`, `ImportId(u64)` (the address calls reach). The `CallBoundary` query keyed `(CalleeKey, World)` holds the evidence half: `Sites { lanes: [JoinedLane; LANES], calls, exhaustive }` for a function under `Closed`, `Import { reads }` (S8's `Placement::reads`) for an import. `Open` joins nothing.
- `JoinedLane.held` marks the lanes a body may leave a result in: the typed three and each lane that is an argument location (SysV xmm1, AAPCS64 q1 to q3). x87 `st0`/`st1` are not held: the x87 stack is empty on entry (SysV 3.2.1), so a body writes them before they hold its value. A `Void` or `Unread` decision needs every held lane `Dead` at every call, and the calls must be every way in (`only_called`).
- A `Returned` lane forwards to `CallBoundary(caller, Closed)`: `Read` there is a read, `Dead` with the caller exhaustive is dead, a database cycle is `ForwardCycle`. Forwarding is asked only where its answer can move the decision (a lane no call reads while every held lane is dead or returned, or a typed lane), so `aa; pdd @ bash 0x2e630` joins 111 boundaries, not 253.
- Presence is decided by `fates::decide(open interface, CallBoundary)` at seal time, not held in the query: a declared interface is left alone; `Read` gives `SourceClosedResult::Read(Integer | Float { bytes } | Pair)`; every held lane dead gives `Void` where the body's causes are only `HandedBack` or `NoReturn`, else `Unread` (D202); a cycle gives `ForwardCycle`. r2ssa applies it in the function's second seal (`FunctionIdentity.closed_result` replaces `result_reads`) and records it on the interface (`SourceFunctionInterface::closed_result`, which replaces the `result_read_by_callers` bool). `Unread` and `ForwardCycle` on a written register only name the cause: the carrier and its returns render as before.
- The closed-world premise: every applied decision puts `Premise::ClosedWorld` on the function and in the response premises (PR #355 review). The proof line says "a call reads the result", "no call reads the result" or "a call returns the result on through a cycle", each "(assuming closed-world)".
- Under `aa` a callee is read in the closed world too: `Resolved` at `Demand::Arity` reseals a callee where its boundary decides (`closed_alone`), so its callers' externs and its own header agree. Members of a cycle (`least_fixpoint`) keep their open results: the fixpoint moves the results it tracks.
- D62, per callee: `mint_recovered_call_site_interface` takes no caller reads. A pair is the callee's at every call; an unproven result with one carrier is that register at every call; with two carriers the call states no result, as base's cold path did. The per-body `reads_after` and `direct_reads` are deleted.
- W46: `SourceOwnedCalleeSignature` carries the header's unproven carrier bits. r2dec's extern for a body-recovered callee is `Prototype::of_projection`: the header's own types, `r2sleigh_result_uN` for an unproven result, refused where the call defines a result and the header is `void`. `of_widths` and `callee_carrier_signature` are deleted. The prelude declares every carrier typedef the unit spells. An assignment from the typedef to its integer takes no cast.
- `CalleeFacts::derive` still projects under the callee's own context: base had no case where the root's context changes a callee's projection, so the move waits for one. No `Dispute` is minted: a declared interface skips the decision, so DWARF and the body never meet here. r2dec `decide_prototypes` stays for callees with no projection.
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
- `scripts/scratch_void.py` over the 35 DecBench builds: exit 0 at base and head, so no false void beyond the 2 named clones. Source values a closed-world read decides (`unstated`) go from 685 to 1,864, and written source values from 3,273 to 2,092. 12 source voids and 2 source values are `ForwardCycle`. `void-open` stays 272 void and 2 value. Closed-world voids are 0 at base and head, and no `Unread` is decided: at some call, some lane a body may hold is never dead (RDX, XMM1, or a lane its caller returns on). Source voids rendered with a value fall from 7 to 6.
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

- `BodyBoundary { slots, locations, results, floor }` is r2ssa `body_boundary.rs`, minted by recovery and carried on `PreparedFunctionFacts::body_boundary` of the sealed artifact. `SlotId` numbers the integer section, the float section (or Win64's one `Shared` section), then the stack slots read. `locations` gives each slot its section, position and location. `results` is `IdVec<LaneId, Option<lanes::Bytes>>` over the typed lanes (integer, float, second): each lane's bytes joined over every return, `None` where a return's value is unresolved. It has no reader yet; S7's `CallBoundary` decision reads it in place of a second seal.
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

Gates, debug build, base `20c1f7832`:

- libz (O2-noinline-libz) `0xe160`: `fcn_e160(r2sleigh_unread_u64 arg0, uint32_t arg1, uint32_t arg2)` (base `(void)`), `malloc(arg1 * arg2)` with no residual.
- fp x86-64 (clang -O2, stripped): fadd `float (float arg0, float arg1)`, dmul `double (uint32_t arg0, double arg1)` in convention order, dcmp `uint32_t (double arg0, double arg1)` (base `float (void)`, `double (uint32_t)`, `uint32_t (void)`). On arm64 the three stay `(void)`: their result is unproven (`EntryInput` on x0), so no float read is observed. That is S7's.
- Certification, radare2 `test/bins/elf --limit 24 --functions 8`: base and head print the same 50 rendered, 30 refused, 0 invented, 0 dropped. Over the 13 DecBench O2 builds at 40 functions each: 518 rendered and 2 refused at base and head; calls graded rise from 109 to 117, with 0 invented, 0 dropped and 0 hole arguments.
- D37's `an_argument_area_read_past_the_prefix_is_a_floor_of_that_cause` (`f(stack0)`) passes unchanged. D100's `a_floor_of_parameters_is_named_on_the_proof_line` runs the clang -O0 `fcntl` wrapper.
- Source-gold over 15 gcc builds: aggregate soundness 0.6065 to 0.6079, with missing facts 13 to 9, marked 196 to 199 and silent 157 to 158. `scratch` rises 0.2222 to 0.2857. `odd` falls 0.1935 to 0.1875: `set_handler`'s function-pointer parameter, missing before, is now present and typed `uint64_t` (D71 A2). The grader reads `r2sleigh_unread_*` as marked, as it reads `r2sleigh_result_*`.
- Census: 15 goldens move. Nine `_start`s gain `rdx`, handed to `__libc_start_main`, behind two holes. -O0 `zero_of` homes its unused `x`, so its caller's call is a floor residual. Proof lines name the floors they rest on.
- Cost, release, instructions retired, base then head: cold `pdd` on 0pack `0x62ecf0` 15.32 to 15.34 G (+0.2%), 0pack `0x58e3d0` 18.69 to 18.72 G (+0.2%), pumasim `0x23fdf0` 19.75 to 19.83 G (+0.4%); bash `0x2e630` `aa; pdd` 22.20 to 22.22 G (+0.1%), output identical. Peak RSS moves within run-to-run noise (0pack `0x58e3d0` 242 to 245 MB over two runs each). The entry values are indexed by register once per body, and `results` adds the float and second lanes' live-out walks.
- pumasim `Gui::Gui(QWidget *, const char *, unsigned)` goes from `(void *arg0)` to three parameters, and its call to `QWidget::QWidget` passes four arguments. 0pack `0x62ecf0`'s proof line names its floor of two and the four calls it rests on.
- Dylint: 8 warnings, the baseline; no `entity_keyed_map`. Structure counts match base finding for finding; `long_comments` falls from 2,498 to 2,493.
- Not run: equivalence. The build host had 1.4 GB free, under one release build.
