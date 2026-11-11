# ADR: the result side of the call boundary

Status: proposed (ROADMAP P7; D206's ruling; rows D310 to D313; the design S15, S16, S24, S25, S26, S30, S31a, S31b and S36 build). It amends doc/adr-call-boundary.md "The callee's boundary" and the as-built sections listed under "Amendments". Read at origin/s10-win64 `d8487d42d`, with an independent design review folded in.

## Problem

Seven slices change the result seam, and no section states the design they share:

| Slice | Rows | What it changes on the result side |
|---|---|---|
| S15 | D218, D219 | which vector lanes a variadic import reads at one call; forwarding through a caller whose result is read |
| S16 | D212, W46 | per-lane pass-through at a call; call-site minting for two carriers; rv_O2 `avg`'s XMM0 double |
| S36 | none yet | false voids: x87 `st0`/`st1` hold no lane; `c_f3_chain_c` reads XMM1 after a `void` extern |
| S24 | D74, G1, G19 | `SourceAbove::Zero` and `Sign` producers; the `COPY:8` constant; the silent `void` |
| S26 | D166, G3, G4 | an import whose row states no result; declaration-against-body disputes |
| S30 | D205 | void from declared callback slots |
| S31 (split into S31a and S31b) | G9, G10 | the one-seal decision; `CalleeEntry` cost; dead `SiteBoundary.written` |

The code at `d8487d42d` shows why one design is needed:

- Three places decide presence. r2ssa `recover_interface` decides the open result (`recover_interface.rs:1572-1800`). r2engine `fates::decide` (`fates.rs:353-432`) decides the closed one at each seal, and r2ssa re-applies it (`:1786-1800`). r2types decides the `Written` or `EntryInput` cause. `CallBoundary` holds evidence and no decision.
- A forwarding cycle is cut by the database. The answer is `Hold::Transient` and depends on which member was asked first (`fates.rs:77-79, 282-291`).
- Recovery holds three lanes: the integer, float and second registers. The convention states six on SysV (RAX, RDX, XMM0, XMM1, ST0, ST1) and six on AAPCS64 (X0, X1, Q0 to Q3). The closed world's `held` leaves x87 out of the lanes that must be dead (`fates.rs:265-267`), and `ResultLanes::of` drops lanes past `OTHERS = 4` without a refusal (`site_boundary.rs:64-87`).
- `void_soundness.py` names 16 x87 header false voids in `known.json`. It grades headers only. The S36 triage (166 builds of 22 programs) counts 799 extern false voids at head and 1,199 at base; 12 are new since #355 (`c_cld_chain_*`).
- The extern voids have one cause: r2ssa `convention_call_boundary` (`semantic/boundaries.rs:858`) states a call's result only in the integer slot. A read of XMM0, XMM1 or ST0 after a call with no contract leaves `results` empty, and r2dec spells `void`.
- Two computations state what a callee does to its entry registers: `preserved_call_carriers` from the prepared SSA (`semantic/shared.rs:775`) and `EntrySummary` from a raw-lift pass (`fates.rs:545-573`). S16's draft adds a third, `EntrySummary::passes`.
- Five computations state what a call reads: `uncertified_call_reads` (`function/mod.rs:3015`), `save_area::read_only_by` (`save_area.rs:297`), `CallEffect.takes` (`fates.rs:689-758`), slot promotion's `CallArguments::of` (`slot_promotion.rs:356-412`) and `unproven_calls_reached` (`recover_interface.rs:2225-2277`). Three walks state frame escape: `FrameReach`, slot promotion's `Reach` (where D217 lived) and `stack_protector::escapes`.
- `fates.rs:422` decides `Void` for a function nothing calls. No call executes it, so no fact decides its result.
- `SourceAbove` has one producer value, `Undefined` (`contracts.rs:508`, `lanes.rs:690`).
- r2engine `function_type` drops a signature whose result is `Unknown` (`declared/mod.rs:382`). 0pack has 1,222 `declaration-disagrees` sites and pumasim 690.
- `SourceLoaderRole` has a reader in `recover_interface` and no producer: `native.rs:2142` always passes `None`.
- `SiteBoundary.written` has no reader and is computed at every `Unknown` site (`site_boundary.rs:137, 911-933`).
- Cost: pumasim `0x3b6b20` `aa; pdd` went from 64.378 G to 66.400 G instructions (+3.1%) over the stack. No profile splits the 66.40 G. `Walked` is `Retention::Newest` (`analysis.rs:125`), so each `CalleeEntry` lifts its callee again.

## Decision

The result side has four parts, each with one owner:

1. The lane set: r2engine `ConventionModel.results`, one record per convention.
2. Two per-lane facts, both stated by r2ssa: supply (what a callee leaves in a lane) and demand (what a caller does with it after a call).
3. One decision per callee and world, held by r2engine `CallBoundary` and solved per strongly connected component. r2types projects it, and the seal applies it.
4. Default-deny constructors. A lane no constructor proves is `Unproven`.

### 1. The lane set

`ConventionModel.results` is the one list of result lanes. It joins the cspec's `<output>` with the cited `SpecOverride::Results` rows. Every reader takes its lanes from it: r2ssa recovery, `site_boundary`, call-site minting, r2engine `fates`, the r2types projection. `ResultLanes::of` and `fates::held_lanes` become reads of this list, indexed by dense `LaneId`.

```rust
pub struct ResultLane {                 // r2source, extends today's ResultLane
    pub storage: CanonicalStorageId,
    pub class: SlotClass,               // Integer or Float
    pub extension: Extension,
    pub stated_by: LaneSource,          // Specification or Override
    pub entry: LaneEntry,               // what the lane holds at entry, by the convention
    pub follows: Option<LaneId>,        // holds a result only beside this lane
}
pub enum LaneEntry {
    Input,       // an argument location: its entry bytes are the caller's argument
    Scratch,     // no argument location: its entry bytes define nothing (scratch-result case 1)
    Empty,       // x87: the stack is empty at entry (SysV 3.2.1)
}
pub struct ResultLaneSet {
    pub lanes: IdVec<LaneId, ResultLane>, // at most LANES = 7, else refused
    pub complete: Option<&'static str>,   // the citation that states the set complete
}
```

| Convention | Lanes, in `LaneId` order | `entry` | `follows` | Complete by |
|---|---|---|---|---|
| SysV x86-64 | RAX, XMM0, RDX, XMM1, ST0, ST1 | RAX Scratch; XMM0, RDX, XMM1 Input; ST0, ST1 Empty | RDX after RAX; XMM1 after XMM0; ST1 after ST0 | psABI 1.0, 3.2.3 "Returning of Values" |
| Microsoft x64 | RAX, XMM0 | RAX Scratch; XMM0 Input | none | Microsoft x64 "Return values" |
| AAPCS64, Apple arm64 | X0, Q0, X1, Q1, Q2, Q3 | all Input | X1 after X0; Q1 after Q0, Q2 after Q1, Q3 after Q2 | AAPCS64 6.9 "Result return" |

Rules:

- `entry` is the convention's default. A body that reads a `Scratch` lane's entry value treats that lane as `Input` for itself. A variadic SysV body reads AL, so its RAX is `Input`, and it is never `void` from case 1 (D200's gate, CI shape `sum_args`). This is today's `entry_defines_nothing`, stated per lane.
- `follows` is cited. The psABI fills INTEGER eightbytes from RAX then RDX, SSE eightbytes from XMM0 then XMM1, and COMPLEX_X87 from ST0 then ST1. AAPCS64 returns an HFA in consecutive registers from v0. A lane whose `follows` lane decides `None` holds no result. This generalizes D213's `integer_undefined`, which exempts RDX beside an undefined RAX.
- A lane set above `LANES` is refused by name: Go's ABIInternal returns in 9 integer and 15 float registers. A refused set makes every result of that convention `Unproven`.
- The set is an upper bound only where `complete` cites one. A convention with `complete: None` never decides `Void` or `None` on any lane. This moves only ungraded conventions (i386, RISC-V, AAPCS32, Go). S36 measures it on the census.
- AArch64 x8 is `SlotClass::HiddenReturn` on the input side. It is no result lane: AAPCS64 does not require x8 back.
- A vector result wider than its lane (`__m256` in YMM0) has no lane. A declaration that states one is `Unproven(Unplaced)`.
- The lift writes x87 results as registers: `FLD` assigns `ST0` (`ia.sinc:5860-5865`), and `fpushv`/`fpopv` shift `ST0` to `ST7` (`:2270-2290`). So the ST0 and ST1 lanes are visible to the same walk as RAX.

### 2. Two facts per lane

#### Supply: what a callee leaves

```rust
pub enum LaneResult {                   // r2ssa; one value per lane, at a callee and at a call
    Unreached,                          // no return path reaches this lane's exit
    None,                               // no return leaves a byte the callee defines or the caller passed
    PassThrough,                        // every return leaves the lane's entry bytes
    Result { width: SourceResultWidth, basis: Basis },
    Unproven { width: SourceResultWidth, causes: CauseSet },
}
```

Owner: r2ssa recovery, in the open read (`CalleeReads`). One live-out walk covers every lane of the set and replaces today's five single-lane walks (`recover_interface.rs:1095, 1131, 1580, 1717, 1767`). It classifies each return path from `lanes::Byte`:

- every byte `Fill::Undefined` (scratch-result cases 1 to 3), or the entry byte of a `Scratch` or `Empty` lane: `None`;
- every byte `Filled { Entry }` of this lane: `PassThrough`;
- any `Data` or `Widened` byte: `Unproven { causes: {Written} }`, with `written_width` and the fill above;
- a path the walk cannot follow (an unresolved tail, budget): `Unproven { causes: {Unknown} }`.

`Result` is never a path fact. It comes only from a constructor in section 3.

The join over return paths, per lane:

| ⊔ | Unreached | None | PassThrough | Unproven(c, w) |
|---|---|---|---|---|
| Unreached | Unreached | None | PassThrough | Unproven(c, w) |
| None | | None | `Scratch`/`Empty`: None. `Input`: Unproven({HandedBack}) | Unproven(c, w) |
| PassThrough | | | PassThrough | Unproven(c ∪ {HandedBack if `Input`}, w) |
| Unproven(c', w') | | | | Unproven(c ∪ c', w ⊔ w') |

- `None ⊔ Unproven = Unproven` is scratch-result's "undefined joined with data is data".
- `None ⊔ PassThrough` on a `Scratch` lane is `None`. The caller's bytes survive only some paths, so no compiled caller relies on them, and a read after the call is a residual.
- On an `Input` lane the same join is `Unproven({HandedBack})`. This is D208: an XMM0 entry byte at a return on some path.
- `w ⊔ w'` joins byte by byte through `lanes::Byte`. `logical` is one past the highest `Data` or `Widened` byte. `above` is `Zero` or `Sign` only where every byte above is that fill on every path.
- Height per lane: 3 element steps (on a `Scratch` lane `Unreached` < `PassThrough` < `None` < `Unproven`, since `None ⊔ PassThrough = None`), 4 width steps (1, 2, 4, 8, 16 bytes) and 1 `above` step (`Zero` or `Sign` to `Undefined`): 8. `causes` is a finite set carried beside the element. It never drives iteration.
- The supply also records, per lane, whether some return path is proven to leave no caller byte (a write or an undefined fill). The decision reads it.

Two projections read one value:

- At the callee's header: `PassThrough` on an `Input` lane is `Unproven({HandedBack})` (EntryInput). On a `Scratch` or `Empty` lane it is `None`.
- At a call: `PassThrough` means the bytes after the call are the bytes before it, and the caller's lowering defines nothing there. `None` means a read after the call is a residual. `Unproven` is the call's carrier, spelled `r2sleigh_result_uN` (D201). `Result` is the callee's value at its width.

`SourceCallResult` becomes one `LaneResult` per `LaneId` on the call-site interface. `Void` at a call means every lane is `None` or `PassThrough`.

#### Demand: what a caller does

Demand is today's `site_boundary::LaneFate`: `Dead`, `Read(ByteMask)`, `Returned(ByteMask)` and `Unknown`. r2ssa states it per call; r2engine joins it over every call into `JoinedLane` flags (`read`, `unknown`, `cycle`, `dead`) and a byte mask. The join is monotone: `dead` falls once, each other flag rises once, and the mask rises by at most 16 bits.

One demand constructor is added. A lane handed to a call whose stated boundary reads that location is `Read`: a cited fixed parameter (`sqrt(double)` after `avg()`), or later an operand a fully parsed format proves. Under `UbFreeSource`, C passes no value it did not define. Today such a hand-off is `Unknown` ("no evidence that the caller reads the result").

### 3. The decision and its constructors

#### One decision, held

r2engine `CallBoundary(callee, World)` holds `BoundaryResult`: each lane's decision, the function's result, its premises and its disputes. It reads the callee's supply from the open read and the joined demand from `SiteFates`. Forwarding is solved per strongly connected component of the forwarder graph on `r2ssa::fixpoint`, so every member gets the same answer, and the answer is held. r2types projects `BoundaryResult` into C types. The final seal reads it as a stated input, like a declaration, and applies it with no rule of its own.

Under the closed world, each lane's supply meets its joined demand:

| Supply at the callee \ demand at every call | Dead at every way in | Read at some call | Otherwise |
|---|---|---|---|
| Unreached | Unreached | Unreached | Unreached |
| None | None | None; a `Dispute` if the callee overwrites the lane on every path | None |
| PassThrough, `Scratch` or `Empty` | None | None (the caller reads its own bytes) | None |
| PassThrough, `Input` | None, premise `ClosedWorld` | Unproven({HandedBack}) | Unproven({HandedBack}) |
| Unproven, causes only `HandedBack` or `NoReturn` | None, premise `ClosedWorld` (D213) | Result at `Solved`, premises `ClosedWorld` and `UbFreeSource`, where some path leaves no caller byte | Unproven |
| Unproven, any other cause (`Written`, `Returned`, `Tailed`, `Clobbered`, `Unknown`) | Unproven({Unread}) (D202) | Result at `Solved`, both premises, where some path leaves no caller byte | Unproven |
| Result (a declaration) | Result | Result | Result |

- `Read` decides `Result` only where some return path is proven to leave no caller byte in the lane. A lane whose paths are only pass-through or unfollowed stays `Unproven`.
- The reason: under `-fipa-ra`, `void f(long x, long y){ sink = y; }` leaves x0 alone, so a caller that keeps its own `a` in x0 across the call and reads it has the same bytes as `r = keep(a, b)`. A path that writes the lane admits no such reading: no compiler keeps a caller value in a register the callee may write.
- "Dead at every way in" needs at least one call. A function nothing calls keeps its open result: no call executes it, so no fact decides it.
- The `Result` width is the written width met with the reads' agreed width, as `fates::forwarded` computes it today.

The function's result follows from its lanes:

- `Void`: every lane `None`, and at least one lane not `Unreached`. A body with no return path is `NoReturn`, never `Void`.
- `Value`: the lanes that decide `Result` form one group (section 4). Every other lane is `None` or `Unproven({Unread})`. A written lane that is `Unknown` beside a `Result` lane makes the whole result `Unproven({Ambiguous})`: a struct `{long, double}` returns in RAX and XMM0, so reading RAX alone proves no `uint64_t`.
- `Unproven` otherwise. The carriers are the `Unproven` lanes, and the causes are the union of each lane's causes. `resolved.rs` `result_owners` reads that union as it does today.
- The open world (a cold `pdd`) has no demand. Its `BoundaryResult` is the supply's header projection.

#### Constructors

A lane that no row below proves is `Unproven`.

| Fact | Constructor | Owner | Basis and premise |
|---|---|---|---|
| Lane `None` | every return path leaves `Fill::Undefined` bytes (scratch-result cases 1 to 3) | r2ssa `lanes`, recovery | `Decoded`; `UbFreeSource` where a decided canary check writes it |
| Lane `None` | the lane's `follows` lane is `None` | r2engine decision, from the cited lane set | as the lane it follows |
| Lane `None` | an `Input` pass-through or handed-back lane `Dead` at every way in, one call or more | r2engine decision | `Solved`, `ClosedWorld` |
| Every lane `None` | a declaration states `void` (DWARF whose arrivals hold, a cited row) | r2engine `declared`, placed by r2ssa `place` | `DebugInfo` or `Declared` |
| Every lane `None` | the loader calls the function: `DT_INIT`, `DT_FINI`, `DT_INIT_ARRAY`, `DT_FINI_ARRAY` entries, cited from the ELF gABI as `void (*)(void)` | r2image states the entries; r2abi cites the row; r2engine sets `SourceLoaderRole` (S22) | `Declared` |
| Every lane `None` | the address flows only into parameters declared `void (*)(...)` (D205) | r2engine `Escapes` taking sites, r2abi typed rows | `Declared`, `UbFreeSource` |
| `Void` | every lane `None`, one return reached | r2engine decision | the weakest basis of its lanes; the union of their premises |
| Demand `Dead` at a call | the forward walk from the call reaches an overwrite or the path's end before any read | r2ssa `site_boundary` | evidence |
| Demand `Dead` at every way in | every call joined `dead`; one call or more; no unread caller; the forwarder component dead; `only_called` holds for the callee and each forwarder | r2engine `fates`, `reads::only_called` | `ClosedWorld` |
| Closed world | `only_called(f, calls)` with positive coverage of every way in (section 4, "The closed world"); the held `ReferenceIndex` counts exactly `calls` call references | r2engine `reads.rs`; under `aa` only (`World::Closed`) | the premise `ClosedWorld` on every decision that rests on it |
| `PassThrough` | the body's held register effect states the lane kept on every path to a return, inner calls included (section 5) | r2ssa register effect, held by r2engine | `Decoded` |
| `Result` | DWARF for this body whose arrivals hold | r2engine `declared`, r2ssa `place` | `DebugInfo` |
| `Result` | a cited library row, through an import binding | r2abi, r2engine | `Declared` |
| `Result` | the decision: a lane `Read` at some call, where some path leaves no caller byte | r2engine decision | `Solved`, `ClosedWorld`, `UbFreeSource` |
| `above: Zero` or `Sign` | every byte above `logical` is that fill on every path | r2ssa `lanes` (S24) | `Decoded` |
| `above` of a declared result | the convention's result extension row; with no row, `Undefined` | r2abi `SpecOverride::Extension` | `Declared` |

Nothing else constructs `Void`, `Dead`, `PassThrough` or `Result`. Names, call-site counts and use patterns construct nothing.

### 4. Cases

#### Forwarding and cycles

- A `Returned` lane at a call forwards to the caller's own demand on the same lane (built in S7).
- D219 needs no engine change: `sites_of` joins each lane on its own, and `DeadIfEveryWayIn` holds whatever the caller's integer lane does (S15's note).
- The forwarder graph is solved per strongly connected component on `r2ssa::fixpoint`, one query per component (doc/adr-query-database.md). A component of two or more members, or one forwarding to itself, decides `Read` where any member's outside call reads the lane. Otherwise it is `Unproven({ForwardCycle})`: a cycle proves no read (the call-boundary ADR's Coverage 2). `every_way_in`'s private memo (`fates.rs:204-244`) becomes the component's answer.
- A tail transfer to a callee is that callee's supply on the path: `PassThrough` through a leaf that leaves RAX alone. Tails inside a cycle start at `Unreached` and rise in `least_fixpoint`, within the height above.

#### The closed world

`only_called` (`reads.rs:15-56`) and `Escapes` (`reads.rs:61-121`) must rest on positive coverage: every byte and word that could name a function is read, and anything unread refuses. At `d8487d42d`:

| Way in | Coverage | Code |
|---|---|---|
| Executable bytes | positive: every byte of a loaded code section (else an executable segment) is held by a walked body, a linkage section or padding, or the closed world refuses (S7 cost, `4b6c83365`) | `unaccounted_code`, `padding` |
| Bodies | positive: one unread body refuses | `index.coverage.unread` |
| Instructions | positive: every non-call reference the index claims escapes, a loop jump excepted | `index.claimed()` |
| File words | positive: every 8- and 4-byte window of every mapped segment, with bit 0 cleared, that equals an entry escapes | `stored_words` |
| Loader writes | partial: a write enters the index only where `stated_address()` is `Some` (`statement.rs:796-806`). `WriteKind::Unknown` (a signed pointer, an undecoded format), `Resolver` (an IFUNC resolver the loader calls) and non-word encodings are skipped | `References::read_words` |
| Entries, exports | positive over the container's lists | `container.entries`, `exported` |
| Machine, format, language | refused outside 64-bit x86 and Arm, ELF and Mach-O, and C, C++ and Rust | `Escapes::compute`, `only_called` |

The loader-write row is a deny list. S31a makes it positive: a `Resolver` write's resolver escapes, and an `Unknown` write, or a non-word write whose target is this image's code, refuses the closed world. Where r2image can state a reserved word, it states it as `NotAnAddress`, and the refusal is lifted at the owner. S31a measures how many binaries of the census and the 35 DecBench builds the refusal costs.

Two gaps stay named: AArch64's large code model (`movz`/`movk`, doc/adr-resolved-bodies.md, item 6), and an `adrp`+`add` inside padding.

S31a's gate adds one mutant per way in: an export, a non-symbol entry, a non-call reference, an 8-byte and a 4-byte stored word, a Thumb bit, a relative loader write, a resolver write, an unknown write, an unread body, an unaccounted code byte, a language, a call count one short. Each mutant drops one way in from `Escapes` or `only_called`, and an engine test that passes on the base must fail on it.

The closed world's yield is 4 of 102 class C functions on the 35 DecBench builds (D203). What caps it (uncited imports, unread lanes) is unmeasured; S18 measures the split.

#### The variadic read bound

An import call reads its row's fixed locations. Under `Unstated`, `Variadic`, `Format` or `VaList` it also reads every later argument location of the convention. Two facts may narrow that tail, and both are all or nothing:

- A count register the convention states (SysV `al`) whose value the call's block states (`Counted`, built).
- A format the call's own constant states and r2ssa `printf.rs` parses fully: every conversion known, every position valid, the text in static data no write reaches. Then the vector tail is exactly the format's floating operands. S15 builds the case of zero floating operands. A format with floating operands keeps every location until a row extends the same parse to count them.

Any refusal (no literal, a spilled format, an unknown conversion) keeps every location. A partial parse never narrows. Integer reads are never narrowed by a format.

#### Struct in registers

A result spanning lanes is one group, decided per callee (D62 generalized). The ABI's groups:

| Convention | Groups |
|---|---|
| SysV x86-64 | {RAX}, {RAX, RDX}, {XMM0}, {XMM0, XMM1}, {RAX, XMM0}, {XMM0, RAX}, {ST0}, {ST0, ST1} |
| AAPCS64 | {X0}, {X0, X1}, {Q0} to {Q0, Q1, Q2, Q3} (HFA and HVA) |
| Microsoft x64 | {RAX}, {XMM0} |

- A declaration states the group through `place` once it classifies aggregates. The cspec `<rule>` elements are refused today (G18), so a declared aggregate result is `Unproven({Unplaced})` until then.
- Without a declaration, the group is the lanes that decide `Result`. A written lane in no group that is `Unknown` makes the result `Unproven({Ambiguous})`.
- No group proves a C type. `{XMM0, XMM1}` is `struct { double, double }`, `_Complex double` or `struct { float a, b, c, d; }`. The header spells a group through a prelude carrier struct with one member per lane (`r2sleigh_result_xmm0_xmm1`), only where a compile test shows the target's compiler returns that struct in exactly those lanes. Like D201's `r2sleigh_result_uN`, it claims no C type, and `tests/equiv` defines it. A group with no such test spells a residual per lane (Decided 1).
- `c_f3_chain_c`'s callee returns `{float, float, float}` in XMM0 and XMM1. Its XMM1 supply is `Unproven({Written})`, so the callee is never `void`, and neither is its extern.
- rv_O2 `avg` writes RAX (a scratch pointer) and XMM0 (`divsd`). Both lanes are `Unproven({Written})`. A cold header spells the group carrier and names both lanes. Under `aa`, a call that reads XMM0, or hands it to a cited fixed float parameter, decides XMM0 `Result`. RAX then needs `Dead` or `Unread` for `double avg(...)`.

#### Declaration against body

The authority order holds per lane: DWARF whose arrivals hold, then the body, then a library row (imports only), then the convention. A loser is a `Dispute { lane, kept, lost }`. Disputes are refusal evidence and decide nothing. The decision mints every dispute, and `BoundaryResult` holds them.

| Case | Kept | Lost | Output |
|---|---|---|---|
| A declared or body `None` lane that a closed-world call reads, where the callee overwrites it on every path | Declared or Body | Calls | built in S7b |
| DWARF states a result; every lane of its class is `None` on every return path (an IPA-SRA clone such as find `visit_open_fds.constprop.0.isra.0`) | Declared | Body | the declaration's type; each return renders a residual, since no byte defines the value |
| DWARF states `void`; the body writes a defined byte | Declared | Body | `void`; the written lane is named on the proof line |
| DWARF states a float result; the body writes only the integer lane | Declared | Body | the declaration's type; the dispute names the lane |
| A declared width narrower than the written width | none | none | no dispute: `logical` is the declared width and the bytes above are `Undefined` |

DWARF stays first (Decided 5). The body never beats it on the result: the IPA-SRA row mints the `Dispute` and keeps the declared type. The check is `O(LANES)` per seal.

#### Imports with an unstated result

A row may state parameters and no result. Itanium mangling encodes no result for a non-template name (S13). An uncited sdb row is `Tail::Unstated`.

- `function_type` keeps the signature and states its result `Unproven({Unstated})` on every lane the convention kills. Today it returns `None`, so r2dec builds each call's extern from that call's arguments and 1,222 0pack sites disagree.
- The extern spells the parameters and the carrier typedef. One extern per callee.
- S13's `Passing` rule stands. `HiddenResultUnstated` places nothing where the first argument register may hold a hidden result pointer (SysV `rdi`, Microsoft x64 `rcx`). `VttUnstated` places nothing anywhere.
- An import is never `PassThrough` on a lane its convention kills.
- A call to an import with no row, or a call whose callee mints no contract, reads every argument location and defines every killed lane `Unproven`. It is never `void` (S36).

### 5. One held register effect, and the cost

#### What a callee does to its entry registers

S31b replaces `EntrySummary` and the `CalleeEntry` lift with one held fact. S16 builds on `preserved_call_carriers` as it stands, and adds no `EntrySummary::passes`.

```rust
pub struct RegisterEffect {             // r2ssa site_boundary; per body and world, held by r2engine
    pub kept: LaneBytes,                // bytes every path to a return leaves as found
    pub overwrites: LaneBytes,          // bytes every path to a return overwrites
    pub takes: LaneBytes,               // bytes some path reads, forwards in a tail or loses
}
```

- One function computes it from the lift, `O((B + E) × LANES)`.
- The default bound: an inner callee with no held effect takes every argument register, keeps nothing and overwrites nothing known, as an unknown callee does today (`fates.rs:718-722`). A cold `pdd` computes each callee's effect against that bound and recurses into no other effect.
- Under `aa` the survey walk computes every body's effect while it holds the lift, and deposits the rows as it deposits `ComesBack`. An inner call then reads its callee's row. The program-wide fact is solved per call-graph component on `r2ssa::fixpoint`: `kept` only falls and `overwrites` only rises, each bounded by 16 bits per lane. The key holds the world, since cold and `aa` answers differ by design.
- Readers: `SiteFates`' call effects (today `CalleeEntry`), call-site minting, the `PassThrough` constructor. The `CalleeEntry` query and its second lift are deleted.
- `preserved_call_carriers` stays until S31b measures zero yield loss from it. The raw-lift pass does not see a register saved to the stack and restored, which the SSA set does. Until that count is zero, both stand, and the register effect never states a lane `kept` that the preserved set denies.
- An unsummarized image callee takes every argument register. On AArch64 that opens q1 to q3 at every later call, so D213's voids depend on a row being present for every callee.

#### What a call reads, and what escapes

- What a call reads has one owner: r2ssa `CallReads`, derived once per callee statement (an exact interface, a placed row with its `Tail`, or the convention's every-location default). `uncertified_call_reads`, `read_only_by`'s `CallUse` arm, `CallEffect.takes`, slot promotion's `CallArguments::of` and `unproven_calls_reached` read it. Each stops recomputing it.
- Frame escape has one owner: `FrameReach`. Slot promotion and the canary decision run before the seal, so the escape walk moves before them and all three read it. D217's defect lived in the second walk.
- Both are parameter- and frame-side fixes. S25 builds `CallReads`; the escape walk joins it if the phase order allows, and otherwise gets its own row.

#### Where the decision is computed

- The open read (`CalleeReads`) states supply. `CallBoundary(callee, Closed)` decides once and holds `BoundaryResult`. Where the decision moves the result, `Resolved` seals again with it as a stated input, as `closed_alone` and `outside_resolved` do today. S7 measured that reseal under 1% of bash's `aa; pdd` (2 functions decided in bash, 4 in pumasim `0x3b6b20`).
- The decision deletes `fates::decide`, `fates::disputes`, the `closed` arms of `recover_interface` and r2types' cause choice. `SourceClosedResult` stays as the type the seal reads.
- The query graph has no cycle. Traced read-only at `d8487d42d`:
  - `CalleeReads` prepares with `Stated::default()`, whose world is `Open` (`native.rs:1085-1090`, `analysis.rs:200-212`). Its callees are read through `View::read_callee` (`view.rs:275-291`) at `Demand::Result`, so `closed_alone` returns its open read and `outside_resolved` prepares in the open world. `closed_result` (`native.rs:1595`) runs only where the world is `Closed`, so no open read asks `CallBoundary`.
  - `SiteFates` and the entry summary read `Walked`, which "asks for no callee" (`analysis.rs:238`). `ReferenceIndex` reads `SurveyQuery`, `Walked` and the loader writes. `Escapes` reads `SurveyQuery` and `ReferenceIndex`. `SurveyQuery` runs discovery and deposits `ComesBack`.
  - So `CallBoundary` reaches no `Resolved` at `Demand::Arity` and no closed seal.
- A database cycle is a defect. S31a's test fails when a `CallBoundary` compute reaches `Resolved` at `Demand::Arity` or another `CallBoundary` outside the forwarder component. No seal reads a cycle as "no demand", and no `Transient` fallback stays.

#### Complexity

| Work | Cost | Held |
|---|---|---|
| Supply | one live-out walk over every lane, `O((V + E) × LANES)`, replacing five single-lane walks | in the open read |
| Demand at one caller | `O((B + E) × LANES)`; an inner callee's effect read in `O(1)` | `SiteFates` |
| Register effect | `O((B + E) × LANES)` per body, plus a bit-vector fixpoint per component | per body |
| Decision | `O(sites of the callee) + O(LANES)`, forwarding `O(V + E)` per component | `CallBoundary` |
| Every way in | one `only_called` per member of a forwarding component | per component |

The `aa` fixpoint bound becomes `O(k + (s + H)·E)` with `H = Σ register locations + S + 8·R`, R the lanes of the set (6 on SysV and AAPCS64). The call-boundary ADR had `5·R`.

#### Cost gates

Release, median of three:

- pumasim `0x3b6b20` `aa; pdd` at or under 64.38 G (head 66.40 G).
- cold `pdd` on 0pack `0x62ecf0` and pumasim `0x23fdf0` within 0.3% of base.
- bash `0x2e630` `aa; pdd` at or under D153's 15.43 G.
- peak footprint within 2%; output byte-identical where the slice moves no rendering.

The register effect's cost is an estimate. It moves a pass into every `aa`: about 1 G per 450 bodies on bash, inferred from the S7 profile taken before "S7 cost". It removes `CalleeEntry`'s 17.5% of that profile and its second lift. No profile splits pumasim's 66.40 G, so S31b profiles pumasim `0x3b6b20` first (samply), then lands the register effect, the deleted `written` computation and the one-call minimum, measuring each. If the survey pass costs more than it saves, the fallback is the same function asked lazily per call, which keeps one owner.

## Parameter side

Three default-allow constructors on the parameter side came from the same review. Each becomes default-deny at r2ssa recovery, and S25 fixes all three beside D214.

| Finding | Today | Default-deny rule | Owner |
|---|---|---|---|
| An entry value read only by `CallOther`, `CpuId` or `Unimplemented` is `SlotUse::Unread` (`recover_interface.rs:2375-2421`). `ProvenProgramObservations` is not the complement of proven-dead values (`deadphi.rs:48-56`). A `wrmsr` or `out` wrapper probably mints `(void)`, and its callers drop the argument with no floor | `Unread` is the complement of positive observation | `Unread` only for values `DeadPhis::unobserved_values` proves dead. A positive observation is `Read`. Every other use is `Unknown(cause)` with a floor | r2ssa `recover_interface`, `deadphi` |
| A floor whose only cause is `Homed` is exact at every caller (`reads_past`, `contracts.rs:359-364`; `machine_context.rs:3072-3081`). Win64 `Homed` checks only the home's own escape (`escapes_directly`, `recover_interface.rs:2357`). hello_gs `0x140001090` mints `(uint64_t arg0, uint64_t arg1)`, so a call passing a third argument probably drops it with no residual | `Homed` past the reads is exact | `Homed` is exact only where no escaped frame address reaches the home region (`FrameReach` reach). Otherwise the floor stays `AtLeast` and calls stay residual | r2ssa frame model |
| A read crossing two stack slots stops `argument_area_slots` with no floor (`recover_interface.rs:521-524`). Reads with incomplete provenance are skipped (`:439`). With a full register section the arity is exact at the truncated count | a silent stop | a crossing or unprovenanced read is `Unknown` with floor cause `ArgumentAreaRead` | r2ssa `recover_interface` |

A fourth belongs with them: `adopt_convention` sets `results_complete = true` always and `arguments_complete` from caller writes (`boundaries.rs:1244-1271`), which `handed_to` reads as arity proof. `arguments_complete` comes only from a callee statement or a declaration; caller writes stay evidence. This one was read and has no measurement, so S25 writes the failing test first.

## Slices

| Order | Slice | Rows | Builds | Owner | Gates |
|---|---|---|---|---|---|
| 1 | S15 | D218, D219; D221 to D224 | the format read bound | r2engine `Placement::reads`, `fates`; r2ssa `printf.rs` | 13 of 15 aarch64 records `void` under `aa` with `ClosedWorld`; `printf("%f")` keeps q0 read; 3 D218 mutants killed; equivalence on both targets |
| 2 | S36 | D305 to D308 | the lane set (`entry`, `follows`, `complete`, refusal past `LANES`); the supply walk for the lanes outside the typed three; a call with no contract states every killed lane `Unproven`; `void_soundness.py` grades externs | r2engine `ConventionModel`; r2ssa recovery, `convention_call_boundary`; r2dec spells | header false voids 16 to 0, `known.json` x87 entries deleted; extern false voids 799 to 0, with no named remainder and no `known.json` entry; an x87 `long double` leaf is never `void`; `c_f3_chain_c`'s five externs are not `void` |
| 3 | S31a | D314 to D317 | `BoundaryResult` held in `CallBoundary`; the forwarder component solve on `r2ssa::fixpoint`; the loader-write coverage of the closed world; `fates::decide`, `fates::disputes`, the `closed` arms of `recover_interface` and r2types' cause choice deleted | r2engine `fates`, `reads`, `resolved`; r2ssa `fixpoint` | census byte-identical, each move named; `mutants_d213.py` all killed; one mutant per way in killed; the no-cycle test |
| 4 | S16 | D212, W46; D225 to D228 | the supply lattice per lane at the callee and the call; the typed three folded into S36's walk; `SourceCallResult` per lane; groups; the hand-off `Read` for cited fixed parameters; on the existing `preserved_call_carriers` | r2ssa | D212's 10 records: each `void` under `aa` with `ClosedWorld`, or `Unproven(EntryInput)` with its open lane named; W46's 24 pairs to 0 or each named; rv_O2 `avg` never a RAX-only header; 0 false voids, headers and externs; the handed-back `Read(Integer)` arm's moves counted |
| 5 | S24 | D74, G1, G19; D322 to D325 | `above: Zero` and `Sign`; the instruction's write width through the constant fold; the silent `void` traced; gcc's `xor eax, eax` scrub `Undefined` | r2ssa `lanes`, `stack_protector`; the fold's owner | an engine test: a body's 32-bit zero-extended result states `Zero`; D70's `width_wider` bucket falls with no `width_narrower` rise; pigz `alloc` (`0x4044b0`) is not `void` |
| 6 | S25 | D214; D326 to D329 | the parameter side above; `CallReads` | r2ssa `recover_interface`, `deadphi`, frame model | an engine test per finding that fails on today's code; certification invents 0 arguments; equivalence on both targets |
| 7 | S26 | G3, G4; D330 to D333 | signatures with an `Unproven` result; declaration-against-body disputes | r2engine `declared`, decision | 0pack `declaration-disagrees` below 1,222 and pumasim below 690; engine tests: the IPA-SRA shape keeps its declared type and mints `Dispute { kept: Declared, lost: Body }`; a `Passing::Stated` mangled import keeps its parameters and a carrier extern; `HiddenResultUnstated` on SysV still places nothing |
| 8 | S30 | D205; D334 to D337 | the declared-callback `None` constructor | r2engine `Escapes`; r2abi typed rows (after S28) | 4 true, 0 false |
| 9 | S31b | G9, G10; D318 to D321 | the register effect (survey-held, default bound on a cold `pdd`); `CalleeEntry` deleted; `SiteBoundary.written` and `written_before` deleted; the one-call minimum for closed-world decisions | r2engine `fates`, survey; r2ssa `site_boundary` | pumasim `0x3b6b20` profiled first, then the cost gates; the one-call minimum's census moves named (`_dl_relocate_static_pie` and its stripped twin); `preserved_call_carriers` deleted only at zero measured yield loss |

S22 (G11, D237 to D240) is the loader-role producer and runs beside these in group A. S16 rebases onto S31a, so the decision has one home before the lattice grows.

Every slice also holds: `void_soundness.py` at 0 false voids in headers and externs (once S36 grades externs), `scratch_void.py` exit 0, both equivalence ratchets, the touched crates' engine tests, the census judged line by line.

### What S15 changes to fit

- Nothing structural. Its format bound is the demand constructor of section 4, and its per-site effect lives in `SiteFates`, the caller's held query.
- It states the bound as "fully parsed or every location". The zero-float case is the first instance; a format with floating operands keeps every location.
- It keeps integer reads whole.
- It builds no hand-off `Read`: a format with no floating conversion proves no vector operand. The hand-off `Read` for cited fixed parameters is S16's.
- D219 adds its test and no code.
- The two spilled-format records (clang -O0 `shape_stash`, `mixed_touch`) get their own row.

### What S36 changes to fit

- It reads `entry` and `follows` from the lane set. Today's draft subtracts the typed slots and the argument slots from `ConventionModel.results`, and states "second lanes follow their first" in prose.
- Its ST0 and ST1 walk is the supply walk of section 2, written once over every lane outside the typed three. S16 then folds the typed three into it, so no lane keeps a walk of its own.
- It owns the call-site fallback. A call with no contract states every killed lane `Unproven`, so S16's 18 W46 calls with no exact callee interface start from that fact, and S16 does not change the fallback again.
- The gate gains externs with no `known.json` entries, and it holds 0 extern false voids with no named remainder.

### What S16 changes to fit

- Its four fates are the lattice: `Pass` is `PassThrough`, `None` is `None`, `Result` is `Result`, and `Unstated` is `Unproven`.
- `Result` comes only from a constructor. Its draft takes "the integer carrier, else the float carrier" of an unproven result. With two written carriers that picks one, so both stay `Unproven` as one group.
- Its `EntrySummary::passes` is not built. `PassThrough` reads the existing `preserved_call_carriers`. The register effect is S31b's alone.
- It rebases onto S31a, so its lattice feeds the held decision and adds no rule to `fates::decide`, which S31a deletes.
- D212 does not close by pass-through alone. `testf` tails to `setExit`, a leaf that leaves RAX and XMM0 alone. RAX is `Scratch`, so it is `None`. XMM0 is `Input`, so `testf` is `Unproven(EntryInput)` (D208), and `void` only where the closed world finds XMM0 dead at every call; `main` leaves it open. The gate names each record's outcome.
- The as-built arm in which a closed-world `Read(Integer)` makes a handed-back argument the result (`recover_interface.rs:1685-1707`) contradicts the decision table. S16 counts its moves and reads each by hand. Deleting it waits for that count (Decided 2).

## Amendments

- doc/adr-call-boundary.md, "The callee's boundary": `BoundaryResult` and the six presence rules are replaced by sections 2 and 3. `CallBoundary` holds the decision, and `disputes` with it.
- "S6 as built": "The sketch's `results` is not built". The per-lane supply is built, carries causes, and costs one walk over every lane.
- "S7 as built": "x87 `st0`/`st1` are not held" holds for entry bytes only. A body that writes them leaves `Unproven` supply there, and the decision needs them dead.
- "S7 as built": "Presence is decided by `fates::decide` at seal time, not held". `CallBoundary` decides once and holds it.
- "S7 as built", `CallEffect.takes`: "A byte it may take stays open: not dead, and no evidence that the caller reads the result". A lane handed to a cited fixed parameter is `Read`.
- "The result side as built": "A function nothing calls is `Sites { calls: 0 }`. It is decided only where it hands back an input (void)". A closed-world decision needs one call or more.
- "The result side as built": `SourceResultCarriers::integer_undefined` becomes the integer lane's `None` supply, with `follows` exempting RDX.
- "S7 cost": "`CalleeEntry` still lifts each callee of a caller". S31b's register effect replaces it.
- "S2 as built": "Every producer states `above: Undefined`". S24 adds `Zero` and `Sign` from the body's bytes. `a_staged_call_to_a_carried_callee_is_declared_at_its_carriers_widths` changes premise: a body's implicit zero above a 32-bit write is `Zero`, and callers render the extension. `bits_above_a_declared_narrower_result_are_never_zero` stays: a declaration states `Undefined`. S24 adds `a_body_result_zero_extended_on_every_path_states_zero_above`.
- "S6 as built", rule 3: "Every other unobserved use is `Unread`". It becomes `Unknown(cause)` with a floor (S25).
- doc/adr-scratch-result.md, Owners: "Result bytes, `Fill::Undefined` | r2ssa `lanes` (one record, `BodyBoundary.results`)" becomes the per-lane supply in the open read. "Void, Unproven cause | r2engine `CallBoundary`" stands, and r2types' cause choice goes.
- D212's row: its narrow fix (`integer_undefined` plus the tail block kept) becomes `PassThrough` through the tail, with the outcome above.

## D206

D206 asks whether "a write whose only reader is the return" (Ghidra's `onlyOpUse` positive) is `Value` evidence. Scratch-result Decided 5 deferred it to an ADR on the Value side. This ADR states every `Value` constructor, so it rules on D206.

The ruling: rejected as a constructor. A byte-identical pair defeats it:

```c
void h(volatile int *p) { (void)*p; }
int  k(volatile int *p) { return *p; }
```

Apple clang 21.0.0, `-target x86_64-linux-gnu`, compiles both to `mov eax, [rdi]; ret` at `-O2`, and to the same 7 instructions at `-O0`. The load's only reader is the return in both. D206 would declare `h` with a value.

The measured precision (3,011 of 4,039 source values, 4 source voids, all measurement misses) makes it a useful hint. No hint decides `Value` (AGENTS rule 6). D206's gate becomes a negative engine test: `h` is never declared with a value from its body alone. The ruling is taken, pending the maintainer (Decided 4).

## Rejected alternatives

- Keep the typed three and add lanes as cases. The x87 false voids come from a missing case. A seventh case in `recover_interface` adds a seventh place to miss one.
- Decide in r2ssa inside the seal (this ADR's first draft). Forwarding needs a program-wide component solve, which is a query, and a decision inside each seal holds no answer per component.
- Decide in r2engine at each seal and re-apply in r2ssa (today). The rules live twice, and nothing holds the answer.
- `EntrySummary::passes` beside `preserved_call_carriers` (S16's draft). Three computations of one per-body fact. A callee that saves and restores RAX would differ between them.
- `Read` on a pure pass-through lane decides `Value`. `-fipa-ra` lets a caller read its own value across a callee that leaves the register alone, with `keep`'s bytes.
- `None ⊔ PassThrough = PassThrough` at a call. The caller's bytes survive only some paths, so no compiled caller relies on them.
- A closed-world `Void` for a function nothing calls. No execution reads its result, so nothing proves one.
- D206's positive. The volatile pair above.
- Ghidra's negative (another use means no output). 1,011 false voids (scratch-result, "Rejected candidates").
- A partial format parse narrows the tail. One misread conversion drops a read, which makes a lane `Dead`, which makes a false void.
- A C struct type from the lanes read. `{XMM0, XMM1}` is `struct { double, double }` or `_Complex double` with the same bytes.
- A width from a constant's magnitude. clang compiles `long f(void){ return 5; }` to `mov eax, 5`. The machine's zero above is a fact; the type is not. S24 keeps the instruction's write width through the fold and adds no magnitude rule.
- A held answer from a cut cycle. It depends on which member was asked first. The component solve gives one answer.
- `Result` from one read lane while another written lane is `Unknown`. `{long, double}` returns in RAX and XMM0, so `uint64_t` would claim the whole result.
- `CalleeEntry` with a cheaper lift. It keeps a second owner beside the SSA preserved set and re-lifts what the survey already lifted.

## Decided, pending the maintainer

Each default below is taken so the slices run. The maintainer may reverse any of them.

1. Groups without a declaration spell the prelude carrier struct (`r2sleigh_result_xmm0_xmm1`) only where a compile test shows the target's compiler returns that struct in exactly those lanes. Otherwise each lane spells a residual.
2. The as-built handed-back `Read(Integer)` arm is measured first, in S16. Where the handed-back lane is a parameter, deleting it spells `r2sleigh_carrier_uN(argK)` and equivalence holds. Where it is no parameter (a narrowing `ret` that never reads x0), the return traps, and equivalence moves `equal` to `residual-trap`. The deletion follows the count.
3. A convention whose result set no row cites complete (`complete: None`) loses `Void`: i386, RISC-V, AAPCS32 and Go headers move to `Unproven`.
4. D206's candidate is rejected as a `Value` constructor (section "D206").
5. DWARF stays first on the result. A DWARF result whose lanes are `None` on every return path keeps its declared type and mints `Dispute { kept: Declared, lost: Body }`. The body never beats DWARF.

## Open questions

1. The register effect's survey pass is an estimate (about 1 G per 450 bodies on bash). If it does not bring pumasim `0x3b6b20` to 64.38 G, S31b keeps the lazy ask per call with the same function.
2. The loader-write refusal (`Unknown` writes) may cost closed-world yield on binaries whose reserved words r2image does not yet state. S31a measures it before landing.
3. Row numbers come from ROADMAP's "Reserved rows" table. This ADR holds D310 to D313.
