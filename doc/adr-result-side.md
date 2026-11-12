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
- `SourceLoaderRole` had a reader in `recover_interface` and no producer: `native.rs:2142` always passed `None`. S22 deleted it (D238).
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
| Lane `None` at the loader's way in | the loader calls an ELF termination function (`DT_FINI`, a `DT_FINI_ARRAY` entry) passing and reading nothing: the gABI's atexit mechanism and C17's `void (*)(void)` handler. The gABI states no type; constructors have no row (D240) | r2image states the entries; r2abi `loader_call` cites the row; r2engine `Escapes` drops the entry and its stated word (S22, D237) | `Solved`, `ClosedWorld` |
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

##### What caps the closed world's yield (S18, D241)

Measured at `19ff0d899` (S36), release r2s under `aa`, on the 102 source-void class C functions of the 35 DecBench builds ([scratch-result](adr-scratch-result.md), "Evidence"). 29 are `void` in the open world (D200 took them). The closed world decides 0. 73 stay undecided: 50 `Unproven(EntryInput)`, 16 `Unproven(Written)`, 7 refused. The gate's 4 `void-closed` at that base are `mbiter_multi_reloc` and `mbuiter_multi_reloc` in cmp and sdiff (O2-noinline). No call reaches them, they are outside class C, and S31a's one-call minimum moves them to `Unproven`. At S31a `c183bdf75` the count is 0 of 102.

Each of the 73 was traced from its supply cause, its way in and the fate of the result lanes (RAX, XMM0) at every call the engine holds. A function counts under every cause it has; "sole" counts a function with one cause.

| Cause | Functions | Sole | What it is |
|---|---|---|---|
| A way in is unknown | 71 | 5 | `Escapes` refuses the image for 62 (`code no body holds`, 12 builds); 8 a forwarder or an unread caller, 6 a call the engine misses, 5 no call, 1 a stored word |
| An unread lane | 45 | 0 | a callee read at `Depth::Shallow` (41), a lane the walk loses (22), a callee's tail call (17), an indirect call (6) |
| An uncited library row | 41 | 1 | the lane crosses a call to an import whose row is `Tail::Unstated`, here or in a callee |
| Forwarding | 39 | 0 | the lane is returned into the caller (20), a tail call forwards it (9), the supply is a direct call's result (15) |
| The supply is written | 8 | 0 | `Register` or `Written`, no demand question |
| A callee reads the lane | 7 | 0 | a cited import or an image callee reads it |
| Refused | 7 | 0 | the function renders nothing |
| An import with no row | 5 | 0 | 31 names at the class C callers' sites: `__overflow` (25 sites), `fchdir`, `__ctype_get_mb_cur_max`, `fork`, `sysconf`, `dup2`, `wcwidth` |
| A cycle | 0 | 0 | |

Two switches in the engine bound what removing a cause can yield. `MEASURE_CITE` reads every `Unstated` row as `Tail::None`, which is more than any citation can state (it also fixes `open` and `ioctl`). `MEASURE_GO_ON` skips the two whole-image refusals of `Escapes`. Both are upper bounds.

| Run | `void-closed` at `19ff0d899` | at S31a `c183bdf75` | Which, at S31a |
|---|---|---|---|
| base | 0 | 0 | |
| every row cited | 1 | 1 | sdiff `checksigs` |
| the image refusals skipped | 5 | 1 | bzip2 `uInt64_toAscii` |
| both | 9 | 6 | those two, diff `check_color_output` and `print_message_queue`, find `set_option_defaults`, diff3 `output_diff3` |

At `19ff0d899` four of the five skipped-refusal voids were diff `set_color_palette` and `finish_output` (O2 and O2-noinline) with 0 calls held: `main`'s unwalked case blocks call them, so those voids were the refusal's own reason. S31a's one-call minimum decides none of them.

- The causes are a conjunction. No single cause holds more than 5 functions alone. At S31a, with the rows cited and the image refusals gone, 67 of 73 still wait on an unread lane (45 at `19ff0d899`) or forwarding (42).
- `code no body holds` has two causes. In 9 builds (41 functions) a table jump's index has no bound in r2ssa `values`, so its case blocks are in no body: gzip `main` (`0x3b9a`) reaches its dispatch from two guarded predecessors (`ja` at `0x3b98`, `jbe` at `0x3c15`), and a branch assumption holds only where its edge dominates; `printf_fetchargs` (`0x10f89`) tests `cmp [rax], 0x16` and reloads the word. Both read `4294967296 entries`. The other ranges of those builds, untraced, sit in `quotearg_buffer_restyled` (8 builds), diff `main` and `diff_2_files`, find `pred_newerXY`, `get_expr` and `do_fprintf`, grep `grepdesc` and `grepdirent`. Owner: r2ssa `values` and `indirect` (D244). In the 3 bzip2 builds (21 functions) the bytes follow a call to `BZ2_bz__AssertH__fail` (`0x5f80`, `afi`: `noreturn: true`), whose callers were compiled without knowing it: 17 ranges of 4 to 81 bytes in `BZ2_decompress`, `BZ2_compressBlock`, `sendMTFValues`, `mainSort` and `BZ2_hbMakeCodeLengths`. Owner: r2engine `reads::padding` (D244).
- The unread lanes and forwarding are S16's (the per-lane supply and the minted call) and S31b's (the register effect replaces the shallow read).
- The cited rows are this slice's (D242). Their measured bound is 1 function alone and 4 more once the image is closed. `Escapes` stays as it is: skipping its refusals alone yields 1 function, and a sound replacement has to escape everything the unheld bytes name.

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
| 9 | S31b | G9, G10; D318 to D321 | the register effect (survey-held, default bound on a cold `pdd`); `CalleeEntry` deleted; `SiteBoundary.written` and `written_before` deleted; the one-call minimum for closed-world decisions | r2engine `fates`, survey; r2ssa `site_boundary` | pumasim `0x3b6b20` profiled first, then the cost gates; the one-call minimum's moves named (built in S31a: the census twins and 13 equivalence records, "S31a as built"); `preserved_call_carriers` deleted only at zero measured yield loss |

S22 (G11, D237 to D240) runs beside these in group A. It was built as a way in of the closed world, not as `SourceLoaderRole`: a declared `void` outranks the closed world, so it would hide a call that reads the result. Under S31b's one-call minimum, the row's call counts as one call that leaves every lane dead, or the 9 `_fini` return to residuals. S16 rebases onto S31a, so the decision has one home before the lattice grows.

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

### S36 as built (2026-11-11)

What the code said that this ADR did not, and the owner chosen:

- The lane set (D305). r2abi `ConventionRow.results: Option<ResultSet>` states the pairs (`follows`), the lanes empty at entry and the citation that states the set complete: SysV x86-64 (psABI 3.2.3, 3.2.1), Microsoft x64 ("Return values") and AAPCS64 (6.9; Apple arm64 inherits it). r2engine `convention_model` builds `ResultLane.entry` (`Empty` where the row says, `Input` where an argument register overlaps, else `Scratch`), `ResultLane.follows` (a position in `results`) and `ConventionModel.results_complete`. A set of more than `RESULT_LANES` (7) distinct lanes is refused by leaving `results_complete` none. `follows` is a position, not yet a `LaneId`: `LaneId` stays r2ssa's until S16 types the lattice.
- The supply walk (D306) is r2ssa `unheld_lane_written`, one live-out walk per lane past copies and merges, run where the open result is `Void` or `Unproven`. It walks every lane outside the typed three whose entry is not `Input` and whose first lane holds something (st0, then st1). An `Input` lane outside the typed three (xmm1, q1 to q3) follows a typed lane, which decides it. It also walks the float lane for a call's bytes only: a forwarder of an unstated call's XMM0 (ldb.clang `p_ldb_forward_b`, `{long, double}` back in RAX and XMM0, RAX popped) was `void`; S16 folds the typed three into the walk. A body write gives `Written`, an unstated call's bytes `Returned`; either makes the result `Unproven`, and keeps the closed world from deciding `Void` over it (the `Void` arm needs no such cause). `known.json`'s cause, "the struct's long double comes back in x87 st0", was wrong for ldb: the struct is `{long, double}`.
- The walk runs only where a `Void` is being decided: the open result is `Void`, or it is `Unproven` and the closed world decides `Void`. On the float lane a call's bytes count only where the callee's recovered carriers include the float lane, or it states none (an import with no cited result, an indirect call): scratch-result case 2 for the rest, until S16's per-lane supply.
- `complete: None` gives `SourceResultCause::LanesUnbounded`, spelled `LanesUnbounded` on the proof line and in `afi`, below `Written` and `EntryInput`.
- The fallback (D307): `convention_call_boundary`'s call, where the callee states no result (`CalleeStatement.result` none, or no statement), states `SourceCallBoundaryFact.unstated_lanes` (every result lane the call kills) and `unstated_carrier`, the carrier the result is spelled in: the callee header's seed (`CalleeStatement.seed`), else the convention's integer lane at its width (D201). A callee whose body proves `void` states every lane, so its extern stays `void`. r2dec spells a call nothing reads at the carrier r2ssa states (`unstated_carrier`, or a stated register's width), and `void` only where r2ssa states `Void`: it chooses no width of its own (PR #366 review). The field is S16's `unstated_lanes`, set here on the fallback and by S16 on minted calls.
- The gate (D308): `void_soundness.py` renders every function of each stripped build and grades each caller's extern of a read function: `void` fails, a refused call counts, and more than a tenth of read functions with no extern row fails. `known.json` is empty and admits no extern. The `--min-premised 1` floor is replaced by a stronger check: every `ignored` producer forwards what a call wrote, so an unread result rendered `void` fails (D202). The 8 premised voids at s10-win64 were the x87 `ignored` producers: each rested on the x87 hole.

Measured, release r2s on the 22 programs built by gcc 13.3 and clang 18.1 (166 builds, Linux, scored on the Mac with `--prebuilt`):

| | base b86f65f97 | s10-win64 505319748 | S36 |
|---|---|---|---|
| Header false voids | 429 | 16 (all x87 `known.json`) | 0 |
| Extern false voids | 1,199 | 799 | 0 |
| Unread results rendered `void` | 0 | 8 | 0 |
| Calls refused (counted) | | 292 | 292 |

- `c_f3_chain_c` (f3.gcc.O1 `0x138f`): extern `void p_f3_chain_c(uint64_t)` at base and head; now `r2sleigh_result_u64 fcn_1379(uint64_t)`, the callee's header. Its XMM1 read stays a residual (`XMM1_QA_1` never assigned).
- `p_cld_forward_re` (cld.clang.O1 `0x1420`, `call rax; fstp st(1); pop rax; ret`): `void` at base and head; now `r2sleigh_result_u64` with an unstated-call cause. The x87 result has no group carrier yet (S16).
- 12 of the 799 extern voids were introduced by #355 (D200): clang `c_cld_chain_*` declared `uint64_t` at base. The other 787 were at base.
- Every function of the 166 builds: 139 headers move. 24 are source values leaving `void`. 115 are source-void consumers whose return leaves XMM0 as an unstated call left it (`c_v2_chain_lo`: `call p; movsd [sink], xmm0; ret`); `double c(){ double v = p(); sink = v; return v; }` has those bytes, so `Unproven` is the sound header.
- `scratch_void.py` over the 35 DecBench builds: `void-open` 272 to 249, `void-closed` 4 to 4; each of the 23 lost voids returns XMM0 as a call no contract states left it (zlib's `test_flush` ends `call deflateEnd@plt; ...; ret`, an import with no cited result: section 4, "Imports with an unstated result"). Each is named `moves` in `known.txt`, and the recorded floors fall to 249 and 253 by name.
- Release cost, Mac `time -l`, median of 3, base `s37-view-lint`: 0pack `pdd @ 0x62ecf0` 15.41 to 15.43 G instructions; pumasim `aa; pdd @ 0x3b6b20` 66.39 to 66.48 G; pumasim `pdd @ 0x23fdf0` 19.91 to 24.45 G, peak 213 to 236 MB. The root's own result moves (`Gui::Gui` is `Unproven`, 5 more residuals), but the rise is a callee prepared twice: see "The cold step, bisected". Restricting the walk to `Void` decisions left 24.45 G because `0x2312c0` is a `Void` decision.
- Certification (radare2 ELF bins, 24 binaries, 8 functions): 50 rendered, 30 refused, 0 invented, 0 undefined reads, the same as `s37-view-lint`. Coverage sweep: 560 of 562 rendered, no regression.
- Census, every `afl` function of the 23 census fixtures: 1 line moves, `code_pointer_table_O0` `_main`'s extern `void _table_dispatch` to `r2sleigh_result_u64`, the callee's own header.


## Amendments

- doc/adr-call-boundary.md, "The callee's boundary": `BoundaryResult` and the six presence rules are replaced by sections 2 and 3. `CallBoundary` holds the decision, and `disputes` with it.
- "S6 as built": "The sketch's `results` is not built". The per-lane supply is built, carries causes, and costs one walk over every lane.
- "S7 as built": "x87 `st0`/`st1` are not held" holds for entry bytes only. A body that writes them leaves `Unproven` supply there, and the decision needs them dead.
- "S7 as built": "Presence is decided by `fates::decide` at seal time, not held". `CallBoundary` decides once and holds it.
- "S7 as built", `CallEffect.takes`: "A byte it may take stays open: not dead, and no evidence that the caller reads the result". A lane handed to a cited fixed parameter is `Read`.
- "The result side as built": "A function nothing calls is `Sites { calls: 0 }`. It is decided only where it hands back an input (void)". A closed-world decision needs one call or more.
- "The result side as built": `SourceResultCarriers::integer_undefined` becomes the integer lane's `None` supply, with `follows` exempting RDX.
- "S7 cost": "`CalleeEntry` still lifts each callee of a caller". S31b's register effect replaces it.
- "S2 as built": "Every producer states `above: Undefined`". S24 adds `Zero` and `Sign` from the body's bytes. `a_staged_call_to_a_carried_callee_is_declared_at_its_carriers_widths` changes premise: a body's implicit zero above a 32-bit write is `Zero`, and callers render the extension. `bits_above_a_declared_narrower_result_are_never_zero` stays: a declaration states `Undefined`. S24 adds `a_body_result_zero_extended_on_every_path_states_zero_above`. D340's two `bits_above_a_call_result_*` tests change callee: `mov eax, edi; ret` states `Zero` above, so their `narrow` leaves RAX unwritten on one return path, which states no fill.
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

## S31a as built (2026-11-11)

What the code said that this ADR did not, and the owner chosen. Rows D314 to D317.

- The decision is held, keyed by the supply the seal hands in. `CallBoundary` is keyed `(CalleeKey, World, Option<Supply>)` and holds `BoundaryResult { lanes, result, premises, disputes }`. `Supply` is the seal's own result shape: declared, return kind, carriers (float, second, `integer_undefined`) and handed-back-only. Section 5 has the decision read `CalleeReads`. That read resolves callees at `Demand::Result`, so a forwarder of a callee's closed-world result (`a_forwarder_of_a_stated_float_result_its_caller_reads_is_never_void`, `a_forwarding_cycle_decides_the_same_whichever_function_is_asked_first`) carries no carrier there, and no default-deny constructor decides it. Reading the closed read instead is the cycle the no-cycle test forbids. So the first seal states the supply and the decision reads only it, `ComponentForwarding`, `EveryWayIn` and `CalleeEntry`. Over the census, 644 seals asked 330 (binary, function, supply) decisions, and no function was decided under two supplies. S16's per-lane supply composes a callee's supply at the call; the decision then reads the open read alone (D317).
- Forwarding is one query per strongly connected component of the forwarder graph. `DirectSites(f)` joins the calls to `f` and keeps each lane a call returns into its caller. `ComponentForwarding(f)` runs Tarjan's search over those edges (`resolved::Search`, now generic), solves each component on `r2ssa::fixpoint::sparse` (an inflationary join, height `LANES × 134`), and deposits every member. An edge inside a component that reaches no read there is `Cycle`, never dead. `EveryWayIn(f)` is held per function: a dead forwarder is in a later component, so the question ends without a memo. `fates::every_way_in`, its memo and the `Hold::Transient` cut are deleted.
- The edge prune reads the direct calls only: a returned lane is forwarded unless a direct call reads it, or past the typed three while a held lane is already open. The old prune read lanes the same loop was joining, which made the answer depend on caller order.
- Deleted: `fates::decide`, `fates::disputes` and their per-seal call in `View::closed_result`; the guarded `closed` arms of `recover_interface`, now one application of the stated decision; r2types' written-cause choice, now `SourceFunctionInterface::written_cause` beside the facts it reads. `SourceClosedResult` stays the type the seal reads.
- S36's guard stays in the seal: its walk of the lanes outside the typed three runs only where a `Void` is being decided, so the first seal's supply does not carry it, and a decided `Void` yields to a lane that walk finds written (`a_written_x87_result_is_never_void_cold_or_under_the_closed_world`). S16's supply walk over every lane moves it into the supply.
- The one-call minimum, assigned to S31b by the slice table, is built here: a closed-world `Void` needs one call or more, and a loader call a cited row states reads nothing (S22, r2abi `loader_call`) is one, so the 9 census `_fini` stay `void`. A written result's `Unread` moves no C, so only the program's own calls decide it, as S7's cost rule had it. `an_entry_input_lane_nothing_calls_keeps_its_open_result` replaces the void test of a function nothing enters.
- The no-cycle test: `Db` names the query each frame runs, and `Db::defect` counts a forbidden dependency. `Resolved` at `Demand::Arity` under a `call-boundary` frame, or one function's boundary inside another's, is a defect. `a_call_boundary_reaches_no_closed_seal` asserts 0 over five fixtures, and `mutants_s31a.py`'s `a-boundary-reads-a-closed-seal` shows it red.
- Closed-world coverage of loader writes is positive. `References::read_words` takes a stated word, and a `Resolver` write names its resolver, which escapes. An `Unknown` write, or a non-word write whose target is code, is recorded in `Coverage::unstated`, and `Escapes` refuses on it. r2image states two kinds the deny list skipped: `WriteKind::Reserved` for the loader's GOT words (x86-64 psABI 5.2, AAELF64; MIPS's whole table stays `Unknown`), and `WriteKind::Copy` for `R_*_COPY`, whose bytes name this image only through exported definitions.
- Measured cost of the refusal: every dynamic census binary held one 16-byte `Unknown` (the reserved GOT words), and 33 of the 35 DecBench builds held `R_X86_64_COPY` writes besides. With `Reserved` and `Copy` stated, the refusal costs 0 of the 23 census binaries and 0 of the 35 DecBench builds.
- The one way in the ADR lists that no fixture can isolate, a call count one short, is tested on its predicate (`every_call_read`).

Gates, parent S17 (`d4a8999e3`; tests, census, structure and mutants again on the restacked `c27790b8a`), Mac (contabo was held by another session's job):

- Tests: 2,191 pass in the touched crates (r2abi, r2image, r2source, r2ssa, r2types, r2engine, r2dec); clippy `-D warnings` clean over the workspace; Dylint 8, the baseline; `excessive_nesting` 445 to 444 (the direct join's loop moved into a function of its own), `long_comments` 2,485 to 2,484.
- Census: 444 goldens, 4 move, all the one-call minimum: `_dl_relocate_static_pie` in `branchy_gcc_x64_O0`, `hashes_gcc_x64_O2` and `shapes_gcc_x64_O0`, and `fcn_401270` in `hashes_gcc_x64_O2_stripped`, from `void` with the closed-world premise to `r2sleigh_result_u64` with `unproven (EntryInput)`. Nothing calls them, so no fact decides their result; glibc declares them `void`, which only a declaration states. The coverage sweep's three pinned `_dl_relocate_static_pie` go from 0 to 2 gapped obligations (the residual return), and the three `_fini`, `void` since S22, from 2 to 0; `coverage-baseline.json` records both.
- Equivalence: 13 records leave `equal` for `residual-trap`, every one a function nothing in the program calls (the harness reaches it by address; traced `0 calls` on `total_add` and `and_chain_effect` gcc-O1): x86-64 `and_chain_effect` gcc-O1/O2 and `total_add` clang-O1/O2 and gcc-O1/O2; aarch64 `and_chain_effect` gcc-O1/O2 and `total_add` clang-O0/O1/O2 and gcc-O1/O2. D213 made them `void` from no call at all, which section 3 rejects; they return to the residual they had at #355, owner P7 (the result proof; the ratchet takes ROADMAP items, not rows). No other record moves on either target. Source-gold (`void_soundness` 0 false voids in headers and externs, `scratch_void`), certification, the radare2 differential and CI's timing gate pass.
- Mutants: `mutants_s31a.py` 15 of 15 killed (the 13 ways in, the closed-seal read, a decided void over a written lane); `mutants_d213.py` 20 of 20, its decision mutants retargeted at the held decision, `nothing-called-is-never-decided` inverted to the one-call minimum and `a-loader-call-is-no-call` added. Below 4 GiB a 4-byte window holds every 8-byte word's entry, so the 8-byte way in is tested on an image above it (`a_pointer_wide_word_above_four_gib_names_its_function`).
- Cost: release, median of three, instructions retired on the Mac, parent S17 `d4a8999e3` against this slice; every output byte-identical: bash `0x2e630` `aa; pdd` 14.357 to 14.347 G (D153 bound 15.43 G); pumasim `0x3b6b20` `aa; pdd` 66.357 to 66.356 G (head bound 66.40 G); pumasim `0x23fdf0` `pdd` 24.375 to 24.385 G; 0pack `0x62ecf0` `pdd` 15.37 to 15.38 G. Peak footprint: bash 65.1 MB both, pumasim `aa` 205.4 to 204.5 MB, 0pack 220.3 to 224.3 MB (+1.8%); pumasim cold spreads 215 to 238 MB run to run on both sides. A cold `pdd` asks no `CallBoundary`, so the held decision moves nothing there: `outside_resolved`'s second preparation of a function whose result owner now states a result is a supply change, which S16 measures (D226). The bound per cold `pdd` is two preparations of each function the `Demand::Result` closure reaches (`CalleeReads`, then `outside_resolved` where an owner outside its component states a result), plus a cycle's fixpoint rounds.

## S18 as built (2026-11-11)

What the measurement said that the slice's plan did not, and the owner chosen. Rows D241 to D244.

- The plan named uncited rows as the cap. The split (section 4, "What caps the closed world's yield") says otherwise: of the 73 undecided class C functions, an unknown way in touches 71, an unread lane 45, an uncited row 41 and forwarding 39, and no cause holds more than 5 alone. Citing every row has a measured bound of 1 function at the parent S31a `c183bdf75`. The rows are built because they are this slice's and r2abi's, and their yield is that 1.
- The 4 `void-closed` the plan counted are not class C. They are `mbiter_multi_reloc` and `mbuiter_multi_reloc` in cmp and sdiff (O2-noinline), which no call reaches. S31a's one-call minimum moves them to `Unproven`, so the parent's count is 0 of 102.
- `Escapes` is not changed. Skipping its image refusals yields 1 function at the parent (bzip2 `uInt64_toAscii`). At `19ff0d899` it yielded 5, and 4 of those were diff's `set_color_palette` and `finish_output`, called only from `main`'s unwalked case blocks: the refusal was right. The two causes of `code no body holds` go to their owners as D244.
- The rows (D242). 398 rows of `types.sdb.txt` and 20 of `types-linux.sdb.txt` move to `types-posix.sdb.txt` and `types-glibc.sdb.txt`. Each is respelled from the declaration glibc 2.39's header gives under the mode its source names: 351 under `-std=c17` (ISO C17), 54 with `_POSIX_C_SOURCE=200809L`, 4 with `_XOPEN_SOURCE=700`, 9 with `_GNU_SOURCE`. A row keeps its scope: `a_scope_states_each_name_once` holds, so a glibc row that ISO C or POSIX states (`_Exit`, `waitpid`, `sigaction`) stays glibc's where libSystem's or bionic's table has its own.
- The respelling changed 91 of the 418 prototypes radare2 stated (`long int` read as `long`). On each of glibc, bionic and libSystem 56 rows gain a sized type (`arithmetic`, `floating_point` and `func` were radare2's spellings). 5 change a width on glibc and bionic (`readlink` returns `ssize_t`, `strndup` takes `size_t`, `random` returns `long`, `wcstoimax`, `wcstoumax`) and 8 on libSystem, where `chmod`, `fchmod` and `umask` take its 16-bit `mode_t`. `fwscanf` and `swscanf` state their format, and `quick_exit` is noreturn. No row loses a size on any of the three.
- 123 rows stay radare2's, each named with its reason in `data/uncited-rows.txt`, which a test lets only fall. 62 no glibc header declares (BSD, Darwin, Swift, gnulib, the `<math.h>` macros). 22 glibc declares only under `_GNU_SOURCE` while every library reads the portable table (`dcgettext`, 287 sites in the class C callers, `getopt_long`, `bzero`). 7 take or return a record or an array typedef by value. 5 take a function pointer the row reader does not spell (`qsort`, `bsearch`, `signal`, `atexit`, `at_quick_exit`). `basename` has two declarations.
- 26 of the 123 were moved and taken back after the census over the 35 DecBench builds (420 functions moved, residuals up in 19 builds, find 1,199 to 1,266). `open`, `open64`, `openat` and `prctl` are variadic with no format, and r2dec renders a `Tail::Variadic` call as `CallNotRendered` (`missing_format_parameter`): 52 `open` and 11 `openat` sites, and the wrappers that forward to them. 22 rows name a record through a pointer that radare2 spelled otherwise: `void *` (`stat`, `fstat`, `lstat`, `sigprocmask`, `utimes`), a bare tag (`localtime`'s `tm *`) or no `const` (`bind`), and a prototype naming one renders every parameter `uint64_t` (D151): 31 `stat`, 28 `fstat` and 10 `lstat` declarations. Their citations are right and their renderers are not ready, so they wait on those owners.
- `scripts/audit_abi_rows.py --cc gcc`, which CI runs, compiles each cited row of the two tables that names a header against it: `__builtin_types_compatible_p(__typeof__(name), row)` under a mode the row's comment names, after the headers the standard's synopsis lists first (`<stdio.h>` for a `FILE` in `<wchar.h>`) and through the public wrapper of a glibc fortify header. A row citing GCC's `builtins.def` (`__sprintf_chk`) names no header that declares it and is not compiled. The moved rows stay under the script's return check too.
- A second witness for the portable move: Apple clang with libSystem's headers, under the same modes, declares 503 of the 506 compiled portable rows as spelled. The 3: `setstate` takes `const char *` there, and `mkdtemp` and `nl_langinfo_l` sit behind other macros.
- D151's rows, from the same probe on the glibc 2.39 host: `__overflow` and `__uflow` (`<stdio.h>`), `wcwidth`, `__ctype_get_mb_cur_max`, `dup2`, `fchdir`, `fdatasync`, `fork`, `fsync`, `sysconf` and `getpagesize` are glibc rows, since bionic's table states its own; `getchar_unlocked`, `putchar_unlocked`, `endgrent` and `endpwent` are portable. The 7 fortified string builtins leave radare2's table with `__stpcpy_chk` and `__mempcpy_chk` added, cited to GCC's `builtins.def`; GCC 13's `__builtin___*_chk` types agree with all 9. `re_compile_pattern`, `re_search`, `re_match`, `re_set_syntax` and `gnu_dev_makedev` still have no row: they take a record pointer or a type r2abi does not size.
- `mode_t` (D243). `Width::KernelMode` reads `CDataModel::kernel_mode_bits`: 16 on i386 and 32-bit Arm, 32 on x86-64, AArch64 and RV64 (Linux `asm-generic/posix_types.h` and the two overrides; bionic `sys/types.h` types `mode_t` as `__kernel_mode_t`). bionic's `mknod`, `mknodat`, `mkdirat`, `fchmodat` and `__umask_chk` place their mode.
- The bionic guard rows (D243). `guard_row` states bionic's x86 canary slot, `%fs:0x28` and `%gs:0x14`, from bionic's `tls_defines.h` (`TLS_SLOT_STACK_GUARD 5`) and LLVM's `getIRStackGuard` (Android from API 17). bionic's `__stack_chk_fail` moves from radare2's `types-android.sdb.txt` to the cited table, from `private/bionic_ssp.h` and its definition's one call to `async_safe_fatal`.

Gates, measured against S31a `c183bdf75` on the Mac with release r2s; the branch was then rebased onto S20 (`ccacf5df3`, restacked as `626fcb388`), where the touched crates' tests and the class C grade were run again:

| | parent | S18 |
|---|---|---|
| `void-closed`, 102 class C source voids | 0 | 1 (sdiff `checksigs`) |
| `scratch_void.py`, 35 builds: `void-closed` source void, source value | 0, 0 | 1, 0 |
| `scratch_void.py`: `void-open` source void, source value | 247, 2 | 247, 2 |
| `scratch_void.py`: `VOID LOST` against the recorded baseline | 25 | the same 25 |
| `void_soundness.py`, 166 builds: header false voids, extern false voids | 0, 0 of 2,166 | 0, 0 of 2,166 |
| Census, 444 goldens | | 0 move |
| Census, every function of the 35 DecBench builds | | 152 functions move, residuals 7 fewer, refusals unmoved |
| Release `pdd`, instructions retired, median of 3: pumasim `0x23fdf0`, 0pack `0x62ecf0` | 24.403 G, 15.403 G | 24.412 G, 15.408 G, output identical |

- On the PR's parent S20 `626fcb388` and this head: `void_soundness.py` exits 0 (0 headers, 0 of 2,166 externs); `scratch_void.py` counts `void-open` 249 source void and 2 source value on both, `void-closed` 0 and 1 (0 source value), no lost void, and exits 1 on both on the closed floor alone (249 and 250 under the 253 the baseline records).
- With D151's rows on S20: the DecBench census moves 362 functions against the head without them, residuals 8,919 to 7,728, refusals 87 unmoved. 74 `__ctype_get_mb_cur_max`, 43 `__overflow`, 32 `fchdir`, 20 `getpagesize`, 16 `wcwidth`, 9 `sysconf` and 7 `fork` calls render where the import had no declaration, and the callers' results follow. `void-open` rises 249 to 254 source void with 2 source value unmoved, `void-closed` stays 1 and 0, `void_soundness.py` exits 0, and `scratch_void.py` exits 0 (255 over the closed floor 253). The glibc 2.39 host compiles all 574 cited rows of the tree before these rows with 0 errors.
- The 5 new open-world voids are diff's `pr_context_hunk`, `pr_forward_ed_hunk`, `pr_unidiff_hunk`, `print_ed_hunk` and `print_normal_hunk` (O2), all source void. `print_normal_hunk` (`0xcd00`) read by hand: its 4 `__overflow` calls render, no residual is left, and its returns follow the canary check, whose residue is undefined (scratch-result case 3).
- bionic, `ls-toybox` (AArch64), parent against head: 48 functions move, residuals 3,831 to 3,779, refusals 22 unmoved; `mknod`, `mkdir`, `chmod`, `fchmod` and `__umask_chk` calls render their mode where the parent left `CallNotRendered`.
- Not run: `mutants_d203.py` with its `void-row` mutant retargeted at `types-posix.sdb.txt`. It needs the Linux source-gold corpus; `test_scratch_void.py` shows only that the edit applies once.
- The first glibc 2.39 run of the prototype check (CI, GCC 13) passed 547 of 574 cited rows. The 27 failures were the probe's: a missing synopsis header, a fortify header included directly, 4 XSI rows probed under POSIX, 5 asm-redirected names. No prototype was wrong.
- `scratch_void.py` exits 1 at S31a and on the S31a-based head on the same lines: 25 lost voids and the floors (open 247 under 272). They moved between s10-win64 `505319748` and S36 `19ff0d899` (bzip2 -O0 `BZ2_blockSort` is `void` at the first and `Unproven(Written)` at the second), and `decbench_baseline.json` and `known.txt` were not updated there. This slice does not rebless them.
- The 152 moved DecBench functions, each kind read: `memchr` takes `const void *` (ISO C17 7.24.5.1; 32 declarations), `write` takes `const void *` (22) and a record field read through it follows, `mmap`'s offset is signed `off_t` (12), `fchmod` takes unsigned `mode_t` (5), `strtoull` returns `unsigned long long`, `readlink` takes `size_t` and returns `ssize_t`, `strndup` takes `size_t`, and gzip's 2 `modf` calls render where radare2's `floating_point` row stated no prototype. sdiff `checksigs` (`0x4b20`) is `void` and its `return r2sleigh_residual_u64(1)` is `return;`: the import calls after its 4 call sites state fixed prototypes, so three result lanes go from unknown to dead.
- The moved causes on the 35 builds: `Unproven(Written)` 985 to 978 source void, `Unread` 5 to 12, `EntryInput` 137 to 136. A cited fixed prototype stops a call reading lanes past it, so a closed-world read reaches further before it stops. No source value becomes `void`.

## S25 as built (2026-11-11)

What the build found that the plan did not, and the owner chosen. Rows D214, D225, D326 to D329, D282 to D284.

- Finding 11 (D326). `SourceCallBoundaryFact::arguments_complete` states that each listed argument reaches the call, and the certificate reads it to show the registers a caller wrote. It bounds no arity. The arity verdict is `arguments_proven`, read through `may_read_unlisted`: `handed_to`, `unproven_calls_reached`, `read_only_by`'s `CallUse` arm and the formal dependence read it. The two fields differ at one constructor (`adopt_convention` with no callee statement), so neither is deleted.
- The circular proof it ends. Under `aa` a body is recovered again with its own last interface in the context, so `own_parameter` was false for a slot the last round left unread, the count at an indirect call ended there, and the slot stayed unread. A cold `pdd` already minted the floor. Both now mint `HandedOn(Indirect)`.
- Finding 2 (D327). `DeadPhis::unobserved_values` cannot answer during recovery. The obligation inventory holds every definition that reaches a return whose interface is unproven as unsupported (`taint_incomplete_boundary_inputs`), and recovery runs before that interface exists: `xor edx, edx` and gcc -O0's dead home copy were both held by it. The inventory now states `unmodelled()`, the instructions unsupported for a reason of their own. `ProvenProgramObservations::proven_unread` is: no observation depends on the value, and it is outside the closure of the unmodelled instructions' inputs. Cost: one more `O(V + E)` closure, only in a body that holds an unmodelled instruction.
- Finding 3 (D328). `FrameReach::escaped_incoming` states the entry offsets at or above the entry stack pointer that escaped addresses point at, or that one is unplaced. A value the frame places is classified by its own offset; only an unplaced value inherits from its inputs. Recovery counts an offset where it is an argument's place: a stack argument, or a home that holds its position's entry register. MSVC keeps locals and shuffled copies in the home area, and such a home is the body's slot: counting every offset at or above the entry pointer floored 128 of 1,009 recoveries on hello_gs, and the argument-place rule floors 6 functions. The cause is `ArgumentAreaEscapes`; a proven variadic tail is exempt, since its cursor is that escape.
- Finding 8 (D329). `ArgumentArea::unknown` carries three cases to the floor cause `ArgumentAreaRead`, whatever the register sections hold: a read crossing two slots, a read whose address the frame places only up to an index (`indexed_stack_address_root_of`), and a read that may be of the area whose value is neither observed nor proven unread. A read with incomplete provenance asks the memory annotations whether any names the area.
- `CallReads` (D282). One type, three constructors by callee statement: `exact` (a complete, fixed interface: its registers, the reserved stack and each stack slot), `placed` (a library row, built by r2engine `Placement::reads`) and `every_location` (the default). It replaces r2engine `ImportReads` and `FormatTail`, r2ssa `unknown_call_takes` and `argument_takes`, and `SourceMachineContext::call_argument_area`. `CallEffect.takes`, slot promotion's `CallArguments` and `FrameReach`'s call areas read it. `handed_to`, `unproven_calls_reached` and `read_only_by`'s `CallUse` arm read the boundary's verdict of the same statement (`may_read_unlisted`), which adds whether each stated argument reaches the call.
- Not moved onto `CallReads` (D283): `uncertified_call_reads` and the boundary's own argument list. The first is what the rendered text performs at a call, keyed by value class, since copy forwarding renames a `CallUse` input. Moving it needs `CallUse` to name each input's register.
- Frame escape keeps three walks (D284). Slot promotion and the canary decision run in `function/build.rs` on `SSAFunction` operations, before the graph, the prep facts and the object model exist. `FrameReach` runs on those. Promotion's walk also depends on which places it promotes. One owner needs a walk at the build stage that states escaped entry offsets, which `FrameReach` maps to objects.
- The cycle's world. D326 gives a function whose untouched register reaches a call of unproven arity a floor that a member of its component owns, so `least_fixpoint` settles it. `Cycle::resolve` read members in the open world while `closed_alone` and `outside_resolved` seal in the closed one: 36 callers of hello_gs `fcn_140006150` declared `r2sleigh_result_u64` beside its `uint64_t` header. It reads in `world_of(demand)` now, one read per member. A closed read asks `CallBoundary`, which reads `CalleeReads` and never `Resolved` at `Demand::Arity`, so no query cycle forms; S31a's no-cycle test holds.
- D225, taken here because S25 makes more floors. A floor callee mints no call-site interface, so r2types applied no callee signature and r2dec spelled the extern from the call's classes. `apply_callsite_callee_signatures` applies the header projection where the site has no interface and the callee's arity is a floor; r2dec spells it through `Prototype::of_projection` and decides nothing. hello_gs mismatching extern result lines: 26 at the parent, 19 here.
- D214. r2ssa `edge_fold` folds a block's branch and select conditions under each in-edge (this block's merges take that edge's arm; the in-edge's own branch states its condition; 64 operations per condition and edge; anything else is unknown and the arm stays read). `bytes::closure_under` and the inventory's liveness walk carry the in-edges a value is read under, so `DeadPhis::unobserved_uses` holds an arm no path reads and r2dec binds and copies nothing on it. clang 18.1 -O1 `table_walk` renders two parameters and no entry-ECX read; `main` passes two arguments. The gate is met up to D227: equivalence `manual_limits.c::clang-O1::main` leaves `never-assigned` and still traps at its return, an unproven two-register result (`unproven-return`), blessed with that cause.
- Cost. Release, instructions retired, median of 3, against master `ca413c45c`: bash `aa; pdd @ 0x2e630` 14.418 G to 14.416 G, pumasim `aa; pdd @ 0x3b6b20` 64.473 G to 64.497 G (+0.04%). Cold `pdd` is over the 0.3% gate: 0pack `0x62ecf0` 15.455 G to 15.523 G (+0.44%), pumasim `0x23fdf0` 23.953 G to 24.082 G (+0.54%). A release bisect puts all of it on D214: the commits before it measure 15.449 G and 23.944 G. D214 first cost +0.89% and +1.58%, since every byte closure, the liveness walk and r2dec's merge copies carried per-edge sets. `edge_fold::narrows` folds each block once per inventory, and where no fold drops an in-edge the walks are the plain ones and `DeadPhis::arm_read` asks nothing. With the fold check forced off pumasim measures 24.059 G, so the fold is 23 M of the 129 M left; the rest is D214's dead-arm bookkeeping, not attributed (D344).
- A saved tail register handed to a call stays a tail (`TAIL_KEPT`): a variadic header drops no argument, so `read_only_by` denies there only for a home.

## S16b as measured (2026-11-11)

D226 asked for one preparation per function on a cold `pdd`, output byte-identical to S16. Measured on S39 `39ff8eda9` (S16's code), release, Mac. No code is kept.

- Cold pumasim `pdd @ 0x23fdf0` is 24.71 G and 1.39 s. It makes 145 preparations: 107 alone (0.54 s) and 38 second ones (0.28 s, 4.9 G). `0x2312c0` is 0.20 s alone and 0.19 s again (3.4 G each).
- The gate is 20.02 G. Removing all 38 second preparations gives about 19.8 G. That leaves 0.2 G for finding the owners, so `0x2312c0` must be built once and nearly every other second preparation must go.
- One preparation of the 146 splits into `construct` 0.74 s (65%), `SSAFunction::seal` 0.08 s (7%) and `collect` 0.31 s (27%). `construct` is one SSA build that recovery reads and the seal keeps. The callees' statements enter that build (`CalleeBoundaries`, `correlate_call_site_interfaces`), so no part of it is shared between the alone and the stated preparation.
- The owners are a fact of the alone build. `result_calls` reads the live-out values of the SSA, after `recover_interface` decides whether the result is unproven (`returned_result`, `direct_return_result`, `written_bytes`, `defines_nothing`). A probe that stops after recovery still pays 65% per function: about 23 G.
- A re-seal inside one `resolve` (the closed world's `seal_first` pattern) saves the first `collect`: about 1.3 G, to 23.4 G. It needs the owner graph before any seal is dropped, so Tarjan's search would hold seals. Not built.
- A raw backward walk was run in shadow beside the alone read: the last writer of the integer and float lanes at each return, direct tail targets, none where a call is indirect. It costs 1.9 ms over 107 bodies (0.03 G). Two cuts were run on pumasim, neither kept.
  - Cut 1 (one definition per return, tail blocks walked): 19 of 107 functions differ. Cut 2 (every reaching definition, returns only): 17 of 107, and 5 of 23 on 0pack `0x62ecf0`.
  - 12 functions miss their owners in both cuts, `0x2312c0` among them. All 12 dump the same shape: the integer lane's last write is the body's own, and the float lane holds a callee's bytes. Read on `0x35ae60`, that write is the stack protector's `xor rax, fs:[0x28]`. `lanes` records it as `Fill::Undefined` where `stack_protector::decide` decided the check, so the integer lane holds nothing and the callee owns the result.
  - `stack_protector::decide` proves the check on the SSA function: frame definitions, a slot stored once, both guard reads, under `Premise::UbFreeSource`. A copy of it on lifted blocks is a second owner of that proof, and a weaker pattern names an owner where the proof refuses.
  - The other differences moved with the cut: 7 in cut 1 (6 from walking tail blocks), 5 in cut 2 (4 from taking a merged definition, which the alone read states as a register). The two cuts were not combined, so the count with the 12 set aside is not measured.
- Stating a different owner set is sound and moves statements: a missed owner leaves `0x35ae60` `Unproven` where S16 resolves it `Void`.
- S16 against S18 `5fa7c9dc3`, one run each (medians of 3 are in "The cold step, bisected"): cold pumasim 24.46 to 24.71 G, 0pack `0x62ecf0` 15.47 to 15.66 G, bash `aa; pdd @ 0x2e630` 14.38 to 14.40 G, pumasim `aa; pdd @ 0x3b6b20` 66.38 to 66.79 G. Under `aa` the alone read is the `CallBoundary` supply (D317) and names the arity owners, so one preparation does not apply there.

The bound stays two preparations per function the `Demand::Result` closure reaches, plus a cycle's rounds.

## The cold step, bisected (2026-11-12)

Every PR head from #360 to #372 was built in release and measured on the Mac (`/usr/bin/time -l`, instructions retired, median of 3, one `heavy.sh` lock).

| PR | Head | pumasim `pdd @ 0x23fdf0` | 0pack `pdd @ 0x62ecf0` | bash `aa; pdd @ 0x2e630` | pumasim `aa; pdd @ 0x3b6b20` |
|---|---|---|---|---|---|
| #360 s10-win64 | f26030869 | 19.95 | 15.47 | 14.31 | 66.46 |
| #365 s37-view-lint | 33222faf2 | 19.91 | 15.38 | 14.34 | 66.40 |
| #366 s36-false-voids | ec94ec1bf | 24.46 | 15.43 | 14.34 | 66.46 |
| #370 s18-cited-rows | 5fa7c9dc3 | 24.45 | 15.49 | 14.38 | 66.42 |
| #371 s16-result-pass | 64d75c27d | 24.67 | 15.68 | 14.44 | 66.88 |
| #373 master | ca413c45c | 23.94 | 15.44 | 14.42 | 64.46 |

- The step is #366, and f57e1cb57 is its one commit that touches a crate. #361 to #365 and #367 to #370 each move pumasim cold by under 0.04 G.
- Mechanism, read from `R2DEC_TRACE_REFUSAL=1` evidence at #365 and #366. `0x2312c0` (`Gui::languageChange`, 810 blocks, 17,867 bytes) calls `0x3f0010` (`QStringData::deleteSelf`) at `0x235866`, then runs `mov rax, [rsp+8]; xor rax, fs:[0x28]` at `0x23586b` and returns. Its integer lane holds the stack protector's residue, and XMM0 at its return holds what that call left. At #365 its alone read is `Void`. At #366 the float-lane walk of `unheld_lane_written` makes it `Unproven` with cause `Returned(Direct(0x3f0010))`. `outside_resolved` resolves `0x3f0010` (`Void`) and prepares `0x2312c0` again: 1 SSA build to 2. The call to `0x3534e0` (`QTabWidget::changeTab`, header `r2sleigh_result_u64`) stays unstated in that second build; `0x3534e0` is first prepared at #371, where S16 names it an owner too. `0x2312c0`'s own header is `void` at #365, #366 and master, and the root's extern of it is `uint64_t _ZN3Gui14languageChangeEv(uint64_t)` at every head.
- Counts on pumasim cold, #365 to #366: interface recoveries 124 to 135, SSA builds 133 to 144, functions prepared 93 to 101 (8 new owners). Built twice goes 37 to 40: `0x2312c0`, `0x2f2cc0`, `0x30f950` and `0x335830` go from once to twice, the new `0x230db0` and `0x35ae60` are built twice, and `0x333bf0`, `0x333d70` and `0x376450` are built once where they were built twice. 0pack `0x62ecf0` builds 19 functions 20 times at both heads.
- With the float-lane walk skipped, #366 measures 19.99 G (4.47 G lower) and builds 133 times, as #365 does. Its output moves 420 lines against #366: `Gui::Gui` is `void` again. That is a `void` S36 cannot prove (its last call is to an import that states no result), so the walk stays. The 4.47 G is not split per function at #366; S16b's split at S39, with two owners stated, puts `0x2312c0`'s second preparation at 3.4 G.
- S16's own deltas, #370 to #371. 0pack cold +0.19 G: 19 functions and 20 builds become 24 and 28 (5 new owners; `0x48901c`, `0x49274a` and `0x5f8060` built twice), and `outside_resolved` rises from 0.8% to 1.8% of samples. pumasim `aa; pdd` +0.46 G: the build count is 1,739 against 1,740, so the cost is per preparation; `r2ssa::rename::append_call_boundary_defs` rises from 129 to 173 of 8,068 samples (probably the per-lane call definitions, 0.5% of the run). Sampling noise on the loaded machine is 2%, so that attribution is not exact.
- Profile of pumasim cold at #371 (samply, 5,034 samples): `outside_resolved` is 16.4% inclusive, about 4.0 G (S16b's timed split gives 4.9 G). Inside it the SSA build (`from_blocks_for_decompile_with_interface_and_control`) is 33%, the final `collected` 21%. Recovery's own fact collection (`collect_with_context` under `recover_interface_inner`) is 19% of the whole run.

What was tried against the 2% gate (20.32 G), and why none lands:

- An ordering hint from a raw backward walk, with today's second preparation kept where the SSA disagrees. It needs an accept check that yields the alone read's owners from the build against the predicted owners. `construct` hands each stated owner's interface and preserved carriers to `CalleeBoundaries`, which the SSA build reads, so that build is a different SSA and cannot state them. Without the check a wrong prediction moves output.
- The hint's yield, scored on S16b's log at S39 for the shape S36 made: 10 of the 38 second preparations are predicted (258 ms of 299 ms), and 12 functions are predicted an owner the alone read does not name (145 ms of wasted preparation, `0x23da20` alone 95 ms), before the extra owners those predictions resolve.
- Reusing the alone SSA build for the second preparation saves at most its 33%: about 1.3 G, to 23.4 G. Skipping the first `collect` saves about 1.3 G ("S16b as measured"). Both together miss the gate.
- The register effect of section 5 does not decide it cold: an inner callee with no held effect overwrites nothing known, and `0x2312c0`'s other owner at S16, `0x3534e0`, makes calls.

Master is lower than #371 through S38's fixed hasher alone; its output on the four commands is byte-identical to #371's and `0x2312c0` is still built twice.

So the second preparation is the cost of a default-deny `void` on the float lane: `0x2312c0` is `void` at #366 only because `0x3f0010` states `Void`. No code changes here, and D226's gate stands failing.

## S24 as built (2026-11-12)

What the code said that this ADR did not, and the owner chosen. Rows D322 to D325.

- `above` (G1). r2ssa `lanes::above` reads each return path's bytes above the joined width: `Zero` or `Sign` where every byte above is that fill alone on every path, else `Undefined`. `recovered_result_over` collects the paths beside `signed`. A path that leaves no defined byte, a returned value narrower than the slot, a stated extension (`Widened`) and a joined fill state nothing. O(paths × bytes), inside the walk that already reads them.
- The fact travels in the contract: `SourceFunctionInterface::result_above` (set by recovery alone, so a declaration stays `Undefined`), read by `result_width()`, which the three call-site copiers already use, and `SourceResultSeed::above` for an unproven result's carrier. A tail keeps its callee's fill only where every direct return states the same one.
- A cycle's seed is its optimistic start: `seed_result` skips the cyclic calls without lowering the fill, and `resolved::join` lowers it to `Undefined` where a read disagrees. Lowering it at the skip made a member's read (`Zero`) differ from its assumption for ever (`under_aa_a_member_stating_its_result_keeps_it_while_its_arity_is_open`).
- The write width of `mov r32, imm32` (D74). The loss is no fold of ours: Ghidra's `ia.sinc` writes B8+r as `CRmr32 = imm32`, and `CRmr32` exports the 64-bit register, so the lift's first operation was `RAX = COPY imm:8`. The vendored text now reads `Rmr32 = imm32; build check_Rmr32_dest`, the text of its `C7 /0` sibling (`vendor/README.md`; Ghidra master still has `CRmr32`, and the two leave one machine state). `lanes` then records four data bytes and the convention's zero fill. No rule reads a constant's magnitude: `movabs rax, 5` stays eight bytes.
- The silent `void` (D74). pigz `0x4044b0` is gcc's `alloc.part.11`: `xor edx, edx; lea rsi, "not enough memory"; mov edi, 12; xor eax, eax; call try_throw_`, with no return path. `returned_result` made a body closed by calls that never come back `Void`, the one `Void` no constructor of section 3 proves. The contract keeps `Void` as what a call to it leaves, since `Unproven` there mints no call contract and its seven callers lose the call. `SourceFunctionInterface::no_return_reached` states the rest: r2types projects the header and the callers' extern as the carrier word with the cause "no return reached".
- G19 is refused. gcc merges the scrub with a C zero. gcc 13.3 `-O2 -fstack-protector-all` compiles `unsigned n8(const unsigned char *s) { unsigned r = 0; volatile char b[8]; b[0] = 1; if (*s) r = s[1]; return r; }` to one `xor eax, eax` after the guard store, checks in RDX, and returns that zero on the path that skips the load. In `n1` (`for (i = 0; i < 64; i++) b[i] = s[i];`, `-O1`) the scrub is the loop's index (`movzx edx, [rdi + rax]`), and in `g` (`printf("%d\n", x)` after the prologue, `-O2`) it is the vector count in AL before `call __printf_chk`. An `Undefined` scrub would make the returned zero a residual. scratch.rs `a_guard_scrub_a_return_reads_is_the_returned_zero` holds the bytes.
- Groups: the decision is built, the carrier typedef is not (D325). r2ssa states `SourceResultCarriers::float_second`, the lane the cited `follows` row puts after the float one (`site_boundary::ResultLanes::after_float`, read by recovery and by the callers' join), where `lane_supply` finds a written byte at a return. r2engine `BoundaryResult::decided` decides no lane where the float lane and that lane are both read: the result stays `Unproven`, and each lane spells a residual (Decided 1's default). The direct join (`forwarded_lanes`) forwards the lane after the float one where a call reads or returns the float lane; its shortcut joined every lane past the typed three `Unknown` once another lane was open, which hid the read of XMM1 behind `p_f3_chain_c`. A lane it does not forward is still joined `Unknown`, never dead. Forwarding every lane past the typed three cost 0.39 G on bash `aa; pdd @ 0x2e630` (14.479 to 14.867 G): each kept lane is an edge of the forwarder graph, so `ComponentForwarding` solves more callers. `float_second` is the lane's dense id, so r2engine reads no convention view for it.
- The compile test for the carrier, Apple clang 21.0.0, `struct { double xmm0; double xmm1; }` returned by value at `-O1`: `-target x86_64-linux-gnu` returns it in XMM0 and XMM1, `-target aarch64-linux-gnu` in d0 and d1, `-target x86_64-pc-windows-msvc` through RCX in memory. AArch64 returns `struct f3 { float a, b, c; }` in s0, s1 and s2, three lanes at four bytes, a different shape. The rule reads one follower: an HFA's q2 and q3 are not in `float_second`, so a caller that reads q0 and q2 alone still decides q0. Spelling the typedef needs a result kind r2dec returns and reads by member; `Pair` is one integer across two registers and compares whole storages. It is D325's open part.

Gates, parent master `ca413c45c`, Mac release:

- Tests: 2,746 pass in the touched crates (r2abi, r2source, r2ssa, r2types, r2engine, r2dec, r2s with the goldens) and 195 in r2sleigh-lift; clippy `-D warnings` clean over the workspace; Dylint 8, the baseline; `structure-report.sh` and the comment runs unmoved.
- Engine tests: `a_body_result_zero_extended_on_every_path_states_zero_above`, `a_body_result_one_path_never_writes_states_nothing_above`, `a_returned_constant_is_as_wide_as_the_instruction_that_wrote_it`, `a_body_no_return_path_leaves_is_never_void`, `a_guard_scrub_a_return_reads_is_the_returned_zero`, `a_float_result_beside_a_written_and_read_second_lane_is_no_double`; `bits_above_a_declared_narrower_result_are_never_zero` unchanged. Unit: `the_fill_above_a_result_is_stated_only_where_every_path_agrees`, `a_lane_the_prune_does_not_forward_is_unknown_never_dead`, lift `a_32_bit_immediate_move_writes_the_doubleword_and_widens_it`. 20 expectations in older tests move from a 64-bit to a 32-bit result, each a `mov eax, imm` body.
- Census: 24 goldens move. 29 headers `uint64_t` to `uint32_t` and 12 `r2sleigh_result_u64` to `_u32`. Each named source function is `int` or `uint32_t` (`fnv1a32`, `classify`, `nested`, the branchy `gate_*`, checked against `tests/corpus`, `tests/gold` and `tests/fixtures/src`), and the `fcn_` rows are their stripped twins; `deregister_tm_clones` and its stripped twins are glibc `void`, an unproven carrier on both sides. 17 `_start` and `entry0` headers `void` to `r2sleigh_result_u64`, "no return reached". Residual lines 15 to 10: manual_limits_O0 `_main` loses five `| r2sleigh_residual_u64(n) << 32` after AArch64 callees that write w0. The 9 gap lines move only their operation index (one more operation per `mov r32, imm32`).
- Hand-read, `r2s -q -c 'aa; s <f>; pdd'`: the AArch64 gcc -O1 `struct f3` chain (`p_f3_inner` in s0, s1, s2) prints `r2sleigh_result_u64` where master printed `float`; f3 gcc -O1 stripped `0x1149` (`p_f3_inner`: `movq xmm0, [rsp - 0x14]` of two floats, `cvtsi2ss xmm1, rdi`) and `0x1341` (`p_f3_chain_a`) print `r2sleigh_result_u64` with a residual return, where master printed `double`; rv_O0g_stripped `avg` (`0x12ef`) stays `double` (XMM1 is its scratch, read by no call). pigz stripped `0x4044b0`, cold and `aa`: `r2sleigh_result_u64 fcn_4044b0(void)`, the call `fcn_411e60(12, 0x41d138)` rendered, its extern `__attribute__((noreturn)) r2sleigh_result_u64 fcn_411e60(uint32_t, uint64_t, ...)`. Over pigz's 221 functions the `<< 32` residuals after `fcn_403a80` go, and three headers narrow (`0x4035e0`, `0x40a420`, `0x41b8b0`).
- D70 on the source-gold builds (hashes -O0, returns, scratch, clones, gcc 13.3): the facts are equal on master and head, with no silent return row in either width bucket, since a cold `pdd` marks these results unproven. On radare2's pigz (`differential_truth.py`, debug against stripped): silent 35 to 35, with no `width_wider` or `width_narrower` return row on either side (this build's `main` is not graded); correct 73 to 70 and marked 194 to 197, the three source `void` functions that never return (D324's cost). The `width_wider` fall is read on the census alone: the 41 narrowed headers above, no header widened. D74's 19 silent rows were DecBench's, which this slice did not rerun.
- Source-gold on the build host (gcc 13.3): `differential_truth.py` on hashes and returns against their baselines, `scratch_void.py` and `void_soundness.py` exit 0: 1,858 read results, 0 rendered `void`; 2,166 externs of read results, 0 `void`.
- Cost: release, median of three, instructions retired on the Mac, master against head: 0pack `0x62ecf0` `pdd` 15.443 to 15.477 G (+0.22%); pumasim `0x23fdf0` `pdd` 23.940 to 24.122 G (+0.76%); bash `0x2e630` `aa; pdd` 14.421 to 14.468 G (+0.33%, output identical, bound 15.43 G); pumasim `0x3b6b20` `aa; pdd` 64.455 to 64.740 G (+0.44%). The cold rises are the one more operation per `mov r32, imm32`. Peak footprint: 0pack 204.3 to 209.4 MB (+2.5%), pumasim cold 211.0 to 208.6 MB, bash 61.2 to 60.4 MB, pumasim `aa` 189.8 to 191.1 MB.
- Certification (`certify_render.py`, radare2 `test/bins/elf`, 80 binaries of 8 functions): 241 rendered, 0 undefined reads, 0 invented, 0 dropped. Coverage sweep: 560 of 562 rendered, the 109 pinned all rendered, no regression. `mutants_s31a.py`, `mutants_d213.py`, `mutants_d203.py` (`some-path-join` retargeted at the join's new text), `mutants_d68.py` and `mutants_d75.py` apply.
- Equivalence on both targets is left to this PR's full tier.

## Open questions

1. The register effect's survey pass is an estimate (about 1 G per 450 bodies on bash). If it does not bring pumasim `0x3b6b20` to 64.38 G, S31b keeps the lazy ask per call with the same function.
2. The loader-write refusal (`Unknown` writes) costs no census or DecBench binary once r2image states `Reserved` and `Copy` (S31a as built); MIPS's whole reserved table and undecoded Mach-O chain formats still refuse.
3. A cold `pdd` prepares a function twice where an owner's statement moves its result (D226). The step is S36's f57e1cb57 ("The cold step, bisected"). No output-identical one-preparation design was found: the raw walk has no accept check, and SSA reuse saves at most 1.3 G of the 4.75 G. Open for the maintainer: keep the bound of two and regrade D226 against #366 (24.46 G), or fund a design that states a callee's float lane without its resolved body. Owner `resolved.rs`.
4. Row numbers come from ROADMAP's "Reserved rows" table. This ADR holds D310 to D313.
