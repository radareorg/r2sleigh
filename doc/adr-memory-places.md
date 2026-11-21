# ADR: memory places and records

Status: accepted 2026-11-21 for round 18. Extends [aggregates](adr-aggregates.md) and [frame-model](adr-frame-model.md). Rows D640 to D659 in ROADMAP. Counts were taken at `rebuild-design-16` eb327af9a and re-counted on round 17's exit head: body loads 34,819, body stores 20,361, residual sites 7,282, typed address sites 4,721 and functions with a `frame` array 585 are unchanged.

## Problem

`pdd` over DecBench (2,621 functions) spells 34,819 loads and 20,361 stores as `r2sleigh_load_uN` and `r2sleigh_store_uN` calls. The gate reports 39,246 and 23,940 because `stats.py` also counts 8,006 `static inline` helper definitions. Ghidra 12.1.4 spells none on a 40 function sample, and r2s loses on memory and type spelling in 35 to 37 of the 40.

Counts by address class (parsed from `pdd` text, 0 of 55,180 unparsed):

| Class | Sites | State today |
|---|---|---|
| A frame slot not promoted | 9,392 | one anonymous `uint8_t frame[N]` in 585 functions |
| B1 named import data | 995 | named, 318 type refusals on 5 names |
| B2 to B4 unnamed globals | 6,769 | r2ssa `global_objects` has no reader |
| C1 parameter field, typed | 4,721 | `&argN->f_x` inside the byte copy |
| C2 parameter plus constant | 14,186 | layout refused: `Overlap` 3,648, `Indexed` 3,143, local copy 2,853, `OneWidth` 2,495, `NotAffine` 870 |
| D pointer plus index | 3,643 | D360 open |
| E call result plus constant | 1,332 | D71 covers declared returns |
| F loaded pointer plus constant | 11,041 | r2ssa `pointee_expressions` and `pointee_objects` have no reader |
| G unknown base | 3,101 | none |

Three causes cover the table.

1. r2ssa states an access's address in three shapes: `parameter_expressions`, `pointee_expressions` and `ParameterFields`. No single index says which object and which place an access denotes. `ParameterFields` stops at the first load and keeps one refusal per parameter.
2. r2types lays out parameters only. `solver.rs` has `Equal` and `Subtype`, so a field's type cannot be a variable. `aggregates::layout` is a second representation beside the lattice's `StructShape`, and `certified_parameter_pointers` is a second owner (D74).
3. No rule says when a byte copy may become an lvalue. `adr-aggregates.md` forbids it on pointer reached memory, with cause. Frame slots and globals have no rule at all.

Residual sites (7,282) have other owners: P7 holds 68%, and 1,390 r2dec gap sites have no row.

## Decision

The decompiler keeps its design. Memory typing gains one r2ssa index, one r2types solve and one licence rule.

1. r2ssa states one dense place index: each certified access has a base, a place, or a typed refusal.
2. r2types solves records with two new constraints, `Field` and `Element`, inside `solve_evidence_types`. The result is the lattice's `StructShape`.
3. A refusal covers one span. Today one bad access refuses the whole parameter.
4. A byte copy becomes an lvalue only on an object the output declares: a frame object, an image global, or a data object a cited r2abi row declares. Pointer reached memory keeps the byte copy at a typed address.
5. r2dec spells what the owners state and decides nothing.

The round 18 rulings on the open questions:

1. The typed address counter grades D642 to D645, D649 and D652. Loads and stores grade D653 to D657.
2. D658: a member of a pointer reached record is no lvalue. The byte copy stays at the typed address.
3. A record pointer keeps the shipped `struct T *` declaration. Its premise is listed under "Premises".
4. `OneWidth` stays refused.
5. D657 is built only if D656's table shows a floor above 0.
6. D641's frame half is D654's step 0, so the frame rows do not wait on the record rows.

## Owners and contracts

| Fact | Owner | Contract |
|---|---|---|
| Base, place, width and kind of each certified access | r2ssa | `MemoryPlaces` on `SsaArtifact`, dense over the access id and `ObjectId` |
| Which load reads which store | r2ssa | `MemoryVersion` reaching facts (exist) |
| Frame slot fate, reach and ceiling | r2ssa | `SlotFate` (D633), `frame_reach`, `frame_ceilings`, `callee_write_reach` |
| Callee spans per argument | r2ssa interproc | `dereferenced_args` as `(offset, width)` spans |
| Records, members, refused spans, tags | r2types | `Constraint::Field`, `Constraint::Element`, `FunctionTypeFacts::records` |
| Declared import data | r2abi | data object rows with a cited header |
| Global object extent and licence | r2engine | `GlobalObjectFacts` under `Premise::ClosedWorld` |
| Spelling | r2dec | member address, element address, lvalue where licensed |

Deleted when the new owner lands (ROADMAP D1): `ParameterFields`, `collect_parameter_fields`, `ParameterFieldRefusal`, `ObjectModel::access_path`, the `BTreeMap` object tables, `aggregates::layout`, `parameter_aggregates`, the r2dec `members_of` join. `parameter_expressions` and `pointee_expressions` become views of the index. D74 closes.

```
Place = Field { offset: i64, width: u32 }
      | Element { stride: u32, index: ValueId, inner: i64, width: u32 }
      | Unplaced(reason)   // TwoBases, NotAffine, Uncertified, Unmodelled, IndexPastStride
```

The index reuses `StructuredAccessId` and `ObjectId`. `StructuredAccessId` is `{inst, ordinal}` (`r2ssa/src/semantic/facts.rs`), so the index is a column in `memory_accesses` order, addressed in `O(1)` by a first-access offset per `InstId` plus the ordinal. No second id is added. D642 makes dense the tables the index replaces (`objects`, `parameter_objects`, `pointee_objects`, `global_objects`). The other maps keyed by `ObjectId` or `StructuredAccessId` (53 sites at ce498541f) stay with **LX**.

## Invariants

1. Each certified access has one place or one typed refusal. `Unplaced` is the default.
2. A member spelling denotes the access's own address and width. Each member sits at its accessed offset under the psABI, with explicit pads. No record states an extent past its last accessed byte.
3. A value is a record pointer only when an access through its class or a declared prototype says so. A load with no proven reaching store joins nothing.
4. A pointer field joins its pointee record. A scalar field never joins value classes. The join is keyed by field: every value loaded from one pointer field of a record is in that field's pointee class. Invariant 3's store rule covers a load from a place that is no record field (a frame slot, an unplaced address): it joins the stored value's class only through a proven reaching store. A wrong join costs refused spans; the address `q + K` is exact either way.
5. Members are the accesses that contain no other access. A wider access that starts at a member's start and ends at a member's end or in padding is a span, spelled as a byte copy at that member's address. Any other overlap refuses that span as `Straddle` or `Interior`. No union is declared.
6. `OneWidth` stays refused unless an `Element` whose stride equals the width proves an array. `adr-aggregates.md` measured the `argv` regression, and a `uintptr_t` table defeats a ruling by solved types.
7. A declared type outranks an inferred one. A disagreement refuses.
8. An lvalue is licensed only on an object the output declares, when every access that can reach its bytes is proven inside it. A frame object reads its reach from r2ssa. A global reads its reach from r2engine. Default is the byte copy.
9. Tags and class representatives are deterministic: the root (`fcn_<entry>_arg<slot>`) or the lowest accessing instruction address.
10. The key `PointeeObjectKey (base, offset, size, space)` has no memory version. Each reader that treats object equality as must alias is proven or refused before the index replaces the map.
11. A frame address no offset places reaches the escape run of each object it may be based on ("Escape spans" in the frame model), out to a save slot. It refuses those objects and no other. An address with no known base object refuses the whole frame, as today.
12. An import data object has a type only where three statements agree: the container's relocation names the symbol at that address, a cited r2abi row declares that name for the image's C library, and the container's symbol size equals the declared type's size. Any other access keeps the byte copy.

## Algorithm and cost

Per function, with V values and A accesses:

1. r2ssa places each access from its affine address `base + Σ k·v + c`. The base is the single unscaled, non constant term with a known origin. Zero index terms gives `Field`, one gives `Element`, anything else is `Unplaced`. Cost `O(A)`.
2. r2types emits one `Field` or `Element` constraint per placed access. Cost `O(A)`.
3. Unification merges record classes, smaller field map into larger. At most V merges occur, and span states only move forward (clean, span, refused). Cost `O((V + A) α(V) + A log A)`. No fixpoint, round cap or cache.
4. A cyclic class is refused as `Recursive` until D645 admits a cycle that a record class identity closes.
5. A caller imports a callee's spans in `O(spans)` per call site. The callee states them once in `O(callee accesses)`. Cold `pdd` equals `aa; pdd` (D573).
6. `GlobalObjectFacts` is program wide and runs once per session. Its cost and its extent rule are D656's step 0. No global row builds before that number exists.

Timing gate: each of the five timing rows stays within +0.10% of the chain base per row, or the row states a cause and `scripts/cost_causes.txt` carries its line. A rise over 2% on `aa; pdd @ 0x3b6b20` (pumasim) or `pdd @ 0x62ecf0` (0pack) stops the row even with a cause. Peak RSS is reported per row.

## Rendering

| Site | Spelling |
|---|---|
| Record member behind a pointer | `r2sleigh_load_u32((void*)&p->f_10)`, `p` declared `struct fcn_<entry>_<root> *` |
| Span | `r2sleigh_store_u128((void*)&arg0->f_10, 0)` |
| Element | `&p[i]`, `&p[i].f_4`, `&p->f_b[i]` |
| Refused span | today's byte arithmetic, reason on the proof line |
| Promoted frame slot | an SSA local, no access |
| Declared frame object, reach proven inside | `stack_m144 = arg1;` (the frame model's name, as `afv` prints it) |
| Declared frame object, reach unproven | `uint8_t stack_m144[ceiling]`, byte copy at `&stack_m144[k]` |
| Declared import data | `stderr` |
| Licensed `.bss` object | `g_26748 = arg0;`, proof line names `Premise::ClosedWorld` |
| Unlicensed global | `r2sleigh_load_u64((void*)&g_26748)` |

No loop, switch, local, union or type appears that the index or a cited row does not state.

## Tests and gates

Failing first:

1. r2types inline: one indexed access no longer refuses the parameter's constant fields.
2. r2types inline: `{4@0, 8@8, 16@0}` lays out with a span. `{8@0, 4@4}` refuses only the 8 byte span as `Interior`.
3. r2types inline, negative: a field read once as a pointer and once as an integer leaves the integer untyped.
4. engine test: `mov rax,[rdi+0x38]; mov ecx,[rax+8]; movzx edx,byte [rax+1]; mov [rax+0x10],rcx` declares a record with `f_1`, `f_8`, `f_10`.
5. engine test, negative: a reloaded pointer with no proven reaching store gets no record.
6. engine test: a list walk refuses `Recursive` at D644 and declares a recursive struct at D645.
7. Regression: `argv[1..3]` stays a pointer. A declared `FILE *` pointee is not laid out.
8. engine test: a select of two frame addresses refuses two objects and promotes the rest.
9. engine test: a frame object handed to a callee with no proven reach stays a byte array.
10. engine test: a caller passes `arg0` to a callee with spans. Cold output equals `aa;` output.
11. engine test: an unreached `.bss` scalar renders `g_4010 = arg0;`. The twin with its address passed to a call keeps the byte copy.

Gates: equivalence on x86-64 and aarch64, certification, the census with each moved line read, the timing rows, and D640's counters (body loads and stores, typed address sites, lvalue sites, typed pointer locals).

## Premises

1. A `struct T *` declaration asserts the pointer's alignment (C11 6.3.2.3p7). A 16 byte member would let a compiler emit an aligned vector copy. The shipped parameter path has the same exposure. Round 18 keeps the declaration and records the exposure here. A later ruling may replace it with GNU `packed, may_alias` attributes.
2. A global lvalue rests on `Premise::ClosedWorld`, named on the proof line.

## Risks

1. The alignment premise above reaches every record pointer this ADR adds.
2. Unification through a generic `void *` helper merges unrelated records. The result is refused spans, and the byte copy keeps the C true.
3. The global licence needs object extents, which a stripped image does not state. An escaped or indexed address with unproven reach denies every cell above it in its section. The yield may be near 0.
4. The F estimates (1,730 to 10,642) come from `pdd` text. Engine coverage is unmeasured until D641.
5. Frame function counts disagree: one measurement has 102 functions and 4,648 sites, another 217 and 3,519. D654's step 0 states one join.
6. Census churn is about 28,000 lines.

## Not decided here

- A licence for lvalues on pointer reached records. D658 refuses them in round 18.
- Initialized globals in `.data` and `.rodata` (1,025 sites).
- SCC shape summaries and polymorphic records.
- The unknown base classes with a residual base or an integer derived base (2,062 sites).
- The call boundary residuals (P7).

## As built: gate and declared objects (D640, D653, D656, D657, D659)

Open.

## As built: places and records (D641 to D645, D649, D652)

### D641 step 0 (record half): counted from engine facts

A local probe (never committed) printed per function, from r2ssa's address facts and certificates at 5f39d32a6, over DecBench's 2,621 functions. Certified accesses equal the structured accesses one to one, and each instruction's ordinals run from 0 without a gap, so a position column is exact.

RAM accesses (84,079) by the address fact that states them and by index terms:

| Address fact | 0 terms | 1 term | 2 or more |
|---|---|---|---|
| parameter expression | 18,130 | 1,577 | 227 |
| pointee expression | 2,271 | 1,177 | 120 |
| frame expression | 35,561 | 384 | 1 |
| none | 24,631 | | |

These are engine accesses; a promoted slot's access prints no site, so they do not add to the `pdd` site counts.

The loaded pointer class (11,041 parsed sites). An access is based on a loaded pointer where its address, through copies and constant adds, roots at a load:

| Where the pointer was loaded from | Accesses | Join |
|---|---|---|
| a parameter or pointee field at a constant offset (pointee expression) | 2,161 | keyed by field |
| an address with no expression, itself a load root | 4,920 | keyed by field, one level per load |
| a frame slot | 276 + 16 | a reaching store through `MemoryVersion` |
| a global | 164 | none this round |
| an indexed parameter or pointee address | 25 | `Element` (D649) |
| no load root (a merge of two pointers, or an index) | 1,391 with a pointee expression, 19,246 without | none |

D644's pin is in engine accesses, not `pdd` sites: at most 7,081 accesses join by field, 292 more only through a proven reaching store. A promoted or folded access prints no site, so the `pdd` count D644 grades sits below these.

Readers of `PointeeObjectKey` equality as must alias (invariant 10):

1. `build_memory_ssa` (`semantic/objects.rs`): accesses of one pointee object at one offset are one location. Refused as a proof of same content (read, untested): a pointer loaded before a write that re-points its field and dereferenced after a second load of the same field shares the key, and no version tells them apart (`p1 = a->f; f(); p2 = a->f; p2->x = v; y = p1->x` reads `v`'s version).
2. `same_content_reads` (`function/mod.rs`): two reads of one object, offset and width under the same versions hold one content. Over pointee objects, 60 DecBench pairs read through one pointer load (proven: one pointer) and 37 through two loads of one path (unproven, case 1). Refusing the 37 can change liveness and so the output; it is recorded here, and D642 keeps the builder's map.
3. `collect_memory_round_trips` (`semantic/private_objects.rs`): keyed by the address value, not the key, so proven by value identity. Its "no other write" check reads writes of the same object only; a call between the read and the write is not one. Read, untested; recorded for its owner, not built here.
4. `backward_slice` (`slice.rs`): a diagnostic; it prints the versions and decides nothing.

`ObjectId` is minted dense from 0 per function: 2,621 of 2,621 functions, 31,782 objects.

Parameter view: in 177 parameters the places alone (every access whose parameter expression names the slot) lay out another structure than `ParameterFields`' def-use reach (54 with other fields, 93 where the reach refused `NotAffine`, 24 the reach never saw, 6 the other way). D642 keeps the reach so its output is byte identical; D643 drops it.

### D642: `MemoryPlaces`

r2ssa `memory_places.rs`: one `AccessPlace` per structured access in `memory_accesses` order, base `Parameter`, `Loaded`, `Frame`, `Global` or `None`, place `Field`, `Element` (one positive stride with the access inside one stride) or `Unplaced` (`NotAffine`, `IndexPastStride`, `Unmodelled`, `NoBase`). `StructuredDataflowFacts::position` is the first position per instruction plus the ordinal, `O(1)`. A loaded root is a dense column over values filled once; a value on a cycle has none. `ObjectModel::objects` is a dense `ObjectTable`; `parameter_objects` and `pointee_objects` left the model (builder only); `global_objects` stays, a lookup by address. Other maps keyed by `ObjectId` or `StructuredAccessId` stay with LX. DecBench records 0 of 2,621 moved.

Two deviations, recorded. `parameter_expressions` and `pointee_expressions` stay `address.rs`'s maps and feed the index; they are not yet views of it. The loaded-root column is a second affine walk beside `address.rs` (copies, constant adds, phis); D670 moves it into `address.rs` so one owner states every load-rooted affine form.

### D643: `Constraint::Field`

r2types: `Constraint::Field { base, offset, width, value }` adds one record access to the base's class; `IncrementalSolver::equal` moves the smaller record list into the larger, so each access moves `O(log N)` times; `record` sorts one class's accesses, `O(k log k)`. `solve_evidence_types` emits one `Field` per access `MemoryPlaces` states as a constant field of a parameter (`gather_fields`, `O(A)`). `records.rs` lays a class out: members are the accesses that contain no other (a suffix minimum of ends, `O(A)`); a member at a negative offset or unaligned to its width is refused alone; a wider access is a span where it starts at a member and its last byte ends a member or lies in padding, else refused alone as `Interior` or `Straddle`. A member read as two solved types is untyped (its width). `OneWidth` counts members and refused accesses, not spans: `{8@0, 8@8, 16@0}` stays refused, `{8@0, 4@4}` lays out `f_4`. Deleted: `aggregates.rs` (`layout`, `parameter_aggregates`, `InferredAggregate`), `FunctionTypeFacts::{inferred_aggregates, parameter_structures}` (now `records`), and D642's parameter reach (`memory_places/reach.rs`). r2dec `members_of` spells each access through a parameter at the member or span its record states, else keeps the byte arithmetic; the all or nothing rule is gone. A pointer member of an inferred record whose tag the unit cannot name is `void *` (r2dec `tags.rs`); it had refused the whole record once a callee's own record named the pointee.

`argN` always names the entry value: formals are no class members (r2ssa `local_classes.rs` `member`), so `&argN->f_K` is exact wherever the place says base `Parameter(N)`, through a copy, a reload or a merged register name alike.

DecBench at the head: typed address sites 4,721 to 14,207 (+9,486); loads 34,819, stores 20,361, residual sites 7,282, 0 functions moved on any of the three. Gains by the refusal the parameter had at eb327af9a: `Indexed` 4,015, `Overlap` 3,357, `NotAffine` 796, none traced 719, `Unaligned` 336, `Conflict` 153, `OneWidth` 62 (a refused access of another width), `Unmodelled` 48. 502 functions move; every moved line is (a) a byte address to `&argN->f_K` (9,075, and 411 where the text named a copy, reload or merged register), (b) a struct definition with pads (4,755), (c) a parameter's declared type moving to the record pointer, here or as a callee's prototype, forward declaration or argument cast in a caller (1,723), or (d) a proof line (264). `clang -fsyntax-only` with `compile_check.py`'s flags on all 502 with an `offsetof` assertion per member (3,214): 0 assertion fails, errors 2 at base and 2 at the head. Goldens 500 of 500 unchanged. A 16-byte span keeps its byte arithmetic: r2dec spells 128-bit accesses through a path that reads no member (D671).

Not built here: `certified_parameter_pointers` reads the records and stays a second owner (D74 held). A local copy needs no declaration: it is spelled through the parameter.

## As built: frame objects (D654, D655)

Open.
