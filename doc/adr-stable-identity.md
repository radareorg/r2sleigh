# ADR: stable op identity and staged SSA artifacts

Status: accepted, in progress (ROADMAP F1)

## Context

r2ssa keeps an SSA function mutable and keeps the facts derived from it in
step by hand. Facts are keyed by `(block_addr, op_index)`, a position any edit
moves:

- `SourceMachineContext::memory_spaces_by_op`, rebuilt by a remap that was
  safe to run once only because a comment said so (deleted, step 0);
- `SsaGraph::op_inst_by_site`/`op_site_by_inst` (about 45 readers in r2ssa,
  18 in r2dec);
- `promoted_slot_sites`, `op_instruction_addrs` (re-shifted by hand in
  `insert_ops`), `call_results.rs` `callsites_by_op`;
- `CanonicalInstructionSite::Op(op_idx)`, whose doc says the ordinal is
  independent of graph allocation while it is the prepared index;
- nine r2ssa, seven r2types and eight r2dec fact structs carry
  `(block_addr, op_index)` beside an `InstId`: two identities for one fact.

Thirteen in-place mutation APIs (`get_block_mut`, `op_mut`, `cfg_mut`,
`remove_block`, `remove_phi_source`, `optimize`, `insert_ops`,
`Blocks::edit`, the formal-installation pair, r2dec's
`RewrittenFunction::get_block_mut`, `record_code_pointer_entries`) edit the
IR after facts were taken from it. Staleness is caught at run time by
`IrRevision` and an `assert_eq!` in `decompile_prep_facts()`. The graph's
`InstId`/`ValueId` are dense indices recomputed on every build, and the graph
is built twice for a function the demand pass edits.

## Decision

**Identity.** `OpId(u32)` indexes a per-function arena that only grows; phis
draw from the same counter.

- Minted at lift in R2IL order; the slot records
  `OpOrigin::Lifted { block, index, instruction }` (replacing
  `op_instruction_addrs`).
- Ops construction adds (phis, lane `Subpiece`/`Insert`) get
  `OpOrigin::Derived { from, pass }`; lane temporaries keep their spelling, so
  output does not move.
- Rewriting an op in place keeps its id. Deleting tombstones the slot
  (`Dead { origin, by }`); ids are never reused.
- Passes do not mint while iterating: they return an `EditPlan` (replace,
  insert before/after an anchor, kill) that the stage applies in IR order (RPO,
  then op order), so id order cannot depend on hash order.
- A block stores `ops` and a parallel `ids`, private to `block.rs`; readers get
  `ops()`, `sited()` and `position(OpId)`.

`SSAVar` stays the value name. The graph is built once, at seal, so `ValueId`
and `InstId` become stable for an artifact's life; the graph gains dense
`OpId`↔`InstId` maps, and a value's definition becomes
`ValueDef = Op | Phi | LiveIn(storage) | Const | Unspecified(width)`.
`LiveIn` and `Unspecified` are what P1.7 needs. `CanonicalInstructionSite::Op`
carries the `OpId` (obligation schema 7 → 8); its display stays
`0x{block}:op:{n}`.

**Stages.** `Lifted → Prepared → Sealed`, each a type:

```rust
pub struct Lifted   { ir: Ir }
pub struct Prepared { ir: Ir }   // validate_ssa_function holds
pub struct Sealed   { ir: Arc<Ir>, prep: DecompilePrepFacts, graph: SsaGraph, query: SsaQueryIndex }
```

`Lifted::prepare` runs optimisation through `EditPlan`s and validates.
`Prepared::seal` runs a fixed private sequence: boundary constants, entry
lanes, copy forwarding, the demand pass over a borrowed provisional graph,
one fact collection, one graph, the formals and the semantic facts. Nothing
outside `seal` can call a step, so running one twice cannot be written;
`Sealed` has no `&mut` path to the IR. Facts exist only on `Sealed`, with no
revision. Tests that corrupt the IR use a `#[cfg(test)] Prepared::unchecked`.
r2dec's `RewrittenFunction` is a derived copy with its own insert API minting
ids above `sealed.id_limit()`.

The validator (which now also checks dominance) is `Prepared`'s precondition;
it becomes `Sealed`'s once P1.7 removes the version-0 definitions the entry
lanes mint today (626 violations across the corpus).

## Migration

Each step keeps every gate green and deletes what it replaces.

| Step | Change | Deletes |
|------|--------|---------|
| 0 | The memory space of an access is read from the access, which carries the op's own space | `memory_spaces_by_op`, `memory_space_at`, `remap_memory_sites_to_prepared` and its comment — **done** |
| 1 | `OpId` arena, private `ops`/`ids`, `OpOrigin`, graph `OpId`↔`InstId` maps, `EditPlan` | `op_instruction_addrs`, the index shifting in `insert_ops`, the graph's site BTreeMaps — **done** |
| 2 | Stage types; `seal` replaces `prepare_graph`; optimize and demand through `EditPlan` | `get_block_mut`, `op_mut`, `cfg_mut`, public `remove_*`, `optimize()`, `Blocks::edit`, `IrRevision`, the revision assert, `recollect_*` — **done** |
| 3 | Certificates, obligations and downstream maps keyed by `OpId` | every `op_index` field in r2ssa/r2types, `op_site_for_inst`, `inst_id_for_op_site`, `rendered_site` — **done** |
| 4 | With P1.7: `ValueDef::{LiveIn, Unspecified}`, formals as views | version-0 definitions; the sealed validator check switches on |

Positions survive only as an ordering view of an IR that can no longer
change.

Step 1 as landed:

- A phi, an entry lane, a scratch zero and a fixture's operation stand for no
  operation of the program, so `OpOrigin::Derived` names its source as
  `from: Option<OpId>`; the instruction an operation executes for is its own
  when lifted and its source's otherwise (`OpArena::instruction`).
- A block built outside a function (`to_ssa`, a test's
  `SSABlock::from_parts`) numbers its operations itself until a function
  adopts it, which mints in block order.
- Shape changes need the arena, so `get_block_mut` returns a `BlockMut`
  carrying it; a test that writes a block by hand calls
  `replace_ops(Pass::Fixture, …)`. Rewriting an operation in place
  (`ops_mut`) keeps its id.
- r2dec's `RewrittenFunction` holds a copy of its source's arena and mints
  above it.
- The CFG's per-operation instruction addresses stay: they are the lift's own
  record, read once to mint `OpOrigin::Lifted`.

Step 2 as landed:

- `Lifted`, `Prepared` and `Sealed` are in `function/stage.rs`, each wrapping
  the `SSAFunction` the rest of the crate already reads (the ADR's `Ir`).
  `Lifted::prepare` optimises and validates; `Lifted::validate` is the raw
  route, with no optimisation; `Prepared::seal` consumes the function and runs
  the fixed sequence; `Sealed::into_artifact`, private to the stage module,
  collects liveness and the semantic facts and consumes itself into
  `SsaArtifact`, which holds the `Sealed`.
- Nothing is written into an artifact once it is built. Several things used
  to be:
  - the formals the address facts prove were installed into the prep facts
    that the address facts had been collected from;
  - the spellings were assigned after sealing;
  - the obligations were bound to the lift's native spans after sealing.

  Now `SsaArtifact::formal_parameter_of` (and `_of_view`, and
  `formal_parameters`) asks the two owners, the entry and the address facts,
  each for its own evidence. A `Finish` (provenance, spellings, native spans)
  is given to `into_artifact`. One write remains:
  `seal_body_proven_interface` rewrites the interface's format parameter
  from the facts, and that becomes one `Fact` at C1
  (doc/adr-provenance.md).
- Open: no test and no census function changes when the address-proven
  formals are turned off, including an `-O0` callee that indexes through a
  spilled parameter, which is the case their comment names. P7 either proves
  what they are for or deletes them.
- The order inside `seal` is boundary constants, entry lanes, copy
  forwarding, a graph, the demand plan over it (applied, and the graph built
  again, only where a base is released), then the one prep collection. The
  ADR listed the collection before the graph; the prep facts are read by
  nothing the graph or the demand pass computes, so collecting after the
  demand plan is the only order with one collection and no stale fact.
- `EditPlan` grew `ShapeEdit`s (replace a phi, drop the sources a predecessor
  fed, remove an edge, set a terminator, remove a block) and an explicit
  reorder, applied after the operation edits in the order stated. SCCP is four
  plans applied in the order the in-place pass made its edits; inst_combine,
  the condition-code fold, chain fusion and the demand pass are one plan each
  (fusion one per chain).
- `SSAFunction` holds no prep facts, so `DecompilePrepFacts` has no
  revision and is not an `Option` on an artifact. The semantic collectors read
  them from `CollectionOver::prep`, threaded to the twenty-odd helpers that
  used to ask the function; a collection over a function that was never
  prepared passes `None`.
- Interface recovery analyses a provisional function it never seals, so it
  collects that function's prep facts itself (`Prepared::provisional_prep_facts`)
  rather than reading a copy the build left on the function.
- Every artifact constructor seals, so the raw and symbolic routes now carry
  prep facts collected under the context's frame geometry, where before the
  raw route had none. No production route takes either; the decompile routes
  collect under the same interface as before.
- Editing a block is a `Lifted` capability (`Lifted::edit_block`), used by
  r2dec's fixtures; r2ssa's own fixtures use a `#[cfg(test)]` `edit_block`,
  and validator tests corrupt through `#[cfg(test)]` `corrupt_cfg` and
  `corrupt_remove_block`. No test seals an IR the validator refuses, so
  `Prepared::unchecked` was not needed and is not added.
- `compile_fail` doctests on `Prepared` and `Sealed` state that a prepared
  function seals once and that an artifact's blocks are not writable.
- The query index stays a lazily built cache on `SSAFunction`, not a field of
  `Sealed`; the ADR's `ir: Arc<Ir>` is a plain owned field, since nothing
  shares a sealed function's blocks without its facts.
- `def_use_graph` seals a raw function to take its graph, and so now pays for
  one prep collection it discards.

Step 3 as landed:

A fact names the operation it is about by its `InstId` where it is a graph
fact and by its `OpId` where it is an operation's, and the graph's dense
`inst_for_op`/`op_for_inst` translate. Nothing a fact holds is a position.
The census, with what became of each:

| Where | Was keyed by position | Now |
|-------|-----------------------|-----|
| `SsaGraph` | `inst_id_for_op_site`, `op_site_for_inst` | deleted; `inst_for_op`, `op_for_inst`, `block_addr_of` |
| `SsaArtifact` | `inst_op_site`; `{callsite,return,call_result,stack_reload}_certificate_for_op`, `memory_certificate(s)_for_op_site`, `memory_{uses,defs}_for_op_site` | `inst_op_site` deleted; the rest `_for_inst(InstId)` |
| `PreparedFunctionCertificates` | `memory_accesses_by_op: (u64, usize, bool)` | `memory_accesses_by_inst: (InstId, bool)` |
| r2ssa facts | `op_index` (and the `block_addr` beside it) on `StructuredMemoryAccessFact`, `StructuredRecursiveCallFact`, `MemberRunStoreCertificate`, `MemoryAccessCertificate`, `CallsiteCertificate`, `CallResultCertificate`, `ReturnValueCertificate`, `DispatchTableRead`; `MemoryRoundTripCertificate`'s three index fields; `AccessSite`, `StackMemoryAccessInput` | deleted; each already carried its `InstId`, `StructuredAccessId` or `at`, and `StructuredRecursiveCallFact` gained `at` |
| r2ssa readers | three checks that "the instruction stands where the access says" (machine projection, aggregate access, RAM-access match) | deleted: with one identity there is nothing to agree |
| `value_reaching` | `(block_addr, op_index)` | `OpId` |
| obligations | `CanonicalInstructionSite::Op(u64)`, schema 7 | `Op(OpId)`, schema 8; `Display` replaced by `spelled(&SsaGraph)` |
| r2types | `CallsiteKey { block_addr, op_index }`; `OpSiteKey`, `MemoryOpSiteKey`; `FunctionRenderFacts::*_by_op`; site fields on the memory, member, array and return render facts; `*_for_op(block, index, ..)` lookups; `ScalarArrayRenderCandidate`'s site; `LocalMemoryVersionFacts::{stores,loads}_by_site` | `CallsiteKey { at }`; `MemoryEffectKey = (InstId, bool)`; `*_by_inst`; the site fields deleted (`ReturnValueRenderFact` gained `at`); `*_for_inst(InstId, ..)`; `op: OpId`; `*_by_op: OpId` |
| r2dec ledger | `rendered_site`; `Outcome::{Rendered, Gapped} { block_addr, op_idx }` | deleted; the outcome is keyed by the obligation, which names its instruction |
| r2dec fold | `source_op_site_for_normalized_op`, `current_source_op_site`; `LowerFrame::source_call_site: (u64, usize)`; every call-site helper in `calls.rs`, `implementation.rs`, `lowering.rs`; `CExpr::Call::site` | deleted; the call's `InstId` throughout; the operation being lowered carries its source instruction (`current_source`, set once per operation) |
| r2dec analysis | `call_view_by_site`, `call_result_source_by_value`, `UseInfo::call_result_exprs` keyed by `(u64, usize)`; `prepared_call_site_tuple` | keyed by `InstId`; the tuple translation deleted |
| r2dec binding plan, placement, journal | `certified_dead_frame_slot_accesses: (u64, usize)` and the graph scans that resolved it back to instructions; the round-trip site scan; `coalesced_store_sites`; `BlockAnswerParts` sites; `single_evaluation::CallSite` | `InstId` sets read directly; `coalesced_stores: OpId`; the alias deleted |

- Positions survive as views of a sealed function, never as keys:
  `SsaGraph::op_ordinal` spells `0x{block}:op:{n}` and orders what is
  spelled; the crate-private `walk_start` is where a walk over a block's
  operations before or after an instruction starts, and `inst_spelled_at`
  reads back a site a person typed (`pdil` slice seeds, fixtures). The
  walkers in `semantic/boundaries.rs` and `semantic/shared.rs` still carry a
  `(block, index)` cursor between their own helpers; it is never stored.
- The obligation ledger orders itself as the spelling reads, taken from the
  graph once when it opens, so `pddo`'s `refused-ids` and the engine's
  "first refused/unaccounted/conflicting" name the same obligations in the
  same order as before; `EffectObligationAudit` carries them spelled.
- Six readers in r2dec looked a fact up by the *normalized* function's
  position as if it were the source's (call targets, call-result
  definitions, a member-run store, the switch dispatch, a coalesced store,
  the terminal tail-call check). They now ask by the source instruction, and
  where a source instruction has to be found in the normalized function, its
  own block's origin rows are read (`NormalizationOrigins::original_site`).
  The census below shows none of them fired on the corpus.
- Not re-keyed here: `NormalizedOpSite` and `NormalizationOrigins`' rows.
  They are positions in the normalized copy, which normalization still
  edits, and the rows carry phi-edge and relocated-initializer provenance
  as well as translating; keying them by the copy's `OpId` is the next step
  for r2dec. `GapMarker`'s `op_idx` is the normalized position the output
  prints, and stays.
- Evidence: every function of the four pinned binaries, the twelve coverage
  binaries and the nine `eqloc` binaries renders byte-identical `pdd`
  before and after; `pddo` is unchanged (the schema number is not printed).

## Consequences and risks

- Restructured in place, not as a new crate: the ~20k lines of certificates
  read the finished artifact, whose type stays; real change lands in about 15
  files. Re-evaluate if step 2 runs past two weeks or step 1's reader
  migration needs non-mechanical edits in more than about 40 files.
- Determinism of minting is tested by building one function twice and
  comparing arena dumps.
- Step 1's mechanical `.ops()` change conflicts with parallel tracks; it lands
  first and fast.
- The graph is still built twice where the demand pass edits (once
  provisional, borrowed); F2 removes that.
