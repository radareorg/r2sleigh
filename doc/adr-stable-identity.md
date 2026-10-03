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
| 3 | Certificates, obligations and downstream maps keyed by `OpId` | every `op_index` field in r2ssa/r2types, `op_site_for_inst`, `inst_id_for_op_site`, `rendered_site` |
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
