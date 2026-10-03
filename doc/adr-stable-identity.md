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
| 1 | `OpId` arena, private `ops`/`ids`, `OpOrigin`, graph `OpId`↔`InstId` maps, `EditPlan` | `op_instruction_addrs`, the index shifting in `insert_ops`, the graph's site BTreeMaps |
| 2 | Stage types; `seal` replaces `prepare_graph`; optimize and demand through `EditPlan` | `get_block_mut`, `op_mut`, `cfg_mut`, public `remove_*`, `optimize()`, `Blocks::edit`, `IrRevision`, the revision assert, `recollect_*` |
| 3 | Certificates, obligations and downstream maps keyed by `OpId` | every `op_index` field in r2ssa/r2types, `op_site_for_inst`, `inst_id_for_op_site`, `rendered_site` |
| 4 | With P1.7: `ValueDef::{LiveIn, Unspecified}`, formals as views | version-0 definitions; the sealed validator check switches on |

Positions survive only as an ordering view of an IR that can no longer
change.

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
