# ADR: stable op identity and staged SSA artifacts

Status: done (ROADMAP F1)

## Decision

Facts used to be keyed by `(block_addr, op_index)`, a position any edit moves,
and thirteen in-place mutation APIs edited the IR after facts were taken from
it. Identity is now stable and the IR cannot change once facts exist.

### Identity

- `OpId(u32)` indexes a per-function arena that only grows; phis draw from the
  same counter. Ids are never reused: deleting tombstones the slot
  (`Dead { origin, by }`), and rewriting an operation in place keeps its id.
- `OpOrigin::Lifted { block, index, instruction }` is minted at lift in R2IL
  order. Operations construction adds (phis, lane `Subpiece`/`Insert`, entry
  lanes, scratch zeros, fixture ops) are `OpOrigin::Derived { from:
  Option<OpId>, pass }`. The instruction an operation executes for is its own
  when lifted and its source's otherwise (`OpArena::instruction`).
- Passes do not mint while iterating: they return an `EditPlan` (replace,
  insert before/after an anchor, kill, plus `ShapeEdit`s and an explicit
  reorder) applied in IR order, so id order cannot depend on hash order.
  r2dec's `RewrittenFunction` copies its source's arena and mints above
  `id_limit()`.
- A fact names an operation by `InstId` when it is a graph fact and by `OpId`
  when it is an operation's; the graph's dense `inst_for_op`/`op_for_inst`
  translate. Nothing a fact holds is a position.
- `CanonicalInstructionSite::Op(OpId)` (obligation schema 8); it is spelled
  through the graph as `0x{block}:op:{n}`.
- Positions survive only as views of a sealed function, never as keys:
  `SsaGraph::op_ordinal` spells and orders, `walk_start` starts a walk,
  `inst_spelled_at` reads back a site a person typed. A walker's
  `(block, index)` cursor is never stored.

### Stages

- `Lifted → Prepared → Sealed` (`function/stage.rs`), each wrapping the
  `SSAFunction`. `Lifted::prepare` optimises through `EditPlan`s and validates;
  `Lifted::validate` is the raw route; `Lifted::edit_block` is the only block
  edit outside r2ssa's `#[cfg(test)]` fixtures.
- `Prepared::seal` consumes the function and runs a fixed private sequence:
  boundary constants, entry lanes, copy forwarding, a graph, the demand plan
  over it (graph rebuilt only where a base was released), one prep
  collection, the source formals. Nothing outside `seal` can call a step, and
  `seal` returns the validator's typed failure, so a sealed function
  validates.
- `Sealed::into_artifact` collects liveness and semantic facts and consumes
  itself into `SsaArtifact`. Nothing is written into an artifact once built:
  formals are asked of their two owners (`SsaArtifact::formal_parameter_of`),
  and spellings, provenance and native spans arrive as a `Finish`.
- `compile_fail` doctests state that a prepared function seals once and an
  artifact's blocks are not writable. Prep facts carry no revision.
- An entry-lane formal is the caller's value of the lane (version zero, no
  definition); the view solver is seeded with "the formal is its root's low
  bits" (`SSAFunction::entry_lanes`). A whole-register read is the formals
  inserted into the caller's own register, never into an invented zero.

## Done

- Step 0: an access carries its own memory space; `memory_spaces_by_op` and its remap deleted.
- Step 1: the `OpId` arena, private `ops`/`ids`, `OpOrigin`, graph `OpId`↔`InstId` maps, `EditPlan`; `op_instruction_addrs` and position shifting deleted.
- Step 2: stage types; `seal` replaces `prepare_graph`; `op_mut`, `cfg_mut`, public `remove_*`, `optimize()`, `Blocks::edit`, `IrRevision` and the revision assert deleted.
- Step 3: certificates, obligations and r2types/r2dec maps keyed by `InstId`/`OpId`; every `op_index` field, `op_site_for_inst`, `inst_id_for_op_site` and `rendered_site` deleted; `pdd` byte-identical on the coverage binaries.
- Step 4 (with P1.7): formals as live-ins related to their root by a view; version-0 definitions deleted; the sealed validator check on.

## Left

- `seal_body_proven_interface` still rewrites the interface's format parameter after the artifact is built. Exit: it becomes one `Fact` at C1 (doc/adr-provenance.md).
- The address-proven formals change no test and no census function when turned off. Exit: P7 proves what they are for or deletes them.
- r2dec's `NormalizedOpSite` and `NormalizationOrigins` rows are positions in the normalized copy, which normalization still edits. Exit: keyed by the copy's `OpId` (`GapMarker`'s printed `op_idx` stays).
- The demand release keeps `Insert(0, lane, 0)`, printed as `(0 & ~mask) | lane << 0`. Canonicalising it to `zext` in r2ssa let value analysis claim a register bound that holds only for the bytes read. Exit: R's printer spells it, with listing claims made only before meaning-only rewrites.
- `def_use_graph` seals a raw function and discards one prep collection. Exit: an F2 index answers it without a seal.
