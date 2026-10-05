# ADR: the renderer is a printer

Status: proposed (ROADMAP R, after F2, P4 and P5; decision D8)

## Decision

The rendered text is one pure function of the sealed facts, and its proof is
built along with it. r2dec stops re-checking what r2ssa has already proved and
stops retrying when a check fails.

1. **A render plan** is computed once from the indexes (doc/adr-one-ir.md):
   structured control from the dominator tree and the loop facts, each value's
   binding from the frame model and the partition, and each value's inlining
   from its readers in that partition. No step reads a later step's output,
   so there are no rounds. This replaces the fold/partition agreement rounds
   of doc/adr-partition-first.md (decision 5) and the binding plan's own
   fixpoint (`binding_plan/rules.rs`).
2. **Expressions are r2rewrite terms.** Lowering builds terms, and every
   simplification is a proved r2rewrite rule with its termination argument:
   `inst_combine`, the folds, and identities such as `Insert(0, x, 0) =
   zext(x)`. No simplification is written in Rust beside the renderer.
3. **The render tree carries its obligations.** Each node is built with the
   obligation ids it discharges, so the ledger is a walk of the tree. One
   linear checker confirms that every obligation is discharged exactly once,
   is residual, or is refused. The observation journal is deleted (D8).
4. **A certified reload reads its slot.** Where the frame model says a slot is
   a local, a reload certified equal to the stored value is that local. The
   binding follows the object, not the temporary.
5. **No retries.** A render that cannot place a value refuses that value with
   a residual. It does not re-run the plan without it.

## Done

Nothing yet.

## Left

- R0: the render plan beside the current path. Exit: it agrees over the
  census.
- R1: expressions as r2rewrite terms, with the folds and `inst_combine` as
  proved rules. Exit: the Rust-side simplifiers are deleted.
- R2: obligations carried by the tree, with the linear checker. Exit: the
  observation journal is deleted.
- R3: bindings from the frame model, with certified reloads reading their
  slot. Exit: the binding plan's fixpoint and its first-writer-wins use claims
  are deleted.
- R4: no retries. Exit: `apply_decisions_once` and the retry loops in
  `build_product_from_input_with_control` (gaps and splits) and
  `build_function_internal_with_control` (declined rewrites) are deleted.
- Exit for the whole of R: r2dec reads only sealed facts and indexes.

## Consequences

- The census changes at R1 (identities spelled) and R3 (reloads named by
  their slot), and each change is read by hand against equivalence.
- r2dec's three bound-address rules become one.
- No new renderer-side policy lands while R is open.
