# ADR: the renderer is a printer

Status: proposed (ROADMAP R, decision D8)

## Context

r2dec is about 78k lines. Most of them check, again, what r2ssa has already
proved, then retry when the check fails:

- the observation journal (9.1k lines) re-derives, after rendering, which
  obligations the text discharged;
- the binding plan (12.8k) decides variables in a cycle of partition,
  readers and inlining, through a fixpoint of its own
  (`binding_plan/rules.rs`), with about 15 refusal enums and
  first-writer-wins use claims;
- placement (6.2k) applies decisions, discards and retries
  (`apply_decisions_once`);
- the whole render is retried around gaps and splits
  (`build_product_from_input_with_control`) and around declined rewrites
  (`build_function_internal_with_control`);
- the fold (16.5k) carries lowering rules that are term rewrites
  (`inst_combine`'s cousins), spelled in Rust rather than as r2rewrite's
  proved rules.

Two consequences this month:

- **A printer identity was refused.** `Insert(0, lane, 0)` cannot be spelled
  `(T)lane`, because the journal wants every literal operand rendered.
- **More precise facts made the text worse.** A reload certified equal to
  the stored value now binds as a copy of the stored temporary, because the
  binding plan prefers the source value and must keep it in sync.

## Decision

**The rendered text is one pure function of the sealed facts, and its proof
is built with it.**

1. **A render plan** is computed once from the indexes
   (doc/adr-one-ir.md):
   - the structured control from the dominator tree and loop facts;
   - each value's binding from the frame model and the partition (one
     partition, computed once, as doc/adr-partition-first.md states);
   - each value's inlining from its readers in that partition.

   No step reads a later step's output, so there are no rounds.
2. **Expressions are r2rewrite terms.** Lowering builds terms, and every
   simplification is a proved rule in r2rewrite with its termination
   argument: `inst_combine`, the folds, and identities such as
   `Insert(0, x, 0) = zext(x)`. No simplification is written in Rust beside
   a renderer.
3. **The render tree carries its obligations.** Each node is built with the
   obligation ids it discharges, so the ledger is a walk of the tree. One
   linear checker confirms that every obligation is discharged exactly once,
   or residual, or refused. The journal is deleted (D8).
4. **A certified reload reads its slot.** Where the frame model says a slot
   is a local, a reload certified equal to the stored value is the local. The
   binding follows the object, not the temporary.
5. **Retries go.** A render that cannot place a value refuses that value,
   with its residual. It does not re-run the plan without it. Every retry
   loop of r2dec is deleted.

## Migration

| Step | Change | Deletes |
|------|--------|---------|
| R0 | Render plan beside the current path, compared over the census | — |
| R1 | Expressions as r2rewrite terms; the folds and `inst_combine` as proved rules | the Rust-side simplifiers |
| R2 | Obligations carried by the tree; the linear checker | the observation journal |
| R3 | Bindings from the frame model; certified reloads read their slot | the binding plan's fixpoint, first-writer-wins claims |
| R4 | No retries | `apply_decisions_once`, the gap/split and declined-rewrite retry loops |

## Consequences

- r2dec reads only sealed facts and indexes. The three bound-address rules
  become one, and its size is expected to fall by more than half.
- The census changes at R1 and R3 (identities spelled, reloads named by their
  slot), and each change is read by hand against equivalence.
- Depends on F2 (indexes), P4 (frame model) and P5 (values).
