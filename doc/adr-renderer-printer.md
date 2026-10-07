# ADR: the renderer is a printer

Status: superseded 2026-10-07 by [adr-decompiler-rewrite](adr-decompiler-rewrite.md) (ROADMAP D, D20). R1 below is done and carries over as D3's rule set; R0 and R2 to R4 are not pursued.

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

6. **It absorbs three ADRs as invariants.** The partition comes before
   inlining (doc/adr-partition-first.md, decisions 1–4, 6–7; decision 5's
   rounds are what item 1 removes); every access has one spelling from facts
   (doc/adr-access-syntax.md); every effect survives exactly once with one
   typed owner (doc/adr-semantic-preservation-kernel.md). When R lands, those
   three files are folded into this one and deleted.

## Done

- R1a: the CExpr identity and linear folds in fold/op_lower and
  analysis/prepared_semantic are deleted (867 lines). Each ran only on
  operands carrying no render observation, which the audited path never
  has; disabling each left the census byte-identical. Their identities are
  r2rewrite rules (23 identity rules, proved). `structure/rewrite.rs`'s
  `negate_condition`'s float hazard is R1e.
- R1b: zeroes above a value are its zero extension as a proved rule
  (`cast.concat_zero_high`, decreasing a new `Joins` measure component);
  import's `Insert`-over-zero shortcut and the printer's `Concat`-of-zero
  peephole are deleted. Import admits a zero high part of any width as a
  literal, so a byte lane inserted into a zeroed register imports and
  widens where the machine renderer spelled masks (29 census functions).
- R1c (decided 2026-10-06): `inst_combine` stays r2ssa's SSA
  canonicalisation, since every fact is derived after it and r2rewrite sits
  above r2ssa; it is proved there instead. Every identity it applies and
  every fold through a definition is checked against `r2il::eval`,
  exhaustively at 8 and 16 bits (eval gained `Insert`, an r2il operation it
  did not model). Its termination is a measure, not a budget: each step makes
  the operation a copy, makes one more operand a constant, or moves a slice
  to a strictly shallower definition (longest-path depth, computed once in
  O(definitions)); a step that lowers nothing is a defect and panics, where
  the budget kept a partial result. Census byte-identical; no time added.
- R1d: `CExpr::cast_with_role`'s integer collapses are proved against C's
  conversion rules over every chain of two and three conversions among the
  eight integer types and `_Bool`, for every 8- and 16-bit source. The proof
  found `_Bool` treated as an 8-bit integer: `(uint8_t)(_Bool)x` collapsed
  to `(uint8_t)x`, 2 where C gives 1. `_Bool` now takes no part in the
  modular collapses. The pointer collapses rest on C11 6.3.2.3 as cited.
- R1e: ordered float comparisons are their own operators (`FLt`, `FLe`,
  `FGt`, `FGe`, printed as `<` and the rest), from the float lowering and
  the rewriter's float compare terms. `negate_condition` wraps them in `!`
  where it flips an integer relation: a NaN makes `a < b` and `a >= b` both
  false. Float compares reach conditions inline through
  `materialize_term`; the census had no negated one yet.

## Left

- R0: the render plan beside the current path. Exit: it agrees over the
  census.
- R1: done (above). Exit as amended 2026-10-06: no simplifier is unproved;
  each is deleted, an r2rewrite rule, or proved against the evaluator or
  C's rules where it lives.
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
