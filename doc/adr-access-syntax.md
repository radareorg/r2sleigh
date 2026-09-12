# ADR: one owner for how a memory access is spelled

## Context

Twelve of the twenty-four remaining refusals are one shape: the binding plan
decides which values are rendered, the memory renderer decides how each access
is spelled, and each decision assumes something about the other. The plan
elides an address value as `DeadStackBase` on the premise that the access it
feeds has a spelling that needs no address; the renderer finds the spelling by
a six-rung ladder over *rendered expressions*, and when every rung declines it
falls back to dereferencing the address the plan elided. The refusal is then
`OpLowering(memory_renderer.rs)` or `missing program-variable authorization`,
and the two layers have each been right on their own terms.

The ladder, in `render_certified_memory_expr_for_fact`, is:

1. a certified array fact whose base is a parameter slot: `param[index]`;
2. the rewriter's canonical term for the access is a `Subscript`: `base[index]`;
3. a declared member fact at the access's offset inside a declared slot: `slot.field`;
4. the access sits at offset zero of a declared slot: `slot`;
5. a member or array fact matched against the *rendered* address decomposed as
   `base + index * stride + offset`: `base.field`, `base[index]`, `base[index].field`;
6. the address itself: `*(T *)addr`, with a byte cast when the address is arithmetic.

Rungs 1, 2 and 5 consult rendered state: whether a rendered name's declared
type admits a subscript, whether every leaf of a term has a C spelling, and the
shape of the rendered address expression. That is what makes the spelling
undecidable from the plan's side today, and so the plan does not decide it.

## Definitions

An access `a` has an object `o(a)`, an address value `v(a)`, an offset inside
the object `δ(a)` when the memory fact states one, a width `w(a)`, and an op
site. The facts available before rendering are:

- `M(a)`: a member fact, `(field, field_offset)` inside `o(a)`'s declared type;
- `R(a)`: an array fact, `(base, index, element_stride, field_offset)` whose
  base and index are semantic identities (a parameter slot or an expression);
- `S(a)`: the canonical term the rewriter assigned to the access, and the
  canonical term of `v(a)`;
- `D(o)`: whether `o` is a declared stack slot, and the binding `b(o)` the plan
  bound it to;
- `T(x)`: the declared C type of a binding or parameter, which the plan's
  symbol facts own.

A spelling is one of

    SlotName(b)                  the slot's own name
    SlotMember(b, field)         a declared member of the slot
    ParamArray(slot, index[, field])   an element of an array a parameter points at
    Subscript(term)              the rewriter's proven element access
    Linear(base, index, stride, offset[, field])   a member or element off a proven linear address
    Deref(v)                     the address, dereferenced

and `needs_address(σ)` is true exactly for `Linear` and `Deref`.

## The consistency condition

Elision of an address value `v` is sound only if no access spelled from `v`
needs it:

    E(v)  ⇒  ∀ a with v(a) = v :  ¬needs_address(σ(a))

Today `E(v)` is `v ∈ geometry`, a certificate that `v` is only ever used as the
address of a stack object, and `σ` is computed afterwards by a different
component. The condition is not checked anywhere; it is assumed, and every one
of the twelve refusals is an instance of it failing.

## Decision

The plan computes `σ` for every access from the facts alone, stores it as
`access_syntax(StructuredAccessId)`, and derives elision from it:

    E(v) := v ∈ geometry  ∧  ∀ a with v(a) = v : ¬needs_address(σ(a))

The renderer becomes a total function of `σ`: one lookup, one `match`, no
ladder. The three rendered-state conditions become fact conditions:

- `name_may_be_subscripted(base)` is `T(base) ∈ {pointer, array, unknown}`,
  where `base` is the binding or parameter the rendered name would have stood
  for; the plan owns both the binding and its type.
- "every leaf of the term has a C spelling" is: every leaf value of `S(a)` is
  bound or inlinable in the plan's partition, and every operator in the term
  has a rendering. The partition is already the plan's; the operator set is
  the term arena's, fixed.
- the linear decomposition of the address is taken from the canonical term of
  `v(a)`, not from the rendered expression; the rewriter's term is the fact
  the rendered expression was made from.

Rung order is preserved as the priority order of `σ`'s derivation, because it
encodes real precedence (a declared member outranks an address equivalence;
offset zero of a slot is the slot only when the access is as wide as it).

## What step 1 measured

Over the thirteen-binary corpus the plan's `σ` and the ladder agree at every
access the ladder renders. The only disagreements, twenty-five of them, are
accesses where `σ` says `Address` and the ladder refused, and every one has
the same shape: the access's stack object was refused a binding
(`ParameterHomeWidthMismatch` 14, `UnclassifiedSourceRole` 6,
`MissingSourceIdentity` 5), so no slot spelling exists and the address that
would have stood in for it has no name either.

Two corrections follow. The consistency condition above already holds: a
geometry address never needs its value, because the renderer spells a bound
object's address as `&slot`, and the twelve refusals were never a plan-versus-
renderer disagreement. And "derive `DeadStackBase` from `σ`" is wrong as a
step: forcing those addresses to bind was tried and cost 26 functions, since a
bound `sp + k` has no program variable to stand on. The remaining work is the
three object refusals, each a modelling question about the slot, not about
its spelling.

## Steps

1. Add `access_syntax` to the plan, computed at build from the facts above.
   Until the renderer switches, an audit compares the plan's `σ` with what the
   ladder produced for every access rendered, and any disagreement is evidence
   named `access-syntax-audit`. The audit is the proof that the fact
   conditions equal the rendered-state conditions on the corpus.
2. Switch the renderer to `σ`. Delete the ladder and the three rendered-state
   conditions.
3. Close the three stack-object refusals that leave an access with no spelling.
   Done: a parameter home is verified by its stores; an argument slot that is
   no parameter's own location is a local; a slot read at several widths is a
   byte array and its accesses spell through the slot's address, which added
   the `slot-bytes` rung to `σ` and to the ladder alike. The owner path now
   refuses to let a name stand for a narrower access or an array. 763 to 770.
4. Switch the renderer to `σ` and delete the ladder and the audit.

Each step keeps the gate at 54 of 54 and is measured by the census.
