# ADR: one owner for how a memory access is spelled

Status: superseded by D (doc/adr-decompiler-rewrite.md): the binding plan was
deleted with legacy r2dec on 2026-10-10, and the renderer spells an access in
`render::frame` and `render::terms`.

## Decision

The binding plan decides how every memory access is spelled, from facts alone,
and the renderer asks. This replaces a six-rung ladder in the renderer that
inspected rendered expressions after the plan had already elided the values
those expressions needed.

- **`AccessSyntax`** (`crates/r2dec/src/binding_plan/access_syntax.rs`) is
  stored per `StructuredAccessId` and is total: an access that no structured
  shape fits is spelled by its address. Its variants are `SlotName`,
  `SlotMember`, `SlotBytes`, `SlotIndexedBytes`, `ParamArray`, `PtrMember`,
  `Subscript` (the rewriter's proven `base[index]`) and `Address`
  (dereferenced, or decomposed as `base + index * stride + offset`).
- **Derivation is in priority order,** because the order encodes real
  precedence: a declared member outranks an address equivalence, and offset
  zero of a slot is the slot only when the access is as wide as the slot.
- **Every rendered-state condition becomes a fact condition:**
  - `name_may_be_subscripted(base)` holds when the declared type of the
    binding or parameter is a pointer, an array or unknown;
  - "every leaf of the term has a C spelling" holds when every leaf value of
    the access's canonical term is bound or inlinable in the plan's
    partition, and every operator has a rendering;
  - the linear decomposition of an address comes from the canonical term of
    the address value, never from the rendered expression.
- **Elision invariant:** an address value may be elided only if no access
  spelled from it needs the address. A geometry address never does, because a
  bound object's address is spelled `&slot`.
- **An object's address is a term.** The exact base address of a certified
  stack object is `TermKind::ObjectAddress(o)` (`exact_stack_object_address`),
  a leafless constant of the frame, like a `Literal`. The plan admits it as a
  frame constant (`frame_constant`), the renderer spells it in every position
  (`materialize_term`), and the ledger counts repeated occurrences as repeated
  spellings.
- **What makes a frame position an object:** a declared slot, a direct
  access, an address that leaves as a value, a position the stack pointer
  takes, or the base of an indexed access that is not displaced below its
  origin. A folded displacement (`buf + len - 3`) resolves to `buf` with an
  interior offset; an indexed address from a displaced base refuses the array
  layout (`DisplacedIndexBase`). An object whose accesses are indexed is sized
  by its frame gap.

## Done

- The plan computes `access_syntax`; an audit compared it with the ladder
  over the corpus until they agreed.
- The three stack-object refusals that left an access unspellable are closed.
  A parameter home is verified by its stores; an argument slot that is no
  parameter's own location is a local; and a slot read at several widths is a
  byte array (`SlotBytes`).
- `render_certified_memory_expr_for_fact` is one `match` over the plan's
  answer. The ladder and the audit are deleted.
- `ObjectAddress` terms replace the separate call-argument address path.

## Left

Nothing in this ADR. The binding plan itself is replaced by R
(doc/adr-renderer-printer.md), which keeps `AccessSyntax` as the plan's
answer.

## Consequences

- Deriving `DeadStackBase` from the spelling was tried and rejected. Forcing
  geometry addresses to bind cost 26 functions, because a bound `sp + k` has
  no program variable to stand on.
