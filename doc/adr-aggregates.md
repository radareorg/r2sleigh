# ADR: structures laid out from a parameter's accesses

Status: proposed 2026-10-14 (ROADMAP P9's first exit, T's exit).

## Problem

A stripped function that reads a structure through a pointer parameter
renders that parameter as `void*` or `uint8_t*`. Each field read is a byte
load at a computed address. `mixed_touch(struct mixed *value)` in
`tests/corpus/shapes.c` reads a `uint8_t` at offset 0, a `uint16_t` at 2, a
`uint32_t` at 4 and a `uint64_t` at 8. It renders as `fcn_401620(void*
arg0)` with `r2sleigh_load_u16((void*)((uint64_t)arg0 + 2))`.

The engine already proves every fact a structure needs:

- r2ssa states each certified access's width and its address as
  `parameter_expression`: a parameter, index terms, a constant offset;
- r2types solves each accessed value's type;
- r2dec defines declared aggregates (`render::tags`, from the interface's
  `SourceTypeGraph`) and types a parameter as a pointer to one.

Only stripped functions miss these facts, because they have no type graph.
The confidence-scored struct paths that tried to fill the gap reached no
graded output. They are measured and deleted under ROADMAP T.

## Decision

A pointer parameter whose every access is a constant-offset field is typed as
a pointer to a structure laid out from those accesses. Any other parameter
keeps today's rendering, and the proof line states the reason.

What the accesses prove is the layout: which bytes are read and written, at
which widths. Spelling that layout as a structure is a choice. A source that
read a serialized `uint8_t *` buffer at the same offsets compiles to the same
loads, so the structure states no semantics the accesses do not. Whether the
source declared a structure is unprovable either way. The tag
`fcn_<entry>_arg<slot>` marks the type as inferred, and the proof line says
`1 structure laid out from a parameter's accesses`.

### The invariant

The parameter's entry value P is **field-addressed** when both hold:

1. Every certified RAM access whose `parameter_expression` names P has no
   index terms. Its offset `c` and width `w` are constants.
2. Every memory operation whose address P reaches is one of those certified
   accesses. P reaches a value through def-use: a copy, an extension,
   arithmetic, a merge, or a reload of P's certified home. Reach ends at a
   load's output. That value is memory contents, a new root, which r2ssa
   states as a `PointeeAddressExpression`. A followed pointer field
   (`n->next`) is therefore the pointee's business, not P's layout. A loop that
   walks `p += 8` reaches its merge, and the merge has no parameter
   expression. An access through it therefore refuses, and so does any
   access r2ssa could not certify, because the layout would miss or
   misplace a field. Reason: `access through the parameter at <inst> is not
   a constant field`.

Other uses of P do not bear on its pointee: a call argument, a comparison,
a spill to its home, or a return. C spells each of them on a structure
pointer. A callee handed P may read more fields. The layout is a lower
bound, which is how the lattice's width subtyping reads a structure.

The accesses give fields `(c, w)`. Two accesses at the same `(c, w)` are one
field. Its type is the meet of the solved types of the accessed values.
`Bottom` refuses the parameter, and the reason names both instructions.
Two fields that overlap but differ in extent refuse. Reason:
`fields overlap at +c`. The fields must have at least two widths. Fields of
one width are as much an array's elements read at constant indices as a
structure's members; a single field at offset 0 is a scalar pointer, which
the solve already types. A field whose offset is not a multiple of its width
refuses. Reason: `field at +c is not aligned`. With every field aligned,
plain C places each member at its offset, and the declaration is a true
statement without `packed`. 

### Owners

| Fact | Owner | Contract |
|---|---|---|
| Accesses, offsets, widths | r2ssa | `certificates().memory_accesses`, `addresses().parameter_expression` (exist) |
| Every access P reaches is a certified constant-offset one | r2ssa | a per-slot fact over def-use, beside `parameter_expression` (new) |
| Layout: fields, their types, padding, the tag | r2types | `FunctionTypeFacts::inferred_aggregates`, keyed by slot, as `AggregateDefinition` (new field, existing type) |
| The parameter's type | r2types | `certified_parameter_pointers`, which already decides each accessed parameter's pointee for signature inference and the exact source signature, returns `Pointer(Struct(tag))` where the layout holds (extended) |
| Definition and spelling | r2dec | `render::tags` defines a tag the type graph states or r2types infers (extended) |

A field's type is the solve's type for the accessed value
(`EvidenceTypes::value_type`), when that is a scalar of the field's width.
Otherwise it is the unsigned integer of that width, as a certified scalar
pointee is spelled today. The tag is `fcn_<entry>_arg<slot>`, never a
hash. Field names are `f_<offset in hex>`. Padding between fields is
`uint8_t _pad_<offset>[n]`. The layout states nothing past the last field.
Accesses reach the object only through the pointer, so no `sizeof` and no
by-value copy reads its extent.

A declared type outranks an inferred one. `apply_exact_source_signature`
upgrades a parameter to a certified pointer only when the interface's graph
holds carrier widths alone (`Basis::CarrierWidth`). A declared graph,
including one with an aggregate, is never re-laid out. P's type therefore
has one last writer, and the layout runs inside it.

### Rendering

First exit: the parameter is spelled `struct fcn_401620_arg0* arg0`, and its
definition is emitted once before the function, as `render::tags` does for a
declared tag. Accesses keep their byte-load spelling. That spelling is what
the declared path renders today: `declarations.rs` asserts no `->`.

Second exit (P9b, inferred aggregates, 2026-10-14): an access through a
parameter that points to its inferred structure is spelled at the member's
address, `r2sleigh_load_u16((void*)&arg0->f_2)`. r2types states each
structure's member per accessed offset (`FunctionTypeFacts::parameter_structures`).
r2dec joins it with r2ssa's `parameter_fields`, which names each access by
its structured access id, and gives that access's canonical cell the member's
address in place of the byte offset. The read or write stays the byte copy
every cell uses. The address arithmetic is discharged as before, so the
proof line does not move. All or nothing per parameter: one access with no
member keeps the byte spelling for every access through that parameter. The
gate is the parameter's rendered type, so a declaration that wins keeps the
byte spelling. Declared aggregates need that check against the declared
layout and are the next step.

Aliasing and alignment: the accesses prove offsets and widths. They do not
prove the effective type or the alignment of what the parameter points to:
a serialized byte buffer read at the same offsets is indistinguishable. So no
member lvalue is formed. `arg0->f_2` would assert both, and optimized C could
then miscompile a valid program. The byte copy at the member's address
asserts neither. Like every byte copy, it is spelled only for a
little-endian target.

Declared pointers (2026-11-12, after the S9 graph converter): a pointer
spells what it points at through a typedef, so `pool *` with
`typedef struct pool pool` is `struct pool*`. S9 began wrapping each named
type in its alias, and `pointee_spelling` refused the wrap, which took pigz
from 30 headers naming `struct T*` to 1. A pointer may also name a tag the
declared graph states, laid out or opaque, that the unit does not define:
`render::tags` declares it incomplete (`struct lock_s;`), which C allows
behind a pointer, and a definition holding such a pointer stays definable.
An inferred `fcn_*` tag is never declared incomplete, since no source states
it. A tag the unit's graphs (its own and each callee's) state as both a
struct and a union has no one declaration: no pointer names it, each falls
to its class, and the proof line names the tag. A call to the function's own entry passes the header's types, and a
declared callee prototype spells each parameter it can, the rest at their
class, so a typed pointer never meets an integer at a call.

### Cost

- r2ssa's reach fact is one forward pass over each formal's def-use closure,
  ending at load outputs, calls and stores: `O(P · (values + uses))` for P
  formals, since closures that two formals share are walked once for each.
- The layout is one pass over the function's certified accesses,
  `O(A log A)`, sorted by offset.
- Neither runs a fixpoint.

## Validation

- Behavior test in `r2engine/tests/engine/native.rs` style: a byte-literal x86-64
  function reading `+0` u8, `+2` u16, `+4` u32 and `+8` u64 through `rdi`
  renders `struct fcn_<entry>_arg0* arg0` and the definition text.
- Negative tests: an indexed access refuses; an uncertified access refuses;
  overlapping widths refuse; a single offset-0 access stays a scalar
  pointer.
- The census moves on purpose, and each moved line is read. Equivalence must
  keep every cell. `mixed_touch`, `shape_struct_pointer` and
  `shape_struct_value` are equal today, so the check is zero loss.

## Measured (first exit, 2026-10-14)

`mixed_touch` renders `struct fcn_401620_arg0* arg0`, and its definition
places `f_0`, `f_2`, `f_4` and `f_8` at their accessed offsets. The census
moves 5 functions, and each one gains a definition and a structure pointer
parameter: `mixed_touch`, `rec_spread`, `out_param_parse` at `-O0` and
`-O2`, and Mach-O `_main`.

A first draft required only two offsets. Under it, `_main`'s `argv` (reads
of `argv[1]` to `argv[3]`) and a 16-byte store split into two `uint64_t`
became structures. Requiring two widths keeps them pointers.

## Not decided here

- Recursive and polymorphic aggregates (P9 after T).
- Structures reached through a local or a global.
- Arrays of structures (`shape_struct_array`).
- Member spelling for locals.
- Callers' declarations of an inferred structure parameter: a caller still
  declares `uint64_t mixed_touch(uint64_t)` while the definition takes
  `struct fcn_4017ac_arg0*`.
