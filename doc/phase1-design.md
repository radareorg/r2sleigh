# Phase 1 design: the text spells one width and one type per object

Derived from measurement before planning, as the standing rule asks, and
reviewed once by a second reader whose corrections are folded in and named.

## 1. What the population pays for

Measured on the arm64 `bzip2` at -O2 used for the Phase 0 census (107
functions radare2 finds, 6017 rendered statements) against the plugin at
`3707db52`, with the r2r suite (95 of 97) and the sixty-cell corpus as the
other two instruments. Ranked by cost summed over the population.

**Refusals: 56 of 107 functions.** 43 are import stubs, twelve bytes apart in
`__stubs`: `adrp x16; ldr x16, [x16, off]; br x16`. Each is one function in
every coverage denominator. Of the 64 functions with a body, 13 refuse, in
six classes, none larger than four:

| class | functions |
| --- | --- |
| `format_argument_not_literal` (a variadic call whose format is not a literal) | 4 |
| return boundary absent or naming another instruction (`implementation.rs:1432`) | 2 |
| `MissingNormalizedSiteContext` | 2 |
| missing program-variable authorization (a memory access with no planned expression) | 2 |
| `CallOther` or a non-memory load (`implementation.rs:1726`) | 1 |
| `unobserved_binding_read` at placement | 1 |
| an effect obligation refused at a call | 1 |

Coverage on `bzip2` is therefore 51 of 107 with stubs in the denominator and
51 of 64 without. The stubs are the multiplier.

Why the stubs refuse: the capture's tail-slot advisory names the `adrp`
page (`0x100014000`) as the slot while the lifted transfer reads
`0x100014010`, so `unique_call_site_identity` matches nothing, no call-site
certificate exists, and the journal refuses an exact use with no rendered
occurrence. The Rust side already recovers the slot correctly from the
`adrp`+`ldr` pair (`terminal_indirect_loaded_slot`); the C side takes
radare2's `op.ptr` of the `br`, which carries the page and not the `ldr`
displacement. Whether that is radare2's arm64 analysis or the capture's
reading of it is the first thing 1a traces.

**Casts: 3001 in 6017 statements.** 1745 sit directly on a name. 731 of
those narrow a 64-bit name to 32 or fewer bits, and 400 of the 731 are on
188 names that are never read at their declared width: `uint64_t X28_2`
read only as `(uint32_t)X28_2`. The object's storage is 32 bits wide and is
declared at the register's width. The remaining 1256 name casts and 1006
expression casts are conversions between an operand's declared type and the
type the operation states, emitted operand by operand after the tree is
built.

**Temporaries: 1360 declared with an initialiser**, 295 read exactly once:
793 arithmetic, 272 loads, 234 copies or width casts of a name, 61 calls.

## 2. The derivation, and what the review corrected

The rendering assigns a type to each *value* (a binding from its widest
carrier, a literal from its spelling, a call from its prototype) and then
asks `convert` to reconcile that type with the type each operation states,
one operand at a time. Every place two local decisions disagree emits a
cast, and nothing sees the whole. Phase 0 removed this shape from the
partition; Phase 1 removes it from widths and conversions. The first draft
overreached in three places, and the review's counterexamples are kept here
because they are the specification's edges.

**Width is storage, not computation.** An object may be declared at the
widest *slice endpoint* any read takes of it -- `offset + width`, rounded up
to a supported width -- while its definition stays at the machine's width
and the assignment truncates. Narrowing the *computation* is a different
claim and a false one: `low32(2^32 / 2)` is `0x80000000`, truncating before
the division gives zero; carry, overflow and signed comparisons read the
full operand. So 1b changes a binding's declared width and leaves every
operation's width where the machine put it; the write projection into a
narrower object is the truncation the assignment performs. And "reads" is
every read: exact use slices, `MemoryAddress` uses, call and store operands,
return boundary values, phi-edge conversions and the live-out set, which
`binding_width` today skips when a use is not `Exact`. A memory object whose
address escapes is not narrowed by SSA reads at all; its width is its layout.
The call-result rule Phase 0 added is one instance and is deleted as a
special case once the general rule proves the same.

**Types are decided per node and per edge, and the seam exists.**
`r2rewrite::typed::TypedBoundaries` already states, for every machine and
canonical-term node, what it produces and what it requires of each operand
*edge* -- one leaf serves a signed comparison and an unsigned addition
without a second copy -- and applies C's integer promotion once. 1c extends
that contract rather than adding a solver over the rendered tree, which
would be a second owner of the same answer. The evidence lattice keeps
`Top` (nothing learned) apart from `Bottom` (two things learned that cannot
both hold); a node at `Top` keeps its machine type and its conversions, a
node at `Bottom` is a refusal with the conflict named, and neither is
"machine width by default".

**A dropped conversion is a proved one.** Implicit C conversion is not
semantic equivalence: `uint16_t a = b = 65535; uint32_t r = a * b` overflows
`int` after promotion; `uint8_t t = a + b; return t == 0` folded to `return
a + b == 0` loses the byte wrap; a shift's result width follows the promoted
left operand; `0xffffffff` legitimately feeds a signed `< 0` and an unsigned
division. So 1c never removes a conversion because the endpoint types
match. It removes one when the operation's own boundary says the conversion
is the identity on the values that reach it: the operand's produced type
already is the required type after promotion, and the operation's width
truncation point is kept. Every operation keeps its width; what goes is
the restatement of a width the text already has. Pointer conversions keep
the same discipline: a `void *` converts implicitly at an assignment,
argument or return and nowhere else, and pointer arithmetic is spelled from
provenance and element width, never from a solved endpoint type.

**A folded load is a sequencing question, not a typing one.** The hazard
rule the folds use checks intervening definitions against binding groups;
it knows nothing of stores, calls, volatility or C's evaluation order. `t =
*p; *q = 7; use(t)` cannot fold when `p` may alias `q`; `t = *p; f(t, (*p
= 7))` folded is an unsequenced conflict; folding into `&&` or `?:` makes an
unconditional load conditional. Load folding is therefore not in Phase 1.
It needs its own memory-dependence and sequencing proof and is Phase 2's
subject. Same-object width projections are not loads and do fold under 1c,
as the use slice they already are.

**A stub is a forwarding, and it is proved.** `x0 = 7; br [slot]` is a
wrapper with a body, not an import declaration. 1a generalises
`variadic_forwarding_stub`'s observable-state check -- nothing stored, no
other call, no register written that the transfer does not carry -- to every
import stub with a prototype, renders the import's declaration and a comment
naming the import, and does not invent a prototype where none is known: a
stub without one renders as a residual naming the import, which is honest
and still counted. Declarations are their own coverage category and both
denominators are reported, as the standing decision on coverage already
says: on `bzip2` the expected outcome is 51 bodies plus 43 declarations of
107, not "94 rendered".

## 3. Decisions

1. Phase 1 is three deliverables, in this order: 1a import stubs as proved
   forwardings; 1b storage width as the maximum slice endpoint over every
   read; 1c conversions decided at `TypedBoundaries` edges and removed only
   where the boundary proves identity.
2. Load folding is Phase 2, with its own dependence and sequencing proof.
3. Phase 1 deletes, once the replacement proves the same obligation and not
   before: the call-result width special case in `binding_width` and
   `seal_width_evidence`; the implicit-pointer arms added to `convert_typed`
   at the end of Phase 0; `variadic_forwarding_stub` as a variadic-only
   route. `expression_renders_inline` and its transitive check stay until
   Phase 2 replaces them with a compositional materialisation guarantee.
4. Each deliverable is measured on the same three instruments before and
   after, with the numbers of section 1 as the baseline.

## 4. Invariants Phase 0 established that Phase 1 keeps

One partition, decided by liveness, refined by nothing downstream: 1b
changes a binding's declared width, never its membership. Copies are value
facts and a projection folded by 1c is a use slice of the same object. The
hazard is judged against the rendered partition, and Phase 1 adds no new
mover. The seal checks the plan, not a second derivation: the width the
seal expects is the same slice-endpoint rule, from the same use set.
