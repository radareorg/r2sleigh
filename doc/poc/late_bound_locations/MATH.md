Late-Bound Locations: The Higher-Dimensional-Algebra Model
==========================================================

This note formalizes the late-bound location model of `doc/scripting.md`. It is
worked out *locally and mathematically* — no external sources — and every claim
here is discharged computationally by the POC in `src/lib.rs` (the test names in
parentheses are the machine-checked witnesses).

The one-sentence thesis: **a debugger location is not a number; it is a section
of a bundle over the execution timeline, its address lives in a torsor, and
resolution is evaluation of that section — defined exactly on its validity
domain.** Everything the design wants ("meaning not addresses", staleness
safety, time-travel, offset math that can't be confused with addresses) is a
corollary of taking that structure seriously instead of collapsing it to a
scalar.


0. Notation
-----------

- `T` — the execution timeline (the **base space**).
- `A` — the set of machine addresses.
- `Z = (ℤ, +)` — the additive group of byte offsets.
- A *down-set* `U ⊆ T` — a set of times closed downward under `≤` (an initial
  segment / interval). Validity domains are (unions of) such sets.


1. The address torsor  (test: `addresses_are_a_torsor_over_offsets`)
--------------------------------------------------------------------

Addresses do not form a vector space or a ring — there is no meaningful "zero
address" and no meaningful "sum of two addresses". What they *do* form is a
**torsor** (a principal homogeneous space, equivalently an affine space) over
the group `Z`:

- an action `+ : A × Z → A`, `(a, o) ↦ a + o`, that is
- *free and transitive*: for every pair `a, b ∈ A` there is a **unique** offset
  `b − a ∈ Z` with `a + (b − a) = b`.

The torsor axioms are exactly the algebra a memory model needs:

```
    a + 0        = a                 (identity)
    (a + o₁) + o₂ = a + (o₁ + o₂)     (compatibility with the group law)
    a + (b − a)  = b                 (difference inverts translation)
```

The crucial *negative* fact is that `A × A → A` (adding two addresses) is **not**
an operation of a torsor. In the POC this is enforced by the type system: `Addr`
implements `Add<Offset>` and `Sub<Addr> = Offset`, but there is deliberately no
`impl Add<Addr> for Addr`, so `addr + addr` fails to compile. The absence *is*
the axiom. This is why "offset arithmetic stays inside the typed location":
offsets live in the acting group `Z`, addresses in the torsor `A`, and the two
can never be conflated.

**Grading by type.** A recovered type `τ` chooses a distinguished basis of `Z`:
a `struct` supplies field offsets, an array of `T*` supplies the stride
`sizeof(T)`. So the offset module is `Z`, but the *type* is the grading that
turns raw integers into named field/element displacements — pointer arithmetic
on `T*` is multiplication of an index by the type's stride. (Tests
`offset_math_is_type_driven_and_stays_inside`.)


2. The execution timeline as a base space
-----------------------------------------

Take `T` with its order `≤`. For the single-threaded / single-trace case `T` is
totally ordered (the POC uses `Time = u64`). The honest general case — needed
for threads and for branching replay — is a **poset** `(T, ≤)` of "happens
before", which is a small category. Nothing below depends on totality; it only
uses that validity domains are down-sets and that restriction goes along `≤`.

Over `T` we have the observable state of the machine as **time-versioned
functions**:

```
    reg  : Reg × T ⇀ Word          reg(r, t)  = latest write to r  at time ≤ t
    load : A   × T ⇀ Word          load(x, t) = latest store to x  at time ≤ t
```

Both are partial (`⇀`): undefined before anything has been written. They are the
POC's `World::reg_at` / `World::load`. Because they are indexed by `t`, the
*same* query answers "what is it now" and "what was it at time t" — this is the
seed of time-travel (§6).


3. A location is a section of the address bundle  (the core)
-----------------------------------------------------------

Form the trivial **address bundle** `π : E → T` whose fibre over each time is
the address space, `E_t = A`, so `E = T × A` and `π` is the first projection.
(Writing it as a bundle rather than "just `A`" is what keeps the time index
attached; over a poset the fibres can differ, e.g. per-thread address spaces,
and `E` stops being a product — hence "bundle".)

> **Definition.** A *location* is a **partial section** of `π`:
> a down-set `U ⊆ T` (its `validity_domain`) together with a map
> `σ : U → E` such that `π ∘ σ = id_U`. Equivalently `σ(t) = (t, addr(t))`
> for a partial function `addr : T ⇀ A` with domain `U`.

Reading off the design tuple `(region, offset, size, type, provenance,
validity_domain)`:

- `type`, `size` are the grading (§1) and the read width;
- `provenance` is *how `addr` is defined* (§4);
- `validity_domain` is `U = dom(addr)`;
- `region`/`offset` are the coordinates provenance uses to compute `addr`.

**Resolution** is evaluation of the section:

```
    resolve(σ, t)  =  addr(t)      if t ∈ U
                   =  ⊥ (a typed error)   if t ∉ U
```

This single line is the entire safety story (§5): `resolve` is a partial
function *total exactly on `U`*, so it either returns the correct in-fibre
address or refuses — it can never return an address for a time where the
location has no meaning. `Location::resolve` in the POC is this function; the
`LocErr` variants are the concrete faces of `⊥`.


4. Provenance = how the section is built  (three shapes)
-------------------------------------------------------

The three provenance kinds are three ways to produce a section, in increasing
"dimensionality" (constant → varying → composite).

### 4.1 Allocation-rooted: a locally constant section
`(test: alloc_rooted_is_constant_over_its_lifetime)`

An allocation is a stable identity with a lifetime `U = [born, freed)`. Its
address is fixed on `U`, so the section is **locally constant**:

```
    addr(t) = base + off          U = [born, freed)
```

This is the "snapshot address, liveness-tracked validity" policy: the value is a
constant (the snapshot), but the *domain* is the live interval. Evaluating at
`t ≥ freed` is out of `U` ⇒ `UseAfterFree`; at `t < born` ⇒ `NotYetLive`.
(Categorically: the constant sheaf on the open set `U`.)

### 4.2 Frame-relative: a genuinely varying section
`(test: frame_relative_rebinds_live)`

A local/parameter is only meaningful during a frame activation `U = [entry,
exit)`, and its address tracks the frame pointer, which is itself a section
`reg(fp, ·)`:

```
    addr(t) = reg(fp, t) + off     U = [entry, exit)
```

This is a non-constant section — `addr` really is a function of `t`. That is
exactly what "live re-bind" means: the same handle resolves to different
addresses as `fp` moves (e.g. `alloca` within one activation), and is undefined
(`OutOfFrame`) outside `U`. It is a section of the *pulled-back register bundle*
translated by `off`.

### 4.3 Type-projected: fibered composition
`(tests: projection_rewalks_at_evaluation_time, null_deref_is_an_error)`

`obj->next->data` reads a pointer out of a base section and lands past it:

```
    addr(t) = load(addr_base(t) + p, t) + q
    U       = { t ∈ U_base : load(addr_base(t) + p, t) is defined and ≠ 0 }
```

where `addr_base` is the base location's section, `p` the pointer-field offset,
`q` the result offset. This is a **composition** of sections through the
memory map `load` — a fibre-product / pullback in the slice category over `T`.
Because `load(·, t)` is evaluated at the *current* `t`, the pointer chain is
**re-walked at evaluation time**: repointing `next` in memory moves where the
identical handle lands, with no re-query. A null or unmapped pointer removes
that `t` from `U` (`NullDeref` / `Unmapped`) — again, refusal rather than a wild
address.

Projection is where "higher-dimensional" bites: a location is no longer a point
but an arrow built by composing sections, and the interesting locations
(`a.b->c[d]`) are morphisms in this category, not integers.


5. The safety theorem  (test: `stale_handle_raises_never_returns_garbage`)
--------------------------------------------------------------------------

> **Proposition.** For every location `σ` with domain `U`, and every `t`,
> `resolve(σ, t)` returns an address **iff** `t ∈ U`; and when it does, that
> address equals `addr(t)`. In particular it never returns an address for
> `t ∉ U`.

*Proof.* By construction of §4: each provenance arm computes `addr(t)` only
after checking its domain predicate, and returns `⊥` otherwise; composition
(4.3) propagates `⊥` from the base and from `load`. ∎

The consequence is the whole point of the design. Stale bytes may still sit in
memory (`load(x, t)` can be defined past `freed`), but a *location* whose domain
has ended will not resolve there, so `read`/`write` raise instead of handing
back a stale value. The POC test asserts both halves: the raw bytes are still
`0xdead` in memory, and yet `handle.read` returns `UseAfterFree`.


6. Restriction, stalks, and the escape hatch
---------------------------------------------

Sections over an ordered base come with **restriction maps**: for `V ⊆ U`,
`res^U_V : Γ(U) → Γ(V)` just shrinks the domain. Two derived operators of the
design are restriction phenomena.

- **`.at(t)`** `(tests: at_evaluates_at_a_chosen_timepoint,
  at_cascades_into_projection)` is evaluation at the **stalk** over `t`:
  restrict to `{t}` (when `t ∈ U`) and take the value. It is well-defined
  precisely when `t ∈ U`, which is why the same handle can read a *historical*
  state (`t` in the past, `now` far in the future) and unifies live debugging
  with replay: live is the special case `t = now`. In the POC the pin cascades
  into a projection's base, so an entire `a->b->c` walk is evaluated coherently
  at one timepoint.

- **`.snapshot(t)`** `(test: snapshot_opts_out_of_validity)` is the deliberate
  **forgetful** map: evaluate `addr(t)` once and keep only the bare address,
  discarding the section structure (domain and restriction maps). The result is
  an element of the constant presheaf `A` — it no longer knows any validity, so
  reading through it after `freed` succeeds (returns stale bytes) *by explicit
  choice*. It is the only door out of §5's guarantee, and it is greppable.


7. Why the scalar model fails (the degenerate collapse)
-------------------------------------------------------

The conventional "a location is an address" model is the **0-dimensional
collapse** of this structure: forget the base `T`, forget provenance, keep a
single fibre element. Under that collapse:

- restriction maps vanish ⇒ no validity domain ⇒ use-after-free is a silent
  wrong read (the §5 theorem has nothing to state);
- the torsor degenerates to "addresses are numbers" ⇒ offsets and addresses are
  the same type ⇒ pointer/offset confusion;
- sections degenerate to constants ⇒ no live re-bind, no re-walk, no `.at(t)`,
  no unification with replay.

Every capability the design asks for is precisely a piece of structure the
scalar model threw away. Keeping the extra dimensions — time as a base, address
as a torsor, location as a section, projection as composition — *is* the
feature. The POC shows the structure is small, total, and implementable without
a new language: it is a data type plus one evaluation function.


Correspondence table
--------------------

| Design term (`doc/scripting.md`) | Mathematical object | POC symbol | Proof |
|---|---|---|---|
| address / offset | `Z`-torsor `A` and its group `Z` | `Addr`, `Offset` | `addresses_are_a_torsor_over_offsets` |
| execution position over time | base poset `T`; state sections | `Time`, `World` | (substrate) |
| location handle | partial section `σ : U → E` | `Location` | all |
| `validity_domain` | `U = dom(addr)` | domain guards in `resolve` | §5 tests |
| resolve at read/write | evaluate `σ(t)` | `Location::resolve` | all |
| provenance: allocation-rooted | locally constant section | `Provenance::Alloc` | `alloc_rooted_*` |
| provenance: frame-relative | varying section `fp(t)+off` | `Provenance::FrameRel` | `frame_relative_rebinds_live` |
| provenance: projected | fibered composition | `Provenance::Project` | `projection_rewalks_*` |
| stale handle raises | partiality of `resolve` | `LocErr::*` | `stale_handle_raises_*` |
| `.at(t)` | stalk evaluation / restriction | `Location::at` | `at_*` |
| `.snapshot()` | forgetful map to constant presheaf | `Location::snapshot` / `Frozen` | `snapshot_opts_out_*` |
