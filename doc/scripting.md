Dynamic Analysis Scripting: Language & Location Model
=====================================================

Status
------

Design decision. This document records the outcome of a research effort into
whether r2sleigh should ship a **purpose-built dynamic programming language**
for live debugging and exploitation — one that operates on registers, memory,
threads, and breakpoints at a lower level than GDB+pwntools while letting the
user script in terms of program *meaning* (functions, variables, types) rather
than raw addresses.

The decision is **no new general-purpose language**. Instead, r2sleigh should
expose a typed execution model, a small query/expression layer over it, and a
restricted probe sublanguage for in-target injection, with existing languages
(Python first) as the glue. The centerpiece of the model is a **late-bound,
typed location** with an explicit temporal validity domain.

This is a design note, not an implementation commitment. It exists to keep the
reasoning durable and to give later work a fixed target.


The Question
------------

The appeal is real: when you debug, you think "the `len` field of the request
struct the parser just allocated," not "`[rax+0x18]`." A tool that lets you
*name the thing by what it is* and computes the address later would collapse a
lot of manual offset bookkeeping. The proposal was to make that a language:
late-bound locations, offset math that stays inside a typed location type, and
a raw address materialized only on an actual read or write.

The open sub-question was **binding time**: when you later read or write
through a handle like `heap.find(req)`, does it use the address captured *at
query time* (snapshot) or re-resolve against *current* execution state (live)?


Decision: No New General-Purpose Language
-----------------------------------------

New general-purpose debugger languages have a consistent track record of
failure, and the successes point elsewhere. The evidence:

| Prior art | Outcome | Lesson |
|---|---|---|
| Acid (Plan 9), Duel (GDB), MzTake, Expositor, PTQL | Died, or rebuilt on an existing host language | General-purpose debugger DSLs don't spread |
| WinDbg `dx` + LINQ over an object model | Widely adopted | Success came from an **object/query model**, not new syntax |
| GDB agent bytecode, Frida CModule, DTrace `D`, bpftrace | Shipped and used | Fast paths are **restricted, compiled subsets**, not full languages |
| Narrow probe/condition DSLs | Spread | Narrow beats general for the in-target case |
| Python (pwntools, angr, GEF) | Ecosystem dominance | Users already know it; the libraries already exist |

Two findings settle it:

- **"Meaning, not addresses" comes from facts, not syntax.** The ability to say
  `req.len` instead of `[rax+0x18]` is produced by type recovery, allocator
  knowledge, and ABI models — exactly what r2sleigh already computes. A new
  grammar adds nothing to it; a type-aware *model* provides all of it.
- **Real-time behavior depends on where code runs, not on the language.** An
  in-target check costs tens of nanoseconds; a round-trip to an out-of-process
  scripting host costs hundreds of microseconds. The lever is *placement*
  (in-target vs. host), which is an execution-model concern, not a syntax one.

A new syntax also carries an adoption tax that is now measurable: agents and
humans alike are far more fluent in Python than in any bespoke grammar, and the
dominant failure mode for novel syntax is trivial syntax errors. Inventing a
language spends effort on the one axis with the worst return.


Decision: Four Layers
----------------------

Split the capability into four layers, none of which is a new general-purpose
language:

1. **Typed execution model** — functions, parameters, types, and execution
   positions over time. This is the actual product: the facts that make
   "meaning, not addresses" possible. Built on r2sleigh's existing SSA, type
   inference, and (planned) R2IL VM + event tracing.

2. **Query / expression layer** — a small, C-like expression syntax with LINQ-
   style pipelines for selecting and projecting over the model. Deliberately
   *not* a general-purpose language: no unbounded loops, no user-defined
   control flow beyond pipeline combinators. This is the WinDbg `dx` lesson.

3. **Restricted probe sublanguage** — for conditions and actions that must run
   *in the target*: guaranteed to terminate, no calls back into arbitrary
   target functions, compiles to native code or bytecode for injection. This is
   the GDB-agent-bytecode / DTrace-`D` / bpftrace lesson.

4. **Existing-language glue** — a Python client for pwntools/angr/agent
   fluency, since that is where users and their libraries already are. An
   embedded scripting host (e.g. Luau) can come later if a genuinely in-process
   dynamic language is needed, but it is not on the critical path.

The rest of this document specifies the data type that layers 1 and 2 share:
the late-bound location.


The Late-Bound Location Model
-----------------------------

A location handle is **not an integer address**. It is a typed descriptor that
carries enough provenance to resolve to an address on demand and to know *when*
that resolution is meaningful:

```
Location = (region, offset, size, type, provenance, validity_domain)
```

| Field | Meaning |
|---|---|
| `region` | The address space / memory region the location lives in (heap, stack frame, a mapped segment, a register file). |
| `offset` | Offset within the region. All offset arithmetic stays *inside* the location type; the bare integer never escapes to the user. |
| `size` | Extent in bytes, from the recovered type. |
| `type` | The recovered type (from r2types / decompiler / DWARF), which gives field names, element strides, and projection. |
| `provenance` | *How this location's address is determined.* This field selects the resolution policy (see below). |
| `validity_domain` | *When* the location is meaningful — the set of execution positions (or replay timepoints) at which resolving it is well-defined. |

This is the CodeSurfer-style abstract-location tuple with one addition:
`validity_domain`, the temporal dimension. It is the piece that answers the
binding-time question.

The raw address is **materialized only at the moment of a read or write**, and
that materialization is checked against the current execution position. A
handle whose `validity_domain` does not contain the current position **raises**;
it never silently reads or writes stale memory.


Resolving the Binding-Time Question
-----------------------------------

Snapshot-vs-live is a false binary, because "a location" is not one kind of
thing. Sort locations by **provenance** and the correct policy falls out per
kind:

### 1. Allocation-rooted locations

Example: `heap.find(req)` returns a specific heap chunk.

A chunk is a stable *identity* with a lifetime (malloc → free). Its address is
fixed for that lifetime, so the address is effectively **snapshotted**. But the
handle **live-tracks validity** against the allocator model: after the chunk is
freed, a read does not return stale bytes — it raises.

> Policy: snapshot address, liveness-tracked validity.

Depends on allocation tracking (malloc/free instrumentation) — an r2sleigh
advantage GDB lacks out of the box.

### 2. Frame / register-relative locations

Example: a local variable, a parameter, `rsp+0x10`.

These are meaningless except *at* a program point where the frame is live. The
handle must **re-resolve** each time that frame instance is entered, and is
invalid outside it. Its `validity_domain` is a specific frame activation.

> Policy: live-bind, scoped to a frame instance.

Depends on the recovered stack-frame layout and ABI model (r2sleigh's variable
recovery + calling-convention model).

### 3. Type-projected locations

Example: `obj->next->data`.

A **path** rooted at a location of one of the kinds above. The root carries the
policy; the projection re-walks the pointer chain at evaluation time using the
recovered type. Offset math stays inside the typed location; the user never
handles the intermediate integers.

> Policy: root's policy, projection re-evaluated at read/write.


Defaults and escape hatches
---------------------------

- **Default is safe**: reads and writes error on a stale or out-of-domain
  handle. Staleness is a *typed error*, not a class of silently-corrupt reads —
  which is exactly the kind of bug that turns a debugging tool against its user.
- **Explicit, greppable escape hatches**:
  - `.snapshot()` — deliberately freeze the current address into a plain
    pointer, opting out of validity tracking.
  - `.at(timepoint)` — evaluate the location at a chosen execution position or
    replay timepoint; the result is well-defined exactly when `timepoint ∈
    validity_domain`.

There is no *implicit* staleness anywhere in the model.


Why This Fits r2sleigh Specifically
-----------------------------------

- **It reuses the analysis brain, not a new grammar.** `type` comes from
  r2types / the decompiler / DWARF feeding; frame layout from variable recovery;
  allocation identity from (planned) event tracing over the R2IL VM. The
  "meaning, not addresses" property is produced entirely by facts r2sleigh
  already computes, surfaced through the location type — never by syntax.

- **It unifies live and time-travel debugging under one abstraction.** Because a
  location can be evaluated `.at(t)` and `validity_domain` states which
  timepoints are meaningful, the *same* handle works during live execution and
  over a recorded trace. The R2IL VM + event tracing item on the roadmap
  (Phase 7.2) is the substrate this rides on.

- **It stays in the existing crate boundaries.** The location type belongs in
  the typed execution model (layer 1), alongside SSA/type/ABI facts. The
  query/expression layer (layer 2) is a thin projection over it. Neither
  requires a new language runtime.


Relationship to the Roadmap
---------------------------

This design does not add a new roadmap phase; it constrains how a future
dynamic-analysis capability should be shaped, and it leans on items already
planned:

- **Phase 7.2 (R2IL VM + event tracing)** — the execution substrate. Event
  tracing (mem read/write, branch taken, and — needed here — alloc/free) is
  what makes allocation identity and validity domains computable.
- **Type inference / DWARF feeding (Phase 1.1–1.2, Phase 4)** — the source of
  the `type` field and field-name projection.
- **ABI/calling-convention model (Phase 6.1)** — the source of frame-relative
  location resolution.
- **Pattern matching DSL (Phase 7.4)** — a natural consumer/sibling of the
  query layer; both are narrow, non-general query surfaces, consistent with the
  "no new general-purpose language" decision.


Open Items
----------

- **Probe compilation target.** Whether the restricted probe sublanguage
  (layer 3) compiles to R2IL-derived bytecode, to native via a small JIT, or
  reuses an existing agent-bytecode format. Out of scope here; decide when
  in-target injection is actually built.
- **Allocator model fidelity.** Liveness tracking is only as good as the
  malloc/free instrumentation. Custom allocators, arenas, and pooling break the
  simple chunk-identity model and need explicit handling.
- **Validity domains over multi-threaded execution.** Frame-relative validity
  must be scoped per thread; the domain representation needs to carry a thread
  identity once threads are modeled.
- **Python client surface.** The exact shape of layer 4 (how location handles
  are represented across the process boundary to a Python client) is
  unspecified and should be designed alongside the query layer.


Summary
-------

Do not build a new general-purpose dynamic language. Build a typed execution
model, a small query layer over it, and a restricted in-target probe
sublanguage, with Python as the glue. The unit that makes "meaning, not
addresses" real is a **late-bound, typed location** carrying `(region, offset,
size, type, provenance, validity_domain)`. Binding time is decided by
provenance: allocation-rooted handles snapshot the address but track liveness;
frame-relative handles live-bind to a frame instance; projected handles re-walk
at evaluation time. The address materializes only at read/write, checked against
the current position — a stale handle raises rather than reading garbage — with
`.snapshot()` and `.at(t)` as the only, explicit ways out.
