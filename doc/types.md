r2types: type inference
=======================

`crates/r2types` turns a prepared SSA artifact plus declared context into
`FunctionTypeFacts`: the merged signature, calling convention, stack slots,
visible bindings, callee facts, data-object types, and the field, array,
out-parameter and signature certificates that justify them. How these sit
beside `FunctionFacts` and `SourceOwnedFunctionFacts` is in AGENTS.md
("Canonical Contracts").

Inputs
------

`TypeAnalysisRequest` takes the `Arc<SsaArtifact>`, a `ParsedExternalContext`
(what the binary's debug information and the library prototype tables
declare, placed by `r2engine/src/declared/`) and optional interprocedural
summaries. With debug information a prototype is read; without it every type
has to be earned from evidence.

Evidence (`evidence.rs`) is what the prepared function already proves: each
callee's prototype at each call site, the width of every certified memory
access, and the identities SSA guarantees. Its nodes are the artifact's values
and memory objects, so a call result and a stack home go through one solver.
Register aliasing is asked of the machine (`register_identity.rs`).

Types
-----

Types are interned in a `TypeArena` as `Type`: `Top`, `Bottom`, `Bool`,
`Int { bits, signedness }`, `Float`, `Ptr`, `Array { elem, len, stride }`,
`Struct(StructShape)` (fields by offset), `Function` and `UnknownAlias`.

A type is a regular tree: a finite graph that may have back edges, because C
types are cyclic (zlib's `z_stream` and `inflate_state` point at each other).
`is_subtype` is coinductive (Amadio-Cardelli, `O(n²)`), and `meet` is a
memoised product construction with at most `|A|×|B|` nodes, so neither needs a
depth limit (`lattice.rs`).

Constraints and solver
----------------------

A `Constraint` is `Equal { a, b }` (one class) or `Subtype { var, ty }` (an
upper bound). Constraints only tighten: a join, an override or a rewrite of a
typed field cannot be written. `ConstraintSource` (`Inferred`,
`SignatureRegistry`, `External`) records provenance and carries no priority;
two bounds that cannot both hold meet at `Bottom`, which refuses that type.

`solve_constraints` merges `Equal` classes by union-find, then folds
`meet` over each class's bounds in constraint order. There are no rounds: once
the fold has met a bound, the class type lies below it. Cost is
`O(C α(N))` plus one memoised meet per bound. A node no bound reaches stays
unresolved.

Projections
-----------

`analysis/` reads the solution into the signature, bindings, stack
parameters, access-certified struct and array layouts, globals and operator
assumptions, each with its certificate or refusal. `r2dec` only converts the
result to C types (`variable.rs`).
