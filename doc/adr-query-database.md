# ADR: one query database for the program

Status: proposed (ROADMAP Q, decision D13)

## Context

A program-level fact is computed on demand and kept, and today each one has a
cache of its own, kept current by hand:

- `query::memo::Memo` for per-function analyses, keyed by entry with a
  `Moved` range check;
- `PerRevision` for callee reads;
- `Mutex<Pointers>` and `Mutex<Returns>`, each with its own revision check;
- `references: Option<(Revision, Arc<_>)>`;
- the discovery survey, held per `(identity, byte_revision)` since this
  month, after every `afl` was found re-walking the whole program (42 s each
  on libc);
- the entry modes, with `modes_at` and `entries_revision` maintained beside
  them;
- the names table, with `names_revision`.

`Revision` has four axes because no one axis says what an answer depended on.
Every public request begins with `ensure_current()`, and each cache decides
for itself whether a write touched it. A cache that forgets a dependency
returns a stale answer; one that over-invalidates throws away work. Nothing
checks either.

## Decision

**Every derived fact about the program is a query in one database.** The
engine holds the database. A command, the visual mode and the agent surface
ask it.

- **Inputs** are the only state that changes:
  - the container, which is fixed while the program is open;
  - the bytes, revisioned per written range;
  - later, the user's facts: names, types, comments (V6).

  An input changes only by an explicit write.
- **Queries** are pure functions of inputs and other queries, each with a
  typed key and an `Arc` value:
  - decode an address;
  - the discovery survey;
  - walk a body;
  - lift it;
  - seal it, with its index (doc/adr-one-ir.md);
  - a function's summary;
  - its rendering;
  - the reference index;
  - the names table.
- **Dependencies are recorded, not declared.** While a query runs, the
  database records every input range and every query it read. On the next
  request it reuses the value if no recorded dependency changed, checking
  bottom-up the way salsa and rustc's query system do (red-green). A write
  invalidates exactly the queries that read the range written, transitively.
- **Cycles are values.** Interprocedural facts (returns, summaries) form
  cycles over the call graph. One query solves a strongly connected component
  of the call graph on the fixpoint driver and returns every member's answer.
  The members' queries read that component's answer. No query recurses into
  itself (P6).
- **Determinism.** Queries are pure and their order of evaluation is
  irrelevant to their values. The database is the only place a computed fact
  is kept: no `Mutex` table, `OnceLock` or memo anywhere else in r2engine.
  The Dylint against entity-keyed maps (D12) gets a sibling against `Mutex`
  and `RwLock` state outside the database.
- **Implementation.** A small engine of its own in r2engine, not the `salsa`
  crate:
  - the dependency recording is about 500 lines;
  - salsa's macros would spread through every crate that defines a query;
  - the inputs here are byte ranges, which salsa does not model.

  This is re-evaluated if the engine grows past a thousand lines.

## Migration

| Step | Change | Deletes |
|------|--------|---------|
| Q0 | The database: inputs (container, bytes by range), query keys, dependency recording, red-green revalidation; a property test that a random sequence of writes and requests answers as a fresh open does | — |
| Q1 | Discovery, the survey, entry modes and the names table as queries | the survey cache, `modes_at`, `entries_revision`, `names_revision` |
| Q2 | Decode, walk, lift and seal per function as queries | `query::memo::Memo`, `Moved`, `PerRevision` |
| Q3 | Returns, pointers and callee reads as queries, cycles by component (with P6) | `Mutex<Pointers>`, `Mutex<Returns>`, `callee_reads` |
| Q4 | References and renderings as queries; `ensure_current` and `Revision`'s four axes deleted | the reference cache, `Revision` |

## Consequences

- Exit: a session of random writes and requests equals a fresh open (the
  property test). There is no cache outside the database.
- Every answer can say what it was computed from, which A's `explain` needs.
- The visual mode's worker caches nothing of its own; it asks the database,
  which answers a repeated request at once.
- Parallel evaluation becomes possible because queries are pure. It is not
  part of Q.
