# ADR: one query database for the program

Status: in progress (ROADMAP Q, decision D13)

## Decision

Every derived fact about the program is a query in one database, held by the
engine. Commands, the visual mode and the agent surface all ask it.

- **Inputs** are the only state that changes, and only by an explicit write:
  the container (fixed while the program is open), the bytes (revisioned per
  written range), and later the user's facts (names, types, comments; V6).
- **Queries** are pure functions of inputs and other queries, each with a
  typed key and a shared value: decoding an address, the discovery survey,
  walking, lifting and sealing a body (with its index, doc/adr-one-ir.md), a
  function's summary, its rendering, the reference index and the names table.
- **Dependencies are recorded, not declared.** While a query runs, the
  database records every byte range and every query it read. A repeated
  request is revalidated red-green, bottom-up: it is reused when nothing it
  read changed, and a recomputed value equal to the old one keeps its
  `changed_at`, so its dependents stay good. A write invalidates exactly the
  queries that read the written range, transitively.
- **Cycles are values.** A query that reaches itself gets `Cycle` instead of
  recursing. Interprocedural facts (returns, summaries) are solved by one
  query per strongly connected component of the call graph, on the fixpoint
  driver, and each member's query reads that component's answer (P6).
- **Determinism and single ownership.** Queries are pure, so evaluation order
  does not affect values. The database is the only place a computed fact is
  kept: no `Mutex` table, `OnceLock` or private memo elsewhere in r2engine. A
  Dylint against `Mutex`/`RwLock` state outside the database joins the
  entity-keyed-map lint (D11).
- **Implementation.** A small engine in r2engine
  (`crates/r2engine/src/query/db.rs`), not the `salsa` crate: salsa's macros
  would spread into every crate that defines a query, and salsa does not model
  byte-range inputs. Revisit this if the engine grows past about a thousand
  lines.

## Done

- Q0 (deda98de): `Db`, `Inputs`, `Query`, dependency recording, red-green
  revalidation, and the property test `a_session_answers_as_a_fresh_open`.
- Q1, first half (2bf3f0a3): the name table and the import stubs are queries
  read through `Recorded`. `derived_at`, `names_revision` and
  `entries_revision` are deleted.

## Left

- Order (2026-10-06): Q3's returns and survey land before Q2, since the
  analysis reads both. Callees over a maximal walk (every callee returns but
  those declared not to) give components independent of returns; each
  component's returns is one query, and a callee outside it is another
  component's answer.
- Q2: decode, walk, lift and seal per function as queries. Exit: `Memo` and
  `Moved` are deleted.
- Q3: the discovery survey and entry modes (moved here from Q1, because they
  read the call-graph returns), plus returns, solved by component together
  with P6; pointers and callee reads read the analysis, so they follow Q2.
  Exit: the `survey` cache, `modes_at`, `modes_revision`, `Mutex<Returns>`,
  then `Mutex<Pointers>` and `PerRevision` (`callee_reads`) are deleted.
- Q4: references and renderings as queries. Exit: the reference cache,
  `ensure_current` and `Revision` are deleted, and the D11 Dylint is fatal in
  r2engine.
- Exit for the whole of Q: the random-write property test holds over the real
  program inputs, and no cache exists outside the database.

## Consequences

- Every answer can say what it was computed from, which A's `explain` needs.
- The visual mode's worker keeps no cache of its own. It asks the database,
  which answers a repeated request immediately.
- Queries are pure, so they could be evaluated in parallel. That is not part
  of Q, and the database is single-threaded (`Rc`/`RefCell`) today.
