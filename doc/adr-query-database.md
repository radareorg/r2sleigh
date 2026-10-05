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
- Q3, returns and survey: the container's and machine's fixed facts are
  inputs (Q3a), the conventions assembled as the machine loads (Q3c);
  `ComesBack` (Q3b), `SurveyQuery` and `Modes` (Q3d) read the program
  through one `View`. `Db::held` and `Db::deposit` share answers;
  `Mutex<Returns>`, the `survey` cache, `modes_at` and `modes_revision` are
  deleted. `PointerParameters` (Q3e) answers a callee's pointer
  parameters; a call cycle is the database's `Cycle`. `Mutex<Pointers>` is
  deleted. A query says how each answer is held (`Hold`): held; transient,
  which depends on where a cycle was entered, is not held and hands its
  reads to its asker; or the request's stop, which taints its asker. A
  cut is transient; a callee prepared under a stop is a stop. Body-to-body
  forwarding needs callee interfaces a callee prepared alone does not
  have yet, so no cycle is reached today; the Db tests cover each hold.

## Left

- Order (2026-10-06): Q3's returns and survey land before Q2, since the
  analysis reads both.
- Returns are not solved per component. Components over a maximal walk
  (every callee returns but those declared not to) are independent of the
  answers, but the closure is what a single `pdd` would pay: 35/231/1991/1148
  bodies and 0.7/3.5/19/14% of release `pdd` on the four timed cases, against
  3/44/396/370 bodies for the lazy fixpoint, which walks a callee only while
  an undecided caller waits on it. `ComesBack(f)` runs that fixpoint, reads
  answers already held (`Db::held`, recording a dependency, never computing,
  so no cycle arises) and deposits the others it found with its own
  dependencies; the least fixpoint is unique, so a deposited answer equals a
  computed one. P6's summaries may still want components; they decide that
  with their own measurement.
- Q2 (Q2a, Q2b): a stop of the request is typed (`NativeRefusal::Stopped`,
  `Unreadable::Stopped`); a query names its stops, which are returned and
  never held, nor is what read one; a query may bound its table. The
  request's control is an input read by work and never by an answer.
  `Analysed` (capacity one), `CalleeReads` and `Sealed` replace the memo;
  `Memo`, `Moved`, `Consulted`, `PerRevision` and `Recording` are deleted.
- Q3: the discovery survey and entry modes (moved here from Q1, because they
  read the call-graph returns), plus returns, solved by component together
  with P6; pointers and callee reads read the analysis, so they follow Q2.
  Left: summaries with P6.
- Q4a: the reference index is the `ReferenceIndex` query over the View,
  which also lists, decodes and asks pointer parameters; the reference
  cache is deleted, and `revision(db)` and `endian` have one owner.
- Q4b: a value dropped past a table's capacity keeps its dependencies,
  so what read it stays good, and a value computed again from unmoved
  reads keeps its `changed_at`. `Rendered(entry, thumb, tier)` holds
  sixteen renderings with the name they define and the callees left
  unread, so a redraw reads no analysis; a sealing refusal is held unless
  the request's control could have caused it
  (`EngineExecutionControl::stopped`: cancellation is sticky and the
  deadline only passes). Measured: six render commands over two 0pack
  functions in one session, 11.1 s to 4.9 s.
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
