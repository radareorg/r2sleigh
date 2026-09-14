# Debugger build plan

Proposed design, 2026-09-13. This document specifies future implementation;
it does not claim that the debugger described here already exists.

Build a debugger in which an investigation survives client disconnects,
execution history can be revisited, and every explanation points to evidence.
Integrate it into radare2 and the existing r2sleigh analysis spine. Missing
capabilities are implementation work, not reasons to preserve a bad boundary.

The product objective is the shortest time to a correct, reproducible diagnosis
across a published target matrix. Measure target overhead, storage, query
latency, information coverage, and agent effort separately. Universal superiority
on every workload is not an actionable acceptance condition.

## 1. Product contract

A user or agent can open a binary, attach or record, inspect a failure, follow
its dependencies, leave, and continue the same investigation. It can ask where a
value came from without manually coordinating breakpoints and parsing output.

The debugger supports live execution, core dumps, recorded execution, and
bounded modeled experiments through one typed interface. Each backend publishes
its supported operations and evidence coverage. Unsupported recording must not
prevent ordinary live debugging.

The governing invariants are:

1. Historical observations never silently change meaning.
2. Every reference has an explicit execution, object, and code lifetime.
3. Every answer identifies its evidence, assumptions, coverage, and scope.
4. Missing evidence remains unknown; absence claims require complete coverage.
5. A repeated client request cannot silently perform a second target mutation.
6. Recorded observations and modeled alternatives remain distinguishable.
7. One canonical fact has one owner; indexes are derived views, not independent
   sources of semantics.
8. Work is bounded, cancellable, observable, and reusable with valid keys.
9. Source rendering and type recovery obey the existing authority contracts.

## 2. Architecture and ownership

Use one logical execution/evidence model with specialized storage and evaluation
strategies. Do not require one physical database or universal evaluator.

| Owner | Responsibility |
| --- | --- |
| radare2 `libr/debug` and backend adapters | Target lifecycle, thread control, register/memory access, breakpoints, recorded observations, checkpoint capabilities, durable trace storage and mechanical indexes |
| `r2source` | Trusted typed import of runtime observations; execution/code provenance; validated connection to `OwnedFunctionSnapshot` |
| `r2sleigh-lift` and `r2il` | Canonical instruction semantics and exact instruction-to-IL correspondence |
| `r2ssa` | Static and dynamic dependencies, memory read-from evidence, slicing, abstract interpretation, semantic certificates and missing-evidence reasons |
| `r2rewrite` | Canonical term simplification and proved algebraic reductions |
| `r2types` | Type/layout/signature constraints and projections with explicit evidence scope |
| `r2engine` | Investigation lifecycle, request planning, execution-controller arbitration, budgets, query jobs, cache policy and witness-validation orchestration |
| `r2dec` | Source presentation of justified facts, historical annotations and explicit residuals |
| `r2plugin`, SDKs and UI adapters | Transport, commands, presentation; no semantic or route ownership |

Introduce runtime contracts in the owning modules above. Do not put an entire
execution into the function-shaped `OwnedFunctionSnapshot`. Bind a runtime
observation to the relevant source transaction and exact `SsaArtifact` instead.
If trace storage eventually needs a separately packaged library, extract the
existing owner and remove its old implementation in the same migration.

The current `EngineSession` is stateless. Extend the engine with an explicit
investigation lifecycle; do not mistake that existing name for durable state.
The current radare2 checkpoint restore writes captured registers and memory.
Expose that capability accurately until a backend also restores the environment
required for execution replay.

Some older roadmap sections use historical crate names. Follow current code and
AGENTS.md ownership. This plan develops the existing P3 replay/trace direction.

## 3. The canonical model

An investigation references these canonical objects:

- **Execution manifest:** binary/module identities, machine profile, backend
  version, input artifacts, capture configuration, dependencies and integrity
  metadata. A live execution gains immutable captured prefixes as it progresses.
- **Execution position:** execution ID, process and thread instance IDs, backend
  position token and before/after boundary. An rr event number alone is not an
  instruction coordinate. Opaque tokens are versioned and validated.
- **Observation:** registers, memory spans, mappings, events or stop metadata at
  a position, including observed/derived origin and capture completeness.
- **Object identity:** module instance and code generation; observed allocation
  instance; call instance; or a time-scoped memory range when stronger identity
  is unavailable. OS PIDs, TIDs, symbols and raw addresses are not durable IDs.
- **Evidence graph:** observations and checked derivations, referring to exact
  canonical operations and their dynamic instances.
- **Query artifact:** normalized request, assumptions, coverage requirements,
  dependencies, result or progress, and analysis version.
- **Experiment:** parent position, proposed intervention, environment model,
  execution outcome and validation scope. It never modifies the parent trace.

Represent recorded execution order, happens-before and observed read-from as
separate relations. A racing read may observe a write without a happens-before
edge. A single timeline is useful for navigation but cannot replace the memory
model. Include atomic ordering, synchronization, mapping changes and external
writes where the backend observes them.

Every answer carries independent fields for evidence scope and search status:

- Scope: observed execution, derived execution fact, or modeled behavior.
- Search: complete within a stated domain, partial with coverage gaps, unknown,
  unsupported, cancelled, or budget exhausted.
- Evidence: positions, operation identities, derivation rules, assumptions and
  counterexamples where applicable.

An empty result is not an absence proof unless the relevant interval, event
families and object lifetime were completely covered.

### Persistence and authority

Persist source captures, trace data, checked derivation recipes, bookmarks and
query metadata. Preserve exact `Arc<SsaArtifact>` authority while a service lives.
After service restart, validated loading must establish fresh runtime authority
and rebind local handles. Never deserialize a hash or database row into an
authoritative `SourceOwnedFunctionFacts` without the canonical validation path.

Historical bytes remain immutable. Better type or unwind analyses produce new
versioned interpretations; they do not rewrite the observations.

## 4. Execution service and programmable interface

Run a supervised local service that owns radare2 target handles and engine
investigations independently of SDK connections. A remote worker uses the same
contract. The initial recording worker is Linux x86-64; a macOS client can access
it remotely. Native macOS debugging remains a separate live capability.

Expose a typed Rust-facing engine contract and a versioned RPC protocol with a
Python SDK first. JSON is acceptable at the external transport boundary; internal
facts remain typed. Encode addresses and wide counters without numeric precision
loss. Add other language SDKs from the same schema. Provide DAP compatibility and
agent tools as adapters, with extensions for historical references.

The read interface takes explicit coordinates:

```text
snapshot(position, selection)
read_memory(position, range)
read_registers(position, thread)
stack(position, thread)
search_events(interval, predicate, budget)
previous_writes(position, range, coverage_requirement)
explain_value(position, value_ref, budget)
compare(first_observation, second_observation)
```

The control interface takes an expected revision and request ID:

```text
advance(session, expected_revision, stop_condition, request_id)
interrupt(session, request_id)
set_breakpoint(session, logical_location, request_id)
write_state(session, expected_revision, changes, request_id)
```

Use one writer lease per target controller and concurrent immutable readers.
Journal command intent and completion. On transport retry, return the recorded
outcome. On a crash between backend execution and journal completion, reconcile
with backend state or return an indeterminate outcome; never blindly repeat.
Reads are observational by default: evaluating an expression must not secretly
call target functions or run unbounded pretty-printer code.

Queries support batching, pagination, bounded output, progress, cancellation and
continuation tokens. Job state survives disconnect. A capability describes
whether a job can also recover across worker restart. A live target lost with
its worker is reported as lost; saved observations remain usable.

Provide a timeline, assembly/source view, history-aware registers and variables,
an evidence navigation view and a persistent investigation notebook. The GUI and
SDK use the same query operations. Improving normal radare2 views takes priority
over inventing a parallel public command vocabulary.

## 5. Recording, history and indexes

Integrate a proven record/replay backend first, starting with rr on supported
Linux targets. Implement the adapter in the debugger backend boundary. Validate
protocol coverage explicitly; implementing a GDB remote client is not by itself
proof that every rr extension or reverse operation works.

Capture enough environment information for the backend's replay contract:
relevant syscall effects, signals, mappings, process/thread events and supported
nondeterministic instructions. Bundle or identify executable dependencies. Detect
unsupported events and replay divergence, and invalidate dependent answers.

Intel PT/CoreSight control-flow support is optional acceleration. It is not a
substitute for memory values or nondeterminism capture. Build detailed observation
indexes during instrumented replay or another validated capture path.

Start with immutable chunk files, atomic manifests, a transactional catalog and
per-chunk indexes behind the radare2 history API. Choose concrete storage
libraries with recorded workloads before the storage implementation lands. Measure
point reads, interval searches, sequential ingest and dependency expansion. Keep
columnar export for analytics optional; avoid two independently mutable histories.

Index these in order of demonstrated query value:

1. Process/thread/module/mapping events and execution positions.
2. Executed code locations and call/return events where supported.
3. Memory and register writes for selected intervals.
4. Memory reads and dynamic definition-use edges for requested slices.
5. Allocation, synchronization and runtime events with validated producers.

A call tree must represent incomplete unwinds, tail calls, signals, exceptions,
coroutines and stack switches rather than force all execution into ordinary
well-nested calls. Allocator event adapters require valid ABI/runtime contracts;
function-name matching alone cannot establish allocation semantics.

History reads combine initial captured state with subsequent writes. Handle
partial and overlapping writes, endian order, mapping lifetime, address reuse,
kernel-written memory and code changes. A multibyte value may have several
contributing writers. Unknown initial bytes remain unknown.

Keep a simple bounded linear interpreter as an independent query oracle. The
optimized index must agree with it on complete recorded intervals and return
the same gaps on incomplete intervals.

Support full, windowed and selected-region capture with explicit retention
policies. A retained replay window needs a sufficient initial checkpoint and
subsequent nondeterminism; an arbitrary ring-buffer fragment is insufficient.
Pin evidence dependencies or report their eviction. Adaptive checkpoints use
measured query locality and a storage budget; claim no universal entropy-optimal
or square-root reconstruction bound.

## 6. Semantic analysis and mathematical engines

Use one canonical instruction semantics with several specialized evaluators:

1. Concrete execution/replay establishes observed behavior.
2. Dynamic SSA binds executed instances to canonical static operations; memory
   dependencies carry observed address, byte span, lifetime and read-from facts.
3. Backward slicing follows relevant data, address and control dependencies.
4. Abstract interpretation computes conservative known bits, intervals,
   congruences and address-region possibilities.
5. Incremental SMT solves bounded bitvector, memory and floating-point questions
   when cheaper analyses cannot answer. Start with an existing solver integration
   where available; otherwise use Z3 behind a narrow typed solver boundary.
6. Counterexample-guided refinement expands abstractions after a spurious result.

Facts from a concrete path do not justify global type or control-flow claims.
Keep observation scope through `r2types` and native rendering. Dynamic evidence
can identify an indirect target on one run without proving the complete target
set. Disagreement with lifted semantics produces a mismatch witness and stops
the affected derivation.

A concolic query starts at a concrete state, makes selected inputs symbolic and
declares its environment assumptions. If exploration leaves the original slice,
expand dependencies or return a model-boundary result. A finite machine address
space is not necessarily a tractably small symbolic domain. Never silently
concretize symbolic addresses to make a proof finish.

Reproduce candidate counterexamples through fresh controlled execution or a
backend that explicitly supports the intervention. Matching one execution
validates that witness only. It does not prove all schedules or environments.
An absence proof requires a sound model, complete bounded search or an invariant
checked against initial states and transitions. A timeout is unknown.

### What to take from the mathematical proposal

| Proposal | Engineering decision |
| --- | --- |
| Store comonad/time-indexed observation | Adopt explicit position and consistent point/range observation laws. A partial, budgeted API represents practical access. Generic comonads do not automatically compose or prohibit private state. |
| Semiring provenance | Share compact derivation circuits for suitable positive relations; evaluate reachability, lineage and additive costs where their semantics apply. Keep solver and query planning specialized. |
| Counting equals model counting/information leakage | Reject the equivalence. Derivation multiplicity can double-count the same input. Model counting needs distinct satisfying assignments; information measures additionally need a distribution/channel model. |
| Recording entropy bound | Use conditional joint information as a compression perspective, not a byte or runtime guarantee. Entropies add only under the appropriate independence/conditioning assumptions. |
| Happens-before-only recording | Research scheduling/read-from capture under an explicit memory model. Dynamic race detection alone is not a complete replay recorder, especially for native weak-memory execution. |
| Persistent history and adaptive checkpoints | Adopt. Account for initial state, ingest, metadata, query output, replay distance and storage. Succinct representation cannot eliminate arbitrary execution information growth. |
| Naturality/differential semantics | Adopt cross-ISA semantic differential tests with mismatch witnesses. Passing a finite test set is evidence, not a general proof of lifting equivalence. |
| Affine machine algebra | Use only inside a proved domain. XOR-affine GF(2) operations and modular-addition affine operations are different domains; arbitrary mixed operations do not reduce to one Gaussian elimination. |
| CEGAR and learned search | Adopt refinement; optionally learn query/search priorities later. Concrete execution checks witnesses within its scope, and is not a perfect simulator for arbitrary alternative futures. |

Semiring evaluation can count derivations and obtain least-cost derivations,
but those interpretations are explicitly different operations in
[ProvSQL's documentation](https://provsql.org/docs/user/semirings.html).
Recursive provenance has multiple semantics with different properties; specify
the chosen fragment rather than treating it as universally interchangeable
([Bourgaux et al., 2022](https://proceedings.kr.org/2022/10/kr2022-0010-bourgaux-et-al.pdf)).
Negation already has substantial research, so novelty is not established by
proposing it ([Grädel and Tannen](https://arxiv.org/abs/2412.07986)).

Negation over trace relations requires complete coverage of the relevant domain.
Store provenance as shared circuits instead of eagerly expanding every possible
explanation. Demand-directed graph queries come first; introduce a restricted
Datalog frontend when real extensions need recursive composition. Solver hooks
are explicit budgeted jobs, not hidden per-tuple callbacks.

## 7. Build sequence and release gates

Stages are dependency gates, not calendar estimates. Each stage includes public
workflow tests, failure cases and manual inspection. No milestone is satisfied
by adding unused types or achieving a cosmetic benchmark score.

### Stage 0: Contracts, reference workflows and baseline

Write executable contract tests for positions, identities, coverage and mutation
retries. Inventory real radare2/debugger capabilities. Establish fixtures with
known source and independently inspect their native behavior. Benchmark a
persistent GDB/MI baseline and GDB+rr, plus LLDB on relevant native targets.

Gate: reproducible baseline records target setup, stepping, memory queries,
diagnosis quality, client disconnect/reconnect and failure handling. Freeze the
hardware, binaries, compiler options and question set for each comparison.

### Stage 1: Reconnectable live investigation

Implement the supervised service, typed runtime snapshot collector, immutable
observations, logical breakpoint references, request journal, client SDK and
basic notebook. Add launch/attach/detach, interrupt, continue/step, breakpoint and
watchpoint behavior, thread selection, registers, memory and stack inspection.

Gate: disconnect/reconnect preserves the target and discoveries; stale mutations
are rejected; duplicate requests do not double-step; worker loss produces an
honest outcome. New SDK clients can continue without scraping earlier output.

### Stage 2: Reproducible recorded investigation

Implement the rr adapter, recording manifests, exact historical position tokens,
bookmarks, checkpoint capabilities, replay jobs and divergence reporting. Use a
dedicated Linux worker when the developer machine cannot run the backend.

Gate: one real recorded failure produces the same selected registers, bytes and
control-flow observations across service restarts and a supported second worker.
Dependency mismatch and unsupported capture are visible failures. Internal
prefix replay is measured; the agent does not repeat setup.

Stages 1 and 2 deliver the first usable release.

### Stage 3: Indexed historical questions

Implement history chunks, coverage-aware indexes, previous-writer and event
queries, resumable index construction and bounded lazy replay. Validate indexes
against the simple linear oracle. Feed actual query locality into checkpoint
placement and cache decisions.

Gate: reconstruct values assembled by overlapping writes across allocation and
mapping lifetimes. A deliberate capture gap cannot yield a complete last-writer
answer. Warm queries avoid redoing completed searches, within declared retention.

### Stage 4: Explain values through the canonical SSA spine

Bind dynamic operations to exact lifted bytes and static artifacts. Build
register/memory dependency evidence, backward slices, observed callsite facts,
allocation provenance and type constraints. Add source/assembly evidence views.

Gate: on a real stripped optimized memory-corruption fixture, explain the
contributing input and write chain with independently verified evidence. Partial
register writes, aliasing, indirect calls, source optimization and unsupported
operations produce correct facts or visible residuals. Repeat representative
semantic tests on a second ISA without downstream register-name heuristics.

Stages 3 and 4 deliver an explanation-focused release.

### Stage 5: Bounded counterfactual analysis

Add selected-input concolic execution, abstract-domain reduction, incremental
solver contexts, model boundaries and candidate validation. Support questions
such as whether an arithmetic operation can overflow under explicit constraints,
or what input reaches an alternate parser branch within a stated bound.

Gate: a generated input reproduces its predicted behavior in controlled concrete
execution. Spurious candidates trigger refinement. Timeouts, unsupported memory
and changed environmental assumptions never become absence proofs.

### Stage 6: Broad debugger and performance coverage

Expand Linux architectures, native macOS/Windows adapters, remote targets, core
dumps, debug-information readers, optimized-variable location evaluation,
unwinding, thread/process lifecycle and language/runtime adapters. Preserve both
machine truth and honest source-variable unavailability.

Publish a matrix indexed by OS, ISA, ABI, execution mode and runtime. For each
cell state support for live control, source inspection, replay, history and
semantic explanation. A supported source-debugging cell must include ordinary
breakpoints, stepping, signals/exceptions and optimized-code behavior, not just
crash analysis. Start this compatibility work earlier where it is independent
of the history model; gate releases by tested cells.

Gate: sustained workload comparisons show where the debugger improves diagnosis
time and where it costs more. Large processes remain responsive under configured
memory, capture and query budgets. Ordinary live inspection does not invoke SMT
or require full-history indexing.

### Stage 7: Multicore and specialized execution research

Develop multicore recording using explicit synchronization, atomics, observed
read-from and scheduler constraints. Consider hardware-assisted tracing and
instrumentation together. Extend to system/VM and device-backed workloads with
explicit environmental boundaries. Distributed causality requires participating
process/service traces and message identities, not a fabricated global clock.

Gate: memory-model litmus suites and real concurrent failures replay correctly;
missed interference and unsupported devices are detected. Compare overhead with
the serialized baseline. A new recorder replaces an existing backend only after
the full replay and compatibility gates pass.

## 8. Complexity and performance contract

Let E be indexed events, W observed writes, B returned bytes, and S visited
dependency nodes/edges. These are targets with stated prerequisites:

| Operation | Target and accounting |
| --- | --- |
| Stable ID lookup | Expected O(1) or O(log E); deterministic presentation |
| Event range query | O(log E + returned events) with a matching index |
| Historical byte read | Predecessor search over that byte/region's writes plus initial-state access; range reads pay for B and overlap resolution |
| Backward slice | O(S) traversal after required indexes exist; include index construction and provenance output separately |
| Replay seek | Checkpoint lookup + restore cost + distance replayed |
| Capture/index ingest | O(E) or O(E log E) for the chosen layout; account for instrumentation, sorting, compression and I/O |
| Symbolic query | Explicit solver/exploration budgets; no polynomial guarantee |

Cache keys include execution identity, position, code generation, machine model,
source revisions, assumptions, analysis version and required coverage. A partial
result cannot satisfy a later complete query. Share content across analyses only
through validated ownership. Query-independent capture can proceed concurrently
with readers; publication occurs through atomic complete chunks.

Report cold and warm latency separately, including p50/p95/p99, capture slowdown,
indexing throughput, storage growth, peak memory, replay distance, SDK round trips
and returned data size. Do not advertise warm index lookup as recording cost.
Stage 0 sets numerical budgets from the actual target hardware and baseline;
later changes must meet those budgets or document the specific tradeoff.

## 9. Correctness and completion gates

Maintain a behavior-level corpus spanning memory corruption, allocation reuse,
integer overflow, wrong results, optimized variables, indirect calls, signals,
thread races, deadlocks, mapping changes and changing code. Include binaries with
debug information and stripped optimized variants. Use independent native or
instrumented evidence; never score source-shaped guesses as recovery.

Mechanical guardrails:

- Dylint: no runtime fact repair or route policy in plugin/rendering layers.
- Kani/property proofs: span arithmetic, register lanes, generation separation,
  coverage composition and controller state transitions.
- Fuzzing: trace/wire decoders, manifests, corrupted indexes, position tokens and
  debugger packet parsing; malformed input cannot mint authority.
- Mutation tests: missing coverage, stale reference acceptance, wrong writers and
  duplicate execution must be caught by behavior-level tests.
- Fault injection: disconnect during advance, worker death, interrupted manifest
  commit, cancelled indexing and missing trace chunks.
- Differential checks: native versus lifted behavior and simple-history oracle
  versus indexed queries. A finite passing corpus is not a universal proof.

For implementation changes, run the full required validation bar in AGENTS.md,
including both repos for typed debugger seams, plugin installation and r2r.
Run the rewrite quality gate for architecture-sensitive work. Record exact manual
commands, fixtures, observations and refusals in each implementation report.

The first flagship demonstration is one recorded real failure, a contributing
write located from the crash, a dataflow explanation, agent disconnection and
reconnection, and continued investigation from saved evidence. The negative
demonstration removes a required interval and demands an explicit unknown.

Judge agent performance against a properly persistent scripted debugger baseline:
correct diagnoses, reproducibility, redundant target execution, round trips,
tokens, time and incorrect confident assertions. Do not reward merely fluent
explanations or penalize honest unknowns as if they were wrong answers.

## 10. First implementation series

1. Establish the capability inventory, baseline harness and typed position,
   coverage, observation and control-revision contract tests.
2. Add the consolidated runtime snapshot collector to radare2 and its validated
   `r2source` ingestion; exercise the real debugger path end to end.
3. Add engine-owned investigation state and supervised service lifetime, with
   journaling and an initial Python client driving existing debugger operations.
4. Add reconnect/stale-request/fault-injection regression coverage and a manual
   session report. This closes the first user-visible repeated-work failure.
5. Implement the recording adapter and historical-position contract, then build
   indexing and dynamic explanations through Stages 2–4.

The backend abstraction must allow replacement, but its first implementation
must drive an actual supported target. Avoid an extended framework-only phase.

## References

- [rr implementation report](https://arxiv.org/abs/1610.02144): practical low-overhead
  user-space record/replay on supported hardware and operating systems.
- [rr usage and checkpoints](https://github.com/rr-debugger/rr/wiki/Usage): replay,
  checkpoint operations, temporary cloned function calls and workload costs.
- [GDB process recording](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Process-Record-and-Replay.html):
  distinction between full recording and branch tracing without data history.
- [Pernosco query-based debugging](https://robert.ocallahan.org/2019/11/omniscient-printf-debugging-in-pernosco.html):
  historical expression queries evaluated against an execution database.

Local starting points: `libr/include/r_debug.h` and `libr/debug/dsession.c` in
radare2; `crates/r2source/src/lib.rs`, `crates/r2ssa/src/function.rs`,
`crates/r2types/src/function_facts.rs`, and `crates/r2engine/src/lib.rs` here.
