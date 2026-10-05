The debugger (design)
=====================

Draft of 2026-10-04, not yet on the roadmap. **No debugger code exists.** This
page keeps the decisions and the build order; the full derivations and the
research notes are in git history (`f531b719:doc/debugger.md`, before the move to `doc/drafts/`). If adopted, it
starts only after `ROADMAP.md`'s Q, P4, R and M land, because until then it
would bind to register names and a renderer that are being replaced.

What it is
----------

Three things: a backend seam that reads a target's state, a trace database
that answers questions about a run in sublinear time, and the static engine's
facts bound to time. It is not radare2's debugger (the engine links nothing
from `libr`), not a rebuilt rr, and not a gdb plugin.

Its audience is radare2's: stripped binaries, exploit development, firmware,
cross-architecture work. For source-level debugging of a large program with
DWARF on Linux x86-64, gdb with rr is the better tool and this does not
compete there.

The motivating complaint is step-and-query (reach a breakpoint, read a value,
lose the state, start again). The answer is record-and-query: record once, then
answer every question, including reverse execution, against the recording.

Invariants
----------

1. Observations never change meaning; better analyses add versioned
   interpretations.
2. Executions, objects and code have explicit lifetimes; PIDs, TIDs and raw
   addresses are not durable identities.
3. Every answer states its evidence, assumptions, coverage and scope
   (observed, derived, modeled) and its search status.
4. Missing evidence stays unknown. An empty result is an absence proof only
   over a fully covered interval.
5. A repeated client request cannot mutate the target twice.
6. A displayed value is exact or refused, never stale.
7. Dynamic evidence never becomes rendered C: a run may refute a static fact
   or propose a hypothesis; only the static prover makes a fact.
8. Time is exact where the engine steps, and stated as ambiguous where it
   does not. A serialized trace is never presented as a weak-memory model.

Semantics
---------

A run is fixed by its start state σ₀ and its environment events E (syscall
results, signals, schedule, nondeterministic instructions); the step relation
is r2il's. A recording is exactly (σ₀, E), as in rr. Replay divergence is
detected and invalidates every dependent answer. An emulated run has an exact
step index; an rr point is (retired branches, registers) and may be ambiguous;
a live target has only its current stop. Each position carries its activation,
so a value is never read from the wrong instance of a recursive frame.

Ownership
---------

| Owner | Holds |
|-------|-------|
| `r2target` (new) | What the target states: registers, memory, threads, mappings, stops; launch, attach, step, breakpoints. Two backends behind one `Target` trait. No inference. |
| `r2il::eval` | Step semantics; the reference oracle for every faster evaluator |
| The query database (`r2engine`, D13) | The trace, checkpoints, segment summaries, the write index, live bytes and registers as versioned inputs, investigation state as user facts |
| `r2ssa` | Value availability, the value-at-time rule, chops for symbolic queries, refutation evidence |
| `r2rewrite` | Inverse expressions that recover overwritten values |
| `r2types` | Layouts applied to live memory |
| `r2dec` | Rendering live values and refusals beside the C |
| `r2s` | radare2's `d*` spellings and a `gdbstub` export |
| The machine profile (D15) | Register layout, conventions; the target's `target.xml` or `qRegisterInfo` is mapped onto it at connect |

No service, no RPC protocol, no Python SDK: persistence is the query
database's and the scripting surface is roadmap item A.

Backends
--------

- **RSP client.** One GDB Remote Serial Protocol client reaches `gdbserver`,
  `debugserver`/`lldb-server`, the qemu gdbstubs, OpenOCD, and `rr replay`
  (which serves `bc`/`bs`, giving time travel on Linux x86-64 without a
  recorder). Limits: no reverse `vCont`, one range per range-step request.
- **Emulator** over r2il: the replay engine for recorded segments, the runner
  for foreign architectures, and the stepper for symbolic windows. Built in
  tiers, each differentially tested against the one below: a tuned
  interpreter with a block cache, then liveness-driven flag elimination, then
  (only if needed) a Cranelift JIT.
- **Hybrid window.** Run natively to the point of interest, snapshot, emulate
  only the window being looked at.
- **`gdbstub` export**, so gdb, lldb and pwndbg can drive the emulator or a
  trace.

On a shared host and OS the fastest emulator is none, so recording is native
(syscalls logged, threads serialized, copy-on-write fork checkpoints), and the
emulator replays offline and in parallel.

The trace index
---------------

With a checkpoint every K steps and, per segment, the interval set it wrote,
`lastwrite(loc, t)` costs `O(log(n/K) + K)` in `O((n/K) · |summary|)` space:
K = 1 is Pernosco, K = n is rr. K is chosen per trace from a storage budget,
and hot segments are indexed fully on demand. A bounded linear interpreter is
the index's oracle and must report the same values and the same gaps.

The derivations this rests on, none yet machine-checked:

- **B, write-set pruning**: a location no segment's sound may-write set
  contains since a checkpoint holds its checkpoint value, with no replay.
- **C, value at a time**: an SSA value whose definition dominates the current
  point and is live there equals the output of the last execution of its
  definition in the same activation. Every in-scope C variable of a stripped
  binary then has an exact value on a trace.
- **C′, live recovery**: at a live stop a value is available where a forward
  must-analysis says a location holds it; otherwise an inverse expression may
  recover it; otherwise it is refused.
- **D–F**: proven loop summaries skip iterations, proven-pure calls are
  memoised, and segments index in parallel.

Static and dynamic facts
------------------------

Static facts accelerate the dynamic side (dead flags, proven indirect targets,
pruned replay). Dynamic facts check the static side: an observed state outside
a fact's concretization is a refutation naming the failed premise, and a CI
gate checks every certified fact at every executed point of corpus traces.
Symbolic queries start from a concrete stop over a gated-SSA chop, use only
proven invariants as assumptions, unroll to a stated budget, and reproduce
every counterexample before reporting it. Taint is the forward closure over a
trace's read and write edges.

Build order
-----------

| Phase | Adds | Exit |
|-------|------|------|
| D0 Target seam | `r2target`, RSP client, `d*` verbs, live state as query inputs | attaches to gdbserver, debugserver, qemu; `dr dm db dc ds` diff clean against radare2 |
| D1 Live values | availability index, inverse recovery, live values in `pdd` | every in-scope variable of a stripped optimised fixture exact or refused, checked against a DWARF build |
| D2 Traces | interpreter, flag elimination, native recording, the K index, `bc`/`bs`, `gdbstub`, rr as a source | last-writer and value-at-time equal the linear oracle, gaps included |
| D3 Navigation | statement stepping, definition-attached conditions, frame watchpoints, slices | each is an index lookup |
| D4 Refutation gate | facts enumerable per pc, the CI job | every certified fact holds at every executed point, or its premise is named |
| D5 Concolic and taint | solver boundary, chops, budgets, witness reproduction | a generated input reproduces; a timeout is `Unknown` |
| D6 Research | importing rr events as E to test the lifter | a divergence is a lifter bug with a witness, or the import is abandoned |

The JIT is a separate decision after D2. Deferred: Windows, multicore
recording under a memory model, core dumps, DAP.

Risks: a foreign OS's syscall layer is unbounded work (the first recording
target shares the host OS); macOS has no rr-style recorder and fork
checkpoints of a ptraced process there are unverified; rr's trace format is
internal, so D6 may fail; the owner of refutation evidence and the index
layout inside the query database are open.
