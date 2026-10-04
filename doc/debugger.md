# The debugger

Draft, 2026-10-04, not yet on the roadmap. It supersedes
`doc/debugger-build-plan.md` (2026-09-13), whose ownership was the radare2
plugin's; section 16 says what is kept from it. Nothing described here exists
yet. If adopted, the debugger comes after the program in `ROADMAP.md` (F2, Q,
P4, R, M) and must not start before R lands, because until then it would bind
to register names and a renderer that are being replaced.

## 1. What it is, and what it is not

The debugger is three things: a backend seam that reads a target's state, a
trace database that holds a run and answers questions about it in sublinear
time, and the static engine's facts bound to time. It is not the radare2
debugger (the engine links nothing from `libr`), not a rebuilt rr (rr's
mechanism is hardware counters and a kernel-level recorder, and it is Linux
only), and not a gdb plugin (pwndbg and gef live inside gdb's Python API, where
gdb's own model of frames and symbols fights ours).

Its audience is radare2's: stripped binaries, reverse engineering, exploit
development, firmware, cross-architecture work on any host. For source-level
debugging of a large native program with DWARF on Linux x86-64, gdb with rr is
the better tool, and this design does not compete there.

What makes it different is that every static fact the engine owns becomes a
dynamic fact for free. A decompiled C variable is a bound SSA value; an SSA
value has an exact value at every moment of a trace (section 7, theorem C). A
symbolic query starts from a concrete stop and uses the engine's proofs as
solver assumptions (section 9). A run is a check on the engine (section 8).

## 2. Invariants

1. Historical observations never change meaning. Better analyses produce new
   versioned interpretations; they do not rewrite the observations.
2. Every reference has an explicit execution, object and code lifetime. OS
   PIDs, TIDs, symbols and raw addresses are not durable identities.
3. Every answer identifies its evidence, assumptions, coverage and scope.
   Scope is one of observed, derived or modeled; search status is one of
   complete, partial, unknown, unsupported, cancelled or budget exhausted.
4. Missing evidence stays unknown. An empty result is an absence proof only
   when the interval, event families and object lifetime were covered.
5. A repeated client request cannot perform a second target mutation.
6. Recorded observations and modeled alternatives stay distinguishable.
7. One fact has one owner; an index is a derived view, never a second source.
8. Work is bounded, cancellable, observable and reusable under valid keys.
9. Rendering and types obey the existing authority contracts.
10. A displayed value is exact or refused, never stale. This is LLVM's debug
    information contract: correctness means never showing a wrong value, not
    showing every value.
11. Dynamic evidence never becomes rendered C. A run may refute a static fact
    or propose a hypothesis; only the static prover may turn a hypothesis into
    a fact.
12. Time is exact where the engine owns the stepper, and stated as ambiguous
    where it does not (section 3).
13. A sequential trace semantics describes a serialized execution only. It is
    never presented as a model of weak-memory concurrency.

## 3. Semantics and time

A state is σ = (R, M, pc): registers, memory, program counter. The step
relation is the r2il semantics, `r2il::eval::step`. A run is fixed by its
start state σ₀ and its environment events E = ⟨e₀ … eₙ⟩: syscall results,
signals, the schedule, and the results of nondeterministic instructions
(`rdtsc`, `rdrand`, `cpuid`). Then

    τ = σ₀ σ₁ … σₙ,   σₜ₊₁ = step(σₜ, eₜ)

and τ is a function of (σ₀, E). A recording is exactly (σ₀, E), the inputs
that cross the process boundary, which is rr's model. Replay is all or
nothing: one missed source of nondeterminism and the replay diverges, so
divergence is detected and every dependent answer is invalidated.

Time is a position in τ. Its identity depends on who stepped:

- an emulated run (section 5.2) has an exact step index t, because the engine
  counted the steps;
- an rr recording identifies a point as (retired conditional branch count,
  general-purpose registers). rr's authors state this can fail to be unique,
  for example in a loop that only increments memory;
- a live target has no history, only the current stop.

A position carries its execution, process and thread instance, the backend's
token, and a before/after boundary. The activation α(t) is the frame instance
executing at t, tracked by call and return with a stack-pointer check for
`longjmp` and unwinding, so that a value is never read from the wrong
instance of a recursive frame.

Execution order, happens-before and observed read-from are three relations,
kept apart. A racing read may observe a write with no happens-before edge. The
timeline is for navigation; it is not the memory model. rr serializes threads
on one core, so a recording made that way cannot show a weak-memory bug, and
this design states the same limit for its own recorder.

## 4. Ownership

| Owner | Holds |
|---|---|
| `r2target` (new) | What the process states: registers, memory, threads, mappings, stop reasons; launch, attach, step, continue, breakpoints, watchpoints; reverse operations where the backend has them. Two backends behind one `Target` trait: the RSP client and the emulator. No inference, as `r2image` has none: it reports what the target says. |
| `r2il::eval` | The step semantics and exact time. The bounded evaluator that exists today stays the reference oracle for every faster evaluator. |
| The query database (`r2engine`, D13) | The trace (σ₀, E), checkpoints, segment summaries, the per-location write index, and the live target's bytes and registers as versioned inputs keyed by (position, range) beside the container bytes. Investigation state (bookmarks, user facts about a run) is user facts, an input of Q, and persists as Q persists. |
| `r2ssa` | The location-availability index, the value-at-time rule, gated-SSA chops for symbolic queries, refutation evidence, dynamic def-use over a trace. |
| `r2rewrite` | Inverse expressions for recovering overwritten values; simplification of path conditions. |
| `r2types` | Type and layout facts applied to live memory, with scope kept explicit. |
| `r2dec` | Rendering live values and refusals beside the C it already prints. No dynamic policy. |
| `r2s` | radare2's `d*` spellings (`db`, `dc`, `ds`, `dr`, `dm`, `dbt`, `dso`, `dcb`), and the `gdbstub` export so gdb, lldb and pwndbg can drive the emulator or a trace. |
| M, the machine profile (D15) | Register layout, stack pointer, return address, conventions, address spaces. The target's register description (`target.xml` or `qRegisterInfo`) is mapped onto it once, at connect. |

There is no supervised service, no RPC protocol and no Python SDK in this
design. Persistence is Q's; the agent and scripting surface is roadmap item A,
and the debugger adds verbs to it rather than a second protocol. If a separate
process is ever needed for a remote worker, it speaks RSP, because the backend
seam already does.

## 5. Backends

### 5.1 The RSP client

The GDB Remote Serial Protocol carries everything a time-travel backend needs:
`bc` and `bs` for reverse continue and reverse step, advertised through
`ReverseContinue+` and `ReverseStep+`; `vCont` for per-thread actions and
range stepping `r start,end`; and register-layout discovery through `target.xml`
(gdbserver, the QEMU gdbstub, OpenOCD) or `qRegisterInfo` (LLDB only). One
client reaches:

- `gdbserver` on Linux;
- `debugserver` and `lldb-server`, the native path on macOS;
- the qemu-user and qemu-system gdbstubs, for cross-architecture Linux
  binaries and for whole systems;
- OpenOCD and probes, for firmware over JTAG and SWD;
- `rr replay`, which serves the reverse packets, so time travel on Linux
  x86-64 arrives without writing a recorder.

Known limits: reverse execution is all-stop with no reverse `vCont`; range
stepping takes one contiguous range per request, so an IL block spanning
several ranges needs several; `qRegisterInfo` is LLDB's, and a client must
handle both discovery forms. The claim that `jThreadsInfo` returns a whole
stop snapshot in one round trip did not survive verification and must not be
designed against.

### 5.2 The emulator

The emulator runs r2il over a state the engine holds. Its uses are, in order
of value: the replay engine for recorded segments (section 6), the only runner
for a binary whose architecture or operating system the host lacks, the
stepper for a symbolic window (section 9), and a microscope on the same host
when every instruction must be seen.

Today's `r2il::eval` is a reference evaluator: state in `BTreeMap<u64, u8>`
per byte, `u128` values, decoding on every visit. It stays as the oracle. The
production evaluator is built in tiers, each differentially tested against the
tier below on the corpus:

1. a tuned interpreter: a flat register file indexed by Sleigh offset,
   `unique` as per-block scratch, a page table with a small translation cache,
   a block cache keyed by (address, bytes, context), ops pre-decoded;
2. flag elimination: the liveness index (F2.2) deletes flag definitions that
   no later op reads before the next definition, which removes most of the
   six flags Sleigh computes for every x86 arithmetic op;
3. a JIT over Cranelift: guest registers in host registers, blocks chained by
   direct jumps, indirect targets that the switch prover or callee resolution
   proved turned into direct jumps, an inline cache for the rest.

Exact time survives the JIT: a compiled block knows its instruction count, and
a stop inside a block replays that block in the interpreter.

### 5.3 The hybrid window

When host and target match, the target runs natively up to the point of
interest, the RSP client snapshots registers and mappings, and the emulator
continues from that snapshot for the window the user is looking at. The
emulation cost is paid only where the user is looking.

### 5.4 The `gdbstub` export

`r2s` exposes the emulator and any loaded trace through the Rust `gdbstub`
crate, which implements the target side of RSP including `bc`/`bs`. A user
keeps gdb, lldb or pwndbg as a front end and gains the engine's time travel
and cross-architecture execution underneath it.

### 5.5 Per platform

| Target on host | Runs natively | Emulation is for |
|---|---|---|
| Linux x86-64 on Linux x86-64 | yes | the microscope: replay, symbolic windows |
| Linux arm64 on Linux x86-64 | no | running it; syscalls forward to the host kernel |
| Linux ELF on macOS | no | running it, plus a syscall model, the expensive case |
| macOS binary on macOS arm64 | yes, via `debugserver` | the microscope |
| Firmware | no host | the CPU plus a device model, or a real board over OpenOCD |

## 6. Recording and the trace index

### 6.1 Recording

Where host and target share an operating system, the target is recorded
natively, not emulated. Syscalls are intercepted at the boundary and their
results logged; threads are serialized onto one core; signals are delivered at
syscall boundaries. The last choice loses rr's exact asynchronous placement,
which needs the retired-branch counter and is Linux-only; the recorder states
that a signal's position is a boundary, not an instruction. Checkpoints are
copy-on-write forks, so a checkpoint costs the pages dirtied since the last
one, not the stores executed. On Linux, `rr replay` is also a recording source
through the RSP client, and an rr recording is imported as (σ₀, E) only if
section 14's research item succeeds.

Where the target cannot run on the host, the emulator is the recorder and
time is the step index.

### 6.2 The index

Classic record and replay (rr, UndoDB, Microsoft TTD) answers a question about
the past by restoring a checkpoint and running forward; every query pays a
replay. Pernosco records cheaply, then replays once under instrumentation,
offline and in parallel across sections, into a database of every write; every
query then reads an index, at the cost of a database that its authors report
at about 100 GB for an hour of indexing on 36 cores.

This design holds both with one parameter. Let K be the checkpoint interval
in steps. The trace is (σ₀, E), a checkpoint every K steps, and for each
segment a summary: the set of locations it wrote, as intervals, from the
copy-on-write dirty pages or from the emulator. Then

    lastwrite(loc, t):  O(log(n / K) + K)
    space:              O((n / K) · |summary|)

K = 1 is Pernosco and K = n is rr. K is chosen per trace from a storage
budget, and segments the user keeps returning to are indexed fully, on demand,
as a Q query whose dependencies are the segment's checkpoint and events.

History reads compose the initial captured bytes with the writes at or before
t. A multibyte value may have several writers; overlapping and partial writes
resolve byte by byte; mapping lifetime and address reuse are part of the key;
unknown initial bytes remain unknown; a write to code bytes invalidates the
lifted range. A retained window needs a sufficient checkpoint plus the
nondeterminism after it; an arbitrary ring-buffer fragment is not replayable.

A bounded linear interpreter over the log is the index's oracle. The index
must agree with it on complete intervals and report the same gaps on
incomplete ones.

## 7. The theorems

These are the engine's own derivations. The research found none of them in
the literature in this form, and none has been machine-checked. Each states
its invariant, owner, complexity and the obligation that must be proved before
it may be used.

**Theorem A (checkpoint skip).** With checkpoints every K steps, a read of any
location at any time costs O(log(n/K) + K). Owner: Q. Obligation: none beyond
determinism of replay.

**Theorem B (static write-set pruning).** Let W(s) be a may-write set for
segment s, an over-approximation of the locations s writes, from dirty pages
or from the static summaries of the code s executes. If loc ∉ W(s) for every
segment between checkpoint c and time t, then val(loc, t) = val(loc, c), with
no replay. Cost: one interval test per segment inspected. Owner: Q holds W(s);
r2ssa supplies static may-write summaries. Obligation: W(s) is sound, which is
exactly what abstract interpretation gives and what a recorded dirty bitmap
gives.

**Theorem C (value of an SSA value at a time).** Let v be an SSA value with
defining operation d(v), and let π(t) be the static operation executed at step
t. If d(v) dominates pc(t), and pc(t) is within v's live range, then

    val(v, t) = output of the last step t′ ≤ t with π(t′) = d(v) and α(t′) = α(t).

Proof: every path from entry to pc(t) passes through d(v) (dominance); v is
assigned only at d(v) (SSA); after the last execution of d(v) in this
activation v cannot change; a loop re-executes d(v) and the last execution is
the current iteration's; a phi executes on block entry and the rule applies to
it unchanged. With an index per (definition, activation) the lookup is
O(log). Owner: r2ssa for the rule, Q for the index. Obligation: the activation
tracking of section 3 is exact.

Consequence: the printer (R) binds every C variable to SSA values with
provenance, so on a trace every in-scope variable of a stripped binary has an
exact value at every moment, and out of scope is a refusal. This is stronger
than DWARF, whose location lists compilers emit incompletely without saying
why: a confirmed gcc bug dropped a constant-folded variable that
`DW_AT_const_value` could have expressed.

**Theorem C′ (live recoverability, no trace).** At a live stop there is no
history, so a value must be available now. v is available in location ℓ at
point p if ℓ holds v on every path from d(v) to p: a forward must-analysis,
O(n · L) with bitvectors over L locations, kept as an index in r2ssa. Where v
is gone from every location, r2rewrite searches for an inverse expression over
values that are available (a subtraction undone, a constant added back, an xor
repeated), which is Srivastava's 1986 recovery of noncurrent variables by
inverting reversible operations. The result is a lattice value,
`Exact(location | expression) | Refused(reason)`, and the renderer prints
exactly that.

**Theorem D (closed-form skip).** If a loop has a proven summary S(k) for its
state after k iterations (induction variables; bodies of `memset` and `memcpy`
shape), the state at iteration k costs O(1) instead of O(k). This is the one
place a question is answered faster than native execution could run, because
native must execute the k iterations. Owner: r2ssa for the summary, Q for its
use. Obligation: the summary is proved, not pattern-matched on a name. The
roadmap has no induction analysis yet; it is a natural extension of P5.

**Theorem E (purity memoisation).** If a function f is proved pure (its only
effect is its result, and it reads only its arguments and immutable memory), a
replayed call with the same arguments reuses the cached result. Owner: P6's
callee summaries. Obligation: the proof of purity; a name is not one.

**Theorem F (parallel indexing).** Segments replay independently from their
checkpoints, so building an index over n steps takes O(n / cores) wall clock
while native execution is serial. Owner: Q.

The statement that follows from A to F, put plainly: the first run is bounded
below by native speed; every question after it is sublinear in the run.

## 8. Harmony between static and dynamic facts

### 8.1 Static facts accelerate the dynamic side

- Liveness deletes dead flag and temporary definitions before interpretation
  or compilation (section 5.2).
- Proven indirect targets become direct jumps in compiled code.
- The machine profile gives the emulator a dense register layout.
- May-write summaries prune replay (theorem B); loop summaries and purity
  proofs skip it (theorems D and E).

### 8.2 Dynamic facts check the static side

A static fact a at point p claims that every concrete state at p lies in
γ(a), its concretization. An observed state σₜ with π(t) = p and σₜ ∉ γ(a) is
a refutation, a concrete counterexample. Because every fact carries its
`Basis` (D4, item C), the refutation names the premise that failed: an engine
defect, the `UbFreeSource` premise, an immutability assumption, or a summary.

Checkable classes, each at O(facts at pc) per step:

- value ranges and constants (P5);
- jump-table and indirect-call target sets;
- must-alias claims;
- argument counts: the callee reads only the formals the engine claimed;
- frame extents: every access stays inside its frame object (P4);
- immutable-memory folds: the live bytes differ, so the premise fails;
- code bytes: a write to code means JIT or self-modification, and the range
  is re-lifted.

The direction is one-way (invariant 11). An observation may propose a
hypothesis, as Daikon and SYNERGY do, and the static prover proves or drops
it. A static ⊤ that is constant on every observed run is a precision hint,
never a fact. Runtime refutation runs as a CI gate (section 13): every
certified fact is checked at every executed point of the corpus traces.

### 8.3 Time scrubbing is free of static work

Static queries depend only on the container bytes and user facts. A dynamic
view is a static fact composed with val(·, t). Moving t invalidates no static
query, so scrubbing costs O(visible values · log n). A static query re-runs
only when live code bytes differ or a refutation fires, both of which Q's
red-green revalidation handles because the live bytes are an input.

### 8.4 Semantic navigation

Each is an index lookup, O(log), on a trace:

- next or previous C statement: the smallest t′ > t whose operation belongs
  to a different statement in the same activation, and the symmetric reverse;
- a conditional breakpoint such as `break if len > 100` attaches to the
  defining operations of `len`, so it costs the executions of those
  definitions, not every step;
- watching a frame object: its extent is a hardware watchpoint live and a
  range query on a trace;
- last writer of a byte, every value a variable took, and the backward slice
  of a value, as closures over the read and write edges, O(|slice| · log).

## 9. Concolic execution and taint from a stop

A symbolic query starts at a concrete state σₜ. The user names the symbolic
set S: input bytes, a register, a memory range. Everything else is concrete.

- In an acyclic SSA region a phi is an `ite`, so the region between pc and a
  target block is its own bitvector formula, linear in the region's size, and
  states merge at the immediate postdominator for free. Symbolic execution
  over such a chop is a translation, not a path enumeration.
- Proven static invariants hold on every run and are added as solver
  assumptions; unproven ones are not.
- A symbolic pointer whose frame object is known ranges over that object's
  extent as an `ite` over its bytes, not a full array theory. A pointer with
  no proven object is concretized only with an explicit, recorded constraint
  that the answer carries; never silently, and a finite address space is not
  by itself a tractable symbolic domain.
- A loop uses its induction summary when one is proved, otherwise it unrolls
  to a stated budget and the answer past the budget is `Unknown`.
- Results are Q queries keyed by (region, S, hash of the concrete values the
  formula read).
- A candidate counterexample is reproduced by fresh controlled execution
  before it is reported. Matching one execution validates that witness only.
  An absence proof needs a sound model, a complete bounded search, or an
  invariant checked against initial states and transitions. A timeout is
  unknown.

Dynamic taint is the forward closure from S over the trace's read and write
edges. Implicit flows come from control dependence, read from the static
postdominator tree. A taint answer states whether implicit flows were
included.

## 10. The cost of emulation

For one guest instruction, native costs c_n: on the order of a nanosecond,
with registers renamed, branches predicted and addresses translated by the
hardware. Software executing the same instruction pays

    c_e = c_fetch + c_decode + c_dispatch + c_sem + c_state + c_mem + c_ctrl + c_obs

| Term | Interpreter floor | JIT floor | Why |
|---|---|---|---|
| decode | microseconds (Sleigh), or cached | amortized to zero | block cache keyed by (address, bytes, context) |
| dispatch | one indirect branch per op, about 15–20 cycles on a mispredict | zero with chained blocks | one dispatch site cannot learn guest control flow |
| state | a load and a store per operand, with store-to-load latency of 4–5 cycles per hop | about zero with register allocation | hardware renaming costs 0–1 cycles |
| semantics | 3–10 P-code ops per instruction, flags computed eagerly | about native with dead flags removed | Sleigh computes CF, OF, SF, ZF, PF, AF that the next instruction overwrites |
| memory | a translation per access | one add (`guest_base`), or zero with an identity map | the host MMU translates when guest space is reserved in the host |
| control | a hash lookup per indirect jump or return | the same unless the target is proved | the hardware has a BTB and a return stack |
| observation | one extra store per store, if writes are logged | the same | native never pays it; checkpoints avoid it |

So c_e ≥ c_n + c_obs even with perfect code generation when host and guest
share an ISA: the hardware is the fastest executor of its own instruction set.
In practice an interpreter runs 30–100× slower than native, QEMU's TCG 3–10×,
a JIT with cross-block register allocation 1.5–3×, same-ISA copy-and-annotate
tools (Pin, DynamoRIO) 1.1–1.5×, and rr's native recording 1.2–2×. HP's
Dynamo once beat `-O2` by a few percent through trace layout; that is an
anecdote, not a target.

The consequences are the design: on a shared host and OS the fastest emulator
is none, so recording is native (section 6.1); the emulator is the replay
engine, offline and parallel, where 2–3× is acceptable; and the questions a
user asks are answered without replay wherever theorems B to E apply.

## 11. What a user gets

1. C-level live debugging of a stripped binary: at a stop `pdd` prints
   `len = 0x41` and `buf = "AAAA…"` beside the code, and `<not live: reason>`
   where the value is refused.
2. Reverse execution with exact time: who wrote this byte, step back one C
   statement, every value `i` took, each answered from the index.
3. Questions to the solver from a stop: which input reaches this `abort`;
   can `idx` exceed 16. The answer is an input, `no`, or `unknown (budget)`.
4. Taint from the input bytes to a `memcpy` length, live.
5. Cross-architecture debugging on any host, without qemu or gdb-multiarch
   setup.
6. Their own front end: gdb, lldb and pwndbg attach to the emulator or to a
   trace through `gdbstub`.
7. Trust: a displayed value is exact or refused, and when the engine is wrong
   a run says so.

Against gdb with rr: on a source-level native program on Linux x86-64, and on
large or heavily multithreaded workloads, gdb with rr wins and this design
says so. On a stripped binary, in exploit development, on macOS or arm64, on
firmware, and for "who corrupted this" in a small or medium program, it is a
different class of tool.

## 12. Phases

Each phase runs beside nothing it replaces, because nothing exists; each
deletes nothing and must say what it adds to the census. All phases depend on
Q, P4, R and M. Effort is for one engineer with agents, after those land.

| Phase | Adds | Exit | Effort |
|---|---|---|---|
| **D0** Target seam | `r2target`, the RSP client, the `Target` trait, the `d*` verbs, live memory and registers as Q inputs | `r2s` attaches to `gdbserver`, `debugserver` and the qemu gdbstub; `dr`, `dm`, `db`, `dc`, `ds` diff clean against radare2 under `scripts/diff_r2.py`; a stop re-runs only the queries whose input ranges changed | 1–2 months |
| **D1** Live values | the availability index (C′), inverse recovery in r2rewrite, the refusal lattice, live values rendered in `pdd` | on a stripped optimized fixture every in-scope variable is exact or refused, verified against a DWARF build of the same source; no stale value in the corpus | 1.5–2.5 months |
| **D2** Traces | the tuned interpreter and flag elimination, native recording with fork checkpoints, (σ₀, E), the K-segment index, `bc`/`bs` over the index, the `gdbstub` export, rr replay as a client source | a recorded failure answers last-writer and value-at-time from the index, equal to the linear oracle; the index and the oracle report the same gaps on a deliberately cut interval; the emulator tiers agree with `r2il::eval` on the corpus | 4–8 months, the syscall layer dominating |
| **D3** Navigation | statement stepping, definition-attached conditions, frame-object watchpoints, slices | each navigation is an index lookup; no query replays more than one segment | 1–2 months |
| **D4** Refutation gate | facts enumerable per pc (C2), the per-step check, the CI job over corpus traces | every certified fact holds at every executed point, or the failing premise is named | about 1 month |
| **D5** Concolic and taint | the solver boundary, gated-SSA chops, bounded memory, budgets, witness reproduction, taint closure | a generated input reproduces its predicted behavior in controlled execution; a spurious candidate triggers refinement; a timeout is `Unknown` | 3–4 months |
| **D6** Research | importing an rr recording's events as E and replaying them under r2il, so that divergence from hardware tests the lifter | a divergence is a lifter bug with a witness, or the import is abandoned with the reason recorded | 2–3 months, may fail: rr's format is internal |

The JIT (section 5.2, tier 3) is a separate decision after D2, taken only if
users record programs the interpreter cannot keep up with.

Deferred past this program, each with its own design when its consumers
exist: Windows, which needs a second syscall model; multicore recording under
an explicit memory model; core dumps as a read-only backend; DAP and language
runtime adapters; distributed causality.

## 13. Gates

- The emulator tiers against `r2il::eval`, and the index against the linear
  oracle, on every corpus trace.
- The refutation gate of section 8.2 as a CI job.
- A negative corpus: a cut interval must yield an unknown, not a last writer;
  a value without a proof must render as refused; a symbolic timeout must
  render as `Unknown`.
- Behavior-level fixtures spanning memory corruption, allocation reuse,
  integer overflow, optimized variables, indirect calls, signals, mapping
  changes and self-modifying code, with and without debug information.
- Fuzzing of RSP packet decoding, trace manifests and position tokens:
  malformed input cannot mint authority.
- Kani for span arithmetic, register lanes, the K-index invariants and the
  controller's state machine.
- Cold and warm latency reported apart: recording slowdown, indexing
  throughput, storage growth, replay distance, and p50/p95/p99 per query.
  Warm index lookup is never advertised as recording cost.

## 14. Risks and open questions

- The syscall layer for a foreign operating system is unbounded work; qemu's
  `linux-user` is about fifty thousand lines of C. The emulator's first
  recording target is a binary whose OS the host shares, where syscalls
  forward.
- macOS has no rr-style recording path: no deterministic counter, weak
  `ptrace`. The native path is `debugserver` plus fork checkpoints, and
  whether a ptraced process forks cleanly as a checkpoint on macOS is
  unverified.
- rr's trace format is internal and changes; D6 may fail.
- Concurrency is serialized only (invariant 13).
- Which crate owns refutation evidence, and how a refutation feeds back into
  r2ssa without unbounded recomputation, is open; the one-way rule bounds it
  but does not design it.
- The index layout inside Q, and its storage bound, are open; K is the only
  knob so far.
- The ASPLOS 2023 citation below was credited to two different author lists
  by the verification pass; the author list must be checked before it is
  quoted anywhere durable.

## 15. What is verified and what is ours

Verified by the research pass of 2026-10-04, with two or three of three
independent votes each:

| Finding | Source |
|---|---|
| rr's execution point is (retired conditional branch count, registers); it records only what crosses the process boundary; replay is all or nothing; the point can fail to be unique | O'Callahan et al., [arXiv 1610.02144](https://arxiv.org/pdf/1610.02144); [ACM Queue interview](https://queue.acm.org/detail.cfm?id=3391621) |
| rr serializes threads on one core; weak-memory bugs are not observable under it | same |
| rr, UndoDB and TTD reverse by checkpoint restore and forward replay; TTD's index makes it partly omniscient | ACM Queue; [Pernosco related work](https://pernos.co/about/related-work/) |
| Pernosco records cheaply, then indexes every write offline and in parallel; queries read the index | [Pernosco vision](https://pernos.co/about/vision/) |
| RSP has `bc`/`bs`, `vCont` with range stepping, and `qRegisterInfo` on LLDB; no reverse `vCont`; one range per request | [GDB packets](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packets.html); [LLDB extensions](https://lldb.llvm.org/resources/lldbgdbremote.html) |
| The Rust `gdbstub` crate implements the target side including reverse execution | [gdbstub README](https://github.com/daniel5151/gdbstub) |
| DWARF for optimized code is incomplete without saying why; a confirmed gcc bug dropped a constant-folded variable | [ASPLOS 2023](https://www.diag.uniroma1.it/~delia/papers/asplos23-full.pdf), author list to check |
| Noncurrent values are often recoverable by inverting reversible operations, in linear time | [Srivastava 1986](https://link.springer.com/chapter/10.1007/3-540-17179-7_3) |
| Debug information must never show a wrong value; "optimized out" over a stale value | [LLVM Source Level Debugging](https://releases.llvm.org/21.1.0/docs/SourceLevelDebugging.html) |
| Ghidra puts a trace database between its UI and the target, as an asynchronous cache with stale pages marked | [Ghidra Debugger course, A4](https://ghidra.re/ghidra_docs/GhidraClass/Debugger/A4-MachineState.html) |

Refuted: that `jThreadsInfo` returns a whole stop snapshot in one round trip.

Ours, unverified by any source and not yet machine-checked: theorems B, C,
C′, D, E and the K-parameterised index of section 6.2; the refutation
framing of section 8.2 as a gate; the gated-SSA chop of section 9 as the
symbolic formula; the cost bound of section 10. The research pass found no
surviving claims on concolic execution, symbolic memory models, solver
caching, abstract-interpretation refinement or trace query databases, so
sections 7 to 10 rest on derivation.

## 16. What is kept from the 2026-09-13 plan

Kept, and folded into the sections above: the invariants of its section 1;
execution positions with a before/after boundary and durable object
identities; the three concurrency relations; scope and search status on every
answer; history reads that compose initial bytes with writes, with unknown
initial bytes staying unknown; the linear oracle for the index; the retention
rule for windows; the call tree that admits tail calls, signals and stack
switches; its table rejecting the over-claims of an earlier mathematical
proposal (semiring provenance as model counting, an entropy bound as a byte
guarantee, mixed affine domains as one elimination); its correctness corpus
and mechanical guardrails.

Dropped: ownership by radare2's `libr/debug` and the plugin, binding to
`OwnedFunctionSnapshot`, the supervised service, the RPC protocol, the Python
SDK, the DAP adapter and the notebook as debugger deliverables, and a stage
order that built the service before any semantic capability. Added: the
emulator and its cost model, exact time, theorems A to F, the refutation gate,
the `gdbstub` export, the hybrid window, and the dependency on Q, P4, R and M.
