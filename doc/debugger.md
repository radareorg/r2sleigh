# The debugger

Draft, 2026-10-05, reviewed 2026-10-09, not yet on the roadmap. It supersedes
`doc/debugger-build-plan.md` (2026-09-13), whose ownership was the radare2
plugin's; section 21 says what is kept from it. Nothing described here exists
yet. If adopted, the debugger comes after the program in `ROADMAP.md` (F2, Q,
P4, D, M) and must not start before row D, the decompiler rewrite, switches
`pdd` to the staged pipeline, because until then it would bind to register
names and a renderer that D replaces.

Roadmap fit, from the 2026-10-09 review. The phases are G0 to G5 (section 17),
named apart from the decompiler's D0 to D5 and from the roadmap decisions this
text cites (D4, D7, D13, D15). G0 and G1 carry exit criteria worth committing
to; G2 to G5 add 9 to 13 engineer-months on top of their 3 to 5 and stay design
until G1's exit holds. Sections 10A, 10B, 12A and 15A are research directions
with no phase and no exit criterion, and theorems B to E are unproved (section
20). The design enters the roadmap as one deferred row, after the D switch.

## 1. What it is, and what it is not

The debugger is three things: a backend seam that reads a target's state, a
trace database that holds a run and answers questions about it in sublinear
time, and the static engine's facts bound to time. It is not the radare2
debugger (the engine links nothing from `libr`), not a rebuilt rr (rr's
mechanism is hardware counters and a kernel-level recorder, and it is Linux
only), not a rebuilt qemu (qemu runs the binaries; section 5.2), and not a
gdb plugin (pwndbg and gef live inside gdb's Python API, where gdb's own model
of frames and symbols fights ours).

Its audience is radare2's: stripped binaries, reverse engineering, exploit
development, firmware, cross-architecture work on any host. For source-level
debugging of a large native program with DWARF on Linux x86-64, gdb with rr is
the better tool, and this design does not compete there. Windows binaries are
out of scope; Wine exists.

What makes it different is that every static fact the engine owns becomes a
dynamic fact for free. A decompiled C variable is a bound SSA value; an SSA
value has an exact value at every moment of a trace (section 8, theorem C). A
symbolic query starts from a concrete stop and uses the engine's proofs as
solver assumptions (section 10). A run is a check on the engine (section 9).
And because the decompiler refuses rather than guesses, binding runtime state
to its output is safe, which is what no plausible-C decompiler can offer
(section 15).

## 2. Invariants

1. Historical observations never change meaning. Better analyses produce new
   versioned interpretations; they do not rewrite the observations.
2. Every reference has an explicit execution, object and code lifetime. OS
   PIDs, TIDs, symbols and raw addresses are not durable identities.
3. Every answer identifies its evidence, assumptions, coverage and scope.
   Scope is one of **observed** (seen in a run), **stated** (declared by the
   container or the runtime: DWARF, symbols, BTF, a JIT's own description),
   **derived** (proved by the engine), **assumed** (admitted by the user),
   **modeled** (a solver's or an experiment's alternative), or **refused**.
   Search status is one of complete, partial, unknown, unsupported, cancelled
   or budget exhausted; a refusal also names which wall it hit (section 19.3):
   `impossible`, `unsupported`, `unimplemented` or `budget`.
4. Missing evidence stays unknown. An empty result is an absence proof only
   when the interval, event families and object lifetime were covered.
5. A repeated client request cannot perform a second target mutation.
6. Recorded observations and modeled alternatives stay distinguishable.
7. One fact has one owner; an index is a derived view, never a second source.
8. Work is bounded, cancellable, observable and reusable under valid keys. No
   command blocks past its budget.
9. Rendering and types obey the existing authority contracts.
10. A displayed value is exact or refused, never stale. This is LLVM's debug
    information contract: correctness means never showing a wrong value, not
    showing every value.
11. Dynamic evidence never becomes rendered C. A run may refute a static fact
    or propose a hypothesis; a hypothesis becomes C only as an explicit user
    assumption that the output carries, or as a fact the static prover proved.
12. Time is exact where the engine owns the stepper, and stated as ambiguous
    where it does not (section 3).
13. A sequential trace semantics describes a serialized execution only. It is
    never presented as a model of weak-memory concurrency.
14. Nothing in the debugger turns an unknown into a displayed value. The lints
    that forbid decompiler-side fact repair apply to `r2target`, the stop
    record and the view unchanged.
15. Granted information is used first, inference fills where it is silent, and
    every stated fact is checked where a proof exists. A stated fact that
    fails its check is shown as a conflict with both values, never dropped and
    never silently overridden (section 9).

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

- a run replayed by the engine's emulator (section 5.3) has an exact step
  index t, because the engine counted the steps;
- a qemu run under `-icount` has an exact instruction count; a qemu-user run
  recorded by the plugin (section 6.1) has the plugin's count;
- an rr recording identifies a point as (retired conditional branch count,
  general-purpose registers). rr's authors state this can fail to be unique,
  for example in a loop that only increments memory;
- a live target has no history, only the current stop.

A position carries its execution, process and thread instance, the backend's
token, and a before/after boundary. The activation α(t) is the frame instance
executing at t, tracked by call and return with a stack-pointer check for
`longjmp` and unwinding, so that a value is never read from the wrong
instance of a recursive frame. Positions are identities and the session's
cursor is a convenience (section 13).

Execution order, happens-before and observed read-from are three relations,
kept apart. A racing read may observe a write with no happens-before edge. The
timeline is for navigation; it is not the memory model. rr serializes threads
on one core, so a recording made that way cannot show a weak-memory bug, and
this design states the same limit for its own replay.

## 4. Ownership

| Owner | Holds |
|---|---|
| `r2target` (new) | What the process states: registers, memory, threads, mappings, stop reasons; launch, attach, step, continue, breakpoints, watchpoints; reverse operations where the backend has them. Two backends behind one `Target` trait: the RSP client and the emulator, the latter with the replay personality (section 6.2). No inference, as `r2image` has none: it reports what the target says. |
| `tools/qemu-plugin/` (new) | A small TCG plugin in C that logs (σ₀, E) and the instruction count from a qemu run, in the engine's trace format. |
| `r2il::eval` | The step semantics and exact time. The bounded evaluator that exists today stays the reference oracle for every faster evaluator. |
| The query database (`r2engine`, D13) | The trace (σ₀, E), checkpoints, segment summaries, the per-location write index, and the live target's mappings, bytes and registers as versioned inputs keyed by (position, range) beside the container bytes. The request journal, revisions and user assumptions are user facts, inputs of Q, and persist as Q persists. |
| `r2engine` | The session: socket, writer lease, budgets, revisions, the stop record (section 13). |
| `r2ssa` | The location-availability index, the value-at-time rule, gated-SSA chops for symbolic queries, refutation evidence, dynamic def-use over a trace. |
| `r2rewrite` | Inverse expressions for recovering overwritten values; simplification of path conditions. |
| `r2types` | Type and layout facts applied to live memory, with scope kept explicit. |
| `r2dec` | Rendering live values and refusals beside the C it already prints, and the render plan the view consumes. No dynamic policy. |
| `r2s` | radare2's `d*` spellings, `-d`, `-S` sessions, `j` on every verb, the `gdbstub` export, and `monitor` dispatch of engine verbs for foreign front ends. |
| `r2s-tui` | The view (section 14), a consumer of the render plan. It never calls the engine while drawing (D7). |
| An MCP adapter (new, separate) | One tool, `cmd`, over the session socket, plus `schema`. It owns no policy. |
| M, the machine profile (D15) | Register layout, stack pointer, return address, conventions, address spaces, per-arch syscall numbers and struct layouts. The target's register description (`target.xml` or `qRegisterInfo`) is mapped onto it once, at connect. |

There is no supervised service, no RPC protocol, no SDK, no DAP adapter and no
syscall layer in this design. Persistence is Q's; the agent surface is roadmap
item A, reached over the session socket in r2pipe's shape; the environment is
qemu's (section 5.2). If a separate process is ever needed for a remote
worker, it speaks RSP, because the backend seam already does.

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
- `qemu-user` and `qemu-system` gdbstubs, for cross-architecture Linux
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

### 5.2 qemu is the runner

Decision, 2026-10-05. The CPU is emulatable for every Sleigh architecture on
any host; the environment is not. A Linux ELF makes about three hundred
syscalls whose numbers, struct layouts and `ioctl` codes differ per
architecture, and qemu's `linux-user` is about fifty thousand lines of C for
that alone; firmware talks to memory-mapped devices of which qemu-system models
hundreds. Writing either again would buy convenience qemu already provides and
would make the engine a kernel maintainer. So:

- Linux ELF on any architecture runs under `qemu-user` (Linux host; on macOS
  inside a Linux VM or container, as people already do);
- firmware runs under `qemu-system` with its board models, or on a real board
  over OpenOCD;
- Mach-O runs natively under `debugserver`;
- the engine attaches to all of them through the one RSP client.

The engine's emulator is not a runner. It is the replay engine for recorded
segments, the stepper for symbolic windows, and the only runner for a window
where every instruction must be seen. It never needs a real syscall: a replay
answers syscalls from the log (section 6.2), and a symbolic window ends at a
syscall the log cannot answer.

What this gives up: `qemu-user` has no record mode, so native-speed recording
on Linux x86-64 is rr through its replay gdbstub, or the plugin at TCG speed;
and a Linux ELF cannot run on a macOS host without a VM. If users ask for the
latter, a pure-model Linux personality for static, single-threaded, CTF-grade
binaries, about sixty syscalls with explicit refusal beyond them, is a bounded
later item, acceptable because the refusal is explicit. It is not in the
phases.

### 5.3 The emulator

The emulator runs r2il over a state the engine holds. Today's `r2il::eval` is
a reference evaluator: state in `BTreeMap<u64, u8>` per byte, `u128` values,
decoding on every visit. It stays as the oracle. The production evaluator is
built in tiers, each differentially tested against the tier below on the
corpus:

1. a tuned interpreter: a flat register file indexed by Sleigh offset,
   `unique` as per-block scratch, a page table with a small translation cache,
   a block cache keyed by (address, bytes, context), ops pre-decoded;
2. flag elimination: the liveness index (F2.2) deletes flag definitions that
   no later op reads before the next definition, which removes most of the
   six flags Sleigh computes for every x86 arithmetic op;
3. a JIT over Cranelift, decided after G2 and only if replay cannot keep up:
   guest registers in host registers, blocks chained by direct jumps, indirect
   targets that the switch prover or callee resolution proved turned into
   direct jumps, an inline cache for the rest.

Exact time survives the JIT: a compiled block knows its instruction count, and
a stop inside a block replays that block in the interpreter.

`CALLOTHER` operations carry no semantics (`crates/r2sleigh-lift/src/disasm/mod.rs`
says so). Each one the corpus hits becomes a Rust handler or a refusal that
names the operation. Sleigh specifications are tested by decompiling, not by
running, so flag and float corner cases surface only here; `tests/equiv`
extends to every architecture the emulator claims, with host-compiled
originals under `qemu-user` as the oracle.

### 5.4 The hybrid window, and recording turned on mid-session

When host and target match, the target runs natively up to the point of
interest, the RSP client snapshots registers and mappings, and the emulator
continues from that snapshot for the window the user is looking at. The
emulation cost is paid only where the user is looking.

This is also how any live RSP target gains a recording without a recorder. At
a stop, `dts+` switches the stepper from the target to the emulator over the
target's memory through the page cache, logging every step into (σ₀, E). A
syscall inside the window is not modeled: it is **injected into the stopped
target**, gdb's `call` technique — write the guest registers, point `pc` at a
`syscall; brk` gadget, continue, read the registers back. The file
descriptors, pid and mappings are the target's, so nothing is faked. `dts-`
writes dirty pages and registers back and resumes natively. From `dts+` on the
session has both a growing immutable past and a live future (section 6.0), at
interpreter speed, on Linux and macOS alike, with no syscall layer. Every
answer from the window carries its caveats: other threads are frozen, so the
interleaving differs from native; a syscall that changes the address space
(`mmap`, `mprotect`) is injected and the maps re-read.

### 5.5 The `gdbstub` export

`r2s` exposes the emulator and any loaded trace through the Rust `gdbstub`
crate, which implements the target side of RSP including `bc`/`bs`. A user
keeps gdb, lldb, pwndbg or gef as a front end and gains the engine's time
travel and cross-architecture replay underneath it. Engine verbs that RSP
cannot express reach the stub through `qRcmd`, which gdb spells
`monitor <verb>` (section 12).

### 5.6 Per platform

| Target on host | Runs under | The emulator is for |
|---|---|---|
| Linux x86-64 on Linux x86-64 | native, `gdbserver`, rr | replay, symbolic windows |
| Linux arm64 on Linux x86-64 | `qemu-user` | replay, symbolic windows |
| Linux ELF on macOS | `qemu-user` in a VM or container | replay, symbolic windows |
| macOS binary on macOS arm64 | `debugserver` | replay, symbolic windows |
| Firmware | `qemu-system` or OpenOCD | replay of recorded MMIO, symbolic windows |
| Linux kernel | `qemu-system` (TCG or KVM), KGDB, JTAG | symbolic windows over kernel code through recorded page tables |

## 6. Recording and the trace index

### 6.0 Modes: live, replay, both

| Mode | Target runs under | Past | Future | Speed |
|---|---|---|---|---|
| Live | `gdbserver`, `debugserver`, a qemu stub | none | native stops | native |
| Replay | `rr replay`, `qemu-system` replay, the emulator over a log | all of it | none | index lookups |
| Both | a runner that records while serving stops | since recording began | live stops | the recorder's |

Both comes free under qemu (stub and plugin in one process) and under the
emulator; it comes mid-session on any live target through `dts+` (section 5.4);
it never comes under `rr record`, which is the only tracer of its process, so
rr is record first, replay after. The timeline shows the frontier between the
indexed past and the live future; stepping back past where recording began
answers `impossible: not recorded before t₀` (section 19.3). The session never
asks for a mode: it is live until a recording is loaded or turned on.

### 6.1 Recording

Three sources, all producing (σ₀, E) in the engine's format:

- **The TCG plugin.** A small plugin of ours against qemu's plugin API logs
  the syscall numbers and results (`vcpu_syscall` and `vcpu_syscall_ret`
  callbacks in user mode), signals, the instruction count, and, when a full
  index is wanted, per-instruction memory writes. In user mode the host
  kernel writes syscall output buffers behind TCG's back, so the plugin
  carries a per-syscall table of output extents (`read` writes `buf[0..ret)`,
  `stat` writes one `struct`), keyed by the machine profile's per-arch
  layouts. rr carries the same table; it is a fraction of a personality.
- **`qemu-system` record mode.** `-icount ...,rr=record` replays
  deterministically and serves reverse execution on qemu's own gdbstub. The
  plugin runs during qemu's replay to build the index, and the engine's
  emulator is used only where exact P-code semantics are needed.
- **`rr replay`** on Linux x86-64, through the RSP client, for native-speed
  recordings. Its positions carry rr's identity, not a step index. Measured:
  Firefox's `mochitest` records at 1.49× and replays at 1.01×; Octane under
  the JS shell records at 1.79× and replays at 1.56×, most of that being
  single-core serialization of a multi-core workload (rr, USENIX ATC 2017,
  Table 1). No Chromium workload has been measured under rr. Mozilla's own rr
  guidance attributes extra recording overhead to the content sandbox's
  `SIGSYS` traps and the background hang monitor's syscalls, and offers
  disabling each as an optional speedup, with no published numbers.

Where a trace is recorded, threads are serialized and signals land where the
recorder placed them; the plugin states a signal's position as an instruction
count, rr as its own identity. Checkpoints during replay are copy-on-write
forks of the emulator's state, so a checkpoint costs the pages dirtied since
the last one, not the stores executed. Boothe's bidirectional debugger (PLDI
2000) is the K = n precedent: no trace, fork-based checkpoints, logged and
replayed syscalls, event counters compiled in as positions, reverse movement
in at most two passes at a cost "usually bounded within a small constant
factor of the temporal distance moved back".

### 6.2 The replay personality

The only environment layer the engine builds. During replay the emulator
reaches a syscall instruction, and the replay personality answers it from E:
the return value into the convention's register, the output extents into
memory, the signal if one was logged at this count. It performs no real
syscall, needs no host and is deterministic by construction. Its per-arch
tables (syscall register, number, struct layouts) come from the machine
profile. An event the log lacks is a divergence, reported with the count, not
guessed.

### 6.3 The index

The design space has two measured poles. **Omniscient (K = 1):** every write
is indexed, and a value-at-time query is a predecessor lookup over a sorted
per-location list. TOD (OOPSLA 2007) measures this at about 5× the raw event
in storage, with roughly ten index updates per event, and answers single-field
queries in 120–350 ms; its indexes are larger than the already bulky trace.
Lewis's ODB (2003) is the naive form, a per-variable history list of
(timestamp, value) with the closest-previous entry as the answer. **Pure
replay (K = n):** no write index, Boothe's O(d) re-execution, where d is the
distance moved back, bounded by checkpoint spacing.

The decisive datapoint for this design is **STIQ** (Pothier & Tanter, ECOOP
2011), which sits between the poles and is the nearest published relative of
what follows. It divides the trace into bounded execution blocks, discards the
blocks themselves, and keeps only a summary per block plus a lightweight
fork/copy-on-write snapshot at each block boundary; a query locates the block
in O(log n) and then replays that one bounded block to find the exact event in
O(1). The key measurement: **coalescing all writes to one location within a
block into a single index entry cut index entries by 95%**, because of
temporal locality. STIQ's DaCapo indexes are 0.16–0.27 GB against 1.1–5 GB
traces (the index smaller than the trace, the inverse of TOD), and memory
queries average 8.6–27 ms with maxima under 0.5 s. TTD's published rule of
thumb agrees on the shape: its `.idx` is typically 1–2× the `.run`, is a
discardable derived artifact rebuilt by `!index`, and its size scales with the
breadth of distinct memory locations accessed, not with trace length alone.
WET (Zhang & Gupta, TACO 2005) adds that in a dependence trace timestamps
compress 130–231× while values compress only 11.5×, so storing one last value
per location per segment, not every value, is where the saving is.

This design holds both poles with one parameter. Let K be the checkpoint
interval in steps. The trace is (σ₀, E), a copy-on-write checkpoint every K
steps, and per segment a **write summary**: for each touched page a dirty-word
bitmap, and for each dirty word its last value and last-write position within
the segment (coalesced, STIQ's 95% reduction). Per page, a **sorted list of
the segment ids that dirtied it**. Then `lastwrite(loc, t)`:

1. locate segment j = ⌊t / K⌋ in O(1);
2. if `loc` is dirty in segment j before t, replay from checkpoint j for at
   most K instructions (or read an optional intra-segment per-word log);
3. otherwise binary-search page(loc)'s segment list for the greatest j′ < j
   that dirtied it, O(log(n/K)), and read the value from summary j′ in O(1);
   the exact write position is recoverable by one bounded replay of K.

Cost:

    lastwrite(loc, t):   O(log(n / K) + K)
    space:               Σ_j |W_j| ≤ n words, shrinking with locality
    checkpoints:         n / K copy-on-write snapshots

K = 1 degenerates to TOD/ODB (the write index becomes per-event), K = n to
Boothe (no index, O(d) replay). K is chosen per trace from a storage and
latency budget: at emulator speed v and an interactive budget L, K ≈ L·v; for
uniform cost, √n checkpoint spacing minimizes checkpoints × replay. Segments
the user keeps returning to are indexed fully, on demand, as a Q query whose
dependencies are the segment's checkpoint and events. The literature (within
what survived verification) describes no published structure combining
per-segment write summaries with per-page predecessor lists, so the exact
layout above is this engine's derivation; STIQ's block-summary-plus-replay is
the closest prior art, and its numbers bound what to expect.

The invariant the index must preserve: for every address `loc` and position t,
`lastwrite(loc, t)` equals the value a full linear replay to t would read. A
bounded linear interpreter over the log is the oracle, and the index must agree
with it on complete intervals and report the same gaps on incomplete ones.

History reads compose the initial captured bytes with the writes at or before
t. A multibyte value may have several writers; overlapping and partial writes
resolve byte by byte; mapping lifetime and address reuse are part of the key;
unknown initial bytes remain unknown; a write to code bytes invalidates the
lifted range. A retained window needs a sufficient checkpoint plus the
nondeterminism after it; an arbitrary ring-buffer fragment is not replayable.

## 7. Debug mode: what the existing commands see

In `-d` mode the verbs do not change; what they read does. Live state is a Q
input, not a debugger mode.

- Q's inputs are the container bytes, the user's facts, and in `-d` mode the
  target's mappings, registers and memory keyed (position, range).
- For a range the target maps, the target is the authority for bytes. The
  container stays the authority for what it states: sections, symbols,
  relocations, imports, DWARF.
- Each mapped module (`xyz`, `libc.so.6`, `ld.so`, the vDSO) is its own
  container input with its own slide, discovered from the target's maps and
  `link_map`. Imports resolve through the live GOT to the library's symbols,
  so `pdd` prints the callee's name rather than its stub.
- Rebasing is one index: file address plus slide. Functions are keyed by
  stable ids (F1), so a sealed function does not move; only its address
  projection does. Nothing is re-analysed for ASLR.
- Live bytes that differ from file bytes in a code range (JIT, self-modifying
  code, a patched GOT) make Q re-lift that range through red-green
  revalidation. No special case.
- Memory reads are cached per stop at page granularity and invalidated on
  resume. A page not yet fetched is shown as stale, Ghidra's pattern. On a
  trace the cache is keyed not by one position but by the maximal position
  interval [p_lo, p_hi) over which the range is unchanged, because a read of
  range r at p equals the read at p′ exactly when no write to r falls in
  (p′, p]. The write index (section 6.3) supplies the next write to r after p
  in O(log(n/K)), so an entry's p_hi extends lazily and a miss at p is served
  by `lastwrite`. Layout: per page a BTreeMap from interval start to (interval
  end, bytes), lookup O(log w) for w versions of that page. Invalidation is
  red-green and range-local: a new segment or a user write (`w`/`wx`) marks
  only the pages its write summary names, never a global revision bump. This
  constancy-interval cache is a corollary of `lastwrite` and is the engine's
  derivation; no surviving source describes caching reads across positions.
- `s`, `px`, `pd`, `pdf`, `afl`, `axt`, `agf`, `f`, `/` work at runtime
  addresses; `iS`, `is`, `ie`, `ir`, `iz` print both `paddr` and runtime
  `vaddr` as radare2 does; `dm` is the source of every slide; `dr`, `dbt`,
  `db`, `dc`, `ds` are the target itself; `w` and `wx` write to the target,
  journaled under invariant 5, and writing the file instead needs radare2's
  explicit `io.cache`.
- Heap and stack have no container: target-only ranges with no static facts.
  `px` works; `pdd` over them is a refusal.
- Before `ld.so` relocates a range, the file bytes are correct and the GOT
  holds pre-relocation values. Which is which is a `Fact` scope, printed as
  such.

`r2s` stays a command surface; it never resolves an address itself.

## 8. The theorems

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

Consequence: the staged printer (row D) binds every C variable to SSA values with
provenance, so on a trace every in-scope variable of a stripped binary has an
exact value at every moment, and out of scope is a refusal. This is stronger
than DWARF, whose location lists compilers emit incompletely without saying
why: a confirmed gcc bug dropped a constant-folded variable that
`DW_AT_const_value` could have expressed. The rule applies to SSA values that
were never named in C, which is what keeps the view working when the
decompiler refuses (section 15).

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

## 8A. Granted information, used in full and at scale

Invariant 15 is that the engine never skips information the container or the
runtime grants. Each kind has a stated owner, a lazy load, and a check against
the engine's own proof where one exists. A stated fact is authority for its
name and scope; the proof is authority for correctness; a conflict is shown
with both values (invariant 15), which is exactly the compiler-debug-info bug
class that ASPLOS 2023 documented.

| Granted | Used as | Checked against | Loaded by |
|---|---|---|---|
| DWARF types, layouts, prototypes | authority over inferred types | inferred constraints | `r2image` → `r2types` |
| DWARF variable locations, scopes | a candidate for C′, plus name and scope | the availability index (C′) | `r2image` → `r2ssa` |
| DWARF inlined-subroutine entries, call-site parameters (`DW_OP_entry_value`) | inlining boundaries the binary lost | stated scope only | `r2image` → `r2dec` |
| Line tables, source on disk | source beside the decompile | per-line correspondence | `r2image` → the view |
| CFI (`.eh_frame`, `.debug_frame`) | stated frame extents, save slots (item I) | the frame model's proof (P4) | `r2image` → P4 |
| Symbols, exports, imports | names | hints only, never semantics | `r2image` |
| BTF / CO-RE | kernel types and prototypes | as DWARF | `r2image` |
| Breakpad / Crashpad symbol files | names and types for release builds | as above | `r2image` |
| GDB JIT descriptor, V8 / SpiderMonkey jitdump, perf maps | names and bytes for JIT code | the live bytes | `r2target` → Source, user facts |
| Live mappings, `link_map`, module lists | slides, module identity | the bytes themselves | `r2target` → Q |

Three things keep this safe rather than naive:

**Lazy, not skipped.** Cheap whole-image accelerators are read at open; the
expensive per-unit parse is deferred. Address-to-compilation-unit lookup is
O(log n) over an accelerator (`.debug_names`, `gdb-index`, `.debug_aranges`),
and a compilation unit's DIEs are parsed on first touch and memoized in Q keyed
by the container byte range they read, so a rebuild touching one shared object
re-reads only that range. Measured scale: Chromium's own guidance is
`symbol_level=2`, `use_debug_fission=false` (trade link time for "significantly
faster" load), and `build/gdb-add-index`, which takes symbol load from 22 s+ to
about 4 s. The engine's rule follows: an index lookup is O(log n), never a
whole-image DWARF parse.

**Build-dependent fidelity.** LLVM's assignment tracking, which keeps DWARF
variable locations accurate through optimization, is on by default in Clang but
silently off for LTO and ThinLTO builds, under LLDB debugger tuning (the Darwin
default), and at `-O0`. Chromium's official ThinLTO builds and macOS builds
therefore ship without it. So for an optimized browser frame "no stated
location" is the common case, and the engine falls to C′ recovery, never to a
backfilled guess.

**JIT code is a Source.** The GDB JIT interface registers an in-memory ELF
object (symbols plus DWARF) through `__jit_debug_register_code` and a linked
list in `__jit_debug_descriptor`; V8 and SpiderMonkey emit jitdump and perf
maps. `r2target` reads these and hands the engine a code region exactly as a
container hands it bytes-plus-what-it-states, through
`r2engine::program::Source`. The engine never distinguishes JIT code from file
code except in provenance; a region with no stated names renders at tier 2 or
tier 3 (section 18). Bytes that change between stops re-lift through red-green,
the self-modifying-code case of section 7.

The `Program`/`Source` trait has six methods today and no channel for
variables, scopes, inlining, line tables or runtime code regions. Widening it
is the concrete contract work behind this section and behind roadmap item I;
nothing above reaches the engine until that widening lands.

## 9. Harmony between static and dynamic facts

### 9.1 Static facts accelerate the dynamic side

- Liveness deletes dead flag and temporary definitions before interpretation
  or compilation (section 5.3).
- Proven indirect targets become direct jumps in compiled code.
- The machine profile gives the emulator a dense register layout.
- May-write summaries prune replay (theorem B); loop summaries and purity
  proofs skip it (theorems D and E).

### 9.2 Dynamic facts check the static side

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
it, or the user admits it as an explicit assumption (section 15). A static ⊤
that is constant on every observed run is a precision hint, never a fact.
Runtime refutation runs as a CI gate (section 18): every certified fact is
checked at every executed point of the corpus traces. The anti-hack standard
of AGENTS.md has been enforced by review and lints; here it is enforced by the
hardware that ran the binary.

### 9.3 Time scrubbing is free of static work

Static queries depend only on the container bytes and user facts. A dynamic
view is a static fact composed with val(·, t). Moving t invalidates no static
query, so scrubbing costs O(visible values · log n). A static query re-runs
only when live code bytes differ or a refutation fires, both of which Q's
red-green revalidation handles because the live bytes are an input.

### 9.4 Semantic navigation

Each is an index lookup, O(log), on a trace:

- next or previous C statement: the smallest t′ > t whose operation belongs
  to a different statement in the same activation, and the symmetric reverse;
- a conditional breakpoint such as `db parse if len > 0x40` attaches to the
  defining operations of `len`, so it costs the executions of those
  definitions, not every step;
- watching a frame object: its extent is a hardware watchpoint live and a
  range query on a trace;
- last writer of a byte, every value a variable took, and the backward slice
  of a value, as closures over the read and write edges, O(|slice| · log).

## 10. Concolic execution and taint from a stop

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
  under qemu before it is reported. Matching one execution validates that
  witness only. An absence proof needs a sound model, a complete bounded
  search, or an invariant checked against initial states and transitions. A
  timeout is unknown.

Dynamic taint is the forward closure from S over the trace's read and write
edges. Implicit flows come from control dependence, read from the static
postdominator tree. A taint answer states whether implicit flows were
included.

## 10A. Asking the symbolic and taint questions

Research direction, not a phase: no exit criterion, and nothing here enters the
roadmap with G0 or G1.

Added 2026-10-06. Section 10 states the semantics; this states the spelling,
the cost of each form, and how a query composes with the `Hit` of section 12A
and the values of theorem C. Nothing here changes section 10's rules.

### 10A.1 The two directions

Every question a stop raises is one of two closures over the same graph.

| Direction | Question | Mechanism |
|---|---|---|
| Backward | what made this value what it is | the gated-SSA chop from the value's defining ops back to the symbolic set S, over the trace's def-use |
| Forward | what does this value reach | taint's forward closure over read and write edges, with implicit flows from the postdominator tree |

The decompiler already needs both for its own work, so the owners exist:
`r2ssa` holds def-use, the chop and the postdominator tree, `r2rewrite` holds
the simplification, and the trace index holds the dynamic edges. A symbolic query joins those three at a position.

### 10A.2 The spelling

```
$h  = search(p64(0x4141414141414141) * 0x100, in: heap)[0]
$rip_at_crash = taint(from: $h, to: rip)
why(rax)                        ; backward: the chop that made rax this value
reaches($h.at)                  ; forward: every value this spray byte feeds
solve(rip == 0x401000, free: stdin)   ; concolic: an input that lands here
```

Each returns an `Answer<T>` with the scope of invariant 3 and the search
status of invariant 3's second half: complete, partial, unknown, unsupported,
cancelled or budget exhausted. `solve` adds **modeled** scope, because a solver's alternative is a computed possibility, and invariant 6 keeps modeled and recorded distinguishable.

`why(v)` and `reaches(v)` are the common forms and need no solver at all. They
are closures over edges that exist, so they answer at index speed and refuse
only where the trace has a gap. `solve` is the form that calls a solver, and the only one that can time out.

### 10A.3 Cost, per form

| Form | Cost | Bound |
|---|---|---|
| `why(v)` on a trace | `O(d)` edges walked, d the chop's size | the chop is bounded by the region between the definition and the stop, and theorem C gives each value's position in `O(log)` |
| `why(v)` live, no trace | theorem C′: `O(n · L)` once per function for the availability index, then `O(1)` per value | a value gone from every location goes to `r2rewrite`'s inverse search, which returns `Refused(reason)` where no inverse exists |
| `reaches(v)` forward taint | `O(e)` over the trace's read and write edges from v | e is the edges reachable, which a budget caps; a partial answer names where it stopped |
| implicit flows | one postdominator tree per function, `O(n)` to build, cached in Q | the answer states whether implicit flows were included, per section 10 |
| `solve(...)` | the formula is linear in the chop's size for an acyclic region; the solver is the unbounded part | a stated budget, and a timeout is `unknown` and never `unsatisfiable` |
| a loop in the chop | `O(1)` with a proved induction summary (theorem D), otherwise unrolled to a budget | past the budget the answer is `Unknown`, per section 10 |

Theorem C is what makes this cheap: a value's history is an index lookup. A backward question over 10,000
steps walks the def-use edges that matter and reads each value in `O(log)`,
where a replay-based debugger re-executes the whole interval.

### 10A.4 What composes

- **A spray hit to a crash.** `taint(from: $h, to: rip)` joins section 12A's
  `Hit` to the faulting register. The answer is the chain of reads and writes
  from those bytes to the control transfer, each step a position and an
  instruction. This is the question an exploit developer actually asks, and
  the parts are the `Hit`'s `at`, the trace's edges, and the stop's registers.
- **A field to its writer.** `why($obj.vtable)` over a corrupted object names
  the write that put the value there (`lastwrite`, section 6.3) and then the
  chop that produced it.
- **An input to a reachable state.** `solve(rip == target, free: stdin)` is
  concolic from σₜ with everything but `stdin` concrete, per section 10, and
  the candidate is reproduced under qemu before it is reported.
- **A refuted static fact.** A taint answer that contradicts a proven static invariant locates a bug in the engine, and section 9.2 already makes a run a check on the engine.

### 10A.5 The walls, restated for these forms

Section 19.3's four walls decide what each form may answer, and naming the
wall is the answer when one is hit:

| Wall | Which form hits it | What it says |
|---|---|---|
| `impossible` | taint across a many-core race (invariant 13), object identity across a moving GC | the question has no answer in this model |
| `unsupported` | a symbolic query with no trace on a backend with no reverse execution | the backend lacks it, and which backend would have it |
| `unimplemented` | a `CALLOTHER` with no handler inside the chop, an unmodeled syscall | which handler is missing |
| `budget` | the solver, an unrolled loop, a forward closure capped mid-walk | how far it got and what raising the budget would cost |

Non-negotiable 8 of `AGENTS.md` applies unchanged: a taint path the engine
cannot establish is a visible refusal, and a plausible path is never printed.
A solver's model is **modeled** scope and never evidence for a static fact.

### 10A.6 Ownership

| Part | Owner |
|---|---|
| The chop, def-use, liveness, the postdominator tree, refutation evidence | `r2ssa` (section 4) |
| Inverse expressions, path condition simplification | `r2rewrite` |
| Dynamic read and write edges, value-at-time | the trace index (section 6.3) and theorem C |
| The formula, the solver call, the budget | `r2engine`, as a Q query keyed by (region, S, hash of the concrete values read) |
| Reproducing a candidate | qemu, per section 5.2 |
| The spelling and `j` output | `r2s` |

The solver is a dependency. It answers a formula `r2engine` built, and `r2engine` decides what the answer means. A solver result that
contradicts a proof is reported with both values, per invariant 15.

## 10B. Fuzzing and coverage-guided exploration from a stop

Research direction, not a phase: no exit criterion, and nothing here enters the
roadmap with G0 or G1.

Added 2026-10-06. This is the forward counterpart of section 10A: section 10A asks the solver for one input that reaches a state, and this runs many inputs from a stop and keeps the ones that reach new code. Section 11's numbers decide what
is honest here, and section 11 is why this engine is not a general-purpose
fuzzer.

### 10B.1 What this is, and what AFL++ already does better

AFL++ and libFuzzer execute a target at native speed with a compile-time
coverage map, and a modern fork-server or snapshot fuzzer reaches tens of
thousands of executions per second. Section 11's table says the emulator's
floor is `c_e ≥ c_n + c_obs`, and an interpreter runs 30 to 100 times slower
than native, with a JIT at 1.5 to 3 times. So an engine-driven fuzzer loses
raw throughput by one to two orders of magnitude and cannot win a
blind-mutation race. Stating that first is the only way the rest is useful.

What the engine has instead is the state at the stop and every fact about the
code ahead of it. Three consequences, each a different product from AFL++:

| Property | AFL++ | From a stop |
|---|---|---|
| Starting state | process start, or a fork-server snapshot at `main` | any position, including one reached after an hour of real work, with a trace behind it |
| What an input is | a file or a byte buffer | any symbolic set S of section 10: bytes, a register, a field of a live object, a heap chunk's contents |
| Why an input was kept | new edge in a compile-time map | new edge, or a proven-reachable branch the corpus has never taken, named by `r2ssa` |
| What a crash yields | a reproducer and a stack | a reproducer, the trace, `why(rip)`, and the write that corrupted the value |

The engine's fuzzing is therefore **targeted exploration of a reachable
region from a deep state**, and the throughput budget is spent where a
mutation has a stated reason to matter.

### 10B.2 The loop

```
dts+ fuzzpoint                       ; a named checkpoint, section 12 item 8
$s = symbolic(buf, len: 0x40)        ; the set S, as section 10 defines it
explore($s, until: new_edges == 0, budget: 60s)
dts- fuzzpoint                       ; roll back; results stay modeled
```

Each iteration is: restore the checkpoint, write a mutated S into the state,
run forward under a budget, record the edges taken, keep the input if it
reached an edge no earlier input did. The restore is the copy-on-write fork of
section 6.1, so an iteration costs the pages the previous one dirtied and not
a process launch.

Every input and every edge is **modeled** scope (invariant 3), because an
experiment's alternative is a computed possibility. Invariant 6 keeps modeled
results distinguishable from the recorded run they branched from, so an
explored path can never be reported as something the program did.

### 10B.3 Coverage, and what makes it better than a bitmap

AFL++'s coverage is a hash of edge pairs into a fixed map, which collides and
forgets which edges exist. The engine knows the CFG of every function it
prepared, so coverage is an index over dense block ids
(`doc/adr-one-ir.md`), exact and with no collisions.

| Fact | Owner | Why it steers better than a bitmap |
|---|---|---|
| Which blocks and edges exist ahead | `r2ssa` CFG | an unreached edge is nameable, so the loop can report what it failed to reach instead of only what it reached |
| Which branch condition gates an unreached edge | `r2ssa` def-use to the condition's defining ops | the mutation can target the bytes that feed the condition, which is what a chop already computes in section 10A |
| Whether an edge is reachable at all | the switch prover and callee resolution | an edge proved unreachable is removed from the denominator, so coverage stops being a fraction of a number nobody can reach |
| Which edges a trace already took | the trace index | the starting corpus is the real run, so exploration begins from observed behavior |

The useful output is the unreached set with its gating conditions. A percentage needs a denominator, AFL++ computes one over a colliding map, and the engine has the exact edge count from the CFG.

### 10B.4 Where the solver and the fuzzer meet

Section 10A's `solve` and this section's `explore` are the two halves of
concolic fuzzing, and the split is on cost:

- mutation is cheap and dumb, so it runs first and covers the easy edges;
- an edge no mutation reached after its budget is handed to `solve` with the
  chop that gates it, which is SAGE's and Driller's division of labour;
- a solver model is reproduced by fresh controlled execution under qemu
  before it is reported, per section 10, so a model that does not reproduce refines the formula and becomes no finding.

This is the one place the engine's expensive machinery pays for its
throughput loss: a magic-value comparison or a checksum that blind mutation
never passes is one solver query over a chop that `r2ssa` already has.

### 10B.5 Cost

| Step | Cost | Mechanism |
|---|---|---|
| Restore the checkpoint | the pages the last iteration dirtied | copy-on-write fork, section 6.1 |
| Write the mutated S | `O(|S|)` | the typed value path of `doc/adr-scripting-surface.md` section 8 |
| Run forward | instructions executed, at section 11's emulator rate | a per-iteration instruction budget, and a timeout is recorded as an outcome |
| Record edges | one index write per new edge | dense block ids, so a repeated edge costs a bit test |
| Decide novelty | `O(1)` per edge | a bitset over the function's edges |
| One iteration, total | dominated by the forward run | so the lever is a short window from a deep state, never a long run from the start |

The design consequence: iterations are short and start late. A fuzzer that
replays an hour of setup per input loses to AFL++ on every axis, and a fuzzer
that starts from the stop where the interesting state already exists pays the
emulator's tax on only the window that matters. That is the same argument
section 5.4 makes for the hybrid window, applied to exploration.

### 10B.6 Ownership

| Part | Owner |
|---|---|
| Checkpoint, restore, forward execution | `r2target` and the emulator (section 4) |
| The CFG, the unreached set, the gating chop, reachability | `r2ssa` |
| The coverage index, the corpus, novelty, the budget | `r2engine`, as Q state keyed by (checkpoint, S) |
| The formula and the solver call | `r2engine`, per section 10A.6 |
| Mutation strategy | `r2engine`, with the strategy stated per run so a result is reproducible |
| The spelling and `j` output | `r2s` |

Mutation strategy is a policy, so it lives with the other route and budget
policy in `r2engine` and never in the shell or the renderer. A run records its
strategy and its seed, because an exploration nobody can repeat is not
evidence of anything.

### 10B.7 What stays walled

| Wall | Case |
|---|---|
| `impossible` | a bug that needs a many-core interleaving (invariant 13); coverage of code the input cannot reach, which the reachability proof states as unreachable |
| `unsupported` | exploration on a live RSP target with no checkpoint mechanism; a syscall inside the window that the injection of section 5.4 cannot perform |
| `unimplemented` | a `CALLOTHER` with no handler on a path the exploration takes, which stops that path and names the operation |
| `budget` | the per-iteration instruction cap, the wall-clock budget, the solver |

A crash found here is **modeled** until it is reproduced by a fresh controlled
run, per section 10. An unreproduced crash is reported as a candidate with its
seed and strategy, never as a bug in the target.

### 10B.8 Where it sits

This is a phase after G5, because it needs G2's checkpoints, G3's named
checkpoints, G5's solver boundary and the reachability work of P5 and the
switch prover. It is not in section 17's table yet, and it should not enter it
until a real session proves the targeted form beats running AFL++ beside the
debugger, which is the only comparison that matters.

## 11. The cost of emulation

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

The consequences are the design: the runner is qemu or the hardware (section
5.2); the emulator is the replay engine, offline and parallel, where 2–3× is
acceptable; and the questions a user asks are answered without replay
wherever theorems B to E apply.

## 12. The command language

Decision, 2026-10-05: the `r2s` shell keeps radare2's grammar. gdb users get
gdb itself through the `gdbstub` export.

- One shell, one grammar. `pdd @ addr`, `~`, `j`, `@@` compose with `db`,
  `dc`, `dr` today. A second grammar (`break *0x400a3c`, `x/16gx $sp`) beside
  the first is two parsers at one prompt, a cost on every line.
- Imitation of gdb is never complete (`info frame`, `tbreak`,
  `display/i $pc`, `p $_siginfo`, `.gdbinit`, Python), and a partial clone
  frustrates a gdb user more than a different language does. lldb users have
  a third grammar. Serving them their own front end is the complete answer.
- Engine verbs that RSP cannot express (last writer, statement step,
  concolic) reach foreign front ends through `qRcmd`: `monitor dtw idx` in
  gdb. pwndbg can wrap them in its own commands later.
- radare2 already names the time-travel verbs: `dts` (trace session), `dsb`
  (step back), `dcb` (continue back), `dcu`, `dcr`, `dso`, `dsf`. New verbs
  with no radare2 name take gdb's or rr's where one exists; rr's `when`
  (current position) is such an import. Spellings for last writer, concolic
  and the `gdbstub` serve verb are not yet decided.
- One cheap concession if wanted: a `gdb_alias` column in the `VERBS` table so
  `b`, `c`, `n`, `s`, `bt`, `finish` dispatch to `db`, `dc`, `dso`, `ds`,
  `dbt`, `dcr`. Same table, so help and completion cannot disagree. Single
  words only; never `x/`, `info` or `$` expressions, which would be a second
  parser.

## 12A. Bulk memory queries: the spray case

Research direction, not a phase: no exit criterion, and nothing here enters the
roadmap with G0 or G1.

Added 2026-10-06, with section 12 and `doc/adr-scripting-surface.md` section 8.
The example that fixes the requirement: a heap spray was written, and the
question is where it landed, which copies survived, which one the vulnerable
pointer will reach, and what wrote each of them.

### 12A.1 What the existing tools make of it

| Tool | The command | What it costs | What it cannot say |
|---|---|---|---|
| gdb | `find /g 0x0, 0xffffffffffffffff, 0x4141414141414141` | a linear read of every readable page over RSP, one `m` packet per chunk | which allocation each hit belongs to, who wrote it, or which hits are the same object seen twice |
| radare2 | `/x 4141414141414141` in `-d` mode | the same linear read, `dm` chosen by hand per map | the same |
| pwndbg, gef | `search -t qword`, `grep` | the same read, with a nicer table | the same |

Every one of them answers "these addresses hold these bytes". The question a
spray actually asks is "which objects hold my pattern, how many, where do they
start, which are reachable, and which write put them there". That gap is the
engine's opening, because every missing part is a fact the engine already owns
or can own.

### 12A.2 The query

One statement, in the language of
`doc/adr-scripting-surface.md` section 8:

```
$spray = p64(0x4141414141414141) * 0x100
$hits  = search($spray, in: heap, align: 8)
```

`search` returns `Answer<Vec<Hit>>`. A `Hit` carries six fields where gdb's
`find` returns one address:

| Field | Owner | What states it |
|---|---|---|
| `at` | `r2target` | where the match starts |
| `region` | `r2target` | the mapping, from `dm`: which heap, which thread's arena, the permissions |
| `object` | `r2types` | the allocation it falls in, with the offset into it, where an allocator's metadata or a recorded `malloc` return states one |
| `length`, `repeats` | the search | how far the pattern runs and how many times, so a 2048-byte spray repeated 512 times in one region is one `Hit` with `repeats: 512`, where gdb prints 512 addresses |
| `wrote` | the trace index | `lastwrite(at, now)`: the position, the instruction and the call stack that put these bytes here |
| `scope` | invariant 3 | **observed**, since the bytes were read from a live target |

The `repeats` field is what turns an unreadable wall of hits into an answer. A
spray is one pattern repeated, so the useful output is the shape of the spray:
how many copies, at what stride, in which regions, with what gaps. The
addresses one per line are the input to that answer.

### 12A.3 Cost

A whole-address-space search is `O(bytes read)` and nothing avoids that. What
the design can state is how few bytes get read and how the work composes.

| Step | Cost | Mechanism |
|---|---|---|
| Choosing what to read | `O(maps)` | `in: heap` resolves through `r2target`'s mapping list. A spray search reads the heap and the mapped regions the user named, never the whole 64-bit space |
| Reading | `O(bytes)`, one bulk transfer per region | RSP's `m` packets are chunked by the stub's `PacketSize`. The query issues one request per region, so the per-packet round trip is amortized over the region and not paid per candidate |
| Matching | `O(bytes)` single pass | Two-way or Boyer-Moore over the region, with `align: 8` reducing candidate positions by 8. A repeated pattern is detected during the pass, so `repeats` costs nothing extra |
| Attributing an object | `O(log k)` per hit | a sorted interval list of k known allocations, binary searched. The list comes from recorded allocator returns on a trace, or from the allocator's own metadata where the machine profile states its layout |
| Attributing a writer | `O(log(n / K) + K)` per hit | `lastwrite` from section 6.3, unchanged. This is the one part that needs a trace, and it refuses cleanly on a live target with no recording |
| Total | `O(bytes + h · (log k + log(n/K) + K))` for h hits | each term stated, each with a budget |

Three rules keep it honest. The search takes a budget and returns a partial
`Completion` with the regions it finished rather than running unbounded, per
invariant 8. Attribution is per hit and lazy, so 10,000 hits cost 10,000
attributions only if the user asks for all of them, and `repeats` usually means
they do not. On a live target with no trace, `wrote` is a refusal naming the
missing recording, per invariant 4 and section 15, which is the whole point:
the field is absent and labelled, and no plausible writer is invented.

### 12A.4 What composes on top

Each of these is an existing engine fact joined to a `Hit`, so none is new
analysis:

- **which copy the bug reaches.** The vulnerable pointer is an SSA value at a
  stop. Its value at that position is exact (section 8, theorem C), so the
  question "which `Hit` does it land in" is an interval lookup, and "which
  field of the object" is a `r2types` layout read.
- **what the object is.** A spray lands in allocations whose type the engine
  may already know from the callsite that allocated them, so a `Hit` can carry
  a type and the spray can be rendered as the structure it overwrites, field by
  field, with the fields it corrupted named.
- **which writes survived.** A second search at a later position, diffed
  against the first, says which copies were freed and reused. The diff is over
  `Hit` identities and not addresses, so a reallocated chunk reads as a
  different object at the same address.
- **where the gaps are.** The regions the spray did not reach, with the stride
  it achieved, which is the number a spray is actually tuned against.

### 12A.5 Ownership, so this does not become a second owner

| Part | Owner |
|---|---|
| Which regions exist, their permissions, their bytes | `r2target` (section 4) |
| The pattern match over a byte range | `r2engine`, as a Q query keyed by (position, range) |
| The allocation intervals and their types | `r2types`, from recorded allocator returns or a stated allocator layout |
| `lastwrite` | the trace index (section 6.3) |
| The spelling | `r2s`: radare2's `/x` keeps its meaning and gains `~`, `j` and the typed form beside it |

The one new fact is the allocation interval list, and it has one owner. An
allocator's internal layout is a stated platform fact, so it belongs beside the
machine profile's other per-platform rows and never in a heuristic that guesses
chunk headers. Where neither a recording nor a stated layout is available,
`object` is absent and the `Hit` says so.

## 13. The agent layer

gdb fails agents for mechanical reasons: `continue` blocks a tool call until
the harness kills the shell; `gdb -batch` restarts the target per call, so
state and addresses change; output is text with pagination and confirmation
prompts; there is no way to ask whether the target is running or what changed
since the last stop; "before the crash" means another run with earlier
breakpoints; every look is a round trip. Each has a mechanical fix. This
slots into roadmap item A (agent surface) and S1 (`j` on every verb).

1. **The session outlives the call.** One `r2s` process owns the target and
   listens on a Unix socket; the same binary is the client:
   `r2s -d gdb://… xyz --session xyz` once, then `r2s -S xyz 'dc'` from any
   later call. The socket carries command text in and JSON out, r2pipe's
   shape. The MCP adapter is one tool, `cmd`, plus `schema`.
2. **No command blocks past its budget.** `dc` returns on stop, or on a
   wall-clock budget with `{"state":"running","token":…}`. `dw` waits on the
   token, `dk` interrupts. Invariant 8.
3. **One stop record, computed once, returned with every stop:** position,
   reason, frames, registers changed, memory written since the last stop,
   `pdd` at pc with live values, facts refuted at this stop, revision.
   Contents configurable by `e dbg.stopctx`. The deltas are exact on a trace,
   from segment write-sets, and from watchpoints live.
4. **Structured everything.** `j` on every verb; `Fact<T>` fields with scope,
   basis and search status; no pager, no confirmation prompt. An error says
   what to do next: `target running; dw <token> or dk`.
5. **Positions are identities.** Every read verb accepts
   `@@pos:<exec>#<step>`; the cursor is only a default. Two subagents can ask
   about different positions in parallel. One writer lease per session,
   readers concurrent. This is what A's shuffled-order determinism test
   checks.
6. **Mutations carry a revision.** `dc`, `ds`, `w`, `db` take an expected
   revision; a retried request returns the recorded outcome and never steps
   twice. Invariant 5, journaled in Q.
7. **Breakpoints speak C, evaluated in-engine.** `db parse if len > 0x40`
   attaches to the defining ops of `len` (section 9.4).
8. **Time travel ends the restart loop.** `dsb`, `dcb`, last writer and the
   slice work in the same run at the same addresses. Named checkpoints
   (`dts+ name`, `dts- name`) let an agent try an input and roll back;
   results of the experiment stay marked modeled (invariant 6).
9. **One call, one investigation step.** `;` chains verbs; a batch returns an
   array of JSON results under one budget.
10. **The journal is the hand-over.** `r2s -S xyz -i journal` replays an
    investigation for a second agent or a human, and is the transcript A
    tests against.
11. **Discoverability for machines.** `?j` and `<verb>?j` return the verb
    table from `crates/r2s/src/commands.rs`, so help, completion and dispatch
    cannot disagree.

Owners: session, socket, journal, revisions, budgets and the stop record in
`r2engine`, with Q persisting the journal; verb spellings, `-S`, `j`, `?j` in
`r2s`; `pdd` text from `r2dec`; the MCP adapter owns no policy.

Measure: a scripted agent diagnoses the corpus failures, with round trips,
tokens, redundant target executions and wrong confident claims counted,
against gdb-batch and gdb with rr. Fluent explanations score nothing; honest
unknowns are not penalised.

## 14. The view

Terminal first (`r2s-tui`, V1–V5). The render plan is data (row D), so a browser
view later is a second consumer of the same plan with no engine change.

pwndbg's `context` is a dump: all registers, a disassembly window, eight stack
qwords, a backtrace, re-printed on every stop, with meaning guessed from bytes
(`rdi → 0x… ← 'AAAA'`). Every choice there is a workaround for facts gdb lacks.
The engine has the facts, so the view is built from them.

1. **C is the primary surface.** The decompiled function with live values
   inline, cursor on the current statement. Disassembly is a secondary pane
   opened on the C line under the cursor (V4 linked cursors).
2. **Show change, not state.** Registers and memory changed since the last
   stop are bright; unchanged are dim. The stop record supplies the delta.
3. **Objects, not qwords.** The stack is drawn as the frame model says:
   locals with extents, saved registers, canary, return address, each with
   its type and its live bytes. A write that crosses an object's boundary
   renders as an overrun across the boundary line.
4. **Time is an axis.** A timeline strip with stops, checkpoints, syscalls,
   signals and the cursor. `[` and `]` scrub; every value re-renders at
   O(log) each (theorem C, section 9.3). A variable can show its history as a
   sparkline column. Tenet is the reference for the feel.
5. **One colour, one meaning, every pane** (V2): observed, derived, assumed,
   modeled, refused, changed, tainted, symbolic. Shape as well as colour, so
   a refusal reads as `⟨…⟩` and not only as grey.
6. **Taint is painted.** Input bytes and every value derived from them share
   a hue, so the input is visible flowing through the C into the fault.
7. **Honesty in place.** A refused value prints `⟨not live⟩` where the value
   would be; its reason is one keypress away. A refuted fact is a margin mark
   on its line.
8. **Why, on demand.** On a value, `?` opens the slice as an indented DAG:
   ops → values → the syscall and byte it came from; each node is a cursor
   jump, drawn by V5's graph renderer.
9. **Minimal chrome.** Default is two panes, C and a state strip. Frame,
   disassembly, timeline and slice toggle in.
10. **Keyboard-first with radare2's keys.** `V` exists: `F7` step, `F8` over,
    `F9` continue, `F2` breakpoint; `[` and `]` for time.

```
 xyz#3  t=1,204,311  SIGSEGV read 0x8      parse ← main ← _start         rev 42
──────────────────────────────────────────────────────────────────────────────
 int64_t parse(uint8_t *buf, uint64_t len)      buf  0xffff8000 "AAAA…"  ░tainted
 {                                               len  0x41               ░tainted
     entry_t *p = table[idx];                    idx  0x1f ▲ was 0x03    ░tainted
 ▶   return p->size;                             p    ⟨not live: x1 at 0x400b08⟩
 }                                               ⚠ refuted: idx ∈ [0,15]
──────────────────────────────────────────────────────────────────────────────
 frame parse  sp=0xffff7f40                      changed  x0 0x0  x1 0x1f  pc
 ┃ ret   0x400c10 ──────┃ x29 ┃ canary ┃ buf[0x41] AAAAAAAAAAAAAAAAAAAAAA▓▓▓ ┃
 ┃                      ┃     ┃  ok    ┃ ▲ 0x41 bytes written since stop 2    ┃
──────────────────────────────────────────────────────────────────────────────
 ├─────●────────────────○──────────────◆───────────────────────────▶┤  time
   read()#17        checkpoint        stop 2                     now
```

Everything drawn is a fact with an owner: values from Q, extents from P4,
taint from the trace index, the refutation from the gate, the delta from the
stop record. Constraints: D7, the drawing thread never calls the engine, and a
worker prefetches neighbouring positions while the user scrubs; nothing is
rendered without scope. Deferred: the heap as objects, which needs allocator
contracts after P7; a browser front end, its own project, needing nothing new
from the engine. Neither delays V4 and V5, which the view is built on.

## 15. Refusal in the debugger

Source is never available in the normal case, and the decompiler refuses
whenever it cannot prove. The view degrades by tier, never blank, never fake.
Only the code pane degrades; the frame pane, taint, timeline and slice are
built on SSA and the trace, not on C, and keep working.

1. **C with residuals.** Refusal is rarely whole-function. The proven parts
   render as C with live values; the unproven region prints as a marked
   residual block with its instructions and per-operand values.
2. **SSA with live values.** When no C can be justified, the `pdim` tier with
   values beside each SSA value; theorem C does not need a C name.
3. **Disassembly with typed operands.** The floor:
   `ldr x0, [x19, #0x10]   ; x19+0x10: uint32_t idx = 0x1f`.

At the function head, always, the refusal reason: which fact is missing. The
pane shows the highest tier the facts justify and says which tier it is, and
every tier is one keypress from the others.

A run is a fact generator for exactly what refusals name: observed targets of
the indirect jump at `0x400b50`, the observed stack extent, the observed switch
index range. These are hypotheses (invariant 11). The view offers them as
assumptions: *assume targets {…} (observed, 2 runs)*. Accepting makes them
user facts, an input of Q (D13). The decompile re-runs under the assumption,
with the assumption printed in its header and every dependent line carrying
`assumed` scope and colour. Withdrawing the assumption withdraws the C. A
later run that contradicts the assumption withdraws it with a witness.

If the frame model also refuses, the frame pane draws what is proven: `sp`,
the return address if its certificate holds, the bytes, with unknown extents
drawn as unknown. Writes since the last stop still highlight, because that
delta comes from the trace.

This is why the decompiler's refusal discipline is the heart of the debugger,
in both directions. A view that binds live values to C is only safe when
every C line rests on SSA with provenance; a decompiler that guessed a loop
would put a live value beside a statement that never executed as written,
which is why plausible-C decompilers cannot offer this. And a run makes
refusal cheap: a refusal names a gap, the trace fills it with a candidate, the
user admits it explicitly, and the pressure to guess, which every other
decompiler gave in to, is gone. Three consequences: the scope lattice
(observed, derived, assumed, modeled, refused) is one type shared by `pdd`,
the stop record, the view and the gate, living with `Fact<T>` and `Basis`
(item C), not in the debugger; no phase may add a fallback that turns an
unknown into a displayed value (invariant 14); and the debugger has no
semantics of its own, so if the facts lie, it lies faster and in colour.

## 15A. Scaling to kernels and browsers

Research direction, not a phase: no exit criterion, and nothing here enters the
roadmap with G0 or G1.

The engine's facts are per function and position-independent, so none of them
cares that the target is a kernel or a browser. What a large target needs is
not new analysis but new readers and new RSP modes, each a bounded
`unimplemented` item (section 19.3), plus the lazy loading of section 8A so a
200 MB text with over a million functions never pays a whole-image pass.

**Kernels** run under `qemu-system` (TCG for recording, KVM for native speed),
KGDB over serial, or JTAG. Beyond user mode they need: a page-table walker per
architecture (x86-64 4/5-level, ARM VMSA, RISC-V Sv39/48) over `Source`, a few
hundred lines each, with formats from the machine profile; modules as
time-varying container inputs with a KASLR slide from `kallsyms`; BTF as the
type source (`.BTF`, `/sys/kernel/btf/vmlinux`), the single biggest enabler and
about a thousand lines in `r2image`; exception and IRQ frames (`pt_regs`) in the
frame model so α(t) crosses an interrupt; per-CPU bases and `MSR`/`MRS` as
`CALLOTHER` handlers to read `CR3`/`TTBR`. Replay is qemu's; the emulator runs
only symbolic windows over kernel code, translating addresses through the
recorded page tables. Self-modifying code (alternatives, static keys, ftrace,
kprobes, the eBPF JIT) is routine and handled by Q's re-lift on byte change.

**Browsers** work live at native speed today — live values in `pdd`, the frame
pane, stop records, the agent layer — because the static side is per function
and lazy. The entry ticket, which G0 must carry, is: multiprocess attach
(`multiprocess+`, `vAttach`, follow fork; Chromium needs `--allow-sandbox-debugging`
and `ptrace_scope=0` or an ancestor process) and non-stop mode (`QNonStop`),
without which a renderer's hang monitor kills it within seconds of an all-stop.
Hundreds of threads mean the stop record's delta and the view's state strip
summarise, never list. Release builds carry split DWARF, `.dwp` or Breakpad, or
nothing; where symbols are absent, types are inferred per function on demand,
the engine's normal case. Recording a whole browser is rr's job (Mozilla built
rr for Firefox; Pernosco debugs Firefox on it); the plugin under `qemu-user`
would be an order of magnitude too slow at that size. Reverse execution is
therefore rr's `bc`/`bs` through the stub. **Whole-browser omniscient indexing
is Pernosco's scale** (about 100 GB, an hour on 36 cores) and is out of scope;
the engine answers in windows — an rr checkpoint is σ₀, the emulator replays
the window of interest, and the window ends at the first syscall the log cannot
answer, which most hot windows (a JIT miscompile, a use-after-free) do not
contain.

What stays walled even here: many-core races (`impossible`, invariant 13),
object identity across a moving GC (`impossible` without runtime cooperation),
and WebKit on macOS (`unsupported`, no rr). The decisive lever for both targets
is the same — symbols and types from the container (BTF, split DWARF, Breakpad,
FDEs), which is roadmap item I's territory and must be extended before either
target is attempted. The engine's design does not change; what it reads does.

## 16. What a user gets

1. C-level live debugging of a stripped binary: at a stop `pdd` prints
   `len = 0x41` and `buf = "AAAA…"` beside the code, and `⟨not live: reason⟩`
   where the value is refused.
2. Reverse execution with exact time: who wrote this byte, step back one C
   statement, every value `i` took, each answered from the index.
3. Questions to the solver from a stop: which input reaches this `abort`;
   can `idx` exceed 16. The answer is an input, `no`, or `unknown (budget)`.
4. Taint from the input bytes to a `memcpy` length, painted.
5. Cross-architecture debugging on any host through qemu, attached by one
   client.
6. Their own front end: gdb, lldb, pwndbg and gef attach to the emulator or
   to a trace through `gdbstub`, with engine verbs under `monitor`.
7. An agent that never kills the shell: sessions, budgets, stop records,
   positions, revisions, journals.
8. Trust: a displayed value is exact or refused, and when the engine is wrong
   a run says so.

Against gdb with rr: on a source-level native program on Linux x86-64, and on
large or heavily multithreaded workloads, gdb with rr wins and this design
says so. On a stripped binary, in exploit development, on macOS or arm64, on
firmware, and for "who corrupted this" in a small or medium program, it is a
different class of tool.

### 16.1 A session, on paper

`xyz` is a stripped Linux arm64 ELF crashing on a crafted input, run in a
Linux container under `qemu-aarch64 -g 1234` with the plugin writing
`xyz.trace`; the host is a Mac. Verbs marked TBD are not decided.

1. `r2s -d gdb://localhost:1234 xyz`: RSP connect, `target.xml` onto the
   machine profile, static analysis from the container bytes. Nothing has run.
2. `dc`: `SIGSEGV`. `dr`, `dbt`: registers and a backtrace from the frame
   model, with any unproven frame printed as `?` and its reason.
3. `pdd`: the C with `len = 0x41`, `idx = 0x1f`, and
   `p = ⟨not live: x1 overwritten at 0x400b08⟩`. `idx = 0x1f` beside a table
   of sixteen entries is the bug, visible.
4. `dts xyz.trace` (TBD): Q loads (σ₀, E); the stop becomes
   `t = 1,204,311`.
5. `dsb`: one C statement back, an index lookup; `pdd` re-renders with
   `p = 0x0`, exact by theorem C. No static query re-ran.
6. Last writer of `idx` (verb TBD): theorem B skips the segments whose
   write-sets miss the slot, one segment replays under the replay
   personality, and the answer names `t = 1,203,977`, `strb w2,[x19,#0x10]`
   in `read_header`, `w2 ← buf[4] ← read(0, buf, 0x41)`, event `E#17`,
   byte 4 of the input.
7. The gate compares certified facts with the run: the value domain had
   certified `idx ∈ [0, 15]` on a comparison it believed dominated the load;
   the trace shows `0x1f`. `pdd` gains
   `// refuted: idx ∈ [0,15]; basis: dominance at 0x400b20; witness t=1,204,290`.
   A structuring bug in the engine, found by one run.
8. Concolic (verb TBD): S is the `0x41` bytes `read` returned; the chop from
   `read_header` to `0x400a3c` is one formula; the model is re-run under qemu
   and reproduces the fault:
   `sat: input[4] ∈ 0x1f..0xff reaches 0x400a3c with idx > 16; reproduced`.
9. Serve the trace over `gdbstub` (verb TBD); `gdb -ex 'target remote :2345'`
   with pwndbg, `reverse-stepi` and `reverse-continue` work against it.

Never seen: a syscall layer, DWARF, a replay wait longer than one segment, a
guessed value.

## 17. Phases

Each phase runs beside nothing it replaces, because nothing exists; each
deletes nothing and must say what it adds to the census. All phases depend on
Q, P4, D and M. Effort is for one engineer with agents, after those land: 12 to
18 months for all six, of which G0 and G1 are 3 to 5. Only G0 and G1 are
roadmap candidates; G2 to G5 stay design until G1's exit holds.

| Phase | Adds | Exit | Effort |
|---|---|---|---|
| **G0** Target seam | `r2target`, the RSP client with non-stop (`QNonStop`) and multiprocess (`multiprocess+`, `vAttach`, follow fork), the `Target` trait, the `d*` verbs, `-d` mode as Q inputs (section 7), the session socket, `-S`, budgets, revisions, the stop record | `r2s` attaches to `gdbserver`, `debugserver`, `qemu-user` and `qemu-system`; `dr`, `dm`, `db`, `dc`, `ds` diff clean against radare2 under `scripts/diff_r2.py`; a stop re-runs only the queries whose input ranges changed; a scripted agent completes the corpus's live diagnoses without a blocked call; a sandboxed child is attachable and one thread stops while the rest run | 1.5–2.5 months |
| **G1** Live values | the availability index (C′), inverse recovery in r2rewrite, the refusal lattice, live values in `pdd` and the three tiers of section 15 | on a stripped optimized fixture every in-scope variable is exact or refused, verified against a DWARF build of the same source; no stale value in the corpus; a refused function shows tier 2 or 3 with the missing fact named | 1.5–2.5 months |
| **G2** Traces | the TCG plugin, the replay personality, the tuned interpreter and flag elimination, (σ₀, E) in the engine's format, fork checkpoints during replay, the K-segment index, `dts`, `dsb`, `dcb`, `bc`/`bs` over the index, the `gdbstub` export with `monitor`, `rr replay` and `qemu-system` record mode as sources | a recorded failure answers last writer and value-at-time from the index, equal to the linear oracle; the index and the oracle report the same gaps on a deliberately cut interval; the emulator tiers agree with `r2il::eval` on the corpus; pwndbg reverse-steps a trace through the stub | 3–5 months |
| **G3** Navigation and view | statement stepping, definition-attached conditions, frame-object watchpoints, slices, named checkpoints, the view of section 14 on V4 and V5 | each navigation is an index lookup; no query replays more than one segment; the view draws nothing without scope | 2–3 months |
| **G4** Refutation gate | facts enumerable per pc (C2), the per-step check, assumptions as user facts with withdrawal on refutation, the CI job over corpus traces | every certified fact holds at every executed point, or the failing premise is named; an admitted assumption withdraws with a witness | about 1 month |
| **G5** Concolic and taint | the solver boundary, gated-SSA chops, bounded memory, budgets, witness reproduction under qemu, taint closure and painting | a generated input reproduces its predicted behavior under qemu; a spurious candidate triggers refinement; a timeout is `Unknown` | 3–4 months |

The JIT (section 5.3, tier 3) is decided after G2, only if users record
programs the interpreter cannot keep up with. Importing rr's own trace format
is no longer a phase; rr is reached through its replay stub.

Deferred past this program, each with its own design when its consumers
exist: the pure-model Linux personality for macOS hosts; multicore recording
under an explicit memory model; core dumps as a read-only backend; the heap as
objects; a browser view; DAP and language runtime adapters; distributed
causality. Windows is out of scope.

## 18. Gates

- The emulator tiers against `r2il::eval`, and the index against the linear
  oracle, on every corpus trace.
- The refutation gate of section 9.2 as a CI job.
- A negative corpus: a cut interval must yield an unknown, not a last writer;
  a value without a proof must render as refused; a symbolic timeout must
  render as `Unknown`; a refused function must show its tier and the missing
  fact.
- Behavior-level fixtures spanning memory corruption, allocation reuse,
  integer overflow, optimized variables, indirect calls, signals, mapping
  changes and self-modifying code, with and without debug information.
- The agent gate of section 13, against gdb-batch and gdb with rr.
- Fuzzing of RSP packet decoding, the plugin's trace format, manifests and
  position tokens: malformed input cannot mint authority.
- Kani for span arithmetic, register lanes, the K-index invariants, revision
  handling and the session's state machine.
- Cold and warm latency reported apart: recording slowdown, indexing
  throughput, storage growth, replay distance, and p50/p95/p99 per query.
  Warm index lookup is never advertised as recording cost.

## 19. Risks and open questions

- qemu's plugin API is versioned but has grown; register reads arrived in
  recent releases. Pin a minimum version and keep the plugin small.
- `qemu-system` record mode is fragile around some devices and networking;
  firmware time travel is best effort until tested per board.
- `qemu-user` has no record mode, so recording there is at TCG speed.
- `CALLOTHER` handlers and Sleigh spec fixes are owed for every architecture
  the emulator replays.
- Concurrency is serialized only (invariant 13).
- Which crate owns refutation evidence, and how a refutation feeds back into
  r2ssa without unbounded recomputation, is open; the one-way rule bounds it
  but does not design it.
- The index layout inside Q, and its storage bound, are open; K is the only
  knob so far.
- Induction summaries (theorem D) do not exist; without them a loop in a
  symbolic chop unrolls to a budget.
- Harvard and banked memory in SSA and the frame model are unverified.
- The ASPLOS 2023 citation below was credited to two different author lists
  by the verification pass; the author list must be checked before it is
  quoted anywhere durable.
- STIQ, TOD, ODB and WET numbers are 2003–2011, Java source-level or Trimaran
  IR events on Pentium- to Xeon-class hardware; TTD's `.idx` figures are
  vendor rules of thumb over an unpublished layout. They bound expectations;
  none is a prediction for per-instruction P-code events on modern hardware.

### 19.3 The four walls, and why hitting one is the point

Every refusal names which wall it hit, as a field beside its reason (invariant
3). There are three kinds the engine does not remove and one that is a budget:

- **`impossible`** — the information does not exist in the model. A
  many-core-only race (invariant 13); whole-trace omniscience on a workload
  whose events outrun storage entropy; a value the compiler destroyed (shared
  register, inlined boundary, dead store); timing that observation perturbs;
  object identity across a moving GC. These are laws, not to-dos.
- **`unsupported`** — a different backend or configuration would answer it.
  No recorder on this target (record under rr or `dts+` instead); reverse
  execution the stub lacks; a window that ends at a syscall the log cannot
  answer.
- **`unimplemented`** — the reader or feature is not built yet: a BTF or
  split-DWARF reader, multiprocess or non-stop mode, a `CALLOTHER` handler,
  the heap as objects. Bounded work with a known shape.
- **`budget`** — it may exist and the stated solver, path or replay budget ran
  out. A timeout is unknown, never `no`.

Hitting a wall is the design working, not failing. Every tool that appears to
pass these walls passes them by guessing — plausible C, "likely" values,
source-shaped loops, a backtrace through an unproven frame. The engine's bet,
inherited by the debugger, is that a visible wall with its reason is worth more
than an invisible guess: an agent that reads `impossible` stops retrying, a
user who reads `unsupported` records under rr, a maintainer who reads
`unimplemented` has a work item. Without the field all four look alike at the
prompt, and the user cannot tell a law from a to-do. The classification lives
in the search-status lattice beside `Fact<T>` and `Basis` (item C), not in the
debugger.

## 20. What is verified and what is ours

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

Added by the research pass of 2026-10-05, same vote standard, with STIQ read
directly from the primary PDF:

| Finding | Source |
|---|---|
| STIQ: trace as bounded execution blocks, each discarded and retrieved by partial deterministic replay from a lightweight fork/COW snapshot; a query is O(log n) to the block then O(1) within it; coalescing writes to one location per block cut index entries by 95%; DaCapo indexes 0.16–0.27 GB vs 1.1–5 GB traces; memory queries average 8.6–27 ms, max < 0.5 s | Pothier & Tanter, ECOOP 2011 (Tables 1–4) |
| TOD: full per-event index at ~5× raw-event storage, ~10 index updates per event, single-field query 120–350 ms, indexes larger than the trace | Pothier et al., OOPSLA 2007 |
| ODB: per-variable (timestamp, value) history list, value-at-t is the closest-previous entry; author calls it the naive worst case | Lewis 2003, [arXiv cs/0310016](https://arxiv.org/pdf/cs/0310016) |
| TTD: replay-sufficient `.run` (1 bit–1 byte per instruction) separate from a discardable `.idx` (typically 1–2× the `.run`), index size scaling with the breadth of distinct locations accessed | Microsoft TTD docs; MSRC 2019 |
| Boothe bidirectional debugging: no trace, fork checkpoints, logged/replayed syscalls, event counters as positions, reverse in ≤ 2 passes, cost O(d) in distance moved back | Boothe, PLDI 2000 |
| WET: in a dependence trace, timestamps compress 130–231× while values compress 11.5×; only 6% of dynamic dependences need explicit labels (the rest inferable from static structure) | Zhang & Gupta, TACO 2005 |
| rr on Firefox: `mochitest` record 1.49×/replay 1.01×; Octane (JS shell) 1.79×/1.56×, mostly single-core serialization; sandbox `SIGSYS` and BHR syscalls add overhead | rr, USENIX ATC 2017, Table 1; Mozilla rr docs |
| Chromium guidance: `symbol_level=2`, `use_debug_fission=false`, `gdb-add-index` (22 s+ → ~4 s symbol load), `--allow-sandbox-debugging`, `ptrace_scope=0` | [Chromium linux/debugging.md](https://chromium.googlesource.com/chromium/src/+/main/docs/linux/debugging.md) |
| LLVM assignment tracking off by default for LTO/ThinLTO, LLDB tuning (Darwin) and `-O0`, so optimized browser/macOS frames ship without accurate locations | [LLVM AssignmentTracking](https://llvm.org/docs/AssignmentTracking.html), clang `BackendUtil.cpp` |
| GDB JIT interface: in-memory ELF registered through `__jit_debug_register_code` and the `__jit_debug_descriptor` linked list | [GDB JIT Interface](https://sourceware.org/gdb/current/onlinedocs/gdb.html/JIT-Interface.html) |
| RSP non-stop: `QNonStop`, asynchronous `%Stop` notifications drained by `vStopped`, per-thread `vCont`, multiprocess `pPID.TID` | [GDB Remote Non-Stop](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Non_002dStop.html) |

Refuted by one or both passes, not to be cited: that `jThreadsInfo` returns a
whole stop snapshot in one round trip; that rr's `make` scaling (7.85×/11.93×)
is a browser proxy; that Mozilla states 1.2×/1.4× bare-metal/VM rr overhead;
that Chromium documents specific hang-monitor flag values.

Stated from general knowledge and not passed through verification: qemu's
plugin callbacks and `-icount` record mode, `qemu-user` being Linux-host only,
the size of `linux-user`, and the slowdown figures of section 11. Check each
before it is quoted as a number.

Ours, unverified by any source and not yet machine-checked: theorems B, C, C′,
D, E; the K-interval index of section 6.3 (STIQ's block-summary-plus-replay is
the nearest relative, but no surviving source combines per-segment write
summaries with per-page predecessor lists); the constancy-interval memory cache
of section 7; the refutation framing of section 9.2 as a gate; the gated-SSA
chop of section 10; the cost bound of section 11; the assumption loop of
section 15. Neither pass found a surviving claim on concolic execution,
symbolic memory models, solver caching, abstract-interpretation refinement or
state merging, so sections 10 and 12 and the dynamic side of 9 rest on the
engine's derivation, and the open questions of section 19 name what a third
pass or the ECOOP 2011 successor literature would still settle.

## 21. What is kept from the 2026-09-13 plan

Kept, and folded into the sections above: the invariants of its section 1;
execution positions with a before/after boundary and durable object
identities; the three concurrency relations; scope and search status on every
answer; the request journal, revisions and one writer lease; history reads
that compose initial bytes with writes, with unknown initial bytes staying
unknown; the linear oracle for the index; the retention rule for windows; the
call tree that admits tail calls, signals and stack switches; its table
rejecting the over-claims of an earlier mathematical proposal (semiring
provenance as model counting, an entropy bound as a byte guarantee, mixed
affine domains as one elimination); its correctness corpus, mechanical
guardrails and agent baseline.

Dropped: ownership by radare2's `libr/debug` and the plugin, binding to
`OwnedFunctionSnapshot`, the supervised service as a separate deliverable, the
RPC protocol, the Python SDK, the DAP adapter and the notebook, and a stage
order that built the service before any semantic capability. Added: qemu as
the runner and the plugin as the recorder, the emulator as replayer with its
cost model, exact time, theorems A to F, the refutation gate and the
assumption loop, the `gdbstub` export with `monitor`, the hybrid window, debug
mode as Q inputs, the command-language decision, the agent layer, the view,
the refusal tiers, and the dependency on Q, P4, D and M.
