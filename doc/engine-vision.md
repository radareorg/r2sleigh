# Engine Vision

> What r2sleigh is becoming, and why. This document sits above `ROADMAP.md`:
> the roadmap is the ordered execution list for the current decompiler work,
> this is the shape the whole subsystem is aiming at.

## Thesis

r2sleigh is not a decompiler plugin. It is a binary analysis engine that
happens to ship a decompiler, and it is built agent-first.

Two statements follow from that, and everything in this document is a
consequence of one of them.

The first is that the engine owns its facts. Today radare2 finds the functions,
collects a typed snapshot, and hands it down for r2sleigh to render. The
dependency runs the wrong way for an engine: whoever discovers the work owns the
program, and whoever owns the program decides what is analysed next and what
gets invalidated when a byte changes. The engine has to be the owner.

The second is that the primary consumer is an agent, not a human at a terminal.
Agents fail on binary analysis tools for reasons that are structural rather than
cosmetic: a hidden seek cursor means the tool answers about a location the agent
did not intend, a scripted address-then-reseek-then-print sequence burns a turn
per hop and refills context each time, rendered text has to be parsed before it
can be reasoned about, an empty result is indistinguishable from a malformed
query, unbounded output exhausts the context window on bytes nobody needed, and
a heuristic guess arrives looking exactly like a proven fact. Each of those has
a different fix, and none of them is a better renderer.

The measure of success is not command count or crate count. It is whether an
agent can answer a real reverse-engineering question in one or two calls, with
the engine's confidence attached to every field, and whether it can ask why.

The near milestone, which orders every decision below, is one sentence:

> `r2s -c 'pdd @ 0x401000' binary` emits C with no radare2 present.

Everything that is not on the path to that sentence is optional relative to it.
Discovery, names and value sets are all optional by that test; body lift and the
type and convention data are not.

## Non-goals

These are decisions, not omissions.

**No line-by-line port of radare2.** `libr` is roughly 1.1 million lines: 347k
in `arch`, 210k in `bin`, 179k in `core`, 117k in `anal`. Transliterating it
would produce a worse tool for years and teach the new one the old one's
mistakes. `r2s` replaces radare2 by answering the same questions better from its
own core libraries, and it reaches parity through depth rather than breadth.
Radare2's long tail — 97 binary formats against roughly eight mainstream ones,
51 IO plugins, and 186 architecture plugins against roughly forty Sleigh
specifications — is real, irreproducible, and explicitly not matched.

**No new architectures.** x86 and ARM depth comes first, and stays first, until
the phases below are complete and adding a CPU is cheap and safe. Work that
makes adding an architecture easier still counts as depth work.

**No parallel pipelines.** One implementation per job. When a newer approach is
better the older one is deleted rather than kept behind a flag. This is the
constraint that makes the rest of the document tractable, and it is the one most
easily lost under delivery pressure.

**No per-architecture semantics.** Semantics come from Sleigh, always. ESIL's
failure is that 186 architecture plugins each hand-wrote a stringly-typed
approximation of their own instruction set, most incomplete and many wrong. That
mistake is not to be repeated in any form, for any reason.

### Two non-goals retired

Recorded rather than quietly dropped, because both were load-bearing and the
reversal changes the shape of the project.

This document used to say **no rewrite of radare2**, on the argument that
inverting the dependency and deleting C library by library kept something
shippable at every step while the plugin carried existing users along. It also
ruled out **a native terminal user interface**, because radare2's visual mode
rendered r2sleigh's output and the project got a human surface without owning
one. Both rested on the same assumption — that the plugin survives — and the
plugin is abandoned. `r2s` is the tool, and it grows the surface radare2 users
need rather than borrowing it.

What does not change is the reason those non-goals existed: breadth is still not
the goal, and a worse tool shipped sooner is still worse. The difference is that
parity is now reached by building rather than by borrowing, and the argument for
each piece of surface is made when it is planned rather than assumed here.

## Component topology

Three processes, and the boundaries are chosen for a reason rather than for
symmetry.

**The engine** holds the IL, the analysis layers, the fact database and the
decompiler, in one process and many crates. The decompiler queries analysis
constantly; a serialization boundary between them would be ruinous, and the
project has already spent effort removing JSON-shaped internal seams. Crates
give modularity at no runtime cost. Re-introducing an RPC hop inside this
boundary undoes completed work.

**The debugger** is a separate process, and has to be. It needs different
privileges, it owns `ptrace` or its platform equivalent, the debuggee can crash
it, and remote targets are a first-class case. The protocol is an existing one —
gdb-remote for remote targets, DAP for editor clients — rather than an invented
one.

**Frontends** are clients of a typed engine API. The `r2s` command surface is
one, the agent interface is one, an editor client is another. None of them is
privileged, and the engine never formats output for any of them. This is the
discipline `libr/core` lost: 5793 references to the console layer in 179k
lines, against 93 in the whole of `libr/anal` and zero in `libr/arch`. The
libraries stayed clean; the core fused command dispatch, analysis driving and
rendering into one blob, and that is why radare2 cannot thread its analysis
and cannot be tested at the interface.

## Inverting the dependency

The engine already exists in outline. `r2il` is the substrate,
`r2sleigh-lift` decodes and lifts, `r2ssa` carries the control-flow graph,
dominator tree, def-use, liveness, taint, slicing and interprocedural facts,
`r2types` carries constraint-based type inference, `r2dec` structures and
renders, and `r2engine` orchestrates requests. `r2sleigh-cli` is already a
standalone binary. What is missing is not analysis; it is the things radare2
currently supplies through the snapshot seam.

1. **Function discovery.** The largest gap, and smaller than it appears.
   `r2ssa` already constructs control-flow graphs and dominator trees — what it
   never does is decide which addresses are functions. That is entry seeding,
   prelude scanning with verification, and a worklist, not the bulk of
   `fcn.c`.

2. **Image and IO.** Byte mapping, layers, maps, banks, and patched views.

3. **Binary parsing.** Sections, symbols, relocations, imports, entry points.
   This is the highest-value replacement in the whole plan: `object`, `goblin`,
   `gimli` and `pdb` cover the mainstream formats in a fraction of the lines,
   and format parsers are where memory-safety defects actually live.

4. **Cross-references, flags, strings, and the global name database.** These
   should be queries over the IL rather than separate scanners.

5. **Debug information.** Currently reached through radare2; `gimli` is better
   than the C path for DWARF, and `pdb` for Windows.

6. **Command language, shell, and the r2pipe protocol.** The command language is
   radare2's real moat and has to be reproduced faithfully, including seeking,
   grepping, piping and iterators, or users will not follow.

`r2s` becomes the tool. `r2sleigh` stays the name of the Sleigh toolchain, and
the radare2 plugin is deleted rather than carried: keeping it alive cost roughly
37,000 lines, and every capability listed above has to exist natively anyway.

Item one split in two, and only half of it was hard. **Body lift at a known
address** is recursive descent over direct branches, terminating at returns and
refusing at indirect transfers; it needs no value domain, and refusing a switch
rather than guessing it is the discipline this project already has. **Discovery**
— finding every function, and completing a body whose switch has to be resolved
— is a fixed point over that walk, and it now exists. What it cannot yet do is
cross an indirect handoff, which is what the value domain is for.

## What radare2 supplied, and what replaces it

The bridge was measured before it was deleted, and the measurement is kept
because it says what had to be rebuilt. About 15,500 lines of C —
`snapshot_capture.c` at 8468, `r_anal_sleigh.c` at 5049, `snapshot_walk.c` at
1218, `dwarf_facts.c` at 366, `arch_sleigh.c` at 244, `snapshot_wire.c` at 239 —
plus `ffi_v2.rs` at 5268 and `snapshot_capture.h` at 960, calling **156 distinct
radare2 symbols** at roughly 750 call sites.

The density was the finding. `snapshot_capture.c` was 6 per cent radare2 calls,
`snapshot_walk.c` 1 per cent, and `snapshot_wire.c` touched radare2 zero times
while still being written in C. It was never an FFI layer; it was r2sleigh's own
collection and marshalling logic living on the wrong side of a boundary. The
`r_anal_function_snapshot_*` names were never a radare2 API either — they were
`static` functions inside `snapshot_capture.c`, and the real coupling was to
struct layouts, `RAnal`, `RAnalFunction`, `RAnalVar` and `RList`, walked
directly.

Of the 156 symbols, roughly thirty plus forty-one C-library substitutes
evaporated once the logic was Rust; twenty-two were lookups into static sdb files
that `r2abi` now reads itself; and the genuine remainder was never an FFI
question at all — function discovery and boundaries, cross-references, names and
flags, comments, and variables, the last of which `r2ssa` already recovers better
than radare2's stack-pointer heuristics.

What the engine actually needs is bytes, an architecture and entry points.
`object`, `gimli` and Sleigh supply all three, behind a six-method `Program`
trait: `read`, `is_entry`, `return_address_register`, `name_at`, `import_at` and
`holds_static_data`. Everything else radare2 was asked for is a capability this
project owns.

Three things survive the deletion: the sdb data files, imported natively; the
stream of general radare2 fixes going upstream as their own pull requests; and
radare2 as the differential validation target for discovery, naming, decoding and
cross-references. The last is a dependency of the development process rather than
of the binary, and a disagreement with it may be radare2's defect rather than
ours.

### The lattice, and why refusal is not always available

r2sleigh's contract as a decompiler is *given a function, render it, and refuse
when the facts are not proven*. Certifying refusal is correct for a decompiler.
It is wrong for an analysis engine: a function listing cannot refuse, and neither
can a cross-reference query.

So the fact lattice needs two consumption policies rather than two pipelines. The
engine tier answers best-effort with confidence attached; the decompiler tier
keeps the right to refuse on top of those answers. `r2engine`'s request model and
`r2source`'s fact ownership were both built assuming refusal is always available,
and splitting that assumption is the real work.

The trigger is concrete rather than a judgement call. Everything `r2image`
answers is parsed out of the container format and is genuinely proven, so the
tension only goes live with discovery, because *this address is a function* is
the first inferred fact in the tier. **Every engine-tier fact carries a
confidence field from the first one written**, even while every value of it is
`Proven`. Adding the field costs almost nothing; adding it later means touching
every producer and every consumer. `Confidence` exists today and is mentioned in
exactly one file, which is the gap rather than the state of the art.

## The IL, in tiers

One substrate is not enough, and the reason is diagnostic rather than
aesthetic. When output is wrong today there is no inspectable middle, so the
defect cannot be localised to a lowering. Three tiers, each one crate with one
job, each independently printable:

**Low** is `r2il` as lifted from Sleigh: machine-faithful, flags explicit, no
variables. **Medium** is SSA with stack variables, resolved calls and dead flag
elimination — `r2ssa` promoted to a tier with a printable form of its own.
**High** is structured and typed, C-shaped, from `r2dec`.

Each tier gets a rendering, so every defect belongs to exactly one lowering and
can be shown to be there.

Sleigh is the only source of semantics. Capstone, if it is used at all, is used
only for architectures Sleigh has no specification for, behind the same decoder
interface, and it never produces IL. Sleigh's decode cost is the known
objection; the answers are ahead-of-time compilation of the specification into
match tables at build time — `r2sleigh-export` is the right home — and caching
decoded instructions keyed by bytes and context.

## Analysis capability

The honest accounting is that radare2 has more than its reputation suggests and
r2sleigh has more still, and that the most valuable gaps are ones neither has.

Radare2 has and does adequately: FLIRT, zignatures, Itanium and MSVC RTTI,
vtables, DWARF, PDB, the Go pclntab, IO layers, and search. None of that should
be rebuilt. Radare2 has but does weakly: jump tables as 1868 lines of
per-architecture heuristics, variable recovery as stack-pointer heuristics, type
inference in 799 lines, and binary diffing in 366 lines. The ESIL dataflow graph
is 2219 lines down a dead end.

r2sleigh already has constant propagation, taint, slicing, interprocedural
facts, indirect-call handling, aggregate access, interface recovery,
fingerprinting, and constraint-based type inference with a lattice and a solver.

Neither has strided intervals, a points-to or alias model, loop and induction
variable analysis, exception-handler recovery, or deobfuscation.

### Tier one: the keystone

**Value-set analysis.** Abstract interpretation over the medium tier with
strided intervals and widening. This is the single biggest hole in the stack.
`indirect.rs` is heuristic because it has no value domain to consult, and
radare2's jump table code exists at all because radare2 has no value domain. One
pass over the IL replaces both, and it is architecture-independent, so it
deepens x86 and ARM rather than widening.

**A memory model.** Abstract locations in the CodeSurfer sense: memory
partitioned into a region and an offset, where the region is a global, a named
stack frame, or an allocation site. `aggregate_access.rs` is doing structure
recovery without one, which is exactly why it is small and why it will not grow
past guessing until this exists.

These two are one fixpoint, not two projects.

**Solver escalation, and the lesson from the deleted crate.** The symbolic crate
was 67k lines with z3 in seventeen files and one reach from the render path, and
it was deleted for exactly that reason. The lesson is not that SMT is
unnecessary; it is that a solver subsystem with no consumers does not pay for
itself, and that building the subsystem before its consumers is the mistake.
Value-set analysis and hypothesis verification are the consumers. Build them
first, and let the solver come back as an escalation behind the facts API —
domains answer first, escalate when blocked and the budget allows, one call
site, one direction of flow.

### Tier two: what the keystone unlocks

**Interprocedural control-flow graph to fixpoint**, with indirect calls resolved
from value sets, vtables and RTTI, and type signatures, iterated against the
call graph. This is the largest single improvement available to decompiler
output quality.

**Loop and induction variable analysis.** Largely built since this was written:
`r2ssa` carries `InductionStep`, `InductionFact` with its own re-derivation
check, `collect_induction_facts`, the natural-loop walk with its bounds, and a
`ForLoopCertificate`; `r2dec` emits `CStmt::For` from them and `r2rewrite`
recovers `a[i]` from the induction step. What remains is the array recovery
that sits on top of a value domain.

**Structure and array recovery from access patterns**, probabilistically, over
the memory model. Both Ghidra and IDA are weak here, so this is genuine
differentiation rather than catching up.

**Exception-handler recovery.** `.eh_frame` and `.gcc_except_table` into real
`try`/`catch`, and the MSVC and SEH equivalents on Windows. Radare2 parses
`.eh_frame` for unwinding and never recovers handlers. Well-specified, no
research risk.

### Tier three: absent from both, high value

**Binary diffing at current state of the art**, in two layers: structural
matching over the call graph and control-flow graphs, propagating outward from
confident anchors, and feature-vector matching over the decompiled IL for the
fuzzy case. `fingerprint.rs` is already the seed of the second layer. This is
the highest user-visible value per line of code on the list.

**Corpus-scale similarity and library identification.** FLIRT is exact-pattern
and brittle across compiler versions and optimisation levels; fuzzy matching
against a corpus built from source beats it badly on optimised code.

**Static rewriting and reassembleable output.** Nothing in the radare2 world has
this. It converts the tool from one that reads binaries to one that transforms
them, and it depends on symbolisation being correct, which depends on tier one.

**Deobfuscation passes.** Opaque predicate detection, control-flow flattening
reversal, and mixed boolean-arithmetic simplification. The dispatcher analysis
already in the tree is the natural starting point for the second, and
`r2rewrite` is the correct home for the third.

### Tier four: language runtimes

Go beyond the pclntab — runtime type metadata, interface tables, channel and
goroutine structure. Rust, which has no demangler in `libr` at all, and whose
release binaries carry panic locations that hand over file, line and function
identity for free if anyone harvests them. C++ finished rather than started: the
RTTI data is already parsed and then not consumed, so class hierarchies never
reach `this` typing, method signatures or the rendered output.

### Tier five: research-grade, judged separately

Probabilistic and superset disassembly for stripped and obfuscated code, and
learned function-boundary detection. Both are real and published, both are
expensive, and neither should start until stripped-binary quality is
demonstrably the bottleneck.

### Tier six: the thing nobody ships

**Equivalence checking of the decompiler's own output.** Re-lift the emitted C
and compare its IL against the original function's under a solver, and report
divergence instead of emitting something wrong in silence. This follows directly
from the certifying discipline the project already has, no shipping decompiler
does it, and it is the only mechanical answer to "is the decompiler right" —
a question currently answered by hand, one function at a time.

## The agent interface

This is the differentiator, and most of the machinery already exists:
`observation_journal.rs`, `contracts.rs`, `obligation.rs`, `evidence.rs`,
`ledger.rs` and `proven.rs` together are a substantial evidence system. What is
missing is a surface that exposes it.

### Principles

**Stateless, addressed queries.** Every call carries its own target. There is no
cursor, ever. A query is idempotent, cacheable, order-independent and safe to
retry.

**Compound questions in one call.** The round-trip tax disappears only if the
agent can express the whole question. *Which functions reach `memcpy` with a
size derived from an argument and not bounded by a comparison* has to be one
query, and the interprocedural, taint and slicing layers already compute the
facts it needs. The facts exist; the query surface does not.

**Confidence on every field, never optional.** Every returned fact is proven,
inferred, guessed or unknown. An agent branches on that and a human ignores it,
which is why the certifying discipline that constrains the decompiler is an
asset here rather than a cost. The wire format must make confidence impossible
to drop.

**Token budget as a parameter.** Every call takes a budget; the engine elides to
fit and reports what it elided and how to fetch it. Context is the scarce
resource, not processor time.

**Progressive disclosure.** The default answer is a summary plus stable handles,
and the agent drills only where it needs to. Nothing dumps by default.

**Decompiled C as the default rendering.** Models read C far better than
assembly and it is several times cheaper in tokens. Assembly and IL are
drill-downs, not the starting point.

**Errors teach.** A malformed query returns the schema, the nearest valid form,
and what was wrong with the input. Silence is the failure mode that makes agents
confabulate.

### Two primitives nobody else has

**Explain.** Given any fact, return its evidence chain from the obligation
ledger. An agent that can interrogate its tool's reasoning hallucinates far
less, and the data structure is already built.

**Verify.** Given a hypothesis — this function is a CRC, this loop cannot
overflow, these two functions are equivalent — return proved, disproved with a
counterexample, or unknown, from emulation and the solver. This inverts the
relationship: the agent proposes and the engine disproves. It is what makes the
tool trustworthy inside a loop rather than a confident liar.

### Shape of the surface

Agents degrade past roughly thirty tools, so the surface is small: an overview,
a function listing, an inspection of one function at a chosen depth, a
decompilation with a tier selector, cross-references with a depth bound, a
general query with an introspectable schema, explain, verify, strings and data
with references resolved, annotation that records agent provenance and is
undoable, search, and diff. Roughly a dozen.

Function decompilations are exposed as addressable resources, not just tool
results, so an agent can reference one without refetching it and the host can
cache it outside the conversation.

Writing radare2 command strings is an escape hatch at most and never the
interface, because command strings reintroduce every failure mode named at the
top of this document.

## The debugger

The complaint that motivates this design is really about step-and-query: reach a
breakpoint, read a value, lose the state, start again. The fix is
record-and-query.

Record a trace once, then answer every question declaratively against the
recording — what was this register at the third execution of this address, what
wrote to this stack slot before the fault, which branch selected this path.
Reverse execution becomes another query. Nothing is re-run and no state is lost,
which is exactly what the multi-turn agent loop needs.

The query layer over recordings comes before live stepping. Replay at IL level
also answers questions a native debugger cannot.

## Invariants

Violating any of these costs more than the work it saves.

1. One fact, one owner. One implementation per job.
2. The engine never formats output. Rendering is a separate crate.
3. No implicit cursor anywhere in the query surface.
4. Confidence travels with every fact and cannot be stripped.
5. Semantics come from Sleigh. No hand-written per-architecture semantics, ever.
6. No serialization boundary inside the engine process.
7. Analysis is demand-driven and invalidated incrementally, not batched.
8. Every tier of the IL is printable.
9. A defect is fixed where it originates.

## Sequencing

Dependency order, and each step ships something.

1. **Native body lift at a given address.** Recursive descent over direct
   branches, refusing at indirect transfers. Nothing below this is callable
   without it. *Done: `r2ssa::body`.*
2. **The sdb type and convention import.** A dependency of a useful `pdd`
   through `callee_facts`, not an independent win. *Done: `r2abi` reads the
   conventions and the five hundred library prototypes.*
3. **Native request construction**, and `pdd` end to end in `r2s`. *Done, on
   x86-64, aarch64 and ARM 32-bit.*
4. **Printable IL tiers.** Every tier inspectable from a command, so a defect
   belongs to exactly one lowering. *Done: `pdil`, `pdim`, `pdih`.*
5. **Discovery**, with confidence attached. *Done as a fixed point over direct
   transfers; it does not yet cross an indirect handoff.*
6. **Delete the plugin and the bridge**, and rebuild the gate natively. The
   plugin is not ported and not preserved.
7. **The name database, cross-references and strings.** One address-to-name
   table with a kind, a size and a confidence, plus a reverse index, replacing
   every rival naming rule in the tree. Queries over the IL, not separate
   scanners.
8. **Discovery across a typed handoff.** A constant argument counts as a
   function where the callee's declared prototype says that parameter is one.
9. **Write and patch mode**, with incremental invalidation, which is the first
   thing that actually exercises demand-driven analysis.
10. **Value-set analysis and the memory model.** One project. Partly landed:
    `values.rs` carries strided intervals with widening and `indirect.rs`
    consumes them, and what remains is the memory model and the rest of the
    consumers.
11. **Interprocedural control-flow graph to fixpoint.** Callees are walked one
    level deep today.
12. **Exception-handler recovery**, and structure and array recovery over the
    memory model.
13. **Binary diffing.** Independent of the above and high value.
14. **Solver escalation**, with verification and value-set analysis as its
    consumers, so it does not repeat the deleted symbolic crate's fate.
15. **Equivalence checking**, which makes every later claim mechanical rather
    than hand-checked.
16. **The rest of the command language and r2pipe compatibility.** Begun: `r2s`
    already spells its commands as radare2 spells them so the two can be diffed.
17. **The agent surface**, at the merge: the stateless typed query API in
    `r2engine`, confidence carried through `r2source`'s contracts, explain over
    the existing ledger, a protocol of about a dozen tools plus function
    resources, and budget-aware rendering with elision reported and fetchable.
    The query API is the real work; the protocol is a wrapper.
18. **Trace recording and query.**

Step seventeen is small and makes this the best agent-facing binary analysis
tool in existence, because nothing else ships confidence and nothing else can
explain itself. It is late because it is worth more over an engine that owns its
facts than over a bridge into someone else's.

## Open questions

**Naming — settled, and kept.** The `r2` prefix stays on the binary and on
every crate. It reads as a guest's prefix only if compatibility is incidental,
and it is not: `r2s` reproduces radare2's command language on purpose, and the
prefix is what says so. There is no rename. `r2sleigh` stays the name of the
Sleigh toolchain, and `r2s` is the host binary.

**Incremental recomputation.** Query-keyed memoisation with dependency tracking
is the right model — patch a byte, invalidate only what depended on it — and it
is the difference between opening a large binary instantly and waiting for a
batch analysis. Whether to adopt an existing framework or hand-roll it is
undecided; the model is not.

**The plugin interface for the standalone engine.** Rust has no stable ABI, so
native extension means a C interface, sandboxed extension means WebAssembly, and
scripting means r2pipe compatibility. Radare2's ecosystem is C-ABI plugins, and
this decision determines whether any of it follows.

**The vendored Sleigh dependency — decided, and now a distribution question
rather than an open one.** `Cargo.toml` patches `libsla`, `libsla-sys` and
`sleigh-config` to the project's own forks' `main` branches, which is settled
policy. What is not settled is that a shipped `r2s` would depend on three git
forks; the compiler specifications the engine now reads for the return-address
carrier are carried there too, and belong upstream in Ghidra.
