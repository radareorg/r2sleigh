# Handoff: the engine inversion

> Open threads on the track that makes the engine own its facts. The
> decompiler-quality thread has its own handoff in
> `doc/handoff-location-ssa.md`; this one does not touch it.
> `doc/engine-vision.md` holds the design and the order.

## The plugin is deleted, and `r2s` is the tool

The user reversed two of `doc/engine-vision.md`'s non-goals: *"ditch the plugin
entirely and just focus on r2 core libs, improve it and make r2s as main r2,
which would be fast, correct, thread safe, sota."* The document used to say no
rewrite of radare2 and no native terminal surface, both resting on the plugin
surviving to carry users. It does not survive. `doc/engine-vision.md` is
rewritten, and its sequencing renumbered, around that.

**63,176 lines went in one commit.** `r2plugin` entirely — 17,514 lines of C and
headers, 16,021 of Rust — plus `crates/r2source/src/snapshot_wire.rs` at 3,898,
`tests/e2e`, `tests/r2r` and its fixtures, the two plugin-only cargo aliases,
and the wire-only setter on `OwnedFunctionSnapshot`. Three things had to move
rather than vanish: `AdvisoryCallSite` gained a public `described` constructor,
because an `r2ssa` test had been building one by encoding it to the wire and
decoding it back; `r2source` lost three schema constants nothing read; and
`r2ssa` lost a re-export of one of them.

**Nothing regressed.** The workspace suite is green with *no* failures for the
first time in this branch — the two standing `plain_o2_lift_fixtures` failures
were the plugin's and died with it, so they never needed re-blessing. The
certification gate reports the same 98 rendered, 0 refused, 0 undefined reads
over the same twenty-four ELF binaries.

### The gate this cost, and what replaced it

All 128 `r2r` tests drove `pd:s` or `a:sla`; **none** drove `r2s`. Deleting the
plugin therefore deleted the project's largest gate on the same day, which the
user chose knowingly over freezing the plugin as a reference oracle.

The `r2r` database could not be ported as written: its tests use
`FILE=malloc://64`, `wx`, `|` pipes, `>` redirection and `a:sla.debug.*` — an IO
scheme and a command language `r2s` does not have, plus a debug surface that
died with the plugin. So the replacement is a Rust integration suite, which is
how the engine's own tests already work.

`crates/r2s/tests/commands.rs` runs the binary through `CARGO_BIN_EXE_r2s`, so a
test can never measure an older artifact than the code it checks — the structural
fix for the stale-binary mistake that once had a harness describing a tree
several changes old. Thirteen tests: symbols, grep suffix, discovery with a
confidence on every row, temporary seek, disassembly, rendered C with its proof
line, the three tiers answering differently, an unmapped address refused rather
than invented, and four `insta` snapshots pinning `pdil`, `pdim`, `pdih` and the
C for one function. The fixture is `tests/coverage/pinned/hashes_gcc_x64_O2`,
which the repository ships as bytes, so the same assertion means the same
program on every machine.

The four snapshots were read against `tests/corpus/hashes.c` before blessing.
`fnv1a32` renders as a seed return for the empty case and a pointer-bounded loop
otherwise, which is what GCC's `-O2` makes of `for (i = 0; i < n; i++)`; the
types are register widths because the pinned binary carries no DWARF. The medium
tier gives every elided value a named reason. All four are right.

`scripts/diff_capture.py` became `scripts/certify_render.py`: its left column was
the plugin's capture, and with one column left the name was a lie. It is now the
native certification gate and nothing else.

`tests/coverage/sweep_binary.sh` drives `r2s -q -c 'afl'` and `pdd` instead of
radare2 with the plugin installed. **The baseline has not been re-blessed**: the
function set changes from radare2's `aaa; afl` to this engine's discovery, so
every cell key moves, and that re-bless needs the new output read rather than
accepted.

CI lost the `r2r`, `source-gold`, `fixed-performance` and `e2e` jobs. `quality`,
`capture-gate` (now `certify_render.py`) and `coverage` remain, and `quality`
gained the `--no-fail-fast` it should always have had.

### Owed, and named so it is not a baseline

- **`source-gold` has no replacement yet.** It ran `scripts/reversing_benchmark.py`
  with `tests/gold/closure_manifest.json` and `tests/gold/source_oracle.json`
  through radare2 with the plugin staged. The oracle files survive; the 6,800-line
  harness around them is plugin-coupled down to fingerprinting the installed
  `.so` and probing `a:sla?` for help text. Porting it wholesale is not obviously
  right — extracting the closure gate into a small native harness probably is.
- **`fixed-performance` likewise**, against `tests/gold/mem_scan2_performance.json`.
- `scripts/kernel_smoke.py`, `scripts/differential_truth.py`,
  `scripts/bench_semantic_metadata.py` and `tests/decbench/` all still shell out
  to radare2 with the plugin.
- The coverage baseline re-bless, above.
- `tools/dylints/r2sleigh_lints` carries lints written for plugin-side policy
  (`type_writeback_policy`, `engine_policy_ownership`, `raw_direct_call_target`
  and their neighbours) whose UI fixtures live under a `ui/r2plugin/` path. They
  can no longer fire on real code and need auditing rather than leaving.

### One defect found while checking the README

`r2s -q -c 's <entry>; pdd' /bin/ls` on this machine's Mach-O `/bin/ls` returns
`Parse error: machine-derived CFG contradicts the owned advisory source CFG at
0x100001784: machine names [], source names [(Fallthrough, 4294973320, None)]`.
The advisory successor is `0x100001788`, one instruction on, while the machine
CFG names nothing — so a terminator is being read as leaving the function where
the capture says it falls through. The twenty-four ELF binaries in the
certification gate do not reproduce it, so it is Mach-O-shaped or specific to
that function. Not traced yet.

## Where `engine/inversion` stands

Verified at `007ff29b`, by running each gate rather than by recollection.

    cargo test --workspace --all-features --no-fail-fast
        every target green except two, both named below
    scripts/diff_capture.py --bins <radare2>/test/bins/elf --limit 24
                            --functions 8 --native-only
        98 rendered, 0 refused, 0 undefined reads
    make -C tests/r2r run
        102 OK, 14 BR, 4 XX -- all four in db/wip/r2sleigh_regression_watch
    cmp, sdiff, diff3, diff built -O0 -g
        869 of 878 rendered, 9 refusals

**Pass `--no-fail-fast`.** Without it `cargo test` stops at the first failing
target, so one crate's known failure hides every failure after it. Two `r2ssa`
tests were red for a day behind the plugin's two, and a session reported the
suite as green apart from the plugin eight or nine times.

**The two standing failures, with their causes**, because a failure count with
no cause is a lens that filters out everything not already in it -- which is how
the forty-seven `r2r` failures survived as a "baseline" while being a one-line
format-version mismatch that had killed the whole plugin route:

  * `plain_o2_check_secret_has_exact_offline_lift` and
    `plain_o2_sum_array_has_exact_vectorized_offline_lift` pin an SSA hash of
    the offline lift. Both drifted at `9a9df9f6a934275a` and
    `6ac396ef9837c6bd`. The hash is the fixture's, not a correctness claim; the
    renderings were read and are right, and the fixtures need re-blessing after
    someone reads the new lift rather than because it differs.

**This branch has diverged from `origin/engine/inversion` deliberately.** Every
commit from the branch point carried a `Co-Authored-By: Claude` trailer and a
`Claude-Session:` URL, which the standing rule forbids on anything feeding a
pull request. All 154 were rewritten locally to drop them; the trees are
byte-identical and the gates were re-run after. `origin` still holds the 93
attributed commits it had, by choice -- rewriting published history is a
force-push and was not taken. The divergence has to be resolved before this
branch pushes again, and the pre-rewrite tip is kept at
`refs/original/refs/heads/engine/inversion`.

## Where the milestone stands

`r2s -c 'pdd @ <addr>' <binary>` emits C with no radare2 present, on x86-64 and
on aarch64, for both Mach-O and ELF images. The route is: `r2image` opens the
binary, `r2ssa::body` walks the function by recursive descent, `r2source::native`
mints a capture, and from there it is the trusted lift, the trusted SSA
artifact, and the same engine request the plugin uses.

Checked by hand on a three-function binary built at `-O0` for both machines:
`add_two` recovers `uint32_t (uint32_t, uint32_t)` and returns the sum, `pick`
recovers the conditional, and `main` renders `_add_two(1, 2)` with the callee's
recovered prototype declared above it.

Sequencing items one to four of `doc/engine-vision.md` are done: a `main` in an
ELF hello world renders its string literals as text, names its imports, and
calls them with the arguments their declared prototypes state.

The route also reads the binary's own debug information, so a function with one
states its source signature and names its locals. `count_newlines` out of
`diffutils`' `cmp`, built `-O0 -g`:

```c
uint64_t count_newlines(int8_t* buf, uint64_t bufsize)
{
    count = 0;
    lim_2 = (int8_t*)((uint64_t)tmp_11f80_1 + tmp_11f80_2);
    int8_t ch = (int8_t)*lim;
```

`buf`, `bufsize`, `count`, `lim`, `ch` are the source's names, read from DWARF
by `crates/r2image/src/debug.rs`; six of this function's locals are.

Against radare2 over its ELF corpus,
`scripts/diff_r2.py --bins <radare2>/test/bins/elf --limit 30` agrees on

    px 64   21 of 24        ie   24 of 24
    pd  8   14 of 24        iS   24 of 24
                            is   23 of 24

of the twenty-four it opens; six of the thirty are not opened, four for an
unrecognised magic and two for an architecture with no mapping. Quote a figure
from a run, not from this paragraph: every number in this document that was
inherited rather than measured has been wrong by the time someone read it.

## Discovery, and the first fact that carries confidence

`afl` lists every function the program has. It was the symbol table, so a
stripped binary had none -- while its entry point, its initialiser and
finaliser arrays and a linkage stub per import were all parsed already and only
the program's own entry was read.

Discovery is the least set of addresses closed under "walk it and take where it
transfers", started from what the image states. It terminates because the set
only grows and the image is finite. `crates/r2engine/src/discovery.rs` holds
the fixed point; the seeds are the host's, because the engine must not depend
on the loader -- that is what `Program` is for.

    cmp                 is 143 functions    afl 214
    cmp, stripped       is   0 functions    afl  75

**Every address says why it is believed**, because this is the first inferred
fact the engine produces and a consumer that cannot tell a format's statement
from this engine's reading of one instruction has to treat both as the weaker:

  * `Stated` -- an entry point, a function symbol, a linkage stub the format
    declares. Nothing is inferred.
  * `Called` -- a walked body calls it, with a constant target.
  * `Reached` -- a walked body leaves for it without returning, where whether
    the target is a function of its own is exactly what a tail call makes
    ambiguous.

Found twice, an address keeps the stronger reason, so the order a walk happens
to take does not decide how far a fact can be trusted.

**Its reach is bounded, and the bound is named.** On a stripped binary the
entry point tail-calls `__libc_start_main` and hands it `main` as a pointer, so
`main` is never a direct call target and neither is anything below it. The
seventy-five are the stubs, the entries, and `deregister_tm_clones`, which one
walked body calls. Crossing that handoff is an indirect transfer, which is the
value-set analysis the order already sequences after this.

## What grades the capture

`scripts/diff_capture.py` renders one function from radare2's capture through
the plugin (`pd:s`) and from the engine's own through `r2s pdd`, and diffs the
C. Both sides run the same decompiler, so a difference is a difference in what
the capture carried. Nothing graded this before, and every quality judgement
about the inversion was therefore an opinion.

It paid immediately. It proved that the unconnected call chain in a rendered
`main` -- every call's result dropped, every argument from an unrelated
temporary -- is *pre-existing decompiler quality* and not inversion damage: the
plugin's capture renders the same shuffling on the same function. It also found
that the first import stub of any ELF was named at the `nop` padding before it,
so every call to it stayed anonymous.

Over eight ELF binaries, six functions each: two identical, seven differing,
three refused natively where the plugin rendered, seven refused by both. The
three native-only refusals are the measure to drive to zero.

## The capture is made twice

Preparation proves things a capture would have to state, which is a circle: the
interface is recovered from the instructions, and the slots that interface
should declare are only known once it exists. So the capture is made twice. The
first pass carries no interface and preparation recovers one; the second states
that interface again with the frame slots the first proved, and preparation
folds the spills into the parameters they home.

This is what took `_dup` from refusing outright to reading like its source: a
`strlen`, a `malloc` of its result plus one, a copy into it, and the pointer
returned.

The second pass costs one more preparation per function. It is skipped entirely
when the first pass proves no slot and finds no new text, which is every
function that keeps its arguments in registers.

## What the route does not do yet

**Stack arguments have no placement.** `SourceConventionSlots` is built with
`with_stack_arguments(None)`, so a function with more arguments than the
convention has registers refuses rather than reading them off the frame. The
placement is arithmetic over the shadow space and the return-address slot;
radare2 spells it `r_anal_cc_argslot`, and it needs a register profile as well
as the `cc` data because the word size is refined by the first register argloc.

**Callees are walked one level deep.** Deeper is what an interprocedural
fixpoint is for. A callee that fails to walk leaves its call unproven.

**A saved callee register renders as a read of nothing, under `0 refused` --
closed on x86-64, open on aarch64.** What a call leaves standing is stated on
the machine roles now, read from the compiler specification's `<unaffected>`
list, and it has to be the roles rather than the interface because the roles
are read in the first capture pass, before an interface exists to hold it.
Without it every function that calls lost the facts about its own frame. `main`
in an ELF hello world went from forty-six rendered lines to thirty-four, against
the plugin's thirty-five, with no uncertified read left.

aarch64 carried it until the declaration landed. No `.cspec` in Ghidra names a
return-address register for ARM or AArch64, so the certificate compared the
saved value's carrier against the program counter and failed. Declaring `x30`
and `lr` in the `sleigh-config` fork closed it: `_dup` renders with no
uncertified read and its caller lost three lines of dead frame. The
declarations belong upstream in Ghidra.

A second class, unrelated: the cold partitions of C++ library functions
(`..._create_hard_link...part.37` and its neighbours) read `RAX_1` and `RAX_2`
under `0 refused`. Those are post-call values rather than prologue saves, so it
is a different defect wearing the same shirt.

The original wording, kept because it names the shape:
The prologue's `stp x29, x30, [sp, N]` on aarch64, and `push rbp` on x86-64,
render as `stack_m8 = X30_0` and `stack_m8 = RBP_0`. The entry value is
declared as a local, never assigned, and then read -- while the proof line says
nothing was refused. That is a certification defect rather than a quality one:
the output claims a fact the program does not make. The oracle counts these
separately, and there are two in a three-function binary. The plugin's capture
elides the save entirely, so the question never reaches its renderer.

**Three functions in the sample refuse natively where the plugin renders.**
That is the number to drive to zero, and the oracle names which ones.

**The aarch64 address fold is closed.** `adrp` plus `add` never becomes one SSA
constant, and the harvest was scanning for constants that could not exist. The
fold itself was written four times -- the term layer, `constant.rs`,
`data_ref.rs` and SCCP -- and the capture asked none of them;
`SsaArtifact::folded_value` is now the one public answer and the second pass
asks it. `_dup("x")` renders.

**A `char` is spelled `int8_t`.** The declared type graph carries a signed
eight-bit integer, which is what `char` is, and the renderer has no reason to
prefer one spelling.

**Code pointer tables are captured empty**, because finding one means proving
what indexes it, which needs the value domain.

**Only the default convention is used.** Every function is assumed to use the
convention `default.cc` names. A binary mixing conventions needs per-function
evidence to choose, and there is none yet.

**No discovery.** `pdd` takes an address. The function list comes from the
symbol table, so a stripped binary has none. This is deliberate and sits behind
the value-set keystone.

## Facts worth keeping

**The return-address carrier is the program counter on both machines**, and that
is not a convention. Sleigh lifts x86-64 `ret` as `Load RIP <- [RSP]; RSP += 8;
Return RIP`, and aarch64 `ret` as `Copy pc <- x30; Return pc`. The carrier the
`Return` reads is the program counter in both cases, so no link-register table
is needed and none was added. No aarch64 `.cspec` names a return address at all.

**Machine roles must carry register names, not only storages.** The trusted lift
restates every carrier in its own architecture's numbering and looks them up by
name (`arch_resolved_source`), so roles built with storages alone lose both
carriers and every function refuses with `no stack pointer carrier`. This cost
an hour; it is one call to `with_role_register_names`.

**`captured_fields.return_address_storage` describes the interface, not the
roles.** A capture with no function interface must set it false even when the
machine roles do carry the storage, or the mint refuses with
`InvalidFunctionInterface`.

**Sleigh lifts `call $+0` as a store and a branch, not a call.** The
instruction-local control normaliser reads a call whose target is the next
instruction as a local skip. That idiom is real 32-bit PIC code
(`call next; pop ebx`), so this is worth revisiting when PIC binaries matter.

**The stack pointer comes from Ghidra's compiler specification**, which
`sleigh-config` did not embed until `0verflowme/sleigh-config@fc0ace6`. The
`.cspec` also carries the prototype models; they are deliberately not read,
because calling conventions come from the vendored `cc` data and two owners for
one fact is worse than either.

## What the differential oracle still reports

`scripts/diff_r2.py` over radare2's ELF corpus, thirty binaries, twenty-four of
which `r2s` opens: `px` twenty agree, `pd` thirteen, `ie` twenty-three, `iS`
twenty-four, `is` twenty-one.

The remaining `pd` disagreements are four causes, none of them analysis:
radare2 resolves an ARM literal pool to the symbol it holds and prints
`ldr ip, sym.x` where the bare load says `[0x817c]`; Sleigh and Capstone spell
some ARM instructions differently (`pop {r1}` against `ldr r1, [sp], 0x4`);
radare2 maps a relocatable object at `0x8000000` where `r2s` maps it at zero;
and one Thumb function decodes differently, which is a real gap rather than a
spelling.

## A disagreement can be radare2's defect

Two of the three symbol-listing disagreements were radare2's, and matching them
would have meant adopting the bug. `_set_arm_thumb_bits`
(`libr/bin/format/elf/elf.c`) cleared the low bit of *any* symbol whose address
was odd. On ARM that bit selects Thumb on a **function** address; a data object
at an odd address is at an odd address. The ELF says
`zeroes` is `STT_OBJECT` at `0x677d7`, and radare2 reported `0x677d6` -- one
byte before the object, labelled sixteen-bit code.

Fixed in the fork on `fix/arm-thumb-bit-on-data-symbols`, with a regression
test in radare2's own suite, and waiting to be raised upstream. The format
suite goes from 241 passing to 242 with nothing else moved. Symbol-listing
agreement went from twenty-one of twenty-four to twenty-three.

The engine had the matching defect in the other direction and it is fixed too:
an entry point kept its Thumb bit, so a Thumb `_start` decoded from an odd
address and every instruction after it read from the wrong place. Entry-point
agreement is now complete. What is still missing is acting on the bit: the
decoder reads ARM whatever the bit said.

## The certification gate is red, deliberately

`scripts/diff_capture.py --native-only` renders every named function and fails
on any rendering that reads a value nothing assigned while its proof line
claims nothing was refused. It runs in CI as *Native Capture Certification
Gate*, needs no radare2, and is the first automated coverage the native route
has had.

It is red today: over twelve binaries, twenty-nine functions render, eight
refuse, and eleven of the renderings are uncertified. Two causes, both traced
and neither hidden behind a threshold. The aarch64 saved link register waits on
the return-address declaration reaching the `sleigh-config` fork. The C++ cold
partitions read `RAX_1` and `RAX_2`, which are post-call values and a different
defect.

A gate that is green because its threshold was raised to meet the defect would
be worth nothing.

## Two plugin lift fixtures drift, and it is not the inversion

`plain_o2_check_secret_has_exact_offline_lift` and
`plain_o2_sum_array_has_exact_vectorized_offline_lift` in
`r2plugin/src/plain_o2_lift_fixtures.rs` fail on an SSA hash: `check_secret`
expects `548f779c1f93e29d` and gets `9a9df9f6a934275a`. Measured rather than
argued: a worktree at `5c9bd947`, the commit this track started from, produces
byte-identical expected and actual hashes, so the drift predates every change
here and belongs to whichever change last moved SSA construction. The
expectations are not re-blessed, because a hash that differs is not a hash that
is right.

## Peeling: what is now dead

Nothing has been deleted yet, by design — the plugin still needs the bridge
until `r2s` answers what the plugin path answers. The native route already makes
`snapshot_wire.c`, `snapshot_walk.c` and `crates/r2source/src/snapshot_wire.rs`
unnecessary for anything but the plugin, which is roughly 5,345 lines waiting on
the proof step.

## The native certification gate, and what moved it

The gate is `scripts/diff_capture.py --bins <radare2>/test/bins/elf --limit 24
--functions 8 --native-only`. It went from `rendered 82 / refused 16 /
undefined reads 3` to `rendered 95 / refused 3 / undefined reads 4` across the
work below. It now reads **98 rendered, 0 refused, 0 undefined reads**; the
figures in this paragraph are the ones that were true when it was written:

- The capture emitting `TailSlot` for a stub's jump through its slot, so a
  walked import stub no longer looks like a body that returns nothing.
- Placing a stub at its own cell, derived from the distance between two
  transfers, instead of after a landing pad that the padding test read as
  padding.
- Refusing to return a register whose one definition is a call clobber whose
  boundary names no result carrier.
- Reading the argument area of a convention that passes everything on the
  stack, which is stated by the compiler specification's stack `pentry`. This
  alone was eleven of the sixteen refusals: x86 cdecl has no argument
  registers, and recovery returned `None` before it started.
- Asking once whether the caller supplied a binding, rather than the plan and
  the seal deriving it differently.
- One canonicalization per inlining round, absorbed as the rendering absorbs.
  The conflict this refusal reported was masking a miscompilation: a shift of a
  rewritten object was duplicated into a tail call argument and read after the
  object had been reassigned.
- Placing a gapped read where it is read rather than where the gap marker sits.
- Letting a body prove a result the convention does not name, which is what a
  position-independent code thunk returns.

The proof line now reports how many values a rendering holds from entry, and
the gate reads that count. A value in one of the convention's argument slots is
excluded from it, so a parameter the recovery missed still reads as a defect
rather than being absorbed by the new column.

## `SourceFunctionReturn` has a third state now, and this is why (closed)

A function whose tail transfer has an unprovable result cannot recover its
parameters, because the guard returns no interface at all. Letting it recover
parameters with a void result was tried and measured: rendered 95 → 89, refused
3 → 9, undefined reads 4 → 11, one test red. `Void` is an active claim that
displaces the caller's convention fallback, so every `.part.NN` function that
had been getting its result that way lost it.

So "this function proves no result" and "this function returns nothing" are
different facts and the contract had one spelling for both. It is now
`SourceFunctionReturn::Unproven`, which a caller treats as unknown and answers
from the convention, exactly as it answers an absent interface. The recovery
side had the same conflation in `Option<RecoveredResult>` and gained the same
third case.

One rule came out of building it, with the measurement that forced it: an
unproven result mints **no call-site contract**. Minting one cost the gate
97 → 93 rendered, because an import thunk reads no argument slot, so its
proven parameter list is empty, and every Qt call in `abcde-qt32::main` lost
its four arguments. The parameters of a body whose tail nobody read are a
floor, not a contract; the caller stays on its convention fallback.

The second fact that gap was holding up also landed. A body whose every return
reloads its control value from the entry stack slot, where nothing writes that
object and every live-out result roots at a read of it, **returns the address
the call pushed** (`SourceFunctionInterface::body_proven_return_address`). The
caller rewrites reads of that carrier to the constant one operation above the
call, before preparation, because `inst_combine` is what folds `const + n` and
nothing downstream of preparation folds. `__x86.get_pc_thunk.si` then gives
`abcde-qt32::main` its string literal instead of `ESI_1 + 0xe0d`, and the
`*_tm_clones` functions compute real addresses (`0x2008`,
`*(uint32_t*)0x1fec`) rather than offsets from a value nothing assigned.

Note for anyone re-deriving this: the value `mov esi,[esp]` reads and the value
the `ret` pops are **not** the same SSA value -- the lift makes two loads of
`[esp]`. Object identity plus "nothing writes it" is what holds.

## Open

- Which repository "just use master" meant. The radare2 fork's integration
  branch is now twenty linear commits on `upstream/master`, which is the
  substance of it; moving the published `master` ref is a separate act, and
  r2sleigh's own `master` is a public protected branch 2452 commits behind the
  working line.
- `observation journal: RenderedValueRequired` on `main` (abcde-qt32) and
  `funcarg` (arg_down_prop): a value the plan bound or inlined has no cell
  because the rewriter spelled it through another member. Three closures at the
  accounting pass were tried and reverted; the cell has to be allocated where
  the rendering happens, not filled in at the seal.
- `StackObjectDeclarationWidth` on `_Z6_startv` (`_Exit (42)`): an access-less,
  address-only stack object becomes a binding that demands a declaration width
  it cannot have.

## ARM 32-bit: Thumb decodes, and `pdd` still does not run

ARM states the instruction set per function, in the low bit of the symbol that
names it. `r2image` masked that bit off the address and discarded it, so every
Thumb body disassembled as ARM: `push {r7, lr}` read as
`addlt fp, r2, r0, lsl 0xb`, a different instruction of a different length, and
everything after it landed off-cut. The bit is now kept as `Symbol::thumb`, the
session holds the Thumb decoder beside the ARM one — the same SLA with Ghidra's
`ARMtTHUMB` processor specification, which is how Ghidra itself ships a Thumb
decoder — and the address chooses. `pd` now matches radare2 on both.

`pdd` on any ARM 32-bit function still refuses before reaching this:
`TrustedSleighProfile::from_tuple` admits only `x86/32`, `x86/64` and
`arm/64`, by a deliberate rule that a tuple enters the list only once it has
been verified against the active analyzer. Admitting `arm/32` is that
verification, not a line of code.

## i386 call sites: the arguments were never looked at

A call with no prototype fell back to the convention, and that fallback walked
only the convention's *register* carriers. On i386 cdecl that list is empty, so
every such call came back **complete with zero arguments** — not a gap but a
false claim, with the arguments sitting beside the call as
`*(uint32_t*)ESP_4 = ...` stores that were then elided as dead. Three things
were wrong on one path and all three are fixed at their own cause:

- The fallback now reads the outgoing argument area after the register slots,
  stopping at the first slot with no store, and refuses the boundary outright
  when the convention passes arguments on the stack and the entering pointer's
  position is unknown. An empty scan there means nothing was looked at, not
  that nothing is there.
- `SourceStackArgumentPlacement::first_offset` carried Ghidra's callee-entry
  coordinate while its own comment promised the caller's. The cspec states
  `stackshift` on the same prototype element, so subtracting it makes the field
  mean what it says; this also removes an off-by-one-slot in the x86-64
  variadic tail probe.
- A function that realigns its stack (`and esp, -16`) had no root for any
  address after the mask, so nothing about its frame could be placed.
  `StackAddressBase::Realigned` names that origin — an origin, not a position,
  because what the mask discarded is unknown. Aliasing still answers "may
  alias" across bases, so no disjointness is claimed.

The Qt `main` in `abcde-qt32` went from 77 of 153 obligations gapped to none,
and its ten calls now carry argument lists that match the machine push for
push. `easiestprintf`'s `main` went from nine argument-less calls to
`setvbuf(stdin, 0, 2, 0)`, `alarm(60)`, `sleep(3)`,
`open("/dev/urandom", 0)`, `read(fd, &stack_m29, 1)`, `_exit(-1)`.

## A convention-preserved register a callee does not preserve

`__x86.get_pc_thunk.si` is `mov esi, [esp]; ret`: it returns the return address
in ESI, which x86 cdecl's `<unaffected>` list calls preserved. The caller
therefore reads `esi` after the call as the value it spilled beforehand, and
the string address in the Qt `main` renders as `stack_m16 + 0xe0d`.

The callee's own interface already proves the answer -- `body_proven_result`
recovers a carrier the convention does not name, and the thunk is declared
`uint32_t __x86_get_pc_thunk_si(void)` in that very rendering. The rule is that
a register the callee's interface names as its result is not preserved across
that call. It must not be widened to "the callee's body writes it": every
save-and-restore callee writes the registers it saves.

## ARM 32-bit is admitted, and what it took

`TrustedSleighProfile::from_tuple` now admits `("arm","arm",32,Little)` and
`("arm","thumb",32,Little)`. Four things had to be true first, each a defect
rather than a policy:

- The snapshot's machine tuple carries a **processor context**. `arm` and
  `thumb` are one instruction set under one architecture name, so the context
  is the only fact that tells the trusted lift which decoder to load;
  `EmbeddedMachine::cpu` and `NativeTarget::cpu` carry it.
- `bx`'s `setISAMode` user operation expands to nothing. The p-code has
  already written the mode bit and masked the target by the time it fires, so
  the operation spells nothing further; leaving it a `CallOther` refused every
  function containing a `bx`.
- A machine reaches its return address through transport the fact did not
  follow: `bx lr` masks the link register's low bit -- the instruction-set
  select, not the address -- and `ldmia sp!,{fp,pc}` pops the frame word
  straight into the program counter. Three near-identical arms became one
  backward walk over the steps a machine uses to reach its control value.
- **ARM predicates whole instructions, transfers included.** `bxeq lr` lifts
  to a local conditional skip over the instruction's own return, and the
  normalizer only converted a skip whose operations were all speculatable
  values, so a predicated transfer became `Unimplemented` and the function
  refused as volatile. A skip that jumps over a transfer to the end of the
  instruction is an ordinary machine edge to the next instruction, and is now
  spelled as one.

Stub naming was rebuilt on the way: the cell is derived from the engine's own
`terminal_indirect_loaded_slot` rather than a stride between transfers, which
an x86-32 PLT (two transfers per cell) and ARM's three-instruction slot
computation both defeated. A relocation slot now answers for its import too,
because a stub's tail transfer names the slot rather than any code address.

Measured on the 20 ARM 32-bit ELF binaries in radare2's corpus, first eight
functions each, from a standing start where every function refused:

    rendered 25 / refused 30 / undefined reads 6

The non-ARM window is unchanged at `77 / 0 / 0`.

## The one wall ARM is behind now

**The engine cannot render an indirect tail call through a value**, and that
is what the 24 `RenderedValueRequired` refusals are. Traced: `SSAOp::BranchInd`
lowers to `None` in `op_to_stmt_impl` ("handled by control flow structuring"),
and the structurer spells its target only through `dispatch_operand_expr`,
which runs when the branch renders as a `switch`. A `bx r0` is neither a
switch nor a certified tail call -- `AdvisoryCallTransfer` has `Call`,
`TailJump` and `TailSlot`, and a register target is none of them -- so nothing
spells the target, no `ObservationTarget::Value` is allocated for it, and the
seal demands a cell nobody owes. ARM dispatchers are built from this shape, so
it accounts for four fifths of what is left there.

An indirect branch that leaves the body is now named as the call it is
(`Native::name_indirect_tail_calls`): a terminal `BranchInd` that dispatches
no switch, reads no relocated slot and has no successor becomes `CallInd`
followed by a return, so every mechanism an ordinary indirect call already has
renders it. It is dormant on this corpus, because the ARM functions shaped
like that refuse earlier, on predication.

## ARM predication needs a conditional-exit terminator, and a naive edge is worse than the refusal

`bxeq lr` lifts to a local conditional skip over the instruction's own return.
Converting that skip into a machine edge to the next instruction was tried and
**reverted**: the transfer's `Return` then stands last in the block, so
`analyze_terminator`, which reads the last control operation, calls the whole
block an unconditional return. `arm-init`'s `cmp r0,0; bxeq lr; bx r0` walked
as one block and the tail call was never lifted at all. Measured: rendered
23 -> 25 while bodies were silently truncated, which is worse than the refusal
it replaced.

The shape is a block that *conditionally leaves the function*, and the block
may legally end at the predicated instruction, because that is an instruction
boundary. Six attempts moved the failure one layer at a time, which is the
project's own signal that the work is in the wrong layer:

1. `cfg.rs::analyze_terminator` calls the block an unconditional transfer,
   because it reads the last control operation. Fixing it there stops the
   truncation and the walk reaches the next instruction.
2. The SSA builder then refuses: the transfer is no longer the block's last
   instruction. Ending the block at the predicated instruction answers that.
3. `disasm.rs::genuine_block_successors` then names no successor while the
   advisory graph names the fall-through, and the two are compared and
   refused. It already carries the concept -- `control_op_is_intra_instruction`
   says an AArch64 `ccmp` skip to the next instruction "decides no successor"
   -- but a predicated *transfer* needs the opposite answer from the same
   shape, and making it say so did not take, so a fourth derivation is
   involved.

Three places derive "where does this block go" and a fourth refuses when they
disagree. The fact that wants stating once, by the lift that knows it, is
**this instruction conditionally leaves the function**; every consumer should
read that rather than re-deriving it from the operation order. A variant on
`BlockTerminator` alone is not enough, which is why the attempt that added one
did not land. The enum has 135 consumers across thirteen files, many with
catch-all arms, so the variant must arrive with the single owner of the fact,
not before it.

The old framing of the same wall follows.

**24 of the 30 remaining ARM refusals are `observation journal:
RenderedValueRequired`** -- one class, the same one three causes of were fixed
for on x86 ("Claim a value cell where the rendering absorbed it"). The
smallest repro is `arm-init` `__atexit_handler_wrapper` at `0x2f4`, three
instructions: `cmp r0,0; bxeq lr; bx r0`. The seal demands `ValueId(0)`,
disposition `Inline { term: TermId(0) }`, and the other unaccounted values are
the flag computation (`IntEqual` into `tmpZR`) and the entry values. So on a
predicated path the condition's own flag values, which the structurer folds
into the `if`, have no cell. Fixing it where the cell should be allocated --
not at the seal -- is the next piece, and it is worth roughly four fifths of
ARM's remaining refusals.

## The wire is not dead, and the deletion waits on the plugin

`snapshot_wire.c`, `snapshot_walk.c` and `crates/r2source/src/snapshot_wire.rs`
were proposed for deletion as the native route's leftovers. They are not
leftovers: `r_anal_sleigh.c` and `snapshot_capture.c` write that wire and
`r2plugin/src/ffi_v2.rs` decodes it, so `pd:s` runs through it -- and so does
the plugin column of `scripts/diff_capture.py`, which is the only instrument
that grades a capture against a known-good one. The wire becomes deletable
when the plugin path does, and not before.


## ARM predication, resolved: one owner, and the majority case was never an exit

The six-attempt chain above ended by asking the wrong question. A predicated
instruction was being treated as a block that conditionally *leaves*, and the
cost of saying so honestly kept rising: a new terminator, a predicate fact with
no second target, a statement shape the renderer had never minted, and an
obligation with no owner. Each layer that had to be taught about it is the
project's own signal that the work sat in the wrong place.

Counting settled it. In `libarm.so` -- 31,415 instructions, 1,000 functions --
there are 997 predicated transfers, and **991 of them are `b<cond> label`**.
Those are ordinary two-target conditional branches: both arms are real block
addresses, and the existing `if`/`else` machinery renders them with nothing new
at all. Only 6 are `bx<cond>` or `pop<cond> {pc}`, the shape that genuinely
leaves. 255 of the 1,000 functions contain a predicated branch, so this is a
quarter of the binary, not an edge case.

That also retired the alternative. Sub-instruction block identity --
`(address, p-code offset)`, which is Ghidra's model and would need no new
terminator -- was costed at 88 files and roughly 2,270 line hits, with four
explicit duplicate-address refusals and the fingerprint schema in the way. It
is the right model in the abstract and the wrong one to buy for 6 instructions
in 31,415.

What landed:

- **One owner for the fact.** `r2il::predicated_transfer` returns *which*
  transfer a skip guards, and `r2il::guarded_transfer` the same for a slice.
  An earlier boolean version of this was wrong: it reported only *that* a
  transfer was guarded, so `beq label` -- which lifts to the same skip-plus-
  transfer shape -- became an unconditional fall-through, silently losing the
  branch target. Reporting the operation is what keeps the two cases apart.
- `analyze_terminator` reads that owner before its reverse scan, which sees
  only the last control operation. A guarded `Branch` becomes
  `ConditionalBranch { true_target: next, false_target: label }`; a guarded
  `Return` or `BranchInd` becomes the new `BlockTerminator::ConditionalExit`.
  A guarded *call* is deliberately not included: both its arms reach the next
  instruction, so its predicate guards an effect, not an edge, and nothing
  renders that guard yet -- it keeps the old refusal.
- Both of `disasm.rs`'s successor derivations read the same owner, so the
  machine graph, the reachability walk and the terminator cannot disagree.
- **`r2ssa::branch_condition`** is now the single answer to "which branch does
  this block turn on", replacing a copy in `r2dec`'s `fold/flags.rs`. It
  accepts a unique `CBranch` that either ends the block or guards its tail.
  The old rule required the branch to be the block's *last* operation, which a
  predicated one never is -- that alone blocked the 991-instruction majority.
- `collect_predicate_facts` reads it too, so a predicated `b<cond>` gets the
  predicate fact its rendering needs.
- The guarded tail of a `ConditionalExit` block is rendered by the structurer
  as `if (!cond) { <transfer> }`, splitting the block's folded statements at
  the guard. The condition comes from the branch's own operand rather than a
  predicate fact, because a fact carries the two blocks a test reaches and one
  arm of this one reaches none.
- The control certificate learned two things: a block that conditionally exits
  expects one edge, the arm that stays (leaving is not an edge, exactly as
  `Return` expects none); and control arriving at the text of the block it is
  already inside continues that occurrence whatever label it carries, rather
  than minting a duplicate.
- `exact_control_obligations` now owns the branch *and* the transfer it
  decides. It had used `rposition(is_control_flow)`, the last control
  operation, which for a predicated block is the transfer -- leaving the
  guard's own obligation unaccounted.

Measured on the native gate (`--bins <radare2>/test/bins/elf --limit 24
--functions 8 --native-only`): **rendered 83 -> 92, refused 15 -> 6**, with
undefined reads unchanged at 1. No function that rendered before refuses now. `arm-init`'s dispatcher renders its
guarded return and its tail call, and `arm1.bin`'s `save_for_backup` -- 257
obligations, 0 refused -- renders its `beq` as an `if`/`else` and its
`movge r4, r3` as a signed `min` ternary, both checked by eye against the
disassembly.

One harness defect was found and fixed on the way: `scripts/diff_capture.py`
read `goto L2;` as a declaration of `L2`, because a word followed by a name and
a semicolon is the shape it matches, and then reported the label as a read of
something nothing assigns. It only surfaced when a function containing a `goto`
newly rendered.

### What ARM is behind now

With predication no longer the gate, the dominant refusal on the predicated
population is `missing machine projection authorization`, which is
`MachineUseRefusal::UnsupportedOperation` reaching the journal as
`RefusedRenderedUse`. On `libarm.so` it is 16 of a 40-function sample, up from
2 at baseline -- the rise is the predication fix letting those functions get
far enough to hit it. `machine.rs::lower_op`'s final `_ =>` arm is where an
operation the machine model does not lower turns into that refusal; the next
step is to name which operations land there on ARM.

## The gate is green, and the tiers are becoming readable

The native certification gate (`scripts/diff_capture.py --bins
<radare2>/test/bins/elf --limit 24 --functions 8 --native-only`) went from
**83 rendered / 15 refused** to **98 / 0** across one session. The undefined
read stayed at one throughout: `main` in `abcde-qt32` reads `R3_3`, which is a
separate and older thread.

Four things moved it.

**ARM predication, from one owner.** `r2il::predicated_transfer` reports *which*
transfer a skip guards, so `b<cond>` becomes a `ConditionalBranch` and
`bx<cond>` the new `BlockTerminator::ConditionalExit`. An earlier boolean form
of the same predicate was wrong: it reported only *that* a transfer was
guarded, which turned `beq label` into an unconditional fall-through and lost
the branch target. `r2ssa::branch_condition` is now the single answer to "which
branch does this block turn on", replacing a copy in `r2dec`'s `fold/flags.rs`
whose rule -- that the branch must be the block's *last* operation -- a
predicated branch never satisfies. That alone had blocked the majority case:
in `libarm.so`, 991 of 997 predicated transfers are `b<cond> label`.

**A load nothing reads still reads.** `frame_dummy` loads `r0` and `r1` at
0x8200 and overwrites `r0` at 0x820c on every path, the linker having elided
the call that used them. The decision taken was to render the load for its
effect, and the blocker was that the binding plan, its seal and the observation
journal each treated *the value is elided* as *the instruction owes no
statement*. `ElisionReason::UnreadEffectfulValue` separates them; the read now
renders as `(void)*(uint32_t*)0x8238;`.

**A branch that leaves a return address is a call.** `flush_cleanup` is ARM's
pre-`blx` idiom: `mvn r3, 0xf000; mov lr, pc; sub pc, r3, 0x3f`, a call to the
kernel helper page at `0xFFFF0FC0`. Sleigh lifts it as a branch because that is
the opcode; the link register holding the address after the transfer is what
makes it a call. `r2il::returns_to` states that once, and the body walk, the
block's declared successors and `lift_owned_function` all read it. The link
register itself comes from the compiler specification's `<returnaddress>`,
never from the shape: `body::Program` gained `return_address_register`, and
`r2s` resolves the name against the architecture's register table.

**The analysis tier is printable.** `pdim` renders `r2engine::native::prepared`,
which is `decompile` stopped before the rendering. One command now answers what
previously needed an `lldb` breakpoint inside `fold_block_with_sites`: whether a
block holds the operations a defect is about. `dump_blocks` was also printing
operations through the derived `Debug` while printing its own phis through
`Display`; it uses `SSAOp`'s `Display` now.

### All three tiers are printable now

`pdil` prints the operations Sleigh produced per block, with the
architecture's register names; `pdim` the SSA; `pdih` the structured tree the C
is generated from, with its statements spelled by the emitter that writes the
C. Invariant eight asked for this and nothing implemented it.

Two corrections to an earlier reading of the tree. There are **not** three
rival IL printers to delete: `r2sleigh-lift`'s `format_varnode` and `format_op`
generate *ESIL text* for radare2, and the plugin's `format_r2il_op_short`
writes short labels inside ASCII CFG boxes. Different consumers, different
jobs, and deleting any of them would remove working function. The one real
duplication was `dump_blocks` printing operations through the derived `Debug`
while printing its own phis through `Display`, which is fixed.

`pdil` spells registers by rewriting `Varnode`'s own Display output against the
architecture's table, rather than by threading a resolver through the
two-hundred-line operation printer or by giving every varnode a name it would
allocate for. A varnode visitor would be the general answer and has exactly one
consumer today, so it has not earned itself yet.

What the tiers still owe: `pdim` prints the SSA but not each value's
binding-plan disposition, which is the half that names an elision reason and
the half that would have answered the dead-load defect directly. `pdih` loses
its structured-region markers, because sealing strips them before the tree is
emission-ready, so block attribution has to come from `pdim`.

The tier tests are targeted assertions in `crates/r2engine/tests/native.rs`
rather than `insta` snapshots. Full snapshots were planned; they are the wrong
instrument immediately before a pass that will churn every tier's output, and
the r2r suite cannot reach the native route at all, which is why the tests live
there and not in `tests/r2r/`.

### Two CI breaks, one of them six days old

`cargo test --workspace --all-features` had not compiled since 14 September:
`r2plugin`'s tests build `r2ssa::SSABlock` literals and the `phis` field was
added without them. A second, from this session, was the same shape on
`r2image::Symbol`'s `thumb` field. Both are fixed. The lesson is that a
per-crate test run without `--features sleigh` clears neither.

`plain_o2_check_secret` and `plain_o2_sum_array` still fail at SSA hash
`9a9df9f6a934275a`, unchanged by any of the above.
