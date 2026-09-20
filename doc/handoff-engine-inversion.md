# Handoff: the engine inversion

> Open threads on the track that makes the engine own its facts. The
> decompiler-quality thread has its own handoff in
> `doc/handoff-location-ssa.md`; this one does not touch it.
> `doc/engine-vision.md` holds the design and the order.

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

Sequencing items one to four of `doc/engine-vision.md` are done. `main` in an
ELF hello world renders its string literals as text, names its imports, and
calls them with the arguments their declared prototypes state:

```c
stack_m32 = (uint64_t)"Hello";
uint32_t RAX_4 = strlen(tmp_11f80_1);
uint64_t RAX_11 = malloc((uint64_t)(int32_t)(tmp_11f00_2 + stack_m40 + 1));
strcpy(tmp_11f80_3, tmp_11f80_1);
```

Against radare2 over its ELF corpus, `pd` agreement went from six of thirty to
thirteen of the twenty-four `r2s` opens.

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
undefined reads 3` to `rendered 95 / refused 3 / undefined reads 4` across:

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
