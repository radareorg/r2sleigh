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

Sequencing items one to three of `doc/engine-vision.md` are done. Item four, the
name database, is next.

## What the route does not do yet

**Stack arguments have no placement.** `SourceConventionSlots` is built with
`with_stack_arguments(None)`, so a function with more arguments than the
convention has registers refuses rather than reading them off the frame. The
placement is arithmetic over the shadow space and the return-address slot;
radare2 spells it `r_anal_cc_argslot`, and it needs a register profile as well
as the `cc` data because the word size is refined by the first register argloc.

**Callees are walked one level deep.** Deeper is what an interprocedural
fixpoint is for. A callee that fails to walk leaves its call unproven.

**Nothing reads the data section.** String literals, named globals and code
pointer tables are all captured empty, so a constant that points at text renders
as the constant. This is the same gap the decompiler-quality thread has, and it
closes for both at once.

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

## Peeling: what is now dead

Nothing has been deleted yet, by design — the plugin still needs the bridge
until `r2s` answers what the plugin path answers. The native route already makes
`snapshot_wire.c`, `snapshot_walk.c` and `crates/r2source/src/snapshot_wire.rs`
unnecessary for anything but the plugin, which is roughly 5,345 lines waiting on
the proof step.
