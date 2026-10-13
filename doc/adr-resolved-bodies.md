# ADR: One resolved body per function (P6)

Status: accepted, done (P6a, P6c1, P6c2).

## Context

A root function is walked, read for dispatch tables, walked again through
them, prepared, restated and prepared again. A callee gets none of that:
`prepare_callee` walks it once with no arms and prepares it against its
imports alone. So a callee's switch arms are never seen, a callee knows
nothing of its own callees, and a parameter a body hands to another body is
never followed (Q3e found the forwarding path unreachable). Two
preparations exist for one function, and which one a function gets depends
on who asked.

## Decision

One function has one resolution, whoever asks: walk through its dispatch
tables (`Walked`), prepare, restate, prepare again (`Native::resolve`). A
root resolves against its callees' answers; a callee resolves against its
imports, and against the callees that own its result (below).

### Demand: results only

Measured 2026-10-06: one callee resolved against its imports costs about
10.5 ms; pumasim `main` reaches 1949 functions (2.5 s to walk them, 21 s to
resolve them), 0pack `main` 1287 (13 s). Demand for parameters prunes
nothing: an argument a body hands on is invisible until the callee's
interface exists, and an unread slot sits beside almost every call. So
demand is for results only:

- r2ssa's interface recovery states `result_owners`: where the result is
  unproven, the direct callees whose unstated result owns it (a tail target
  no prototype describes, or a call whose result reaches an exit).
- `Resolved(f)` is `f` resolved alone where it has no owner; otherwise it is
  `f` resolved again with each owner outside `f`'s demand cycle resolved,
  and only where some owner then states its result.
- `Demand(f)` is the cycle of result demands `f` is in, by Tarjan over the
  owners; members of one cycle read each other resolved alone.
- A callee whose interface mints no call contract, its result unproven or
  its parameters a floor, is stated instead (`CalleeStatement`): a call to it
  reads the registers the caller provably wrote, at least as many as the
  callee's own body proves it reads, and takes the result the body proves.

Parameters a body proves alone are a floor wherever an argument register
reaches a call of unproven arity untouched or unseen: recovery, with no
interface yet, counts any untouched slot as one it may hand on. A caller then
passes what it wrote; past the floor, a slot the count cannot see (a merge)
refuses the call where the caller writes that register on some path, and
ends the count where only arrivals and call clobbers merge there. Before,
recovery stopped silently at the untouched slot and minted an exact
zero-argument contract: gcc -O2 hashes `main` called `combined()` without the
buffer it reads, and crashed. A caller that hands its own untouched slot on to
a floor callee is still counted as ending there; closing that costs C++
methods their calls and waits on prototypes for mangled imports (LP).

The first preparation recovers the interface; a restated one is handed it,
so the owners are taken from the first.

Known refusals this brings to the 300-function samples (pumasim refusals
27 -> 27, 0pack 36 -> 37): one observation-journal `ConflictingValue` on a
merge carrier in 0pack, which R deletes the journal for.

### Caller reads

A body that writes both convention result registers on a path to a return
(RAX and XMM0 on x86-64: vectorized integer code, or a double function whose
loop test leaves RAX written) does not say which is its result. r2ssa's
recovery makes it unproven and says why (`result_ambiguous`), where it
returned RAX before and miscompiled `avg`.

Each call decides it for itself. The callee's interface keeps its exact
parameters and names the two registers (`result_carriers`); r2ssa reads the
caller's own lifted code after the call (`caller_reads::reads_after_call`):
the first touch of each result register up to the next transfer is a read
(the caller takes what the call left there), a write, or nothing. One register
read decides the call's result, a float at the read's width; r2types types it
there (`call_result_type`). Both or neither leave the call without a contract.
The cost is one scan of the call's block, O(ops after the call).

After `aa`, the function's own rendering asks every call in the program: the
walked bodies whose trace calls it (`Survey`, inverted once, O(call edges)),
each lifted without preparation. Every reading call agreeing on one register
decides it; none, or calls that disagree, leave it unproven. Only the
rendered root is prepared again with that evidence (`SourceResultReads`); a
callee read for its caller never asks.

Reading callers surveys the whole program, so a fresh open reads the body
alone and its open result stays a residual. On pumasim, `pdd @ 0x4baf30`
takes 4.6 s alone and 10.3 s with the survey (contabo, 2026-10-13). `aa`
surveys once and sets `Callers::Read`, which every analysis, sealing and
rendering key carries, so a session's answers never depend on which command
first ran the survey. Census, certification, the coverage sweep and
equivalence run `aa` first.

The evidence is as strong as the body's own writes: a compiler reads a
clobbered register after a call only as the callee's result. A caller that
hands the value straight back without reading it (`return f();`) is no
evidence. A void function whose callers read nothing stays unproven, except
in a closed world, below.

### Closed world

An unproven result that every call writes before reading, in each result
register, is read by no call the image shows. It is void only if those calls
are every way into the function: the void rests on `Premise::ClosedWorld`,
which r2engine grants only under `aa` and r2dec spells on the proof line
("no call reads the result (assuming closed-world)"). A proven result is
never made void this way: a helper whose callers ignore its value keeps it.

A call overwrites a result register when its writes cover every byte of it
before any byte is read: `xor eax, eax` lifts to a 4-byte write and a
zero-extension that covers RAX. The float register must be overwritten only
where the body writes it.

`SourceResultReads.exhaustive` states that the calls read are every way in.
r2engine sets it where all of these hold:

1. Every caller the survey found was walked and lifted, and the reference
   index claims exactly as many calls to the function as were read.
2. No reference other than a call names the entry: no jump from another
   function (a tail call), no computed address (`lea`, `adrp`+`add`, a
   loader write). A jump to a function's own entry is a loop.
3. The container states no other entry there: no entry point, initialiser
   or finaliser, and no export (ELF's dynamic table, any non-local Mach-O
   symbol).
4. No mapped file word names it (`Escapes`): every pointer-wide window, and
   on a 64-bit machine every 32-bit one (`imm32`, `.long`), with bit 0
   cleared. This catches a non-PIE vtable or function table, which holds
   absolute words with no relocation and no code reference.
5. The index read every body, and every code byte the file holds is in a
   walked body, a linkage section, or filler: zeros, instructions that lift
   to no operation, traps, or direct transfers to code discovery knows (the
   `bl abort` after a call that never returns). Code no walk decoded, past an
   unresolved transfer or never reached, may call or name anything, so any
   other byte refuses, named on the refusal. The sections the container
   states as code are read, else its executable segments: AArch64's R-X
   segment also holds the headers, `.rodata` and `.eh_frame`. This replaced
   refusing on any unresolved transfer, which crt's `br x16` tail calls
   through the GOT made true of every program (2026-10-13).
6. The machine is x86-64 or AArch64, whose addresses an index claim or a
   word holds whole. `movw`/`movt` and `lui`+`addi` split one across
   immediates and hide it from both. The format is ELF or Mach-O, and the
   function's language C, C++ or Rust: Swift, Objective-C, Go and .NET reach
   functions through tables of relative offsets.

AArch64's large code model builds an address with `movz`/`movk`, which item
6 does not catch. No compiler in the corpus emits it.
x86 `int3` lifts to a software interrupt, an indirect call and a return, so
lld's `int3` padding between functions refuses the closed world; GNU ld pads
with no-operation instructions. Code in a gap is read instruction by
instruction, so an `adrp`+`add` there that names a function is missed, the
large-code-model limit of item 6 in unreachable code.

Cost: `Escapes` is computed once per program under `aa`: one pass over the
references, symbols and entries, and one over the mapped file bytes, with a
range check per word and a search per word in range: O(R + S + B log F).

Two shapes stay residual, measured at #215: a call whose next instruction is
another call (`call crc32_init; call fnv1a32`), where the block-local read
stops at the transfer, and a later call to a stripped local function, which
has no stated interface. Deciding them needs the caller's liveness past later
calls and their callees' entry reads.

### Budget

Resolution follows result demands only, so a request resolves what its
unproven results need; the 300-function samples cost 8% more (pumasim 9.1
to 9.9 s). A stopped owner stops the answer (`Hold::Stopped`); every held
answer is a function of the program alone.

## Complexity

Walks: one per function asked, held. Resolutions: one per callee asked,
plus one per function whose result an owner then proves. Demand cycles:
Tarjan, O(V + E) over result demands only, each component deposited once.

## Steps

- P6a: `Walked` is a query and the root analysis reads it.
- P6b: `Component` and the closure measured on 0pack and pumasim.
- P6c1: a callee runs the root's resolution, on its `Walked`, against its imports.
- P6c2: `result_owners`, `Demand` and `Resolved`; an unproven callee states how many arguments it reads.
- P6d, declined: `read_callees` is the one loop a root reads its callees through. The database
  answers it with `Resolved`; a plain `Program` (tests/native.rs, the model integration test)
  with each callee resolved alone, through the same `resolved_alone`.
