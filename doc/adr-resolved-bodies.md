# ADR: One resolved body per function (P6)

Status: accepted, done (P6a, P6c1, P6c2, SM2); Summaries in progress.

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

- r2ssa's interface recovery states why a result is unproven
  (`SourceUnprovenResult`): the direct callees whose unstated result owns it
  (a tail target no prototype describes, or a call whose result reaches an
  exit) are its owners where every cause is a call.
- `Resolved(f)` is `f` resolved alone where it has no owner; otherwise it is
  `f` resolved again with each owner outside `f`'s demand cycle resolved,
  and only where some owner then states its result.
- `Demand(f)` is the cycle of result demands `f` is in, by Tarjan over the
  owners; members of one cycle read each other as the cycle's fixpoint states
  them ("A cycle's results").
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

### Arity (ROADMAP P7)

A function's arity is `Exact(n)` or `AtLeast(n)` (`r2source::SourceArity`),
stated apart from its result: a callee whose result is unproven keeps an exact
arity, and a call to it hands on exactly its `n` arguments. Recovery states a
floor where its reads cannot see every argument, and why, as typed causes
(`SourceArityFloor`, doc/adr-verified-layers.md D37): a transfer the walk did
not follow, a supervisor call, the argument area read past an incomplete
register prefix, a register slot read past it, or an argument slot handed to a
call of unproven arity.

The last cause alone is one the callee's statement can lift: r2engine reads
the callees of those calls as the floor's arity owners (none where any cause
is another, or a call names no callee). Under `aa` (`Callers::Read`), `Resolved` waits on arity owners as
on result owners: `Component` is Tarjan over both edges, bottom-up, and a
function is resolved again where an owner outside its component states an
exact arity. Without `aa`, a
request demands results only, as above, and pays no closure (D23): measured on
0pack `0x62ecf0`, demanding arity on a cold `pdd` took 20.0 to 36.5 G
instructions, pumasim `0x23fdf0` 18.1 to 21.2 G.

**A cycle's arities.** Inside a component, an owner is a member, and a
member resolved alone leaves the slot a recursive call may be handed a floor
(review.c's `fact`, `AtLeast(1)`, made `main`'s `fact(5)` a counted residual).
Arity is the set of slots whose incoming value may be read, and any read
happens at a finite recursion depth, so the least fixpoint over the members is
exact; the floor was a needless greatest-fixpoint answer. `Resolved`, under
`aa`, answers a member whose floor a member owns (an open member) by a
worklist over the component (`least_fixpoint`):

1. each open member is assumed `Exact` at the count it reads alone; every
   other member an open one calls is stated as `Resolved` answers it, exact or
   a floor;
2. an open member is resolved against its outside owners, as above, and the
   members it calls as assumed;
3. where its read rises above its assumption (a count, then a floor, then no
   interface), the assumption rises and every open member calling it is
   resolved again. An assumption only rises, its count bounded by the slots
   its body can read, so the work is O(k + (s + 2)·E) preparations for k open
   members, s slots and E calls between them.

A member's assumption states its interface alone, its result stripped or
seeded (`SourceFunctionInterface::assumed`), and nothing it preserves or
reaches, so arity moves, and a result only where "A cycle's results" tracks it. A
floor with a non-member cause (an indirect call of unstated arity, an unseen
transfer, a supervisor call, the argument area) survives the member's own
read, and its callers through it stay floors. A read that falls below its
assumption would mean recovery is not monotone in its callees' arities; the
whole component then keeps the floors it had, under refusal evidence
`arity-fixpoint` (none seen over every function of review.c and shapes.c at
six builds, nor on the 0pack, pumasim and gzdoom functions below). The
other open members' answers are deposited, as `Component` deposits its
components. Measured on release `aa; pdd`, with one more walk per open member
at its first resolution (gone since D37: a floor's causes name the members an
open one calls): 0pack `0x62ecf0` 61.89 to 62.44 G instructions,
`0x58e3d0` 74.33 to 74.27 G, pumasim `0x23fdf0` 60.17 to 60.12 G, gzdoom
`0x10070695c` 191.31 to 191.16 G, peak RSS within 4%; no budget is needed.

A recursive root reads itself as its callers do: under `aa` its own entry is
one of the callees it reads `Resolved`, so its recursive call takes the
arity the fixpoint states rather than a count off the registers it wrote
(gcc -O1's `fact` hoists `mov eax, 1` above its compare, and a call handed
`al` is refused that count). It costs one `Resolved(entry)` per
self-recursive root, which any caller's render pays anyway; without `aa` the
root reads only its other callees, as before.

**A cycle's results.** Inside a component a result is the same fixpoint, over
return values instead of argument counts, and it runs in the same worklist
(`least_fixpoint`) on every request's result demand, not only under `aa`.
Recovery states why a result is unproven as typed causes
(`SourceUnprovenResult`, doc/adr-verified-layers.md D37), and a member is
result-open where every cause is a call to a named callee and one is a member.
The lattice is the integer result of one carrier: a width of 8, 16, 32 or 64
bits, then unstated.

1. each result-open member is seeded at the carrier the convention names, at
   the width the paths that return a value of their own write, the calls that
   define the carrier set aside (`seed_result`): no such path, no seed, and the
   member starts unstated;
2. an open member is resolved against the members it calls as assumed
   (`SourceFunctionInterface::assumed`, the seed as a return with its logical
   type), and what its own read states of the result joins the assumption: the
   wider width of one carrier, signed only where both are, else unstated;
3. a member's read is its answer where it states exactly what was assumed of
   it; otherwise no member of the component is, and each keeps the result it
   had under refusal evidence `cycle-fixpoint`.

A seed is where the iteration starts and it only rises: the result is
proven where the paths of its own prove it and every call on a path hands back
the same carrier. A member with no path of its own, one that returns what the
caller left in the carrier, or one returning an indirect call's result is
unseeded or unowned and stays a residual with its partner. Without `aa` the
result is stated all the same; a call to a partner whose arity is a floor
renders as a gap until `aa` resolves the arities.

The width of a call-defined value is still the carrier's, not the callee's
stated width (`recovered_result` reads a `CallDefine` as all data), so a pair
over `int` is `uint64_t` as `int f() { return g(); }` is; a callee's width
on the call fact would narrow both.

### Variadic tail (ROADMAP P7, W14)

A `va_start` prologue saves every argument register past the named ones to
the convention's register save area, and recovery read those saves as
parameter reads: shapes.c's `vfold(unsigned, ...)` was `Exact(6)` on x86-64
and `Exact(8)` on AArch64, and its callers passed slots they never wrote.

**The fact.** A body is variadic with `named` fixed parameters where, in
entry-stack-pointer coordinates and for one area base `A` and slot width `w`:

1. each argument slot `i` from `named` to the last has its entry value stored
   at `A + w·i`, and slot `named - 1` has not, with `named ≥ 1`;
2. nothing else reads those saved values, through merges and copies; a use
   nothing observes (`xor ecx, ecx`) or a call's implicit use reads nothing;
3. `va_start`'s write is there: the bound of the area the convention names
   is stored at some stack position `P`, as a `va_list` holds it, and a
   constant store covers the `va_list`'s offset field at `P + d`, holding
   the first unnamed slot's distance from that bound, `A + w·named - bound`,
   at the field's width. System V AMD64 holds `reg_save_area` (`A`) with
   `gp_offset` at `d = -16` (psABI 3.5.7, Figures 3.33 and 3.34), AAPCS64
   `__gr_top` (`A + w·N`) with `__gr_offs` at `d = +16` ("Variable argument
   lists"); r2abi's cited rows state both, carried by `SourceConventionSlots`.
   clang writes the field with its `fp_offset`/`__vr_offs` neighbour as one
   little-endian word, so a wider store covering the field counts.

Rule 3 separates an O0 body spilling its own six parameters, whose spill
address no `va_list` holds, and a struct of arguments `named..N` whose
address is stored (`struct s = {0, b, ..., g, &s}`), which no `va_start`
wrote an offset field beside; rule 1's named slot separates an aggregate of
every parameter whose address is stored (`struct six s = {a, ..., f}; p =
&s;`), which C before C23 cannot be variadic with; rule 2's other reads
refuse the area, as does a tail slot the recovered reads still show (a
call that takes it). The vector block behind `test al, al` and the
`fp_offset`/`__vr_offs` constant are not required: gcc -O1 and -O2 omit
the block and the `fp_offset` store when no `va_arg` reads a float.

**Owner.** r2ssa (`save_area::register_save_area`, read by interface
recovery); r2abi states the anchor and the offset field; the interface carries it on the one
variadic bit a declaration's `...` sets (`with_variadic_tail`), with the
fixed prefix `Exact(named)`: a slot below the area the body never reads is
a parameter at its slot's width, since the area starts at the first unnamed
slot. The argument area past the registers and a tail register reaching a
call of unproven arity are the tail's, not a floor. r2dec spells `, ...`.

**Callers.** A call mints the existing variadic contract: a format literal
counts its tail, else the call is the counted residual
`VariadicCount(missing_format_parameter)`. A callee whose result is
unproven is a statement, and a statement counts no tail, so it states a
variadic callee `AtLeast(named)`. The body's reads of its tail registers
and of the vector count (`al`) are named "variadic tail registers" on the
proof line.

**The `al` input.** A summary resolves alone, where a local callee is
unread, so a call to `vfold` was counted from the registers written
(gcc -O0's dead `rdx = 0` among them) and proved `shape_variadic_local`
`Exact(2)`, while its root, reading `vfold`'s summary, is a floor of 0:
certification graded `main` calling it with 2, "defined with 0". System V
hands a call to a variadic or unprototyped function its vector count in
`al` (psABI 3.5.7; r2abi's row, on `SourceConventionSlots`), so a register
count is refused (`CountRegisterSet`) where the body sets that register for
the call alone: a constant at most 8 only the call reads, found from the
call's own `CallUse`, O(reads). The call keeps no argument past its callee's
floor, and both grades agree. gcc's stack protector clears its guard from
`eax` with the same `xor eax, eax`, often just before the first call
(pumasim `0x21fb90`, `0x23da20`, `0x23fdf0`): a zero over a compiler-inserted
guard read is the protector's, not a count (one reaching search, only where
the register is set). Where gcc merges the two the call stays counted, as
before. A K&R call to an unprototyped function sets `al` too, so its summary
is a floor until `aa` resolves it against the callee.

**Cost.** One pass over the body's stores and the uses of the saved values,
O(insts + uses), inside recovery's existing pass; per convention boundary,
O(the call's reads). Release `pdd`, instructions before and after:
0pack `0x62ecf0` 19.80 to 19.56 G (`aa; pdd` 62.08 to 61.88 G), 0pack
`0x58e3d0` 23.25 to 23.06 G (74.51 to 74.30 G, output identical), pumasim
`0x23fdf0` 18.32 to 18.16 G (60.36 to 60.17 G). Finding the call's reads by
searching its block first cost 0pack `0x62ecf0` 1.4 G.

**Measured (2026-10-15).** shapes.c, gcc and clang at -O0, -O1, -O2 on
x86-64 and AArch64, stripped, `aa; pdd`: `vfold` renders
`(uint32_t arg0, ...)` on all 12 builds (6 or 8 parameters before), and the
four calls to it in each `shape_variadic_local` are counted residuals where
they passed up to six slots the caller never wrote. `shape_variadic_local`
hands its parameters only into tails of unproven count, so its arity is a
floor of 0 and `main`'s call to it is a `Floor` gap on all 12, never the
never-assigned residuals it passed. Certification over the 12 builds:
invented arguments 1 to 0 (aarch64 gcc -O2's `shape_variadic_local` passed
9 to the 8-ary `vfold`), graded calls 5 fewer per build (the calls now refused); on the
census binaries invented stays 0 and the census moves only
`shapes_gcc_x64_O0`'s three. 0pack `0x62ecf0` renders 10 calls to
`el::base::Writer::construct(int, const char*, ...)` as counted residuals
where they passed three never-assigned ones; pumasim `0x23fdf0` loses its 85
never-assigned residuals (97 under `aa`), invented arguments of callees such
as `QColor::setRgb(int, int, int)`, which handed its unwritten slots to
`qWarning(const char*, ...)` and was 6-ary. Equivalence on shapes.c (both
targets, 23 records moved, each with its cause): five records leave equal
for residual-trap, `shape_variadic_local` on x86-64 clang -O0 and AArch64
clang -O0/-O1/-O2 and x86-64 gcc -O0's `main`, whose C passed the caller's
own unwritten registers on and so matched by accident; the W14 `main`
records stay residual-trap, now at the `Floor` gap rather than
never-assigned arguments. None closes: that needs the count-driven tail.

**What is left.**

- A count-driven tail beyond gcc -O0 on x86-64: see "Count-driven tail".
- The scrub exception rests on the stack-protector check being decided
  (`UbFreeSource`, the platform's guard row); where it is not, gcc's
  prologue `xor eax, eax` before a first call still reads as a count, and
  that call's summary is a floor. K&R calls to unprototyped functions set
  `al` too, so their summaries are floors until `aa`. Measured only on the
  census set, shapes.c and three large functions.
- A floor of 0 renders `(void)` (W11's "no invented `(void)`").
- AArch64 hands no vector count, so a summary there can still count a call
  to an unread variadic callee from registers and disagree with its root
  (AArch64 shapes agreed only because `MayHandOn` fired). Closing it without
  the closure D23 forbids needs a fact of the call site; conditional.
- A tail jump to a variadic callee whose count is unproven is spelled
  `UnsupportedInstruction` plus `TailTransferNotRendered` (pumasim
  `QColor::setRgb`'s `qWarning`), not by its refusal as M3 spells a call.
- pumasim `0x23fdf0` under `aa`: three calls to `QWidget::setMinimumSize`
  that passed three invented arguments are now "another call disagrees with
  its declaration" gaps (P7's 41, conditional).
- Named float parameters (`fp_offset`, `__vr_offs`) with W11; Microsoft
  x64's home area has no row, and Darwin arm64 passes the tail on the stack.

### Count-driven tail (ROADMAP SM, W14)

`vfold(unsigned count, ...)` fetches one slot per trip of a loop that runs while its counter is
below `count`, so `vfold(1u, a)` passes exactly one. The call stays a counted residual
(`missing_format_parameter`) until the body states that bound.

**The fact.** A variadic body with a register save area (above) consumes at most `P` tail
arguments, `P` one of its named parameters, where in entry-stack-pointer coordinates:

1. the `va_list` cells are the convention's rows (r2abi): the bound `va_start` stored at `B`, the
   offset field at `B + offset_field`, the stack pointer at `B + stack_field`;
2. every cursor is a value, wherever it lives (`tail_cursors`): the base (the bound `va_start`
   stores, or its cell's load), an offset (the offset cell's load, or the constant `va_start`
   leaves in it where a merge takes it beside a step of its own value), the overflow pointer (the
   first stack argument's address, or its cell's load), an address in the tail (the base and an
   offset, or either path of a merge of them), or the overflow pointer plus the rounding
   AAPCS64's alignment adds before its mask. Kinds close under copies, widenings of an offset,
   merges (of values something observes) and steps of one slot; where the bound is the first
   stack argument's address (gcc's `__gr_top` is), a value is both until its uses say which.
   Every other use refuses: no address into the tail is passed, stored or indexed otherwise, no
   load reads a tail slot at a constant address, no store reaches a cell but `va_start`'s and a
   cursor's own. A sum of an offset that is only compared (`cmn` beside the `add`) is no step. A
   call's implicit read of a cursor left in an argument register is no read: the registers a call
   reads are the convention's, not the callee's, as for the entry saves above;
3. a step is an add of one slot to an offset or the overflow pointer, or the masked rounding of
   it from a pointer the convention's entry stack alignment puts on a slot; a fetch is a load
   through the overflow pointer or an address. A fetch reads a value no step of its trip made:
   such a value reaches a load only round the loop's header;
4. one loop `L` holds every step and fetch and is not inside another, and its trips are counted
   by either of
   - the header's runs, which `semantic/trips` states (doc/ssa.md, "Loop trip counts"): an
     induction at the width its exit test reads (a counter kept in a 64-bit register steps and is
     tested at 32), an equality exit with an odd step, every latch alike where each latch leaves
     the loop from its own test, and a guard that excludes the zero count. The form is one
     named parameter's entry value at its width, so the header runs `count` times; the induction
     may be the count itself counted down. The value ranges are the empty ones, so only equality
     exits count symbolically (an ordered exit needs constant ends);
   - or a counter cell the body zeroes once and steps by one, which `L`'s only exit, leaving from
     its header `H`, tests `counter < count` (or `!=`) against the count cell, stored once from
     the entry value of a named argument register before `L` (the version that proved gcc -O0);
5. a tally of steps and fetches is recorded at each block on its first arrival and equal on every
   later one: from the header, a path steps at most once and fetches at most once, and at each
   edge back to it has done both or neither (the counter cell's version balances them against its
   own step); a cell's load whose value reaches a fetch or a step comes before the trip's step;
6. where the offset field counts up to zero (AAPCS64's `__gr_offs`, which `va_start` sets to
   `-8 * unnamed registers`) every step of it runs where the value stepped is negative by the
   branches dominating it alone, so the cursor stays at most zero and a multiple of a slot, and a
   branch on it that no value takes one way carries no tally. Without this the register path's
   second step (`__gr_offs + 8 > 0`, then the stack) is a second step on a trip. A condition over
   the one cursor is decided as the set of 32-bit values it holds for (`tail_offsets`): the
   comparisons with a constant, the flags `cmp` and `cmn` set (the carry too, which `b.ls` reads),
   the sign bit `tbz` tests. The sets are unions of intervals, not strided ones, because a sum that
   wraps splits one in two.

Then each header run consumes at most one slot, and the header runs `count` times (or the counter
never passes `count`), so the loop consumes at most `count` slots, at `count`'s width, unsigned,
or signed for the counter cell's ordered test (a negative count runs no trip). The proof does not
read which of the two paths a trip takes: the psABI's selection (registers first, then the stack)
is assumed of the body, as every compiler emits it. `SourceTailCount` carries
`(parameter, width, signed)` on `SourceFunctionInterface`, minted beside the variadic bit.

Rule 4 refuses a loop that tests at its latch unless a guard before it excludes the zero count (a
do-while runs once at count 0), a loop one of whose latches never tests, latches that test
different bounds or step the counter differently, and a loop entered again. Rule 3 refuses
`for (...) { va_arg; va_arg; }` (two slots a trip), an unrolled loop (clang -O2 steps twice a
trip and finishes outside the loop), a conditional `va_arg`, and a fetch through the stepped
pointer (trip `i` reads slot `i + 1`, the `ap + 8` peek). Rule 2 refuses a `va_list` handed to
`vprintf` and a double fetched through `fp_offset`. A frame address into the cells, or arithmetic
past an object into them, is out of bounds in C and not read.

**Owner.** r2ssa (`tail_count`, `tail_cursors`, `tail_offsets`, run inside interface recovery on
the preparation's graph; the header's run count is `semantic::trips`', asked through
`header_trips`), r2abi the `stack_field` row (psABI Figure 3.34, AAPCS64's `va_list`) and the
entry stack alignment row. The callee's interface rides the call site's
`exact_callee_interface`, so no second rule is minted.

**Callers.** A call whose callee states a count, with no format rule, passes the constant it holds
for that parameter (`resolve_const_value`), masked to the counted width, as the tail: `named + count`
arguments. A count no constant fixes is `CountArgumentNotConstant`, a count the call does not carry
`CountArgumentUnavailable`, and a tail past 1,024 `ArgumentCountOverflow`; each is the counted
residual, and `VariadicCallsiteArgumentCountEvidence` names its basis (`Format` or `Count`).
Carriers are placed as for a format count, so the tail past the registers is the stack's.

**Cost.** Only a body with a save area runs it: O(insts + uses) scans (each value is tagged once, a
merge of the overflow pointer with an address once more), a dominator query per store, one
predicate collection, one header trip count per candidate loop (O(latches)), and on AArch64 one
interval set per branch on the offset (O(predicates x dominators)); the callsite is O(1). Release
`pdd` instructions, base and head, two runs each: 0pack `0x62ecf0` 20.30 and 20.30 G to 20.30 and
20.31 G, pumasim `0x23fdf0` 19.23 and 19.24 G to 19.19 and 19.19 G, output byte-identical, peak
RSS 226 and 236 MB to 233 and 226 MB (pumasim 233 and 237 to 250 and 240); under `aa` 0pack
74.13 and 74.12 G to 74.11 and 74.06 G, pumasim 82.00 and 82.26 G to 81.98 and 82.09 G.

**Measured (2026-10-17).** shapes.c, stripped, `aa; pdd @ shape_variadic_local`, the twelve builds
(two compilers, three levels, two targets): nine prove `vfold` and render `vfold(1, a)`,
`vfold(2, a, b)`, `vfold(3, a, b, a ^ b)` and `vfold(5, a, b, a ^ b, a + b, a | b)`, against one
(x86-64 gcc -O0, #312) before: gcc -O0, -O1, -O2 and clang -O1 on x86-64, gcc -O0, -O1, -O2 and
clang -O1, -O2 on AArch64. The three that refuse give a visible reason (`R2DEC_TRACE_REFUSAL`,
site `tail-count`), `vfold` still `(uint32_t arg0, ...)` and the calls still counted residuals:
clang -O0 on both targets reaches the `va_list` through a pointer it keeps in a stack slot and
spills the offset (`a Offset cursor is stored other than to its cell`), and x86-64 clang -O2
unrolls the loop by two and finishes outside it (`no loop holds every step`). On the eight builds
#312 did not prove, `shape_variadic_local` goes from 8 gaps to 0; `main` goes from 4 to 2 on six of
them and from 2 to 0 on AArch64 gcc -O0 and -O2 (the two left are a call with an arity floor of 1).
Each acceptance rule has a test that edits a compiler's bytes to break it and refuses for that
rule's reason (`variadic_registers.rs`).

**What is left.**

- A count-driven tail beyond gcc -O0 on x86-64: see "Count-driven tail".
- The scrub exception rests on the stack-protector check being decided
  (`UbFreeSource`, the platform's guard row); where it is not, gcc's
  prologue `xor eax, eax` before a first call still reads as a count, and
  that call's summary is a floor. K&R calls to unprototyped functions set
  `al` too, so their summaries are floors until `aa`. Measured only on the
  census set, shapes.c and three large functions.
- A floor of 0 renders `(void)` (W11's "no invented `(void)`").
- AArch64 hands no vector count, so a summary there can still count a call
  to an unread variadic callee from registers and disagree with its root
  (AArch64 shapes agreed only because `MayHandOn` fired). Closing it without
  the closure D23 forbids needs a fact of the call site; conditional.
- A tail jump to a variadic callee whose count is unproven is spelled
  `UnsupportedInstruction` plus `TailTransferNotRendered` (pumasim
  `QColor::setRgb`'s `qWarning`), not by its refusal as M3 spells a call.
- pumasim `0x23fdf0` under `aa`: three calls to `QWidget::setMinimumSize`
  that passed three invented arguments are now "another call disagrees with
  its declaration" gaps (P7's 41, conditional).
- Named float parameters (`fp_offset`, `__vr_offs`) with W11; Microsoft
  x64's home area has no row, and Darwin arm64 passes the tail on the stack.

### Count-driven tail (ROADMAP SM, W14)

`vfold(unsigned count, ...)` fetches one slot per trip of a loop that runs while its counter is
below `count`, so `vfold(1u, a)` passes exactly one. The call stays a counted residual
(`missing_format_parameter`) until the body states that bound.

**The fact.** A variadic body with a register save area (above) consumes at most `P` tail
arguments, `P` one of its named parameters, where in entry-stack-pointer coordinates:

1. the `va_list` cells are the convention's rows (r2abi): the bound `va_start` stored at `B`, the
   offset field at `B + offset_field`, the stack pointer at `B + stack_field`;
2. every cursor is a value, wherever it lives (`tail_cursors`): the base (the bound `va_start`
   stores, or its cell's load), an offset (the offset cell's load, or the constant `va_start`
   leaves in it where a merge takes it beside a step of its own value), the overflow pointer (the
   first stack argument's address, or its cell's load), an address in the tail (the base and an
   offset, or either path of a merge of them), or the overflow pointer plus the rounding
   AAPCS64's alignment adds before its mask. Kinds close under copies, widenings of an offset,
   merges (of values something observes) and steps of one slot; where the bound is the first
   stack argument's address (gcc's `__gr_top` is), a value is both until its uses say which.
   Every other use refuses: no address into the tail is passed, stored or indexed otherwise, no
   load reads a tail slot at a constant address, no store reaches a cell but `va_start`'s and a
   cursor's own. A sum of an offset that is only compared (`cmn` beside the `add`) is no step. A
   call's implicit read of a cursor left in an argument register is no read: the registers a call
   reads are the convention's, not the callee's, as for the entry saves above;
3. a step is an add of one slot to an offset or the overflow pointer, or the masked rounding of
   it from a pointer the convention's entry stack alignment puts on a slot; a fetch is a load
   through the overflow pointer or an address. A fetch reads a value no step of its trip made:
   such a value reaches a load only round the loop's header;
4. one loop `L` holds every step and fetch and is not inside another, and its trips are counted
   by either of
   - the header's runs, which `semantic/trips` states (doc/ssa.md, "Loop trip counts"): an
     induction at the width its exit test reads (a counter kept in a 64-bit register steps and is
     tested at 32), an equality exit with an odd step, every latch alike where each latch leaves
     the loop from its own test, and a guard that excludes the zero count. The form is one
     named parameter's entry value at its width, so the header runs `count` times; the induction
     may be the count itself counted down. The value ranges are the empty ones, so only equality
     exits count symbolically (an ordered exit needs constant ends);
   - or a counter cell the body zeroes once and steps by one, which `L`'s only exit, leaving from
     its header `H`, tests `counter < count` (or `!=`) against the count cell, stored once from
     the entry value of a named argument register before `L` (the version that proved gcc -O0);
5. a tally of steps and fetches is recorded at each block on its first arrival and equal on every
   later one: from the header, a path steps at most once and fetches at most once, and at each
   edge back to it has done both or neither (the counter cell's version balances them against its
   own step); a cell's load whose value reaches a fetch or a step comes before the trip's step;
6. where the offset field counts up to zero (AAPCS64's `__gr_offs`, which `va_start` sets to
   `-8 * unnamed registers`) every step of it runs where the value stepped is negative by the
   branches dominating it alone, so the cursor stays at most zero and a multiple of a slot, and a
   branch on it that no value takes one way carries no tally. Without this the register path's
   second step (`__gr_offs + 8 > 0`, then the stack) is a second step on a trip. A condition over
   the one cursor is decided as the set of 32-bit values it holds for (`tail_offsets`): the
   comparisons with a constant, the flags `cmp` and `cmn` set (the carry too, which `b.ls` reads),
   the sign bit `tbz` tests. The sets are unions of intervals, not strided ones, because a sum that
   wraps splits one in two.

Then each header run consumes at most one slot, and the header runs `count` times (or the counter
never passes `count`), so the loop consumes at most `count` slots, at `count`'s width, unsigned,
or signed for the counter cell's ordered test (a negative count runs no trip). The proof does not
read which of the two paths a trip takes: the psABI's selection (registers first, then the stack)
is assumed of the body, as every compiler emits it. `SourceTailCount` carries
`(parameter, width, signed)` on `SourceFunctionInterface`, minted beside the variadic bit.

Rule 4 refuses a loop that tests at its latch unless a guard before it excludes the zero count (a
do-while runs once at count 0), a loop one of whose latches never tests, latches that test
different bounds or step the counter differently, and a loop entered again. Rule 3 refuses
`for (...) { va_arg; va_arg; }` (two slots a trip), an unrolled loop (clang -O2 steps twice a
trip and finishes outside the loop), a conditional `va_arg`, and a fetch through the stepped
pointer (trip `i` reads slot `i + 1`, the `ap + 8` peek). Rule 2 refuses a `va_list` handed to
`vprintf` and a double fetched through `fp_offset`. A frame address into the cells, or arithmetic
past an object into them, is out of bounds in C and not read.

**Owner.** r2ssa (`tail_count`, `tail_cursors`, `tail_offsets`, run inside interface recovery on
the preparation's graph; the header's run count is `semantic::trips`', asked through
`header_trips`), r2abi the `stack_field` row (psABI Figure 3.34, AAPCS64's `va_list`) and the
entry stack alignment row. The callee's interface rides the call site's
`exact_callee_interface`, so no second rule is minted.

**Callers.** A call whose callee states a count, with no format rule, passes the constant it holds
for that parameter (`resolve_const_value`), masked to the counted width, as the tail: `named + count`
arguments. A count no constant fixes is `CountArgumentNotConstant`, a count the call does not carry
`CountArgumentUnavailable`, and a tail past 1,024 `ArgumentCountOverflow`; each is the counted
residual, and `VariadicCallsiteArgumentCountEvidence` names its basis (`Format` or `Count`).
Carriers are placed as for a format count, so the tail past the registers is the stack's.

**Cost.** Only a body with a save area runs it: O(insts + uses) scans (each value is tagged once, a
merge of the overflow pointer with an address once more), a dominator query per store, one
predicate collection, one header trip count per candidate loop (O(latches)), and on AArch64 one
interval set per branch on the offset (O(predicates x dominators)); the callsite is O(1). Release
`pdd` instructions, base and head, two runs each: 0pack `0x62ecf0` 20.30 and 20.30 G to 20.30 and
20.31 G, pumasim `0x23fdf0` 19.23 and 19.24 G to 19.19 and 19.19 G, output byte-identical, peak
RSS 226 and 236 MB to 233 and 226 MB (pumasim 233 and 237 to 250 and 240); under `aa` 0pack
74.13 and 74.12 G to 74.11 and 74.06 G, pumasim 82.00 and 82.26 G to 81.98 and 82.09 G.

**Measured (2026-10-17).** shapes.c, stripped, `aa; pdd @ shape_variadic_local`, the twelve builds
(two compilers, three levels, two targets): nine prove `vfold` and render `vfold(1, a)`,
`vfold(2, a, b)`, `vfold(3, a, b, a ^ b)` and `vfold(5, a, b, a ^ b, a + b, a | b)`, against one
(x86-64 gcc -O0, #312) before: gcc -O0, -O1, -O2 and clang -O1 on x86-64, gcc -O0, -O1, -O2 and
clang -O1, -O2 on AArch64. The three that refuse give a visible reason (`R2DEC_TRACE_REFUSAL`,
site `tail-count`), `vfold` still `(uint32_t arg0, ...)` and the calls still counted residuals:
clang -O0 on both targets reaches the `va_list` through a pointer it keeps in a stack slot and
spills the offset (`a Offset cursor is stored other than to its cell`), and x86-64 clang -O2
unrolls the loop by two and finishes outside it (`no loop holds every step`). `shape_variadic_local`
goes from 8 gaps to 0 on the nine; `main` goes from 4 to 2 on six of them and from 2 to 0 on AArch64
gcc -O0 and -O2 (the two left are the indirect-call floor of #264). Each acceptance rule has a test that edits a compiler's bytes to
break it and refuses for that rule's reason (`variadic_registers.rs`).

**What is left.**

- clang -O0: the `va_list` reached through a stored address needs that address read as the
  cells', which the cursor uses refuse.
- An unrolled loop (clang -O2 on x86-64) steps twice a trip and finishes outside the loop; its
  count bounds the loop and a remainder, which needs the remainder's trip count read.
- A load that starts below the unnamed slots and spans into them is not seen by `uses` (it tests
  the address a value roots at, not the access width); neither gcc nor clang emits one.
- A count in a global or a struct field, and a tail bounded by a sentinel (`NULL`-terminated), are
  not counts of a parameter and stay residuals.

### Summaries (ROADMAP SM, D23)

**The fact.** `Summary(f)` is what a caller reads of a body: its interface
(arity `Exact` or `AtLeast`, result), what it does through each parameter
(`PreparedCalleeSummary`), the registers it preserves, its signature, and the
callees that own what it leaves open. It is `CalleeReads(f)`, `f` resolved
against its imports, and `Resolved(f, demand)`, `f` resolved again against
the summaries of the owners outside `Component(f, demand)`, read bottom-up;
members of one component read each other alone. Key: entry, instruction set,
demand. Owner: r2engine's database; r2ssa states the interface, summary and
owners, r2types the signature. `Retention::Held`, a program-wide fact
computed once (adr-memory-model, decision 2). A prepared body is never held:
it costs about 8 ns per byte to compute again, a summary microseconds.

**Measured (2026-10-15).** The summary is already one held answer per body,
per demand, per session (`two_callers_of_one_callee_prepare_it_once`).
Resolutions by what asked for them:

| Run | Resolutions / bodies | Alone | Again with owners | Root | Root and summary |
|---|---|---|---|---|---|
| sort, all 234 `pdd` | 329 / 234 | 90 | 5 | 234 | 85 |
| pumasim census session, 50 `pdd` | 745 / 649 | 609, each once | 86 | 50 | 10 |
| pumasim `0x23fdf0` | 121 / 93 | 92 | 28 | 1 | 0 |
| gzdoom, 60 sampled `pdd` | 281 / 208 | 148 | 9 | 60 | 17, and 64 restated |

**Two grades, by construction.** A root resolves against every direct
callee's summary, a summary against its owners only. One resolution for both
gives every callee its callees, the transitive closure D23 forbids (pumasim
`main` reaches 1949 bodies, about 21 s), or takes callee evidence from the
root. So a sweep resolves each body once as a root and once as a summary,
and once more where an owner outside its component proves its result or
arity.

**The per-request double, removed.** `Native::resolve` prepared a body in
full, then again where the first folded text it points at (AArch64's
`adrp`+`add`) or the program's calls read an ambiguous result; the second
read none of the first's facts unless a declared frame was restated off
them. The first preparation stops at its seal (`r2ssa::TrustedSeal`: the
machine context, the owners, the folded table), and its facts are collected
only where they are the answer or a declared frame reads them. A refusal
the first fact pass would have raised (an exhausted pass, an unbound span)
now comes from the second preparation, under the same budget; none moved
on the census or certification. Discovery's
handed functions and the dispatch tables read a seal built against the
convention, recovering nothing: a constant that reaches a call's argument or
a table is the body's, which no interface decides. Output md5-identical, and
`aa; afl` identical on radare2's 309 ELF and 137 Mach-O test binaries:
gzdoom `0x10070695c` `pdd` 46.5 to 41.4 G instructions (672 to 618 MB);
`aa; afl` 0pack 77.9 to 43.2 G, pumasim 64.0 to 40.6 G, gzdoom 191.6 to
138.1 G; `aa; pdd` 0pack `0x62ecf0` 96.5 to 62.0 G, pumasim `0x23fdf0` 83.6
to 60.3 G.

**Invalidation and eviction.** A summary records what it read: the walk's
bytes, the names and stubs, its owners' summaries and its component; a write
recomputes exactly what read the written range. `Shared` compares by
identity, so a recomputed summary is never backdated and a write that moves
nothing still recomputes its dependents: P8's, under Q.

**Memory bound.** One summary per body asked, O(Σ summaries): the census
session (50 `pdd`, 649 summaries) peaks at 149.8 MB of heap against
121.9 MB for its largest function alone, so its held summaries cost at most
28 MB, about 43 KB each.

**Complexity.** Per body per demand: one construct and seal, one fact pass
where its facts are read, one more resolution where an owner outside its
component proves. Components: Tarjan, O(V + E) over the owner edges.

**What is left.**

- Callee reads stay 46% of sort `0x3f50` `pdd` against SM's 10%: one
  preparation per callee already (59 over 54 bodies), whose 39.4 points are
  construct 25.3 (recovery 15.7) and seal and facts 12.2. That is recovery's
  fact pass collected again by the seal (P4, LX4) and F2's single
  representation.
- Arity on a cold `pdd`: demanded everywhere it cost 0pack `0x62ecf0`
  16.5 G; under `aa`, where it is demanded, it closes 9 of pumasim
  `0x23fdf0`'s 317 floor gaps and 3 `may-hand-on` gaps of 0pack `0x62ecf0`,
  none on 0pack `0x58e3d0`, sort `0x3f50` or gzdoom `0x10070695c`. The rest
  chain through local Qt constructors to a slot handed on (`may-hand-on`,
  LP) or an indirect call (an indirect call's arity, SM). Conditional on
  those.
- Alone, then with owners: of the bodies with owners on pumasim `0x23fdf0`,
  28 resolve again and 8 do not cold, 89 and 6 under `aa`. Sealing alone,
  and collecting only where no owner proves, saves a fact pass per body
  resolved again and costs a construct per one not: about 5% of callee
  preparation cold, 13% under `aa`. Next.
- One preparation on AArch64: fold literal addresses before recovery, so
  folded text is captured once. The seal folds after boundary constants,
  copy forwarding and demand release, with prep facts; a fold before
  recovery has none of them, so it is a semantic change until the literal
  sets are shown equal over the AArch64 census and a gzdoom sample. Next,
  measured first.

### Calls through a table (ROADMAP P5)

A call is not a branch: its targets are callees, not successors, so a fetched call table never reaches
`SwitchInfo` or `NativeBlock.switch`. After the root's first collected seal, one scan of its graph asks
`r2ssa::indirect::dispatch_table_reads` for the reads that are calls. A read is a table of the container
only where `pointer_table` accepts it (inside one region and the file, read-only or loader-stated, every
entry an instruction), and the root is then sealed again with the fetched tables as `code_pointer_tables`.
r2ssa states the set on the certificate (`CallsiteCertificate::table_targets`) only where every entry the
certified range selects is a recorded code pointer: complete or absent. A bottom-tested loop's counter is
no interval to the branch assumptions, which stop at the header merge, so a selector that is a certified
induction (`StructuredDataflowFacts::induction_range`: a constant start and step, an exact run count, no wrap)
takes the values its runs give. r2types projects the set to `CalleeResolutionFacts::table_targets`, r2dec
names it in the gap (`one of ...`) and renders no C, and the listing claims `Target { call: true }` per
entry. Cost: one O(insts) scan per root, one more preparation only for a root with a certified call table.
Not done: the whole-program reference index reads the walk, which has no call tables, so `ax` does not list
them; the walk needs a trigger for a call through a load that does not seal every vtable caller.

### Budget

Resolution follows result demands only, so a request resolves what its
unproven results need; the 300-function samples cost 8% more (pumasim 9.1
to 9.9 s). A stopped owner stops the answer (`Hold::Stopped`); every held
answer is a function of the program alone.

## Complexity

Walks: one per function asked, held. Resolutions: one per callee asked,
plus one per function whose result an owner then proves; a resolution's
first seal is collected only where it is read (Summaries). Components:
Tarjan, O(V + E) over the owner edges the demand names, each component deposited once.

## Steps

- P6a: `Walked` is a query and the root analysis reads it.
- P6b: `Component` and the closure measured on 0pack and pumasim.
- P6c1: a callee runs the root's resolution, on its `Walked`, against its imports.
- P6c2: `result_owners`, `Demand` and `Resolved`; an unproven callee states how many arguments it reads.
- P6d, declined: `read_callees` is the one loop a root reads its callees through. The database
  answers it with `Resolved`; a plain `Program` (tests/engine/native.rs, the model integration test)
  with each callee resolved alone, through the same `resolved_alone`.
- SM2 (2026-10-15): a first seal no second preparation reads is never collected; discovery's
  handed functions and the dispatch tables read the convention's seal.
- Q/FS reference index (2026-10-16): `ReferenceIndex` reads `Walked` for every function the survey
  walked, so `ax`, `axt`, `pdf`, `afb`, `pdil` and `ResultReads` read one body, a followed
  dispatch's arms included. `Walk::lifted` puts a dispatch's cases on its block as `SwitchInfo`, the one
  carrier: the walked def-use reaches the arms (without it they were unreachable blocks, the graph did not
  build, and 21 libc, 13 0pack and 77 pumasim bodies went unread), and the annotation pass claims one `Target`
  per arm at the dispatch line (`Basis::Solved`), for the listing and the index alike. A walk whose tables
  could not be read keeps the walk that follows none and says why (`Walk::refusal`); the analyses take
  `Walking::resolved`, the listing and the index take the body. The survey's discovery walk is the one other
  plain walk: `Walked` reads the returns it deposits, so it cannot read `Walked`.
  The def-use graph the claims ask is the validated function's, without the seal (`Prepared::def_use_graph`).
  A computed address is left in a register the instruction's operands name, so x87's instruction pointer is
  no reference.
  Cost (`ax`, instructions): O(ops) per function plus the convention seal a function with an unresolved indirect
  branch pays to read its tables, cut to the blocks that reach the branch (`Walked::reaching_unresolved`, a
  value at a dispatch is built from the paths that arrive at it): libc-2.31 11.8 of the 12.9 extra G before the
  cut and 8.2 after (about 480 unresolved indirect transfers walked, 97 dispatches solved); the arms add 7 to 17%
  more code to claim. Without table reading the index is below the old one, which sealed a graph for every
  claim (libc 57.6 to 49.8 G); with it, pumasim +2.5%, 0pack +0.3%, libc +16%, peak RSS pumasim +6%.
  `ResultReads` reads the same body at no measured cost (`aa; pdd` on five census functions, +/-0.5%).
- D6 (2026-10-16): the dispatch tables of a body are the held query `DispatchTables`, read once per function
  and read by the survey and by `Walked`. The survey runs its table-free fixpoint, tells `ComesBack` the
  answers so far (`Walker::answered`, so a table read finds its callees decided), then continues each
  finished trace through its arms (`Trace::dispatch`, `Walker::dispatch`) and the fixpoint with it: the
  arms' callees are believed, and `afl` sizes, `afb`, `afi`, the callers `ResultReads` sees and the
  holders all read the body `Walked` walks. A lone `pdd` asks `DispatchTables` for its own function only,
  so it stays a lazy single-function request. One round: a dispatch first reached through an arm stays
  unresolved, as before.
