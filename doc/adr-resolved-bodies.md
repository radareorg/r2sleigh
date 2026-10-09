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
- A callee whose interface still has an unproven result mints no call
  contract; a call to it reads the registers the caller wrote, and at least
  as many as the callee's own body proves it reads (`CalleeStatement`).

The limit: parameters stay what each body proves alone. A thunk whose
target forwards an argument to a body nothing describes reports only the
arguments it reads itself, so a caller can pass fewer than the source does
(`QString::operator=(const char*)` renders with its `this` alone). Marking
such parameter lists a floor and reading more at the call site was measured
and rejected: the extra arguments were registers written for other reasons
(`murmur3_32`'s rotate count), which AGENTS forbids as invented arguments.

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

r2engine then reads the program's calls to it: the walked bodies whose trace
calls it (`Survey`, inverted once, O(call edges)), each lifted without
preparation, so no answer waits on the function it is about. After each call,
the first touch of each result register up to the next transfer is a read (the
caller takes what the call left there), a write, or nothing. Every reading call
agreeing on one register decides it, at the widest read's width for a float;
none, or calls that disagree, leave it unproven. The function is prepared once
more with that evidence (`SourceResultReads`), only where the first preparation
was ambiguous.

The evidence is as strong as the body's own writes: a compiler reads a
clobbered register after a call only as the callee's result. A caller that
hands the value straight back without reading it (`return f();`) is no
evidence, and a void function whose callers read nothing stays unproven.
Follow-up: a function left unproven this way mints no call contract, so its
calls take their arguments from what each caller wrote (the statement below)
where its own parameters are exact. A contract whose parameters are exact and
whose result is one of two carriers, each call resolving it by what its caller
reads, would keep them.

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
