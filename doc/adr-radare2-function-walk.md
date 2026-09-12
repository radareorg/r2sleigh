# radare2's function walk: what the depth limit is, and how to not need it

This is the derivation behind an upstream change to `libr/anal/fcn.c`. It is
written before the change, so that the change can be judged against it. Every
number in it was measured on the fork at `05b8d1e77b` (upstream master plus the
six open pull requests) on this machine.

## 1. The walk, stated exactly

`fcn_recurse (anal, fcn, addr, len, depth)` at `fcn.c:858` discovers one
function's basic blocks. Written as a recurrence over a block start `a` and a
stack delta `δ`:

    R(a, δ):
      if a block already covers a:            -- fcn.c:939-961, via bbget
          split it at a if a is interior; return
      b := new block at a; b.parent_stackptr := δ     -- fcn.c:310-318
      scan instructions from a, appending to b, until a terminator T;
          each instruction may adjust fcn->stack       -- fcn.c:1230, 1764, 1778
      let δ' := fcn->stack after the scan
      for each successor s of T, in the order the code recurses:
          fcn->stack := δ'                             -- the saved_stack restores
          R(s, δ')
      E(b)                                             -- the `beach` label, fcn.c:2160
      return ret

`E(b)`, the epilogue, pops the `lea` candidates this scan pushed onto
`anal->leaddrs` (`fcn.c:2162`), finalises the decoded op, removes `b` if it is
empty, updates its hash, and drops the reference.

Three facts about this recurrence carry the whole argument.

**Every block is scanned once.** The memoisation at the top means a block start
is scanned the first time the walk reaches it and never again; a later arrival
at an interior address splits the existing block without re-decoding. So the
work is Θ(bytes decoded + blocks + edges): linear in the size of the function.

**`depth` is not a bound on work.** It is decremented once per followed edge on
the current path (`r_anal_function_bb`, `fcn.c:2185`) and restored on return.
What it bounds is the length of the longest chain of edges the walk is standing
on at any moment — the depth of the depth-first search, which is a property of
the function's *shape*, not its size. A fifty-arm state machine exhausts it not
because it is large but because its states form long chains.

**Running out of depth leaves the edges but not the blocks.** The block that
ran out has already recorded `bb->jump` and `bb->fail` before recursing
(`fcn.c:1584-1597`, `1694-1703`), and the child returns `R_ANAL_RET_ERROR` at
`fcn.c:873-876` without creating anything. The function is left with edges
into addresses no block covers. `BZ2_decompress` in bzip2 at `-O0` is left with
480 blocks, 4651 bytes in nine holes, and four blocks whose successors point
into them; at 256 it has 575 blocks and no holes. This is the partition
contradicting its own edges that the plugin now refuses.

## 2. Why the limit exists — measured

The limit protects the C stack, and only the C stack. The frame of
`fcn_recurse`, from `-fstack-usage` on the shipped compile flags (`-g`, no
optimisation):

    fcn.c:858:fcn_recurse    5520 bytes   (-O0, the flags the build uses)
    fcn.c:858:fcn_recurse    3088 bytes   (-O2)

Every followed edge is one such frame, because each recursive call site is
followed by `goto beach` — the recursion happens *inside* the frame, with all
its locals live. (One site is the exception and is dealt with in §4: the
indirect-jump follower at `fcn.c:2025-2026`, behind `anal.jmp.indir`, which
defaults to off and is marked "testing", resumes scanning after it recurses.)
Of those 5520 bytes, 1032 are a `ReadAhead` cache that is zeroed and
invalidated at every entry (`fcn.c:1038-1040`), so a child re-reads from IO
bytes its parent already held. The source says the rest itself at `fcn.c:877`:
*"TODO Store all this stuff in the heap so we save memory in the stack"*.

The two constants are calibrated to stacks, and their history says so:

- `anal.depth` defaults to 128, and to 32 under `__wasi__`
  (`libr/core/cconfig.c:4096-4100`). The commit lowering it to 32 is titled
  *"Lower the anal.depth to 32 on wasm builds (64KB stack size limit)"*
  (`6baa934f48`).
- `R_ANAL_FCN_RECURSE_STACK_LIMIT = 192` (`fcn.c:29`) was added by
  `1c643d2ad1`, *"De-recurse bbtree walks abusing stack usage in wasm/asan"*,
  in March 2026. That commit **converted the block-tree walks in `block.c` to
  an explicit `RVecAnalBlockPtr` stack** — and, for `fcn_recurse`, added the
  clamp instead. The function walk is the half of that commit that was not
  finished.

The arithmetic: 128 frames × 5520 B = 707 KB; 192 × 5520 B = 1.06 MB. The main
thread here has 8 MB (`ulimit -s` = 8176 KB), so on the main thread the cap
costs coverage for nothing. A macOS secondary thread has 512 KB by default,
which is 95 frames — fewer than the default 128, so an analysis run on a worker
thread can already overflow. The wasm target's 64 KB holds 11 frames at these
sizes, so even the lowered 32 is not a guarantee there. The cap is neither
sufficient on the small stacks nor necessary on the large one.

And `r_anal_function_bb` clamps any configured value to 192
(`fcn.c:2182-2183`): a function whose deepest chain needs 193 cannot be analysed
at any setting. Raising the number is not an escape.

## 3. What one frame passes to the next

For the recursion to be replaced by a loop, every piece of state a child
observes on entry has to be accounted for. Reading `fcn_recurse` from its first
line to `beach`, the child receives exactly this:

1. **The arguments.** `addr`; `len`, which is `anal->opt.bb_max_size`
   everywhere except the single-block mode, where it is the block's own size;
   and `depth`, which only feeds the two checks at `fcn.c:868-876` and that
   same single-block mode, where `-1` means "scan this block and follow
   nothing" (`fcn.c:2416`).
2. **`fcn->stack`, the entry delta.** The child reads the global as it stands
   when the call is made. The sites that recurse into two or more successors
   save it before and restore it between them (`fcn.c:1694-1702` for a
   conditional branch, `1721-1743` for a switch, `2064-2066` for a conditional
   return), so every successor of one block receives the same value: the delta
   at that block's exit. The unconditional-jump site at `1586` and the
   push-return site at `2078` do not restore it, and need not: both are
   followed by `goto beach`, so nothing after them in the frame reads it, and
   the *caller's* restore covers the caller's other children. The value is
   already materialised per block: `fcn_append_basic_block` writes it to
   `bb->parent_stackptr` at creation (`fcn.c:315`), and `libr/core/canal.c:3865`
   re-walks from that field.
3. **`anal->leaddrs`, a path-scoped list.** The scan pushes a candidate for
   every `lea`-like instruction (`fcn.c:1327`, `1351`), the jump-table
   detection reads the list newest-first (`fcn.c:1895`, `1960`), and the
   epilogue pops exactly the entries this scan pushed (`fcn.c:2162`). Because
   the epilogue runs *after* the children, a child sees every ancestor's
   candidates on the current path. This is per-path state kept in a global.
4. **`anal->cmpval`, the last compare.** Set on a comparison (`fcn.c:1602`,
   `1609`), copied into the block (`bb->cmpval`, `1610`), read by the
   jump-table walk to size the table (`1674`) and by
   `try_get_cmpval_from_parents` (`fcn.c:461`) from the predecessor block. The
   global copy is "the most recent compare on the current path"; the per-block
   copy already exists.
5. **Monotone or per-block function state.** `fcn->maxstack` is a running
   maximum (`fcn.c:94`); `fcn->bp_off` is set from `fcn->stack` at a
   `mov bp, sp` (`1286`, `1354`, `2095`, `2098`) and is therefore a per-block
   fact given the right entry delta; `fcn->ninstr`, `fcn->type`,
   `fcn->is_variadic`, and callees' `is_noreturn` are sets or flags. None
   depends on the order blocks are visited.
6. **Nothing else.** Every other name in the function — the `ReadAhead` cache,
   the delay-slot tracker, `last_is_push`, `overlapped`, the op storage, the
   `lea_cnt` counter, `bb` itself — is initialised at entry and dead at
   `beach`. A child inherits none of it.

And what the child hands back: `ret`. This is the one thing the walk gets
genuinely wrong today, and the transformation has to reproduce it before it can
fix it. `ret` is one `int` used three ways: as the enum (`R_ANAL_RET_END`,
`ERROR`, `NOP`), as the byte count `read_ahead` returns — reassigned on every
instruction at `fcn.c:1068` — and as a `bool` from the jump-table walkers
(`fcn.c:1407`, `1679`, `1870`, `1989`). Of the recursive sites, some assign
`ret` from the child and some discard it (`fcn.c:1697`, `1733`) or overwrite it
(`fcn.c:1593`), and every site but one is followed by `goto beach`, so a frame
returns the outcome of the *last assigning child it ran* — the rightmost path
of the depth-first search — or whatever `ret` held when it reached `beach`.
Two sites reach `beach` without setting it at all (`fcn.c:1563`, `1709`) and
return the last byte count, a positive number.

That number matters, because the callers branch on it.
`r_anal_function` (`fcn.c:2322-2327`) fires the analysis plugin hook only when
`ret >= 0 || ret == R_ANAL_RET_END`, which excludes `ERROR` — the value the
last child returns whenever it reached a block that already existed, the
common case for any loop. `__core_anal_fcn` (`libr/core/canal.c:783-907`)
deletes the function on `NOP`, retries from a bumped offset on any other
negative value, and loops `while (fcnlen != R_ANAL_RET_END)` — so a leaked byte
count re-runs the whole analysis from `addr + linear_size`. The return value is
therefore both order-dependent and load-bearing. `R_ANAL_RET_DUP` and
`R_ANAL_RET_NEW` are never produced anywhere; `R_ANAL_RET_COND` does not exist;
the "use a higher anal.depth" warning at `fcn.c:873-876` is unreachable, since
`fcn.c:868` already returned for every value it tests.

## 4. The transformation

Replace the C recursion with an explicit stack of two kinds of frame:

    Enter(a, δ)          -- a block to scan, with its entry delta
    Exit(b, n, r, k)     -- a scanned block whose epilogue is still owed:
                            pop n lea candidates, finalise, hash, unref;
                            r is the scan's own ret; k says whether the
                            block's last recursive site assigns ret from
                            its child (the sites at fcn.c:1586, 1700,
                            1742, 2065, 2078) or not (1697, 1733, 1593)

    push Enter(entry, δ₀)
    while the stack is not empty:
        match pop:
          Exit(b, n, r, k):  run E(b) with lea_cnt = n;
                             last := (k ? last : r)
          Enter(a, δ):
              if a block covers a: split if interior; last := ERROR (or END
                                   under anal.recont); continue
              fcn->stack := δ
              b := scan from a                         -- exactly today's loop body
              δ' := fcn->stack
              push Exit(b, lea_cnt, ret, k)
              for s in successors of b, last to first:  push Enter(s, δ')

Pushing the exit frame *beneath* the children and the children in *reverse*
order makes a last-in-first-out stack replay the recursion's order exactly:
scan `b`, then the whole subtree of its first successor, then of its second,
…, then `E(b)`. The `k` flag on the exit frame reproduces the return value
exactly as §3 describes it — the rightmost assigning child's outcome, byte
counts and all — which is what identity requires; giving `ret` a definition is
a separate change (§7).

One site does not fit this shape and is handled by deviating from it. The
indirect-jump follower at `fcn.c:2025-2041`, behind `anal.jmp.indir`
(`cconfig.c:4140`, default off, comment "testing"), recurses into both targets
in the middle of a scan and then keeps scanning, with no save of `fcn->stack`
around it — so today the rest of that block sees whatever delta its children's
subtrees left behind. The loop pushes the two `Enter` frames and continues the
scan at once; the children run after the block finishes, and the block's own
scan sees its own delta. Under the default configuration this site never runs
and the identity claim below is unconditional; with the option on, the result
differs exactly there, and differs in the direction of a per-block delta that is
the block's own.

**Claim.** The loop and the recursion perform the same sequence of scans,
memoisation checks, epilogues, and reads and writes of every global in §3, and
therefore produce identical blocks, edges, cross-references, flags, stack deltas
and jump tables.

**Argument.** By induction on the depth-first tree. At a block `b` with
successors `s₁ … sₖ`, the recursion performs: scan(b); R(s₁, δ'); …; R(sₖ, δ');
E(b). The loop, after scan(b), has the stack `[…, Exit(b), Enter(sₖ), …,
Enter(s₁)]` with `Enter(s₁)` on top. It pops `Enter(s₁)`, and by the induction
hypothesis performs exactly R(s₁, δ')'s sequence before the stack returns to
`[…, Exit(b), Enter(sₖ), …, Enter(s₂)]`; likewise for each sibling in turn;
then it pops `Exit(b)` and performs E(b). The entry delta each child reads is
`δ'`, which is what the restores at `1694-1702` (and their siblings) hand it.
Every global in §3 is read by a child only *during that child's scan*, and the
prefix of operations preceding that scan is the same in both traversals, so the
value read is the same. The scan locals are the only state whose lifetime
changes: in the recursion they stay live across the children on the C stack; in
the loop they die at the end of the scan, and nothing in §3 reads them after
that. ∎

**What this buys.** The C stack depth of the walk becomes constant. The
explicit stack holds at most one `Exit` per block on the current path plus the
pending siblings — bounded by blocks plus edges — and a frame is about thirty
bytes (an address, a delta, a pointer, two integers) against 5520. A million-
block function would take thirty megabytes of heap it does not have today
anyway; a fifty-thousand-block one, the largest plausible, a megabyte and a
half. `anal.depth` and `R_ANAL_FCN_RECURSE_STACK_LIMIT` stop describing
anything and can be removed. The single-block mode survives as a flag on the
top-level call: push no children.

The same shape removes the second cap. `r_anal_jmptbl_walk` carries its own
hard-coded `depth = 50` (`libr/anal/jmptbl.c:390`) for switch cases; cases are
successors of the dispatch block and become `Enter` frames like any other.

## 5. What is actually superlinear in the walk

Reading the path for the equivalence argument also answered the question this
started with. The walk's own traversal is linear — each block scanned once —
but the work *per instruction* is not constant, and several of the helpers it
calls are linear in the function:

- **`bbget` runs once per instruction.** The overlap check at `fcn.c:1142-1156`
  calls it for every instruction scanned until the block first overlaps another
  (`overlapped` is never cleared). Each call is an interval query on the block
  tree plus two heap allocations and a reference per hit (`block.c:179`,
  `133-167`), and with `anal.delay` on — its default — a `malloc`, a `read_at`
  and a backwards re-disassembly of the candidate block's tail (`fcn.c:582-611`)
  to test delay-slot membership. That is Θ(instructions × (log blocks + block
  size)) on architectures with delay slots, and Θ(instructions × log blocks)
  everywhere. `r_anal_block_set_size` at `fcn.c:1170` runs per instruction too
  and re-propagates the tree's augmented maximum root-to-node, another log
  factor per instruction. The fact `bbget` recomputes — whether an address sits
  in a delay slot of an existing block — is a property of that block's tail and
  can be recorded once when the block is closed.
- **`try_get_jmptbl_info` finds a block's predecessor by scanning every block**
  (`libr/anal/jmptbl.c:1264` onward, the `r_list_foreach (fcn->bbs, …)` at its
  line 25). That is Θ(blocks) per indirect jump, Θ(blocks × switches) per
  function. The predecessor is known at the moment the block is entered: it is
  the block whose successor list put the `Enter` frame on the stack. Carrying
  it in the frame makes the lookup constant. This is a second gain the explicit
  stack gives for free.
- **`function_has_ret_between` scans every block, decoding one instruction per
  block, inside the per-case loop of the jump-table walk**
  (`libr/anal/jmptbl.c:433-460`, called at `:993`): Θ(cases × blocks) per
  table, each step a `read_at` and a decode.
- **`anal->leaddrs` is one list for the whole function** and the jump-table
  base search walks it newest-first (`fcn.c:1895`, `1960`); it grows with every
  `lea` on the current path, so the search is Θ(path leas) per indirect jump.
- **The read-ahead cache is per frame** and re-filled from IO at least once per
  block; with the walk's frames gone it becomes one cache for the function,
  which also removes the largest single item in the 5520 bytes.

None of these is what the depth limit is about, but they are what "make the
whole path scale" means once the limit is gone, and the first two sit on the
same critical path as the switch-heavy functions the limit was truncating.
Everything else in the walk was checked and is constant or amortised-constant
per instruction: the cross-reference insert is a hash-table write, the
function-at lookup is a hash probe, the function's range is cached and only
consulted under debug logging, and the block-takeover path is already an
explicit worklist over `RVecAnalBlockPtr` (`block.c:543`) — it just
multiplies by instructions and variables, and runs only under `anal.slow`.

## 6. The part that would change results, and why it is separate

§4 is result-preserving by construction. It leaves one thing exactly as
radare2 has it today: items 3 and 4 in §3 are path state, and a block reached
by two different paths takes the value of whichever path the depth-first
search happened to walk first. That is an order dependence — a jump table whose
bounds check sits on one predecessor and not the other is found or missed by
traversal order — and it is not made worse or better by §4; it is made
*visible*, because with the explicit stack the path state has nowhere to hide.

The correct statement is that the entry delta, the last compare and the live
`lea` candidates are each a forward dataflow fact: labels on the edge that
reaches a block, joined at the block's entry. Equal labels keep; unequal labels
become "unknown", which is a finding (an unbalanced path, a compare that does
not dominate its jump) rather than a silent choice. `bb->parent_stackptr` and
`bb->cmpval` already exist as the per-block halves of this; what is missing is
carrying the labels on the frame instead of in globals, and joining rather than
overwriting. That change alters results, so it is a separate change with its
own measurement, taken only after §4 has landed and been shown identical.

## 7. Proposed sequence

1. **De-recurse `fcn_recurse`** as in §4, with `Enter`/`Exit` frames on an
   `RVec`, matching the idiom `1c643d2ad1` already established in `block.c`.
   The jump-table layer's re-entry through
   `r_anal_function_materialize_switch_case` (`fcn.c:694`) enqueues instead of
   calling, which also retires its hard-coded depths of 50 and 999
   (`jmptbl.c:390`, `1385`). Delete `R_ANAL_FCN_RECURSE_STACK_LIMIT` and the
   unreachable warning at `fcn.c:873-876`. Keep `anal.depth` accepted and
   ignored for one release with a deprecation note, since scripts set it. The
   test is that every `afl`, `afb`, `afij`, `afx`, `afvj` and `pdf` output over
   the local corpus and the radare2 test suite is byte-identical before and
   after under the default configuration — §4 promises identity there, so any
   difference is a bug in the transformation, not a judgement call.
2. **Give `ret` a definition.** With the frames explicit, the return code
   stops being "the rightmost leaf's leftover" and becomes a function-level
   fact: `END` when the entry block scanned, `ERROR` when it could not, `NOP`
   where today's `RJMP` path says so, never a byte count. This changes which
   functions `__core_anal_fcn` keeps and when the plugin hook fires, so it is
   measured on its own. The two dead enum values go with it.
3. **One read-ahead cache for the walk** instead of one per frame.
   Result-preserving; measured as IO reads per function.
4. **Carry the predecessor in the frame** and replace the scan in
   `try_get_jmptbl_info`; record the delay-slot tail per block so `bbget`
   stops re-decoding; hoist `function_has_ret_between` out of the per-case
   loop. Result-preserving; measured on switch-heavy functions.
5. **Edge-labelled path state with a join** (§6). Result-changing; separate,
   measured, after the above.

Each is one pull request from upstream master, in that order, because each is
one idea and the first, third and fourth can be verified by identity.
