# ADR: control structure is the dominator tree; everything else is an edge spelling

Status: done; quality rewrites are ROADMAP SD

## Decision

The old structurer recognised shapes, fell back through seven placement
mechanisms, and proved coverage afterwards with a boolean-formula equality
exponential in nesting depth. Placement is now total and linear, and one
certificate checks the output text against the CFG without knowing how the
text was built.

### §3 The certificate

Reading the rendered body as a program gives a labelled graph `R` over block
*occurrences* (one rendered copy of a block), with `π` mapping each to its
block in `G`. The control certificate `I_S` is:

- (i) every block has an occurrence, and the body starts at the entry's first;
- (ii) at every occurrence of `b`, the labelled multiset of out-edges equals
  `b`'s in `G` (`Normal`, `True`/`False`, a switch arm's case-value set,
  `Default`);
- (iii) an `if` tests `b`'s certified predicate with the polarity its arms
  say, and a `switch` tests `b`'s certified selector.

Consequences of `I_S`: rendered paths equal machine paths, so rendered control
domains equal canonical ones without building a formula; loop body, latches
and exits are implied; a `ControlTransfer` obligation is discharged iff (ii)
holds at every occurrence, a `ControlPredicate` iff (iii). An unconditional
transfer rendered by adjacency is rendered, not elided. A block written twice
is admitted when each copy carries the full out-edge set.

The extractor models every implicit C transfer, or a rewrite could invent
one: adjacency, an `if` without `else`, `case` fall-through, `break` (loop *or*
switch), `continue` (passes through a switch), `goto`, `return`, the loop-end
back edge. A `Gap` reads as the block's declared out-edges. A block with
terminator `None` must end with no out-edge, so a call ends an occurrence only
when the prologue declares the callee `__attribute__((noreturn))`; a trap is
the target's builtin. Fabricating a `return` is not acceptable.

A compound test (a condition chain) is `&&`, `||` and `!` over atoms that each carry the marker of the block whose
test they are, the head's own included, so a `!` is the chain's and never the lowering's. The checker reads the
DAG of those blocks from the CFG: each is a two-way branch, every block past the head is entered only from the chain
and is written nowhere else, and the DAG has two exits. An edge to a later test is an edge of the DAG; one back to the
head or to an earlier test leaves it, so a loop whose test is a chain ends in its own head as one of the two exits. It requires the DAG's exit function to equal the test's by BDD identity:
the test evaluates its atoms left to right and skips the decided ones, so its trace is the reduced ordered BDD of
its function under that order, and the DAG is that trace only if every edge runs forward in the order and no atom
decides nothing. At most 16 atoms and 512 BDD nodes; past either the chain is refused with a typed `ChainFault`
and nothing is written. The head's edges are then the chain's exits, read exactly: no inversion is read into its
arms. The checker never infers a chain; it reads the markers the rewrite put there.

A test of one such atom is read the same way, which is how a rotated loop's polarity is certified: the loop's test is
its block's atom, `!atom` where the machine leaves on the true edge, and an edge back to the lone block is an exit.
A test the lowering wrote carries no marker and is judged by its edges exactly; a swapped pair of labels is a
violation, not an inversion (the certificate used to admit it, so `while (c)` and `while (!c)` certified alike for a
plain test; a stage that dropped a negation was kept). One text change follows the final certificate:
`respell_negations` turns a `!` over a marked integer comparison into the opposite comparison (`Eq`/`Ne`, `Lt`/`Ge`,
`Le`/`Gt`); a table test evaluates all six rows against the negation on every 8-bit pair and the edges of 16, 32 and
64 bits, signed and unsigned, and a float comparison, false on a NaN, has no opposite and keeps its `!`.

Whether a block may be a member of a chain has one owner, the text: the block's text is its test and nothing else
(`Explore::edge`, `test_regions`), so D2 writes a value the function keeps as a statement of its own and `sub esi, 5;
jne` with `esi` returned is a test of its own (`a_second_test_joins_the_chain_only_if_it_computes_nothing_the_function_keeps`),
and a load, store or call is a statement (`a_second_test_that_reads_memory_is_a_test_of_its_own`). r2ssa's
`owes_only_its_branch` was a second owner of the same question and is gone (2026-10-23): replacing it by `true` moved 0
of 3,765 renderings, a condition holds a load in none of them, and no program the engine tests build makes it refuse
what the text accepts. What it guarded is read where it can be read, as below: a statement of a member that the chain
does not carry is a lost statement, a `Statement` violation, and an effect that went unrendered is the ledger's.

A selection `x = c ? a : b;`, written by the readability stage for an `if`
whose arms each assign `x` once, is read as that `if`. The statement carries
the test block's markers and each value its arm block's (one block, or none for
an arm that is the edge itself); that block's occurrence is entered on the
arm's edge. The rewrite records the statement as a selection. The checker
refuses one whose test is not a conditional branch, whose target is not a plain
variable, or whose value writes: that write is a second effect of the arm.

### The statements of a block

`I_T`: every statement the placement wrote for a block is written, and as often as any other statement of that
block. The unit is a block's text, which a copy reproduces whole. A *statement* is a marker (§5) counted by the
marker it stands for (`Placed::statement_of`: itself, or the one `copy_of` copied); the walk meets one at a statement
under a marker, at a value of a selection, and at each test of a chain past its head (the head's own is on its
statement). An edge's copies are statements of the block the edge leaves, one marker each (`Writer::observe_copy`),
which name no instruction, so no line changes, and which open no occurrence, so the walk reads them where it read the
unmarked statement; the latch hoist moves only statements so marked, since a block's own assignment is not a copy its
edge carries. A copy that drops a statement of its block, or a stage that drops the copies a latch carries, leaves
that marker one fewer than the block's others, and a block whose statements are all gone is a pass-through to the
walk (§3 reads a block that rendered nothing through): with every edge the machine's, only this count says it was
not one. O(statements): one pass over the markers met, one over the markers written, a minimum and a maximum by block.

What it does not read: a statement moved from one copy of a block to another leaves the counts equal (no stage does
it); a block of one statement has no other to differ from, so a copy of it that is missing from one site and present
at another shows only in that site's edges; a copy's text is not compared with its original's (`remint` clones the
expressions, so only a producer that rewrites a copy could differ). ROADMAP D61 holds these.

### §4 Placement

Every block except the entry is placed by its immediate dominator `x`. With
`Λ(y)` the natural loops containing `x` but not `y`: if `Λ(y)` is empty, `y`
is placed inline at the arm reaching it (when its only forward in-edge is from
`x`) or as a labelled merge child of `x`; otherwise it goes in the exit list of
the outermost loop in `Λ(y)`, and its whole dominator subtree moves with it
(exit subtrees are whole). A loop header wraps its body in `for (;;)`. An edge
is `continue` to the innermost enclosing header, inline adjacency, or `goto`.
Merge children and exits are written in ascending RPO.

An exit `y` of loop `L` with one forward way in (the edge from its immediate dominator `x`) whose
dominator subtree no edge leaves (*closed*) is written where that edge leaves `L`, not after it,
unless `break` reaches it: the first exit of one loop stays after the loop. `Placement::inlines` is
the one predicate `compute` (the exit lists) and `edge` (the arms) share. A closed subtree holds no
loop another block belongs to, so the text it adds inside `L` leaves no `continue`, `break` or label.
Closedness is the preorder interval of the subtree holding the extremes of its blocks' successors'
positions, `O(B + E)`. The difference-on-tree count over `idom` answers how many edges leave a
subtree and needs the lowest common ancestor of each edge (`O((B + E) log B)`, a lifting table);
only whether any edge leaves is asked, so it is not built.

This writes each block exactly once, satisfies `I_S` for any graph,
reducible or not, runs in `O(|B| + |E|)` after the dominator tree, and makes
every backward `goto` target a loop header or an irreducible-cycle entry.
Every arm ends every path in a transfer. An indirect branch with declared
successors is a `switch` on its own target value (a `SwitchCertificate` with
`cases = {(addr, addr)}`); with none, or an unrenderable target, it is a gap.
An irreducible cycle needs nothing special: its closing edges are `goto`s,
and it has a complete obligation inventory, only no loop certificate.

### §5 The quality layer

Every readability improvement is a rewrite `AST → AST` that must preserve
`I_S`, proven by re-running the checker on its result; a rewrite that fails is
not applied. Each stage must also keep every observed occurrence, since the
certificate is blind to an `if` rebuilt without its observation chain; the
gate checks both and names the failing stage. Asking the plan for an
expression is itself an observation, so merge-write decisions come from
dispositions and expressions are asked for only when written. Preference among
rewrites is fixed: fewest labels, then fewest duplicated blocks, then shortest
text. `break` never crosses a `switch` to reach a loop. `LoopCertificate::condition`
is a rendering choice, not a certificate fact; it stays only for `for_loop`
until that certificate names its exit edge. The stages run in `render::structured`, each kept only while the
control certificate still holds: condition chains (on the tree as placed, where every merge is a `goto` and
every exit is a bare transfer or a block only the chain reaches), `shape`, the latch's copies, loop rotation, the
noreturn guard. The
certificate holds each stage to the machine's edges with their labels, so a stage that changes a test's polarity says
so on a marked atom or is refused (§3).

A terminal tail is a run of at most four expression statements from a label, through the sibling
blocks the text falls into, to a `return`, a call to a callee declared never to return, or a `goto`
to another run (a cycle of jumps has none); it holds no residual or gap, because a copy would be a
second site of one unproven cell (the skipped-block copy asks the same predicate, `tails::copyable`,
so a skipped block holding a residual stays one). Each `goto` to a tail is replaced by a fresh copy (every marker
minted anew), and a tail nothing falls into and no `goto` names goes with the blocks it ran through
(`structure/tails.rs`). A copy carries its blocks' whole out-edge sets, which `I_S` already asks of a
block written twice, so a copy where the edge did not go is refused by the certificate. The pass
runs after the skipped-block copy, which needs the jumps the tail copies replace: `bi_windup`'s
`put_byte` is a block the compiler merged out of two arms and the copy into those arms is the source's
shape, where a tail copied first leaves it shared. The preference order of this section holds: a tail
copy removes a label, so it outranks the duplicate block it costs.

A `return` whose value is a merge of the return's own block, and whose inputs are pairwise-distinct
canonical terms, is copied into every arm end of the conditional that falls into it. That is the
one place a block is duplicated without a label to remove, so it needs a fact the CFG states and a
join does not: the edges carry values no other edge carries (`Values::returns_distinct_merge`, `O(1)`
per return block, over the graph's phi and the canonical terms, never names or spelled text). A
side effect before the return, a label something still jumps to, a merge that carries itself or one
two edges give the same term are not this shape. The assignment before each copy stays
(`x = a; return x;`); folding it touches the merge's ledger accounting and is its own step.
The unguarded form (any `return` after a conditional with two falling arms, `return;` too) was
measured and not shipped: the CFG does not say a source wrote two returns where it wrote one, and
`return a || b` compiles to the same merge of `1` and `b` as `if (a) return 1; return b`.

### §6 Decided branches

Preparation runs sparse conditional constants in `SccpMode::Decide`
(`r2ssa::optimize`, audit D13). A branch whose condition the lattice proves
constant becomes the edge it takes; the edge it leaves, the blocks only that
edge reached and their merge sources go before the seal, so the dead arm owes
no obligation (`mov eax, 0; test rax, rax; je; call rax` through a weak
undefined symbol the linker resolved to 0). No operand is rewritten, which
keeps the provenance the pdd path turned `Propagate` off for. `O(n + e)` once
per round; a round that decides nothing ends the loop.

## Done

- S0: the checker over the old tree; `R2DEC_CONTROL_CERTIFICATE` prints one `control-certificate` line per function (and on the refusal-evidence channel).
- S1: placement in `structure/place.rs`, the certificate in `structure/certify.rs`; the region builders, domain proofs, linearizer, structuring deadline and every `safety_reason` deleted; noreturn prototypes spelled; irreducible cycles keep a complete inventory.
- S2, in part: jump-to-next and unreferenced-label elision, `break`/`continue` to the innermost loop header and the first block after it, and the checker. The rest of the original S2 was in the legacy cleanup pass `structure/rewrite.rs`, deleted with the legacy decompiler in 51b9d6a9 (2026-10-10) and not replaced: while and do-while rotation (the certificate supports both, the writer emits only `for(;;)`), switch-tail absorption, bounded tail duplication of returns, short-circuit `if`, and return into arms. 2026-10-22 measurement on DecBench (`tests/decbench/RESULT-2026-10-17.md`): this is why 40.2% of r2s's scored functions end in a goto.
- S3: DecBench read 680 of 860, every mean above the previous run.
- S2, four of the five (2026-10-22, B5): short-circuit `if` as condition chains (`structure/condition.rs`), `while` and
  `do-while` rotation (`structure/rotate.rs`) with the latch's copies written before its test (`structure/latch.rs`),
  return into arms (`tails::join_returns`) and bounded tail duplication of returns (`tails::inline_tails`); switch-tail
  absorption is still not replaced. See "the recoveries together" below.

- S4 (2026-10-22): the recoveries below, each checked by `I_S` on its result.

## Left

- Labels over functions the old structurer handled exceed what it rendered. Exit: no more labels than before over that set.
- Node splitting of irreducible entries. Exit: gated by the checker.
- Whether lexical ancestry equals dominance retires `region_does_not_dominate_occurrence`. Exit: placement census measured (post-dominance hoisting and `goto` into scope may move the refusal rather than remove it).

## 2026-10-22: what the gotos cost and what recovers it

A classification of all 1,054 DecBench goto functions (8,353 gotos; 150 bodies read by hand against the source and
the other three tools, a parser classifier over all of them, GED scored with DecBench's own code) found:

- A goto is invisible to GED (labels and gotos add no block). GED scores the block graph. Removing the 40.8% of gotos
  that target a terminal block cuts the goto share from 38.4% to 24.0% and gains one perfect function. The loss is
  the CFG features a goto marks: a missing `&&`/`||` (5 per condition), a shared return where the source has several
  (5 for two returns), `while` against `for(;;)` rotation (3 to 5), and the latch's phi copies (3).
- Rule 8 (never invent control) is the cause of none of the classes but one (a loop exit into a shared open tail,
  4% of gotos, no goto-free spelling). Dominators, loop headers, phi inputs, edge copies and selector constants
  already give the facts every other recovery needs.
- Ranked by measured gain: (1) return into arms at a fallthrough join when the returned value is a phi fed by distinct
  edge copies (+15 perfect with 0 lost; +48 net unguarded, 7 lost); (2) bounded duplication of a terminal block at a
  goto site (-2,590 gotos, +16 with (1)); (3) condition chains as `&&`/`||` by BDD identity of the chain's exit
  function (ceiling 29); (4) inlining a sole-predecessor exit at its edge when its dominator subtree is closed
  (-371 gotos, GED-neutral); (5) hoisting a rotated loop's latch copies (ceiling +17). The join classes (48% of gotos)
  are not worth direct work: another tool is perfect on 3 of 567.
- Replication into fallthrough arms conflicts with section 5 (fewest labels, then fewest duplicated blocks) unless it
  is guarded by the phi-of-distinct-edge-copies condition; amend section 5 or ship only the guarded form.

## 2026-10-23: the guards, and what a copy says

The last two skeptics (50 and 59 mutants of the seam over bash, ls-toybox and pigz, 2,508 functions, and 70,000 base
against tip vectors with no wrong C) left findings open on the chains and the tails. ROADMAP D59 and D60 close them;
what they leave is D61.

**A chain that continues to its own head.** `condition::exits` read an edge back to the head, or to an earlier test
of a chain, as an edge of its DAG. A chain whose second test goes back to its head then found one exit where it has
two (`ExitCount { found: 1 }`), and the stage reverted every chain of the function (bash `0x2e540`). Only an edge to a
later test is inside the DAG; any other edge to a member leaves it, as a lone test's always did. Over bash, ld-2.31.so,
fedora_32_bin_ls, ls-toybox, pigz, bashbot O0 and static-glibc (3,765 functions) 12 functions change, none is newly
refused, no goto or residual site is added; eleven move only control lines (more `&&`, `do`/`while` for `for (;;)`,
fewer `break`, the statements equal) and pigz `get_header` writes one copy fewer of a two-statement tail. The engine
program, `top: movzx edx, [rdi]; add rdi, 1; test dl, dl; je done; cmp dl, 0x3a; jne top; done: lea rax, [rdi - 1]`,
rendered two tests in a `for (;;)` and renders `do { c = *p; q = p + 1; p = q; } while (c != 0 && c != 58); return q - 1;`.

**De Morgan.** `rotate::negated` swaps the connective when a loop leaves on a chain's true side. No hand loop at O0 to
Os and none of the 2,508 functions reached it (R1, `let flipped = op;`, survived everything), because a chain that
continues to its head could not be written. D59's program does not reach it either: its continue carries a copy, so
that arm is the `if`'s body and the chain is spelled on the side the loop stays by. Where nothing is copied on the way
round both exits are bare and the chain is spelled on the exit with fewer negations, the one the loop leaves by; the
engine test for that program (`a_loop_that_leaves_on_a_chain_stays_on_both_tests_negated`: `do { ... } while (c != 0
&& c != 58)`) and the unit test beside the rotation each fail with only the connective kept.

**The latch hoist's guards.** Each of the three data guards has an engine test that fails with only it removed, and one
test each: a test that reads what the copy writes (`a_copy_stays_on_its_arm_when_the_test_reads_the_variable_it_writes`),
code after the loop that reads it (a tail too long to copy to its jumps, read after the loop as in pigz `0x4079f0`; the
rule cannot tell which exit reads, so it is conservative where the reader is an exit taken before the latch), and a
test on an unproven call (a copy is not moved across a test that traps where its cell is unproven).

**Statements.** See "The statements of a block" in section 3. Mutants of the previous skeptic that were invisible to
the certificate, run again on this tree through the corpus (3,765 functions of seven binaries, the skeptic's three
binaries among them): L5, the hoist drops its copies: 543 functions change, the certificate reverts the stage in every
one and none loses a statement (before, 388 of 388 changed functions passed); T2, a tail copy drops its first
statement: 488 change and the certificate refuses all 488 (before, 207 of 280 refused and 73 passed); T12, a joined
return's copy drops its first statement: 204 change, 204 refused (before, 144 of 144). The latch hoist took any
assignment of its arm for a copy until the certificate refused it in four functions; it moves only copies an edge
carries.

**Chain members, one owner.** The text decides (section 3); r2ssa's `owes_only_its_branch` is deleted, with the
`NotInert` fault and the certificate's `inert` parameter. Forced to `true` it moved 0 of 3,765 renderings, a condition
holds a load in none of them, and the text refused every program the engine tests build that it refused. The statement
clause is what reads a member's text where the fact claimed to.

**Mutants that were dead code or equal.** `judge`'s `exact` flag (C1) could not change a verdict: a chain head's
terminator is a conditional branch and its two exits differ, so neither the switch nor the converted-conditional
reading can hold; it is gone. A faulted chain's head is skipped, so the chain is the one violation (C4): the test now
asserts exactly one. `remove_run`'s `named` check (T3) was redundant by construction: every `goto` to a label inside a
resolved run was copied, since the run's suffix resolves where the run does; it is gone. The order `append_to_ends`
visits arm ends (T9) changes which end keeps the original's markers and nothing a line, a link or the certificate
reads; the comment no longer claims an order.

**The sweep again.** 61 mutants (the skeptic's 50 and 11 of this change), run against r2dec's unit tests, then the
engine's where those pass, then the golden census: 5 no longer apply (C1, T3, V2 are deleted code; S8 and V4 are
rewritten as S8b and V4b, both killed); of the 56 that run, 42 are killed by unit tests, 8 more by engine tests (S7,
T10, P2, V1, C7, N5, N10, V4b), and 6 survive both: C3, T7 and T13 are
killed by the golden census only (1, 5 and 3 tests), S5 and S6 (the final and the stage roles without the never-returns
evidence) were killed by the corpus only (70 functions refused, 37 changed with 5 more gotos, the skeptic's figures)
until the engine test `an_arm_ending_in_a_call_declared_never_to_return_is_a_conjunction_that_leaves_by_it` (a
conjunction whose exit arm calls `exit`: S5 refuses it, S6 reverts the chain) killed both, and T9 is equal. All 11
mutants of the statement clause, the edge copies and the hoist's copy test die. ROADMAP D61 holds the three
census-only guards.

**Cost.** The statement clause is one pass over the markers met and one over the markers written per certificate, and
a certificate runs once per stage that changed the body and once at the end. Release `pdd` with `aa`, two runs each,
instructions retired, base then this branch: 0pack `0x62ecf0` 71.793G and 71.704G against 71.721G and 71.721G,
pumasim `0x23fdf0` 84.958G and 84.986G against 84.985G and 85.027G (from -0.1% to +0.1%), peak RSS 283 to 301 MB in
both, the renderings byte-identical. Over every function of 0pack and pumasim (23,213, mangled names included) 8
change, all of them the loops D59 reads (a `for (;;)` with a chain's two empty arms and a `break` becomes
`do { ... } while (a || b)`; pumasim `0x2ed240` also writes one statement of a tail once), none is newly refused and
none gains a goto or a residual site. Over bash, ld-2.31.so, fedora_32_bin_ls, ls-toybox, pigz, bashbot O0 and
static-glibc with every name (3,953 functions) the 12 of D59 change and no other.

## 2026-10-23: the guards and the spelling order, stacked

D59 and D60 (the guards) and D58 (D2 spells every block once, in reverse postorder, before this section's placement
writes any; "D2's spelling order" in adr-decompiler-rewrite.md) landed on one base and stack in this order. They meet
in three places. An edge's copy is spelled by `render::spelled` as `EdgeText::Copies` and marked by the Writer as a
statement of the block it leaves (`observe_copy`), which is what I_T counts and what the latch hoist moves. The latch
hoist's reads are counted once for the whole function (`Scan`) and its copy test asks `Placed::edge_copy`. A chain
member is a test whose text is nothing else, so the regions index asks only `test_block`.

No function changes under both: over bash, ls-toybox, pigz, 0pack and pumasim (25,735 listed functions) 17 change under
the guards alone and 55 under the spelling order alone, none is newly refused, and the effects add: residual sites
0pack 47,850 (base), 47,850 (guards), 47,898 (both); pumasim 67,628, 67,628, 67,644; bash 10,316, 10,316, 10,322;
ls-toybox 7,902, 7,902, 7,905; pigz 1,301 throughout. One function gains a goto, bash `0x48140` (1 to 2): D58's rule
reads its tail's `r13_4` as a residual (a forward copy into the merge is a gap), and a skipped block that holds a
residual is not copied into the arms that fall to it (D61 (3)). The write orders: O1, O2 and O3 differ 0, 0, 0 over
bash, ls-toybox and pigz (2,508 functions) at the tip, against 0, 120 and 187 on the base with the knobs alone; the
text moves in 64, 332 and 720 functions, so the knobs are live.

On the mined set (1,570 functions, 1,305 scored, DecBench's GED, the method of the section below):

| Build | Perfect | Mean GED | Total GED | Gotos | Functions with a goto | Held out gotos |
|---|---|---|---|---|---|---|
| base | 206 | 43.795 | 57,153 | 2,661 | 426 | 2,100 |
| and the guards | 206 | 43.795 | 57,153 | 2,661 | 426 | 2,098 |
| and the spelling order, the tip | 206 | 43.795 | 57,153 | 2,661 | 426 | 2,098 |

The guards change no mined-set function. The spelling order changes the text of eight (`inflateCopy` of zlib's four
programs at two optimisation levels: its block-transfer locals are numbered `_2` in reverse postorder) and no graph, so
no GED moves. Held out (23 of radare2's test ELFs, 1,834 functions): rendered 1,496 and refused 338 in every build, none
crashed; the 2 gotos fewer are fedora_32_bin_ls `0xe690` (36 to 34, the chain that continues to its head). Release
`pdd` with `aa`, instructions retired, base, guards, tip, mean of two runs: 0pack `0x62ecf0` 71.71G, 71.78G, 71.75G;
`0x58e3d0` 81.12G, 81.15G, 81.19G; `0x4e5f90` 60.35G, 60.39G, 60.35G; pumasim `0x23fdf0` 84.95G, 85.00G, 85.02G;
`0x1fafb0` 70.03G, 70.06G, 70.02G; `0x2312c0` 73.11G, 73.15G, 73.13G (from -0.02% to +0.10%), peak footprint 156 to 278
MB in every build, the six renderings byte-identical. The census goldens (442) and `stable_temporaries` (24) hold byte
for byte at both heads, so nothing was blessed. The equivalence gate on the tip holds all 828 baseline records on x86-64
(744 equal, 63 residual-trap, 1 slow, 20 unsupported) and on AArch64 (750 equal, 57 residual-trap, 1 slow, 20 unsupported) with none differing.

## 2026-10-23: the noreturn guard

**Invariant.** `if (c) { ...; f(); } else { rest }` where the then arm's last statement is a call to a callee declared never
to return is `if (c) { ...; f(); } rest`: control cannot leave the arm by its end, so `rest` runs on exactly the paths the
else arm took, in the same order, and the machine's edges are the same (the then block has none out of the call; the
`if` without an `else` falls to `rest` on the false edge). Owner: `structure/guard.rs`, the last stage of
`render::structured` (after loop rotation, so it reads what the counterfactual measured and no earlier stage sees a
changed tree). Evidence: `Evidence::never_returns`, the predicate the tails and the certificate already read, which is
the callee's declaration (r2abi's prototype, or r2engine's walk finding no fall-through after the call), never its name.
The stage is kept only while the control certificate holds and is reverted whole otherwise (section 5); the checker
reads the arm's end through the same predicate, so a guard on a call the machine returns from leaves an edge the
block does not have, which section 3 (ii) refuses (`a_guard_the_machine_does_not_have_fails_the_certificate`).
O(statements): each statement is visited once, both arms of an `if` before it is judged, and the statements a guard
frees join the sequence the `if` sits in; the walk recurses to the tree's depth, as the certificate's does.

**The other arm.** `if (c) { rest } else { f(); }` is `if (!c) { f(); } rest`: the call is the guard's body, so the
test is the machine's other edge. A test the lowering wrote carries no marker, and the certificate reads a negation
only over a marked atom (sections 3 and 5; swapped arms under an unmarked test are an `EdgeMismatch`), so the guard
writes the test as one atom carrying copies of the `if`'s markers, as rotation does for a loop (`condition::as_atoms`
and `condition::negated`, which `rotate` now shares), and `respell_negations` writes the opposite comparison once the
final certificate has read the `!`. It does not apply to an `if` nothing observed (no markers to copy). An arm ending
in `return`, `break` or `continue` is not a guard here: the counterfactual gained nothing from it over the noreturn guard.

**Both arms, or neither.** The guard needs a continuation: it applies when exactly one arm ends in the call. Where both do
nothing runs past either, and writing one as the guard writes the other arm's statements as if the function went on
after it. The first build did not ask and lost the one perfect row it could (bzip2 `mySIGSEGVorSIGBUScatcher`, `if (c == 1)
{ cleanUpAndFail(3); } else { showFileNames(); cleanUpAndFail(2); }`, GED 0 to 6).

**Why GED rewards it, and why that is not the reason.** Joern's CFG joins a call to the statement after it, so the
source's `if (p == NULL) exit(1); rest` has the edge `exit -> rest` that the machine does not, and the rendering with
an `else` lacks it. The text is the same program by the callee's contract; the score is the benchmark reading the
source's spelling, and a source that wrote the `else` loses (27 of 275 renderings moved worse in the counterfactual).
The counterfactual's 275 "changed" renderings are the ones that declare a noreturn callee, not the ones with a site:
its respelling also rewrites the trailing newline, and on the mined set 103 renderings change in text and the build
changes 107.

**Measured.** Mined set (bzip2, zlib and grep at O2 and O2-noinline, 1,639 functions dumped, 1,595 scored by DecBench's own
GED, `tests/decbench/mined_set.py`, base `a0d9e34a` against `23728d11`):

| Build | Perfect | Mean GED | Total GED | Better / worse | Gotos | Refused (newly) | Text changed |
|---|---|---|---|---|---|---|---|
| base | 261 | 43.99 | 70,163 | | 3,480 in 507 functions | 40 | |
| the then arm alone (`089bfd50` with the else swap off) | 267 (+7, 1 lost) | 43.93 | 70,063 | 45 / 14 | same | 40 (0) | 107 |
| then and else arm (`089bfd50`) | 267 (+7, 1 lost) | 43.91 | 70,035 | 50 / 14 | same | 40 (0) | 115 |
| and the exactly-one-arm rule (`23728d11`) | 268 (+7, 0 lost) | 43.91 | 70,040 | 45 / 13 | same | 40 (0) | 108 |

The else arm adds -28 at `089bfd50` over the then arm alone (11 rows better, 3 worse: zlib `test_dict_inflate` six rows, grep
`kwsincr` and `update_patterns` two each, bzip2recover `main`; against grep `EGexecute` twice and bzip2 `uncompress`).
The python respelling of `counterfactual_ged.py` on the base renderings of the same set gives 267 (+7, 1 lost) and 70,071
(the then-arm build: 70,063, four more sites). 199 sites stand in the base renderings (182 then arms, 17 else arms, counted on
the text) and none in the head's. The 13 functions that score worse, by 1 to 6 each: `bsGetBit`, `EGexecute` (two rows),
`compressStream`, `uncompress`, `uncompressStream`, grep `main`, `test_flush` (six rows, zlib's three programs at two
levels); the one read through its CFGs, `test_flush`, is one edge misaligned, not a defect: 11 nodes and 13 edges before and
after with one edge moved, against a source of 10 nodes and 14 edges in which only the function's end has no successor, so Joern reads
each `exit(1)` of the source as going on. The changed renderings by class (a classifier over the text:
A, the same statement lines in the same order; B, the same lines in another order with only `if` tests differing, which is
an else arm swapped; C, anything else): 66 A, 34 B and 8 C pairs (24, 16 and 2 functions). The 8 C pairs are
`test_large_deflate` and zlib's shell test `test_dict_inflate`, read by hand: a large else arm that ends in `exit(1)` is the
guard and its small then arm follows, the residual sites renumber in text order and no site is added or dropped, and a
`goto` into the swapped arm keeps its label. The class B diffs read the same way, from an empty then arm
(`if (x == 119) {} else { fcn_1ac0(); }` is now `if (x != 119) { fcn_1ac0(); }`, bzip2recover `bsClose`) to the nested
chains of zlib's `test_gzio`.

The census (442 goldens and 24 `stable_temporaries`) moves nowhere: no census binary calls a function that never returns.
Over bash (1,568 functions), ls-toybox (1,148), pigz (222), 0pack (8,699) and pumasim (15,298), every function `afl` lists, 26,935
in all, base against head by release `pddj` after one `aa` (sessions sharded six ways): 1,136 renderings change (43, 31, 14,
841 and 207), none is newly refused, newly rendered or crashed, the gotos (27,108 in 3,921 functions) and the residual sites
(157,006) are the same in both builds, and 3,035 `else` arms and as many lines are gone. By class: 828 move only braces and
indentation (the same statement lines in the same order), 308 swap an else arm (the same lines in another order, only the
`if` tests differing), and none is anything else once the residual site numbers, which follow text order, are set aside.
Read by hand: the 14 pairs the classifier first left in C before it set the numbers aside (ls-toybox `0x54298` and
`0x61778`, pigz `0x402c10`, eleven of 0pack's) and the smallest diffs of each binary. 0pack `0x491dee`,
`if (r == 0) { return x; } else { __throw_system_error(e); }` is `if (r != 0) { __throw_system_error(e); } return x;`;
0pack `0x47ca92`, the string constructor's `if (p != 0) { ...two writes... } else { __cxa_throw(...); }` is
`if (p == 0) { __cxa_throw(...); }` and the writes after it; pumasim `0x27dec0`, `if (a <= 0 || b >= c) {} else { fwrite(...);
exit(1); }` is `if (a > 0 && b < c) { fwrite(...); exit(1); }`, a chain negated over its marked atoms; 0pack `0x6e3990`,
`if (c != 97) { on_error(this); } else { goto L8; }` is `if (c != 97) { on_error(this); } goto L8;`; bash `0x435f0`, empty
then arms become guards. No stage was reverted by the certificate over the 1,518 functions of the mined binaries that
`R2DEC_TRACE_REFUSAL` was run on (bzip2 and grep at both levels, zlib's `example` at O2).
Held-out set, report only (bash, diffutils, findutils, gzip and libexpat at O2 and O2-noinline, 5,150 functions by `mined_set.py dump`):
203 renderings change (bash 112, diffutils 35, findutils 26, gzip 28, libexpat 2), 131 only in braces and indentation and 72 an
else arm swapped, none newly refused, gotos 13,098 and residual sites 33,918 unchanged. DecBench's GED over the 4,759 scored: perfect 1,350 to 1,357 (7 newly, 0 lost), mean 24.74 to 24.71,
total 117,742 to 117,595 (-147), 80 functions better and 33 worse (by 1 to 4); no rule was chosen by reading it.
Release `pdd` with `aa` on Apple M5, instructions retired, base then head, two runs each: 0pack `0x62ecf0` 71.97G and 71.87G
against 72.09G and 71.91G (+0.11% on the means; the rendering is class A, 21 fewer `else` and 21 fewer lines, 15 gotos
before and after), pumasim `0x23fdf0` 85.18G and 85.18G against 85.14G and 85.16G (byte-identical); peak footprint 250 to 269
MB in both. The stage's own cost is one clone of the body (the cost every stage pays) and one walk.

## 2026-10-22: the recoveries together

Two branches landed on one base and stack in this order: condition chains, `while`/`do-while` and the latch's
copies written before its test (B5-b), then joined returns, terminal tails, sole closed exits and a callee's
declaration read in address order (B5-a). The marker table is one type, `shape::Occurrences`, which implements
`condition::Marks`, so a block's text copied by any stage is an occurrence of that block the certificate reads. In
`render` the order is: placement (a sole closed exit is written where its edge leaves the loop), condition chains
(a stage), `shape` (jumps to the next position, joined returns, the skipped-block copy, terminal tails), the
latch's copies (a stage), loop rotation (a stage) and the noreturn guard (a stage). A stage stands only while the control certificate holds,
`shape`'s copies are certified at the end, and `respell_negations` is the one change after the certificate.

Measured on the mined set (bzip2, zlib and grep at O2 and O2-noinline: 1,570 functions, 1,305 scored in all three
builds) with DecBench's own GED. One method for the three builds: the renderings come from each build on the Mac and
are scored on contabo. These are mined-set numbers.

| Build | Perfect | Mean GED | Total GED | Gotos | Functions with a goto |
|---|---|---|---|---|---|
| base `cb16ec2e` | 203 | 46.095 | 60,154 | 4,654 | 623 |
| chains, rotation, latch copies `0a654255` | 197 (0 newly, 6 lost) | 45.195 | 58,980 (-1,174) | 4,578 | 615 |
| and the tails, the stack's head | 206 (10 newly, 1 lost against the step before) | 43.795 | 57,153 (-1,827 more, -3,001 in all) | 2,661 | 426 |

Held out (23 of radare2's test ELFs, 1,834 functions, none of them mined): rendered 1,496 and refused 338 in every
build, the same 338 functions, none crashed; gotos 2,941, 2,915 and 2,100. One function gains gotos over the base:
freebsd-ls `0x205b40`, 0 to 2. Its skipped block holds a residual cell and the base wrote it into two arms, two
residual sites for one unproven cell; `tails::copyable` is asked of every copy, so the block is written once and the
two arms jump to it. That is the visible residual rule 8 prefers to a duplicated one, and the one case the tails'
own held-out sweep ("no function gains a goto") did not see, since it ran before the rule reached the skipped-block
copy. The equivalence gate on the stack's head holds all 828 baseline records on x86-64 (744 equal, 63
residual-trap, 1 slow, 20 unsupported) and on AArch64 (750, 57, 1, 20) with none differing. Release `pdd` (with `aa`, 2 runs) on the two named
functions and the two largest others of each of 0pack and pumasim moves -0.16% to +0.10% instructions retired against
the base, with peak RSS 191 to 303 MB in every build.

**Kept costs.** The chains cost 0.2 mean GED and win none on the set they were measured on, and the latch's copies
take 438 loops to `do-while` for 0.98 less mean GED at the price of 5 perfect (a single-block source `for` scores
better as a `for (;;)`); the three stages together are 197 perfect for 203 and 0.9 mean GED fewer on this set. Both
are kept for the reason in the section below: they spell the machine's test and loop as the CFG proves them, nothing
was tuned to the score, and the benchmark rewards the source's spelling, which the binary does not state. The tails
win the perfect count back (10 newly perfect, 1 lost) and take 1,917 gotos away. No recovery is added or dropped to
move the sum.

**Ledgered, not fixed here.** ROADMAP D59 (a chain whose exit is a `continue` to its own head faulted `ExitCount` and
reverted every chain of the function: bash `0x2e540`) and D60 (the certificate asked nothing of a copy's statements)
are closed in "2026-10-23: the guards, and what a copy says", and D61 holds what they leave. ROADMAP D58 was ledgered
here and has landed since: whether a statement renders and whether a name reads as a value or as a NeverAssigned
residual are spelled once, in reverse postorder, before this section's placement writes anything ("D2's spelling
order" in adr-decompiler-rewrite.md), so none of this section's write orders reaches a verdict.

**Left**, by when:

- Next: the assignment before a copied or joined return, folded at the owner that spells the edge copy
  (`return a;`); the exit edge's copies after a loop whose only exit is the latch (about 140 loops); D61.
- Conditional: the four-statement bound and the skipped-block-first order were chosen on the mined set, so they move
  with a measurement on projects the analysis did not mine; the unguarded join (+17, 2 lost), only with a CFG fact that
  separates `return a || b` from two returns; a `while` whose exit arm is not a bare `break` (34 loops), once the exit
  is the only way out.
- Deferred: chains whose DAG is not read-once (a selection between two tests); splitting a chain around a block that
  renders text; node splitting of irreducible entries; tails of five to sixteen statements (133 gotos) and jumps over
  a block no rule closes (588); the AArch64 mined set, not measured.
- Unnecessary: the lowest-common-ancestor count for closedness, whose answer the O(B + E) interval extremes give.

## 2026-10-22: condition chains, loop rotation and latch copies

Three of the recoveries the goto analysis ranked landed in this order, each a stage kept only while the control
certificate holds. Measured on the mined set (bzip2, bzip2recover, zlib's libz, example and minigzip, grep; O2 and
O2-noinline; 1,050 functions, 438 with a non-degenerate source CFG), scored with DecBench's own GED (`vj_ged`,
Joern CFGs), which reproduces the 2026-10-17 run's value for 435 of the 438. These are mined-set numbers.

| Step | Renderings changed | Gotos | Mean GED (scored) | Better / worse | Perfect |
|---|---|---|---|---|---|
| base (`d4792d55`) | | 4,143 | 49.11 | | 60 |
| condition chains | 251 | 4,080 | 49.31 | 14 / 51 | 60 (0 newly, 0 lost) |
| while and do-while | +21 loops | 4,080 | 49.31 | 0 / 0 | 60 |
| latch copies | +438 do-whiles | 4,080 | 48.33 | 72 / 12 against the step before | 55 (0 newly, 5 lost) |

Counting each function once (zlib's code also sits in `example` and `minigzip`): 302 scored, mean 47.97, then
48.14 after chains, 47.13 at the end; perfect 48 to 45.

**Condition chains.** Invariant: a decision DAG of blocks that render nothing but their test, two exits, the test
equal to the DAG's exit function by BDD identity. Owner: `structure/condition.rs` (derivation, BDD, check).
O(statements) with at most 16 blocks per head. Rejected: matching
the nested `if` text alone (it cannot see a shared test reached by `goto`, and the checker would infer the chain), and
a name or flag-pattern check for the blocks. The GED got worse, not better: Joern builds a node for each operand of
`&&` and `||` and one for the whole test, so a collapse costs a node and pays only where the source spelled `&&` and
everything else about the function already matches; 13 functions rose by exactly 3. The text is the machine's graph
and reads as the source's (`gate_three`, `bounded_fetch`, `BZ2_bzWriteOpen`'s five-way `||`); the benchmark does not
reward it on this set (analysis ceiling 29 newly perfect, measured 0). Only the DAGs that are read-once collapse:
`a ? (b ? X : Y) : (c ? X : Y)` is refused as `NotShortCircuit`.

**While and do-while.** Invariant: the body is just the header's marked `if` with a bare `break` on one arm, or ends
in the latch's with nothing else going back to the top. Owner: `structure/rotate.rs`, O(statements). The 21 loops
that rotated are GED-neutral. 747 `for (;;)` remain: 450 have an exit arm that is not a bare `break` (many carry the
exit edge's merge copies), 137 a staying arm that is more than copies, 90 copies the next recovery's conditions
refuse, 34 a header `if` with no bare `break` arm.

**Latch copies.** Invariant: the staying arm is plain assignments, the test calls and writes nothing and reads none
of them, nothing of the function outside the loop reads them, no `continue` would reach the test. Owner:
`structure/latch.rs`; the proof is the text's own def-use. Rejected: an r2ssa liveness fact (it is per SSA value, and D2
folds single-use values into the test and names them as C objects, which only the text states). 438 loops become
`do-while`; fnv1a32 and djb2 read as the source's loop. Against the source's `for` it is mixed (each function once):
44 functions improve (22 by exactly 3, the analysis's micro case, up to 34) and 8 worsen, and 3 functions that were perfect are not
(`uInt64_to_double`, `prepare_new_block`, `init_block`): Joern scores a `for` as a cycle of the test and the body, and
a `for (;;)` with the copies on the staying arm is the same two-node cycle, while a `do-while` over one block is a
single node, so a single-block `for` source scores worse as a `do-while` and a multi-block one better.

**Decision: both are kept.** Chains cost 0.2 mean GED (49.11 to 49.31) and win none (13 unique functions rise by
exactly 3; the analysis ceiling was 29 newly perfect, measured 0). `do-while` over a single-block source `for` loses 5
perfect across all binaries (3 unique) while winning 44 functions (22 by exactly 3) and 0.98 mean GED (49.31 to 48.33).
They spell the machine's test and loop as the CFG proves them, nothing was tuned to the score, and the benchmark
rewards the source's spelling, which the binary does not state. The cost is the price of the machine's graph, not a
regression to chase: the next reader should not rediscover it, and no recovery is added or dropped to move it.

What is left of the chains is in "the recoveries together".

## 2026-10-22: terminal tails, joined returns and sole exits

The goto analysis above ranked what the gotos cost on DecBench: GED scores the block graph, a label
adds no block, and the loss is a shared return where the source has several, a missing `&&`/`||`,
`while` against `for (;;)`, and a latch arm's copies. These three landed on top of the chains, each with a
unit test that fails without it, a counter-test where it must not fire, a behaviour test through
the engine (compiled and run) and a `tests/db/cmd/structure` golden on a real function:

- Joined returns (`tails::join_returns`, evidence `Values::returns_distinct_merge`).
- Terminal tails at their jumps, through the blocks after them and through jumps to other tails
  (`tails::inline_tails`), after the skipped-block copy.
- Sole closed exits (`Placement::inline_exits`, `closed_subtrees`).

Measured with the tails alone on the base before the stack, on bzip2, zlib and grep at O2 and
O2-noinline (1,305 to 1,313 binary-function pairs scored in both, 552 distinct functions): these are
projects the analysis mined, so the numbers are mined-set numbers. The stack's are above. Perfect is GED 0 under DecBench's own code, run on contabo over the tip
build's output and each step's (the tip reproduces the 2026-10-17 run's GED on 1,308 of 1,313):

| step | perfect | total GED against the tip | gotos | functions with a goto |
|---|---|---|---|---|
| tip | 203 | 0 | 4,654 | 623 |
| joined returns | 207 (+5, 1 lost) | -213 | 4,654 | 623 |
| tails at their jumps, first order | 199 (+5, 9 lost) | -1,833 | 3,474 | 499 |
| sole closed exits | 199 | -1,835 | 3,460 | 497 |
| skipped block first | 211 (+9, 1 lost) | -1,759 | 3,472 | 497 |
| runs through blocks and jumps | 212 (+10, 1 lost) | -1,937 | 2,694 | 426 |

The 212 are 102 distinct functions of 552 (96 at the tip); the ten new are seven (level, function)
pairs, `BZ2_bzCompressEnd` and `BZ2_bzDecompressEnd` at both levels, `myfeof`, `buf_has_encoding_errors`
and `inflateUndermine` at one (the zlib ones in four binaries); the one lost is `skip_devices`, whose
source is `return a || b`. The unguarded join on the first step: 218 perfect (+17, 2 lost), total GED -452.
Over the 558 distinct functions the goto classes of the analysis go from 2,214 to 1,356: TR1 487 to 22,
TR4 246 to 23, FW 580 to 237; left are JN 305 and JNB 283 (a jump over a block no rule closes), FW 237,
LX 139 (an exit that is not closed), TR16 133 (a tail of five to sixteen statements), SP 86, CC 68,
IR 57.

What is left of the tails is in "the recoveries together".

## 2026-10-23: what the chain and latch passes cost

Review of #328 asked for both passes' bounds. Counted inside the passes on the 5,688 functions that reach the chain
stage (bash, ls-toybox, pigz and libc-2.32.so, of the 6,144 `afl` lists) and on 0pack's 0x58e3d0 and 0x62ecf0 and
fifty of pumasim's largest: 148,668 sequences, the longest 5,743 statements.

**Condition chains: a sequence is indexed once.** Invariant: the statements a chain removes are the regions it
consumes, and no position in a sequence moves while it is walked. Owner: `structure/condition.rs`. `Pass::sequence`
read every statement again to find the regions after each chain (k chains in n statements read O(k·n), and
`Vec::remove` shifted the tail for each region), so 200 sibling chains read 81,200 statements before and 1,200 now.
The index is built once; a chain takes the labels it consumes out of it, their statements stay where they are, and one
pass drops them when the sequence ends, so a sequence costs O(n) plus its chains' own text. Iteration stays ascending,
since descending can change which chains collapse. On the corpus the claim was real and bounded: 1,365 sequences held
a chain and none held two, so the re-reading was 9,011 of 885,426 statement reads (1.0%), at most 1,532 in one function
(libc 0x97e10). A consumed region is skipped, not read for chains of its own (the old removal made that so;
`a_consumed_region_is_not_read_for_chains_of_its_own` pins it).

**Latch copies: the reads are counted once.** Invariant: a loop's copies are written before its test only when every
read of each is inside the loop. Owner: `structure/latch.rs`. `may_hoist` counted the reads of the whole loop body for
each candidate latch, so a statement was counted once per enclosing candidate (O(n·d) for depth d): 50 nested loops
counted 8,100 expressions and 100 counted 31,200 (450 and 900 now). One scan counts the reads of the function and, for
each `for (;;)`, takes the reads of its copies inside the loop as the count at its exit less the count at its entry; a
second walk writes the loops the scan allowed, in the order the scan met them. The scan reads each expression once and
the walk touches no expression, whatever the depth. The scan takes the latch's shape before the loop's body is
rewritten, where the old pass took it after the inner loops were: `live`, `parts` and `continues` stop at a nested
loop and a rewrite only moves statements, so the shape and the counts agree (the census, byte for byte, is the check).
On the corpus the claim was real and bounded: a candidate loop sits at most 5 loops deep (4,993 of 5,688 functions have
no candidate, then 492, 158, 30, 13 and 2 by the deepest one's depth), and the per-latch rescans were 366,432 of
7,704,538 expression visits (4.8%). The worst function, libc 0x16b210, has 16 candidates side by side, which repeat
nothing: only nesting repeats a statement.
