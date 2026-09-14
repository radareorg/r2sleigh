# ADR: control structure is the dominator tree; everything else is an edge spelling

Status: built, measured and landed. S3's DecBench run read 680 of 860 with
every mean above the run before it; see the sections at the end. The
ordering -- this before the value-identity rewrite -- was decided with the user
on 2026-09-10. Read `doc/adr-location-ssa.md`
for the layer contract this sits inside and `doc/handoff-location-ssa.md` from
"A third of what we render has no structure" onward for the evidence.

Every claim below is marked **verified** (read from the code this session, with
the site named) or **to check** (a hypothesis with the check that decides it).
Nothing is a finding until its check has run.

## 1. What is wrong, as one statement

The structurer recognises shapes and then proves, after the fact, that the
shapes it emitted cover the function. Recognition is partial, so placement
falls to whichever of seven mechanisms matches first, and the proof is a
boolean-formula equality that is exponential in the nesting depth.

**Verified.** The seven mechanisms that answer "where is block *x* written":

| mechanism | site |
| --- | --- |
| recursive builder | `region.rs:591` `analyze_region_recursive` |
| iterative builder, entered only when the function has a loop | `region.rs:1340`, early return at `:1346` |
| path copying of a partial join into every path | `region.rs:1467` `working_join_requires_path_copy` |
| hoisted joins placed once behind a label | `region.rs:1957` `hoisted_joins` |
| shared joins appended after the body | `structure.rs:2940` `append_shared_joins` |
| a merge deferred to a sequence sibling | `structure.rs:3092` `sequence_owned_merge` |
| a multi-exit continuation | `Region::MultiExit`, and the second attempt on `wip/multi-exit-continuation` |

and the proof machinery they feed:

| proof | site |
| --- | --- |
| rendered domain as a disjunction of guard conjunctions | `structure.rs:241` `RenderedBlockDomain`, `active_domains: Vec<_>` at `:188` |
| join certification by domain union | `structure.rs:1453` `certify_transfer_domain_join` |
| coverage backstop | `validate_rendered_block_domain_coverage` |
| five-field loop identity check | `structure.rs:770` `exact_rendered_loop_id` |
| the give-up channel | `safety_reason`, set at 29 sites in `structure.rs` |
| the fallback that renders the function again without structure | `consumer_structured.rs:35` `primary_native_body`, `lib.rs:2888` `linearize_function_body` |

Every structural refusal class in both censuses is a face of this: 207 of 744
local functions rendered without structure, `unrepresentable operation` (the
linearizer refusing a switch, `lib.rs:2906`), the structuring deadline, the
irreducible-cycle refusal, the loop-condition mismatch, the control-domain
coverage mismatch, and the multi-exit forwarder.

## 2. The object

A function's control-flow graph is

    G = (B, E, entry)

with `B` the blocks and `E ⊆ B × L × B` a multiset of labelled edges, where the
label `L` is what the block's terminator says about the edge. **Verified** the
terminator vocabulary is closed (`cfg.rs:50` `BlockTerminator`):

| terminator | edges it contributes |
| --- | --- |
| `Fallthrough {next}`, `Branch {target}` | one `Normal` edge |
| `ConditionalBranch {true_target, false_target}` | one `True` edge, one `False` edge, against the block's certified predicate |
| `Switch {cases, default}` | one edge per distinct target, labelled with the set of case values that reach it, plus one `Default` edge |
| `Call {fallthrough}`, `IndirectCall {fallthrough}` | one `Normal` edge when the call returns |
| `Return` | none; the block ends the function |
| `None` | none; the source declared the block terminal (a noreturn call or a trap) |
| `IndirectBranch` | the declared successors if the source resolved them, else none |

`CFGEdge::Back` (`cfg.rs:497`) is not a label of the object; it is a property
of an edge relative to the dominator tree, and it is derived below.

Two derived structures, both already computed in `r2ssa`:

  * the dominator tree `D` (`domtree.rs`, with `idom`, `children`, `dominates`),
    and a reverse postorder `rpo: B → ℕ` (`cfg.rs:772`);
  * the natural loops: an edge `(x, y)` is a back edge iff `y` dominates `x`;
    the body of the loop headed by `h` is `h` together with every block that
    reaches a latch of `h` without passing through `h`. **Verified** these are
    the `StructuredLoopFact` bodies (`semantic.rs`), and a block that lies on a
    cycle but in no natural loop is collected by
    `collect_unstructured_cycle_blocks` (`semantic.rs:9503`).

Definitions used throughout:

  * a **forward** edge is one that is not a back edge;
  * a block is a **merge** block iff it has two or more forward in-edges;
  * a block `y` is a **non-merge child** of `x` iff its only forward in-edge
    comes from `x`.

**Lemma 1.** A non-merge child `y` of `x` is a child of `x` in `D`.
*Proof.* Every path from `entry` to `y` first arrives at `y` by a forward edge,
because a back edge into `y` requires `y` to dominate its source, which cannot
happen before `y` has been reached. The only forward edge into `y` leaves `x`,
so every path to `y` passes through `x`, and no block strictly between `x` and
`y` on the tree can exist because `x` is adjacent to `y`. ∎

**Lemma 2 (exit subtrees are whole).** Let `h` head a natural loop with body
`body(h)`. If `x ∈ body(h)` dominates `y ∉ body(h)`, then no block dominated by
`y` is in `body(h)`.
*Proof.* Suppose `d ∈ body(h)` is dominated by `y`. Take any path from `entry`
to `d` and its suffix after the last occurrence of `h`; that suffix is `h`-free
and ends at `d`. If `y` were absent from every such suffix, then `y` would
precede `h` on every path to `d`, so `y` would dominate `h`; but `h` dominates
`x` which dominates `y`, so `y = h`, contradicting `y ∉ body(h)`. Hence `y` lies
on an `h`-free path to `d`, and `d` reaches a latch of `h` without `h`, so `y`
does too, so `y ∈ body(h)`. Contradiction. ∎

## 3. The invariant, which is the certificate

A rendered body is a C statement tree. Reading it as a program yields a labelled
control graph `R` over *occurrences* of blocks: an occurrence is one rendered
copy of one block's statements, and an edge of `R` is one transfer the text
performs, whether by adjacency, an `if` arm, a `switch` arm, `break`,
`continue`, `goto`, or falling off the end of a loop body. Let `π: R → G` map
each occurrence to its block.

    I_S :  (i)   every block of G has at least one occurrence in R, and the
                 entry block's first occurrence is where the body starts;
           (ii)  for every occurrence o of block b, the labelled multiset of
                 out-edges of o, projected through π, equals the labelled
                 multiset of out-edges of b in G;
           (iii) the predicate an `if` tests at an occurrence of b is b's
                 certified predicate, with the polarity the arm labels say,
                 and the selector a `switch` tests is b's certified selector.

That is the whole certificate. It is checked by one generic procedure that
extracts `R` from the AST and compares it with `G`; it does not know how the
tree was built.

**Corollary 1 (paths).** Under `I_S`, for every execution of the rendered text
there is an execution of `G` through the same block sequence, and conversely.
*Proof.* (i) gives a start; (ii) makes the successor relation at every
occurrence exactly the block's; (iii) makes the choice among successors the
machine's choice. Induction on the path length. ∎

**Corollary 2 (domains).** The set of guard sequences under which an occurrence
of `b` is reached equals the set under which `b` is reached in `G`. So the
rendered control domain equals the canonical one *by construction*, and the
disjunctive `RenderedBlockDomain`, `certify_transfer_domain_join` and the
coverage backstop are subsumed. The domain formula is never built; the
exponent goes with it, and not by a bound.

**Corollary 3 (loops).** Body, latches and exits of every loop in `R`, computed
from `R` the way `G` computes them, equal those of `G`. Four of the five fields
`exact_rendered_loop_id` compares are therefore implied. The fifth,
`condition`, is not a graph fact at all; §5 says what becomes of it.

**Corollary 4 (control obligations).** A `ControlTransfer` obligation of block
`b` is discharged iff (ii) holds at every occurrence of `b`; a
`ControlPredicate` obligation iff (iii) holds. One rule replaces the branch
arm at `fold/context.rs:1383` and the "expressed by placement" elision at
`effect_ledger.rs:251`. An unconditional transfer rendered by adjacency is
*rendered*, not elided: it is an edge of `R`.

**Duplication.** Condition (ii) is stated per occurrence, so a block written
twice is admitted as long as each copy carries the block's full out-edge set.
That is exactly `duplicates_are_exclusive` (`observation_journal.rs:785`) as a
graph condition. The totality layer never duplicates; the quality layer may,
under a budget (§5).

**What the extractor reads as an edge.** The extractor is a small interpreter
of C control, and it must model every implicit transfer C has, or a rewrite
could create one the machine does not have: adjacency between statements; an
`if` arm, and the fall-through of an `if` with no `else`; a `switch` arm, and
the fall-through from one `case` body into the next; `break`, which leaves the
innermost enclosing loop *or switch*; `continue`, which reaches the innermost
enclosing loop and passes through a `switch`; `goto`; `return`; the implicit
back edge at the end of a loop body. A `Gap` statement standing for a transfer
is read as the block's declared out-edges, since the gap is the marker that
the transfer was not rendered.

**Terminal calls.** A block with terminator `None` has no out-edges in `G`, so
its occurrence must have none in `R`. The extractor therefore treats a call
statement as ending the occurrence with no out-edge iff the rendered prologue
declares the callee `__attribute__((noreturn))`, and a trap as the target's
builtin for it; any other last statement falls through and (ii) fails. The
spelling is the fact the source holds -- radare2 removed the successor because
it knows the callee never returns -- and it is stated once, in the prologue,
where the compiler reads it too. The S1 gate includes a function whose only
exit is a call to `abort`.

**Condition chains, as an extension of (iii).** The chain rewrites of §5 emit
`if (p₁ || p₂)` and `while (p₁ || p₂)`, and no single certified predicate has
that value. So (iii) admits a compound test: an occurrence may test a Boolean
function `φ` over certified predicates `p₁ … pₖ`, and it then stands for a
**chain** `C ⊆ B`: a set of blocks, each testing one `pᵢ`, whose internal edges
form a DAG entered only at its head, and whose non-head blocks render no
statement of their own -- a chain block with an effect of its own cannot be
folded into a short-circuit expression without reordering that effect. Clause
(ii) is then checked on `C` as one unit: the labelled multiset of edges leaving
`C` in `G` must equal the arms of the compound test, and for every external
target `t` the set of valuations of `p₁ … pₖ` under which `C` exits to `t` must
equal the set under which the compound test selects `t`'s arm. That equality is
a BDD identity, which is what `ControlBdd` is kept for. Each block of `C` still
counts as occurring under (i). The chain is recorded on the occurrence by the
rewrite that made it and verified by the checker; the checker never infers one.


**What the checker needs from the AST, verified as already there.** Block
occurrences carry `StructuredRegionMarker { entry, kind, anchor }`
(`structured_region.rs:109`), so the extractor knows which block a statement
group belongs to without parsing. It needs one addition: an `If` and a
`Switch` occurrence must carry the `PredicateId` with polarity, respectively
the certified selector, so that (iii) is an identity comparison rather than an
expression comparison. Those identities exist today inside
`certified_branch_condition_from_block` and `SwitchCertificate`
(`semantic.rs:1297`); they are recorded on the occurrence instead of being
re-derived by the proof.

## 4. The totality theorem

**Theorem.** For every `G`, reducible or not, the placement below produces a
statement tree satisfying `I_S`, writes each block exactly once, runs in
`O(|B| + |E|)` after the dominator tree, and orders the text so that every
`goto` is textually forward except a jump to a loop header or to an entry of
an irreducible cycle.

**Anchors.** Every block other than `entry` is placed by its immediate
dominator, at one of two positions. Let `x = idom(y)` and let

    Λ(y) = { L : L is a natural loop, x ∈ body(L), y ∉ body(L) }

If `Λ(y)` is empty, `y` is placed *in* `x`'s region: inline at the arm whose
edge reaches it when `y` is a non-merge child of `x`, otherwise as a labelled
merge child. If `Λ(y)` is not empty, `y` is placed in the **exit list** of the
outermost loop in `Λ(y)`, which is well defined because two natural loops with
different headers are disjoint or nested. Lemma 2 says the whole `D`-subtree of
`y` is outside that loop, so it moves as a unit. This is what the recursion in
the first draft of this document lacked: an exit whose immediate dominator is
an interior block of the loop was reached by a `goto` whose label nobody wrote.

The placement, as a recursion over `D`:

    place(y):
        if y heads a natural loop L:
            for (;;) { body(y) }
            then exits(L)
        else:
            body(y)

    body(x):
        the statements of block x                          -- fold_block, unchanged
        arms(x)                                            -- its terminator, each edge as edge(x, y, label)
        then, in ascending rpo:
            every y with idom(y) = x, Λ(y) = ∅, y a merge block:   L_y: place(y)

    exits(L):
        in ascending rpo, every y whose outermost loop in Λ(y) is L:   L_y: place(y)

    edge(x, y, label):
        if y dominates x:                                  -- a back edge
            `continue` when y heads the innermost loop enclosing x, else `goto L_y`
        elif idom(y) = x, y is a non-merge child of x, and Λ(y) = ∅:
            place(y) inline, at the arm                    -- adjacency
        else:
            `goto L_y`

    arms(x) by terminator:
        Fallthrough / Branch / Call with fallthrough:      edge(x, next, Normal)
        ConditionalBranch:                                 if (p) { edge(x, t, True) } else { edge(x, f, False) }
        Switch with a certified selector:                  switch (sel) { case v…: edge(x, target, {v…}) … default: edge(x, d, Default) }
        IndirectBranch with declared successors:           switch (target value) { case addr: edge(x, addr, {addr}) … }
                                                           when the target value is renderable; else a gap at the transfer
        IndirectBranch with no declared successors:        a gap at the transfer
        Return:                                            return …
        None:                                              the terminal call or trap, spelled as §3 requires

The indirect-branch row is a decision this document makes: C has no computed
`goto`, and a jump whose targets the source declared but whose selector no
certificate names is a `switch` on the jump's own target value, with the
successor addresses as its case labels. That is a `SwitchCertificate` minted by
one rule, `selector = the branch operand`, `cases = {(addr, addr)}`, and it
renders through the ordinary switch arm. When the target value itself cannot be
rendered, the transfer is a gap, exactly as for an undeclared target.

*Proof of (i).* Every block other than `entry` has an anchor, and each anchor
is emitted exactly once: a block with empty `Λ` is emitted by `body(idom)`,
inline or as a merge child, and a block with non-empty `Λ` by `exits` of one
loop. `place(entry)` starts the recursion, and `place` of a header wraps the
same `body` in a loop, so a header is emitted once too.

*Proof of (ii).* `arms(x)` writes one transfer per edge of `x`'s terminator,
and each transfer reaches exactly the block the edge names: `goto L_y` by its
label, `continue` by the innermost-loop rule, an inline `place(y)` by
adjacency. Nothing else in the text transfers control: no statement of a block
is a transfer, and the text never falls off the end of a loop body, an `if`
arm, or a `switch` arm, because by induction every `place` ends every path in
a `return`, a terminal call, a `goto`, a `continue`, or an inline child that
does the same. **Every arm ends every path in a transfer** is therefore an
invariant of the placement, and §5 keeps it: the extractor models C's implicit
edges -- the loop-end back edge, `case` fall-through, an `if` without an
`else` -- and any rewrite that created one would fail (ii).

*Proof of (iii).* The arm labels are taken from the terminator, and the
predicate and selector are the certified ones by construction.

*Order.* A merge child `y` of `x` is written after `x`'s arms and after every
merge child with smaller `rpo`; an exit is written after the whole loop, and
after every exit of the same loop with smaller `rpo`. Take a forward edge
`p → y`. In a reducible graph, `p` is inside the text that precedes `y`: `p`
is dominated by `idom(y)`, so it is in an inline arm or in an earlier merge
child's subtree when `y` is a merge child, and inside the loop or an earlier
exit when `y` is an exit -- an exit reached from outside the loop it leaves
would make the loop's cycle have two entries. In an irreducible graph the
exception is exactly that: an edge `p → y` where `y` lies on a cycle it does
not dominate. Such an edge is neither a back edge nor inside a natural loop;
"forward" by the definition in §2, it can be textually backward, and it is
rendered as a `goto`. So backward `goto`s target loop headers or entries of
irreducible cycles, and nothing else. ∎

Three things fall out of the construction that today require a mechanism each:

  * two non-merge successors of a conditional are placed as its two arms, so an
    `if/else` whose arms converge is already an `if/else` followed by the merge
    label -- the recursive builder's `analyze_conditional`, done by Lemma 1;
  * a merge reached from several arms is the labelled block at their common
    dominator -- the hoisted join, the shared join and the sequence-owned merge
    at once, and never copied;
  * a loop with several exits is a `for (;;)` followed by its exit list, each
    entered by a `goto` -- the multi-exit continuation, with the convergence
    point being simply the first exit in `rpo`.

An irreducible cycle needs nothing: it has no natural loop, so no `for (;;)`;
its blocks are merge children or inline children like any others; and the edges
that close it are cross edges, rendered as `goto`, some of them textually
backward. Node splitting becomes a quality rewrite (§5), not a coverage
decision.

## 5. The quality layer

Everything readers and the graph-distance metric want beyond totality is a
rewrite `T: AST → AST` that preserves `I_S`. Because the certificate is a
property of the output alone, **every rewrite is proven by running the checker
on its result**; no rewrite carries its own proof, and a rewrite that fails the
checker is simply not applied. That is what makes the layer safe to grow.

The rewrites, in the order the residual-shape census (§9) is expected to rank
them; the order is to be taken from the census, not from this list:

| rewrite | shape it removes | proof beyond the checker |
| --- | --- | --- |
| jump-to-next elision | `goto L; L:` | none |
| unreferenced label elision | `L:` with no `goto L` | none |
| break | `goto L_y` where `L_y` is the statement after the innermost enclosing loop or switch | none |
| empty-arm normalisation | `if (p) {} else { … }` to `if (!p) { … }` | polarity, by (iii) |
| while rotation | `for (;;) { if (!p) break; … }` to `while (p) { … }` | none |
| do-while | `for (;;) { …; if (p) continue; break; }` to `do { … } while (p)` | none |
| counted loop | `while` with a `ForLoopCertificate` to `for (init; p; update)` | the certificate, as today |
| condition chain | a header chain each of whose blocks branches either out of the loop or to the next, to `while (p₁ ∥ p₂ ∥ …)` | BDD equivalence of the chain's exit function (`ControlBdd`, `structure.rs:277`, kept for this) |
| short-circuit if | the same shape without a loop, to `if (p₁ && p₂)` | BDD equivalence |
| exit hoisting | a subtree inside a loop none of whose blocks is in the body, moved after the loop | Lemma 2 |
| switch merge | arms ending `goto L_after` to `break`, with the merge label after | none |
| bounded duplication | a small tail written once per predecessor to remove a label, under a size budget derived from the tail | `duplicates_are_exclusive`, and the checker's per-occurrence rule |
| node splitting | an irreducible entry duplicated so the cycle becomes a natural loop, under the same budget | as above |

Preference among applicable rewrites is fixed and not tuned to any benchmark:
fewest labels, then fewest duplicated blocks, then shortest text. That is the
Comb objective and it is what a compiler's source most often was.

Two rewrites are worth a sentence each. `break` inside a `switch` leaves the
`switch`, so the break rewrite applies to a `goto` whose label is the statement
after the innermost enclosing loop *or switch*, and never to one that would
have to cross a `switch` to reach a loop; `continue` crosses a `switch`
freely. And `switch` merge must leave every arm ending in a transfer, because
C falls from one `case` body into the next: the invariant of §4 is kept, and
the extractor would refuse the fall-through otherwise.

The `LoopCertificate::condition: Option<PredicateId>` field (`semantic.rs:1279`)
is answered by this layer and not by the certificate. "The" condition of a loop
is a rendering choice among its exit predicates; a chain has no single
predicate; and the checker proves the rendering by edges, not by naming one.
**Verified** its path: copied into the control facts' loop fact at
`function_facts.rs:4849`, where `condition_value` is derived from it, and read
from there only by the five-field check at `structure.rs:797`, which §3
subsumes. The field stays for `for_loop`, which reads it to find the
induction test, until that certificate names the exit edge instead. No `r2ssa`
change is needed to land the structurer.

## 6. What is deleted, what stays

Deleted at landing, not before:

  * `region.rs` (5,058 lines, 25 tests) and `structure.rs` (8,053 lines,
    51 tests) as they stand; the `Region` enum with `MultiExit`, `Transfer`,
    `Goto` and `Irreducible`; `hoisted_joins`; `working_join_requires_path_copy`;
    `collect_shared_joins` and `append_shared_joins`; `sequence_owned_merge`;
    `RenderedBlockDomain`, `active_domains`, `normalize_rendered_domains`,
    `certify_transfer_domain_join`, `validate_rendered_block_domain_coverage`;
    `exact_rendered_loop_id`'s comparison; every `safety_reason`;
  * `linearize_function_body` (`lib.rs:2888` to `:3089`) and the fallback in
    `primary_native_body`: the totality layer *is* the linear form, placed by
    dominance instead of by address order, and it never gives up;
  * the structuring deadline. Placement and checking are linear; nothing in
    this layer needs a clock. The complexity limit is *not* removed here: the
    remaining superlinear cost is the binding plan's three derivations of
    `rewrite_inlining_partition` (`binding_plan/rules.rs:721`) and
    `inlinable_core` (`:920`), which are outside this ADR. The number to carry: `inflate` renders in 2.4 s at
    433 blocks with the limits lifted, and that time is in the plan, not here;
  * the branch `wip/multi-exit-continuation`.

Kept, unchanged:

  * `fold_block` and everything below it: a block's statements are not this
    ADR's concern;
  * `certified_branch_condition_from_block` and its four gates, which produce
    the predicate expression an `if` spells; when they decline, the predicate
    is an unprovable *value*, and the marked-gap decision renders it as a gap
    at the `if` rather than refusing the function;
  * `SwitchCertificate`, `ForLoopCertificate`, `IfRegionCertificate`;
  * `StructuredRegionMarker` and `SealedStructuredRegionArtifact`
    (`structured_region.rs`), which placement consumes; the new tree seals the
    same artifact. `StructuredRegionKind` (`:88`) today lists `FunctionBody`,
    `Block`, `Sequence`, `IfThenElse`, `WhileLoop`, `DoWhileLoop`, `MultiExit`,
    `Transfer`, `Switch`, `Irreducible` and `Synthetic`; it becomes `Function`,
    `Loop`, `LoopExit`, `IfArm`, `SwitchArm`, `MergeTail`, and the consumers in
    `placement.rs` that match on the old kinds change with it;
  * `ControlBdd`, for the chain rewrites only;
  * the effect ledger and observation journal; only the control-obligation
    rule changes (Corollary 4).

New:

  * `crates/r2dec/src/structure/place.rs`: the placement of §4, about 400
    lines;
  * `crates/r2dec/src/structure/certify.rs`: the extractor and checker of §3,
    about 300 lines, exposed as a gate the census reports;
  * `crates/r2dec/src/structure/rewrite.rs`: the rewrites of §5, one function
    each, applied to a fixpoint in preference order, each followed by the
    checker;
  * the residual-shape census of §9.

## 7. Two things upstream of the structurer

**The irreducible-cycle refusal.** **Verified:** `SemanticObligationInventory::collect`
(`obligation.rs:374`) records an `UnstructuredControlCycle` construction
failure for *every instruction* of every block in `unstructured_cycle_blocks`,
before any rendering, and two tests assert that refusal
(`irreducible_cycle_refuses_complete_inventory`,
`empty_irreducible_cycle_still_refuses_complete_inventory`). Under §4 such a
function renders. **Verified** the consumers of
`unstructured_cycle_blocks` are the copy at `obligation.rs:694`, the accessor at
`:895`, the refusal message at `lib.rs:618`, and the two tests. **Partly verified:** the
consumers of the natural-loop facts in `semantic.rs` are carrier facts
(`loop_carrier_facts`, `:9539`), induction facts (`collect_induction_facts`,
`:3459`), the counted-loop certificate (`:7043`), `loop_condition` (`:10272`),
`loop_bound_value` (`:10366`), and two renderability rules for a phi at a loop
header (`expression_loop_phi_is_renderable`, `:8134`;
`value_renderable_modulo_loop_phi`, `:8193`). The last two are value-layer
consumers: a phi at an irreducible entry is not a loop phi under them, and what
that does to its renderability is the remaining check. **To check** there: the hypothesis is that only loop
certification -- carriers, counted loops, `loop_condition` -- needs natural
loops, and that phi placement (dominance frontiers) and the obligation
inventory do not. If it holds, the failure becomes "no loop certificate for this
cycle" and the two tests assert completeness instead. If something else needs a
natural loop, it is named there and decided then, not worked around.

**Terminal blocks.** A `None` terminator is a block the source says never
continues: a call to a noreturn function, or a trap. The text after it must not
be reachable in C either. **Verified:** `linearized_terminator_stmt`
(`lib.rs:3013`) writes nothing for it, `structure_block` writes nothing either,
and no prologue declaration carries `noreturn` -- the fact exists
(`facts.rs:603` `signature_noreturn`, `:647`, read by `r2engine/lib.rs:1911`)
and stops there, so today every terminal call falls through in the text. The
honest spelling is the fact itself: the callee's prototype carries `__attribute__((noreturn))` when the
source declared it so, and a trap renders as the builtin the target has for it.
Fabricating a `return` is not acceptable, and leaving the compiler to assume a
fallthrough the machine does not have breaks (ii).

## 8. A corollary for declaration placement, to check

Placement (`placement.rs`) refuses `region_does_not_dominate_occurrence` -- ten
functions on DecBench -- when a binding's declaration region does not dominate
one of its occurrences. Under §4 the lexical tree *is* the dominator tree with
loops and exits folded in: a statement's lexical ancestors are dominators of
its block (a merge child sits inside its `idom`'s region; an exit sits after a
loop whose header's `idom` region encloses it; an inline child sits in its
parent's arm). **To check** that with this property the placement calculation
reduces to "declare at the lexical least common ancestor of the occurrences",
and that the ten refusals are instances of the old tree violating the property.
Not to be pre-fixed; measured after the structurer lands.
Two cautions. Placement today also uses post-dominance to hoist a read that
follows a loop, and the lexical tree carries no post-dominance, so the refusal
may move to a different clause rather than vanish; and a declaration at the
lexical LCA can still be textually after a `goto` that reaches its scope from
an irreducible entry, which is a C scoping question the checker does not see.
Both are measured, not pre-fixed.


## 9. Instruments, both durable

**The checker as a gate.** `certify.rs` runs on every rendered function and
prints one evidence line, `control-certificate: ok | <first violated clause>`,
counted by the census. Before the new placement lands, it runs against the
*current* structurer's output, which gives a divergence count for today's tree
with no behaviour change. That number is the first deliverable.

**The residual-shape census.** After totality, every remaining `goto` is
classified by local shape: jump-to-next, to-after-loop (break), to-after-switch,
backward-to-header (continue), exit-from-nested-loop, cross edge, irreducible
entry. The frequency table decides which rewrite of §5 is built first and
predicts the graph-distance trajectory before any is built.

## 10. Sequence and gates

    S0  checker over the current tree; census reports control-certificate.
        Also run the extractor over the 54 corpus snapshots and report which
        clause each failing cell violates: a free calibration of the checker
        against known-good and known-bad output before any placement changes.
        Gate: 54 corpus cells unchanged; the numbers are recorded in the handoff.
    S1  placement (§4), sealing the same artifact; control obligations by
        Corollary 4; irreducible inventory per §7; terminal blocks per §7.
        Old builders, proofs, linearizer, deadline deleted in the same change.
        Gate: checker ok on every rendered function; 54 corpus cells
        compile and match their digest (a goto-heavy body still computes the
        same hash, which is the strongest test we have); all 54 snapshots
        re-blessed under review, since every body changes shape; unit tests
        for the deleted mechanisms replaced by tests of §4's lemmas and of
        the checker on adversarial trees.
    S2  rewrites (§5) in census order, each landed with its checker run and
        its census delta. The if/else-merge, break, while and do-while
        rewrites land with S1 in one DecBench delivery, because totality
        alone scores badly on graph distance and the user has said the two
        are one delivery.
        Interim bound, derived rather than chosen: over the 537 functions
        that are structured today, count the `goto`s they render now (mostly
        zero). S1 lives on the feature branch, and the delivery reaches the
        integration branch only when, over those same 537, the number of
        labels after S2 is no greater than that count. Until then the corpus
        digest gate is the only gate S1 must pass alone.
    S3  DecBench on the delivery; the landing decision is made there, per the
        standing rule for architectural changes.

## 11. Residue

After S2 the structural residue is exactly what C cannot say without a label:
irreducible entries not worth splitting, cross edges a compiler emitted from a
`goto` in the source, and exits that leave two loops at once. A `switch` whose
selector the certificate cannot name renders with a gap at the selector; an
indirect branch with no declared successors renders with a gap at the transfer.
Neither refuses the function. Cost in this layer is linear and unbudgeted.

## 12. Hypotheses, each with its check

  1. Only loop certification needs natural loops (§7). Check: consumers of
     `unstructured_cycle_blocks` and `StructuredLoopFact`.
  2. Lexical ancestry equals dominance retires `region_does_not_dominate_occurrence`
     (§8). Check: placement census after S1.
  3. The 54 corpus digests survive goto-heavy output (S1 gate). Check: run it.
  4. Text-order forwardness holds on every local function. Check: the
     residual-shape census reports no backward `goto` whose target is neither
     a loop header nor an entry of an irreducible cycle.
     that is structured today, so no `ged` regression on those 537. Check:
     snapshot review at S2.

## 13. Reading

  * Ramsey, *Beyond Relooper: Recursive Translation of Unstructured Control
    Flow to Structured Control Flow*, ICFP 2022. §4 is his algorithm with C's
    `goto` in place of the reducibility requirement; his forward `br` targets
    are exactly the `idom`-placed labelled blocks of Lemma 1.
  * Johnson, Pearson, Pingali, *The Program Structure Tree*, PLDI 1994, for
    single-entry single-exit regions in linear time, which is what the merge
    children of a node are.
  * Gussoni, Di Federico, Fioraldi, Agosta, *A Comb for Decompiled C Code*,
    AsiaCCS 2020, for the duplication budget and the label-minimising
    objective of §5.
  * Yakdan, Eschweiler, Gerhards-Padilla, Smith, *No More Gotos*, NDSS 2015,
    for reaching conditions, which is what `RenderedBlockDomain` was.
  * Basque et al., *Ahoy SAILR!*, USENIX Security 2024, for which gotos a
    compiler's output genuinely contains, and for what angr's structurer does
    on the benchmark we are scored against.

## S0, measured

The checker is `crates/r2dec/src/control_certificate.rs`, run on every routed
body at the seam in `lib.rs` after `structure_route`, reported under
`R2DEC_CONTROL_CERTIFICATE=1` (one line per function plus its violations) and
on the refusal-evidence channel. `tests/corpus/control_census.sh <binary>`
runs `a:sla; aaa; s <addr>; pd:s` per function and tallies the *last*
certificate under each marker, since the gap loop structures a function once
per attempt. Unit tests: eleven adversarial trees.

Four facts about today's tree that the checker had to learn before it agreed
with anything, each a fact S1's placement must produce rather than an
extractor rule:

  1. A block's own statements do not carry its identity reliably. A merge
     write normalisation materialises for a header phi is observed under the
     header's block while the text puts it in the latch, so reading a block
     change off a plain statement opened a spurious occurrence of the header
     inside the latch. Occurrences are therefore opened by control statements,
     labels and region markers, and by a plain statement only where the text
     must move on: at the function's start, at a do-while body's entry, where
     several ends converge, or where the one open end's block flows forward
     into the statement's block (`successors` and not dominated by it). Blocks
     that render nothing are read through by contraction.
  2. A loop statement is observed under its header *and* its latches, and a
     composite observation may omit the header's own obligation when a child
     owns it; the header is the candidate that tests, else the one a latch
     falls to.
  3. An `if` or `switch` may carry no observation at all; its region marker
     names its block, so `IfThenElse`, `WhileLoop` and `Switch` markers open
     the occurrence too.
  4. A rendered `default` stands for every table value the arms omit, so a
     jump table whose entries mostly point at one target agrees with
     `default:` for that target.

Census over nine local binaries at the tree of this commit:

    functions 720   certified 686   ok 654   fail 32
    terminal-fallthrough 31   edge-mismatch 1   missing-block 1

The 31 are §7's terminal calls: a noreturn callee whose text continues, in 31
functions, which is what the prototype attribute in S1 closes. The one real
failure is `bzip2recover_O2 dbg_bsOpenReadStream`: the first attempt certifies
(three blocks), a gap is planned, and the second attempt loses the `else` arm
`0x1e24` -- the `return NULL` -- entirely, so the body falls off its end. The
gap retry drops a block; S1's placement cannot, and the checker is what will
say so. Inversions (a rendered test with the machine's polarity swapped) occur
in 132 of the 686; duplicated blocks in 63. Neither is a violation.

## S1 and S2, measured

The placement, the rewrites and the gate between them are in
`crates/r2dec/src/structure/` (`place.rs`, `shape.rs`, `rewrite.rs`,
`certify.rs`); the handoff entry "The structurer is the dominator tree now"
records what was found on the way. Two things learned that this document did
not predict:

  1. **Every rewrite stage has to keep every observed occurrence**, not only
     the certificate. The certificate is blind to an `if` rebuilt without its
     observation chain, which the effect ledger then counts as unaccounted.
     The gate checks both, per stage, and names the stage in the census.
  2. **Asking the plan for an expression is an observation.** Deciding an
     edge's merge writes by calling `planned_value_expr` on every phi made
     stack-pointer merges live and rendered the prologue. The decision is
     taken from dispositions; expressions are asked for only when written.

Numbers, nine local binaries: rendered 648 -> 654; certificate ok on 653 of
654 rendered (the one is a cold-partition edge); labels over the 493 functions
structured before: 19 -> 61, so the interim bound of §10 is not met yet and the
remaining shapes are the bounded duplication of §5. Raw 54, differential 54.

