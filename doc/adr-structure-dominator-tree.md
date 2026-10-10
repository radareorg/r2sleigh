# ADR: control structure is the dominator tree; everything else is an edge spelling

Status: done; quality rewrites in progress (no open ROADMAP item)

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

A compound test `φ(p₁…pₖ)` (a condition chain) is admitted only when the
rewrite that made it records the chain on the occurrence: a DAG of blocks
entered at its head whose non-head blocks render nothing, checked as one unit
by requiring its exit function to equal the test's by BDD identity. The
checker never infers a chain.

A selection `x = c ? a : b;`, written by the readability stage for an `if`
whose arms each assign `x` once, is read as that `if`. The statement carries
the test block's markers and each value its arm block's (one block, or none for
an arm that is the edge itself); that block's occurrence is entered on the
arm's edge. The rewrite records the statement as a selection. The checker
refuses one whose test is not a conditional branch, whose target is not a plain
variable, or whose value writes: that write is a second effect of the arm.

### §4 Placement

Every block except the entry is placed by its immediate dominator `x`. With
`Λ(y)` the natural loops containing `x` but not `y`: if `Λ(y)` is empty, `y`
is placed inline at the arm reaching it (when its only forward in-edge is from
`x`) or as a labelled merge child of `x`; otherwise it goes in the exit list of
the outermost loop in `Λ(y)`, and its whole dominator subtree moves with it
(exit subtrees are whole). A loop header wraps its body in `for (;;)`. An edge
is `continue` to the innermost enclosing header, inline adjacency, or `goto`.
Merge children and exits are written in ascending RPO.

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
until that certificate names its exit edge.

## Done

- S0: the checker over the old tree; `R2DEC_CONTROL_CERTIFICATE` prints one `control-certificate` line per function (and on the refusal-evidence channel).
- S1: placement in `structure/place.rs`, the certificate in `structure/certify.rs`; the region builders, domain proofs, linearizer, structuring deadline and every `safety_reason` deleted; noreturn prototypes spelled; irreducible cycles keep a complete inventory.
- S2, in part: jump-to-next and unreferenced-label elision, `break`/`continue`, while and do-while rotation, switch-tail absorption, bounded tail duplication (`structure/shape.rs`) and short-circuit `if` (`structure/rewrite.rs`), each gated by the checker.
- S3: DecBench read 680 of 860, every mean above the previous run.

## Left

- Labels over functions the old structurer handled exceed what it rendered. Exit: no more labels than before over that set.
- Condition-chain rewrites (`while (p₁ || p₂)`) and node splitting of irreducible entries. `ControlBdd` no longer exists, so chains need a BDD identity check before they land. Exit: both gated by the checker.
- Whether lexical ancestry equals dominance retires `region_does_not_dominate_occurrence`. Exit: placement census measured (post-dominance hoisting and `goto` into scope may move the refusal rather than remove it).
