# ADR: when a select may be spelled as an `if`

Status: Proposed (2026-10-23), for the maintainer. Nothing here is implemented; ROADMAP D75 holds the item.

## Question

`x = c ? a : b;` and `if (c) { x = a; } else { x = b; }` are the same C when both arms are side-effect
free and their operands are already values. DecBench's GED scores the block graph, where `?:` is one node
and the `if` is a diamond, so the spelling moves the score. AGENTS rule 8 forbids control the machine did
not have. May r2dec ever spell a select as an `if`?

## The three owners of a `?:`

A `?:` in a rendering has one of three origins, and the answer differs.

1. **A data select.** An r2il `Select` (a conditional move: `cmov`, `csel`, `fcsel`, and the one-instruction
   skips `r2sleigh-lift/src/internal_control/skips.rs` if-converts) becomes `SSAOp::Select` and `render/terms.rs`
   spells it `Ternary`. The machine ran straight-line code: no branch, no second block.
2. **A guard the renderer writes.** `render/terms.rs::shift` states the machine's answer where a shift count reaches
   the width as `count >= width ? 0 : value << count`. The machine has no select here and the source has no `?:`:
   the ternary is C spelling the machine's semantics.
3. **A branch-born selection.** `structure/shape.rs::select` rewrites an `if` whose arms each assign one
   variable once into `x = c ? a : b;` (ADR structure-dominator-tree, section 3). The machine had the
   diamond: a conditional branch, two blocks, a merge, and the certificate already attests all of it.

## The argument

**Equality.** With side-effect-free arms and operands that are values (SSA values or constants, not loads
that could trap in one arm and not the other), `?:` and `if`/`else` evaluate one operand, write one
variable, and leave every other cell alone. The two denote the same function of the state.

**What the machine had.**

- For (1) it had a `cmov`. Spelling an `if` writes a branch the compiler never emitted. The semantics are
  equal, the control is invented: a reader counting paths, a tool comparing the text's graph with the
  machine's, or the certificate's walk (`walk_selection` refuses a test that is not a conditional branch)
  all see a diamond the CFG does not have. This is rule 8's case, however harmless the C is.
- For (2) it had a shift and nothing else: the guard is C stating the machine's answer for a count that reaches
  the width, so an `if` for it is control about a value, and with a literal count it is a condition decided when
  the renderer wrote it.
- For (3) it had the diamond. The `?:` is the respelling: control the machine has, written as an
  expression. Spelling the `if` is the machine's own graph, and the control certificate holds for it
  with no new clause (it is the text before `select` ran).

**The risk of fabricating control.** The benchmark rewards the source's spelling, which the binary does not
state: `c ? a : b` and `if (c) x = a; else x = b;` can compile to the same `cmov` at O2. A rule chosen by the
score trains the renderer to guess the author's habit. The only sound licence is a fact the container
states (a branch the CFG has, or a line table that shows two statements).

## The counterfactual

`tests/decbench/counterfactual_ged.py --transform select_both` over the stored renderings, 2,623 scored
non-bash rows (RESULT-2026-10-23, section 4): `x = c ? a : b;` as `x = b; if (c) { x = a; }` and
`x = c ? a : b; return x;` as `if (c) return a; else return b;` move 477 renderings better and 46 worse, GED-perfect
+15 and 0 lost, total GED 102,397 to 98,686 (-3,711, -3.6%). The noreturn guard's counterfactual on the same rows
(`--transform noreturn_guard`): 77 better and 27 worse, +12 perfect and 1 lost, 102,397 to 102,305 (-92), so the
select respelling is forty times its size on that set. Both totals are the sums of the `before` and `after`
columns of the script's tsv, one per project, and RESULT-2026-10-23 section 4 now states them.

The script respells every `?:` and cannot tell the three origins apart. The counts below are the output of
`tests/decbench/ternary_census.py DUMP --without-select DUMP2` over the `mined_set.py dump` of the mined set at
`ad64676a` (bzip2, zlib and grep at O2 and O2-noinline: 1,639 functions dumped, 1,599 with a rendering) and the dump
of a build with `shape::select` not run. A **statement** is a rendering line `name = ...;`, counted once however many
`?:` its right side holds; a guard is a `?:` whose condition compares a count with a width, `>= (uintN_t)W`.

| `ternary_census.py` class | sites | functions |
|---|---|---|
| `?:` occurrences, every line | 4,223 | 665 |
| statements holding a `?:` (what this ADR used to call `x = c ? a : b;`) | 2,708 | 555 |
| ... whose right side is one `?:` | 1,182 | 397 |
| statements holding an overshift guard (`... >= (uintN_t)W ?`, W of 8 to 128: origin 2) | 2,100 | 382 |
| ... the guards in them (a statement can hold several) | 2,300 | 382 |
| branch-born (origin 3): holds no guard and the build without `shape::select` does not write it | 50 | 46 |
| data selects and anything else (origin 1): the rest | 558 | 291 |
| statements that begin with a guard whose count is a literal | 462 | 164 |
| ... one cast on the count, `0` for the true value (`(uint32_t)8U >= (uint32_t)32U ? (uint32_t)0U : ...`) | 150 | 40 |
| ... two casts on the count (`(uint64_t)(uint32_t)2U >= (uint64_t)64U`) | 263 | 126 |
| ... a sign fill for the true value (`? x < 0 ? -1 : 0 :`) | 49 | 28 |

The three origins add to 2,708 (2,100, 50 and 558), each statement counted once with the guard first. The earlier
table said 50 branch-born in "2" functions (46), 1,755 guards (2,100 statements), 903 data selects (558) and 140
literal guards in 30 functions (the prose, the ROADMAP row and the commit said 150 in 40, which is the third literal
row: one cast, `0`). A literal guard in any position is 1,629 expressions in 369 functions (`literal count
anywhere`), and one that begins its statement is 462 in 164: the lever is larger than the 150 the fold below
measured.

| Respelling | Perfect | Total GED | Better / worse |
|---|---|---|---|
| none | 268 | 70,040 | |
| every `?:` as an `if` (the script) | 282 (+14, 0 lost) | 67,122 (-2,918, -4.2%) | 369 / 22 |
| the 50 branch-born selections as the `if` the CFG has (a build with `shape::select` not run) | 268 (+0) | 70,099 (+59) | 11 / 27 |
| the 150 one-cast literal guards folded (a counterfactual on the text, not built) | | 68,852 (-1,188) | 40 / 0 |

The lever is not in the one subset a CFG fact licenses (GED-neutral to slightly worse), and most of it is not in
selects at all: 78% of the statements are the renderer's own overshift guards (2,100 of 2,708), and respelling one
writes `if (8 >= 32)`. Those guards cost GED as ternaries, and a literal count decides them when the renderer
spells them: folding the 150 statements of 40 functions that have one cast on the count and `0` for the true value
moves the total from 70,040 to 68,852 (-1,188), 40 better and 0 worse, with no control spelled that the machine did
not have (ROADMAP D75, found here). The other 312 literal guards (263 with two casts, 49 sign fills) are not
folded in that measure and not measured. That fold is rule 8 clean and is worth about ten times the noreturn guard's -123.

## Alternatives

- **A. Keep `?:` everywhere.** No rule 8 risk; leaves the lever. Status quo.
- **B. Spell the `if` only for a branch-born selection; keep `?:` for a data select.** The licence is the
  CFG: the diamond is the machine's. The change deletes a respelling (`shape::select` stops writing the
  ternary for a diamond whose arms the certificate already walks) and adds nothing. A data select is never
  spelled as control. Measured above: no gain on the score (+59 total GED, 0 perfect), so it stands only as a
  readability choice.
- **C. Spell the `if` for a data select when DWARF line tables show the source had two statements.**
  The container states the shape, so rule 8 allows it, and it is the only way a `cmov` could be written
  as an `if` honestly. It needs a line-table fact through `r2image` and `r2engine` per select, and it
  does nothing for a stripped binary, which is every DecBench binary.
- **D. Never spell control for a select; also stop spelling diamonds as `?:`.** The same as B for (3),
  stated as a rule for both origins: an expression for data, a statement for control.

## Recommendation

**A**, with C as the only sound route to what is left. Of the 2,708 statements with a `?:`, 50 are branch-born (B
changes nothing on the score), 2,100 hold the renderer's own guards (fold the literal ones first: that is the measured
lever, and it spells no control), and 558 are data selects whose `if` the machine never had, so rule 8 forbids
spelling them for the score.
C is worth building only for binaries that carry debug info, graded on those and not on the stripped DecBench set.

Gate for C when it is built: failing engine test first (a `cmov` whose arms the line table puts on two lines renders
as an `if`; the same bytes without the table render `?:`), the mined set re-scored on debug builds, certification,
census read line by line. Owner: `r2image` (the line-table fact), `r2engine` (the request), `r2dec` (the spelling).
