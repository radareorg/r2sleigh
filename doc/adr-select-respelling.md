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
+15 and 0 lost, total GED 102,397 to 98,686 (-3.6%, forty times the noreturn guard's -92).

The script respells every `?:` and cannot tell the three origins apart. On the mined set (bzip2, zlib and grep at O2 and
O2-noinline, 1,595 scored, build 23728d11), 2026-10-23:

| | statements | functions |
|---|---|---|
| `x = c ? a : b;` in the renderings | 2,708 | 555 of 1,639 |
| branch-born (`shape::select`; the build without it differs by exactly these) | 50 | 2 |
| the renderer's overshift guard (by the shape of its condition, `... >= (uintN_t)W`) | 1,755 | |
| the rest: data selects (clamps, `cmov` shapes, flag selects) | 903 | |
| ... guards whose condition compares two literals (`(uint32_t)8U >= (uint32_t)32U ? 0 : x << 8`) | 140 | 30 |

| Respelling | Perfect | Total GED | Better / worse |
|---|---|---|---|
| none | 268 | 70,040 | |
| every `?:` as an `if` (the script) | 282 (+14, 0 lost) | 67,122 (-2,918, -4.2%) | 369 / 22 |
| the 50 branch-born selections as the `if` the CFG has (a build with `shape::select` not run) | 268 (+0) | 70,099 (+59) | 11 / 27 |

The lever is not in the one subset a CFG fact licenses (GED-neutral to slightly worse), and most of it is not in
selects at all: 65% of the `?:` are the renderer's own overshift guards, and respelling one writes `if (8 >= 32)`.
Those guards cost GED as ternaries, and a literal count decides them when the renderer spells them: folding the 150
statements of 40 functions whose condition compares two literals (a counterfactual on the text, not built) moves the
total from 70,040 to 68,852 (-1,188), 40 better and 0 worse, with no control spelled that the machine did not have
(ROADMAP D75, found here). That fold is rule 8 clean and is worth about ten times the noreturn guard's -123.

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

**A**, with C as the only sound route to what is left. Of the 2,708 `?:`, 50 are branch-born (B changes nothing on
the score), 1,755 are the renderer's own guards (fold the literal ones first: that is the measured lever, and it spells
no control), and 903 are data selects whose `if` the machine never had, so rule 8 forbids spelling them for the score.
C is worth building only for binaries that carry debug info, graded on those and not on the stripped DecBench set.

Gate for C when it is built: failing engine test first (a `cmov` whose arms the line table puts on two lines renders
as an `if`; the same bytes without the table render `?:`), the mined set re-scored on debug builds, certification,
census read line by line. Owner: `r2image` (the line-table fact), `r2engine` (the request), `r2dec` (the spelling).
