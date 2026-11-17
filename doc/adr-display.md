# ADR: display

Status: proposed (ROADMAP D565 to D569, D574, and D579 to D583, which this ADR
adds). Round 14 builds D580, D579, D583, D581 and D567 in that order.

## Problem

r2s recovers more than radare2, rizin or Ghidra state, and shows it badly.
Release r2s 718a898b2 under `aa; pdf` on 10 functions:

- `(certified)` appears 1,467 times: bash `main` 355, 0pack 0x62ecf0 643. The
  word is on every line, so it says nothing.
- A refusal reads as proven. `sym.imp.__isoc99_sscanf: arguments unproven
  (certified)` puts a proof word on a refusal: the note prints the
  annotation's `support` and never asks whether the kind is a refusal.
- Internal spellings leak: `missing_format_parameter`,
  `arg1@stack+0xffffffffffffffd4` (`listing.rs:463` formats an `i64` with
  `{offset:+#x}`), `r2sleigh_word_u32` in `afi`, `arg1 of 0x4006b9` on every
  setter, and an em dash in `axt`'s coverage line.
- `pdf` has no header, flow lines, xref lines, gap rows, demangling or colour.
  0pack has 64 jumps with no arrow. bash `pdd` nests to column 188 with no
  rails.
- `ret ; returns rax (certified)` sits in bomb `phase_3`, whose result `afi`
  calls `unproven (rax, Written)` (D584).

## Decision

Keep radare2's grid and grammar. Add one mark cell after each `;`. The mark
comes from the fact's `Confidence` and its kind. Every fact below Proven
carries a mark, so colour, pipes and screen readers carry the same proof
state, and colour only repeats the mark.

### Visual grammar

Each note is `; M text`, `M` one ASCII cell. The cell is a space only for a
Stated or Proven fact with no premise.

| Mark | `Mark` | State | Source | Reads as |
|---|---|---|---|---|
| (space) | `Holds` | Stated, Proven | stated, debug-info, decoded, called, folded, certified | holds |
| `*` | `Premise` | Stated or Proven with a premise | `ClosedWorld`, `UbFreeSource`, `GoRuntime`, `FrameIsolation` | holds if the premise holds |
| `~` | `Bound` | Bounded | solved | holds as the bound the text spells |
| `^` | `Declared` | Declared | handed, declared | holds if the declaration is right |
| `.` | `Read` | Read | dereferenced, reached, carrier-width | a width or a use, no type |
| `_` | `Assumed` | Assumed | convention | the ABI default, no evidence |
| `?` | `Unknown` | an unknown kind | unresolved branch, bytes in no block, short xref list | asked, no answer, no reason |
| `!` | `Refused` | a refusal kind | `CallBoundaryRefusal`, `UnprovenCause`, uncounted variadic tail | refused; the reason follows |

`Premise` has 4 variants (`r2source/src/confidence.rs:154-171`), so a
confidence carries one of 16 premise sets. A grade below Proven keeps its own
mark whatever its premises and names them in `asm.proof`'s text. A fact under a
model found by an import's name (a landing pad's personality, a library's
prototype) is Declared, `^`.

`Mark` orders weakest first: `! ? _ . ^ ~ * space`. A line's notes sort by
`(mark, Reverse(confidence))`: mark rank first, then the weaker confidence
first. Mark rank cannot be `Confidence`'s order: `Confidence::cmp`
(`confidence.rs:369-376`) is basis-first, so `stated+closed-world` sorts above
`certified`, while a `*` is weaker than a space.

Rules:

1. The kind decides the mark before the confidence does
   (`AnnotationKind::standing`). A refusal kind is `!` with its reason, an
   unknown kind `?`. Neither prints a basis.
2. A Bounded note spells its bound: `rax in [0x0, 0x7]`, `at least 3 args`.
3. A call note states the arguments once, as `(rdi, 0x20, rdx)`. A setter
   prints `aN`, and the call's address only when that call is not the next
   call line.
4. Inside a call's arguments, a weaker argument carries its own mark:
   `(rdi, ^"th3p4ss")`.
5. An image word reads `[0x844380]=0x0 in file`. A loader-written word reads
   `[0x2d0068]=0xa1524 after relocation`. Two kinds, two spellings.
6. `noreturn` appears only where the engine states it: the `Call` note's
   `noreturn` reads the callee's `Never`; no name decides it.
7. The `ret` note comes from the function's result fact (D584).
8. A word type of no stated sign (r2types `UNSTATED_WORD`) reads `32-bit word,
   sign unstated` with `.`.
9. The argument list ends in `?` only where the engine states a floor.
10. New glyphs are ASCII. Rails and flow lanes use radare2's box glyphs, and
    `scr.utf8=false` switches them to ASCII. `∈ ⊥ ← … ┄` are rejected:
    `unicodedata` reports them Ambiguous width.

### Colour roles (D569)

One table in `r2s-tui/src/theme.rs` paints `pdf`, `pdd`, `afi`, `VV` and
visual mode. Syntax roles keep radare2's hues. Proof roles use only 94, 95, 39
and backgrounds, which `theme.rs` uses for no foreground.

| Token | Meaning | 16 | 256 | Truecolor dark / light | No colour |
|---|---|---|---|---|---|
| `proof.refused` | refusal cell | `41;97` | `48;5;88;38;5;231` | bg #870000 / #B23A00, fg white | `!` |
| `proof.reason` | the refusal's reason | `39` | `38;5;210` | #FF8787 / #A23B00 | text after `!` |
| `proof.unknown` | unanswered cell | `43;30` | `48;5;214;38;5;16` | bg #E69F00, fg black | `?` |
| `proof.bound` | Bounded | `94` | `38;5;74` | #56B4E9 / #0072B2 | `~` |
| `proof.premise` | under a premise | `95` | `38;5;227` | #F0E442 / #7A6A00 | `*` |
| `proof.declared` | Declared | `95` | `38;5;175` | #CC79A7 / #8E3A6E | `^` |
| `proof.read` | Read | `94` | `38;5;36` | #2BC59A / #00785A | `.` |
| `proof.assumed` | Assumed | `95` | `38;5;173` | #D7875F / #8A4B2A | `_` |

A refusal or unknown is a background cell, never confused with `Return` (31)
or `Trap` and `Residual` (1;91). With 16 colours the glyph separates roles
that share a hue. No grade uses dim or italic. Each truecolor foreground
reaches 4.5:1 on its background.

### Column grid (D565, D566)

radare2's grid: `┌ size: name (args);`, the `│` rail, flow lanes, `0x%08x`
addresses, `;` notes aligned at `asm.cmt.col`.

| Width | Flow | Address | Bytes | Instruction | `;` | Mark | Note |
|---|---|---|---|---|---|---|---|
| 80, tty | 1 to 6 | 8 to 17 | off | 20 to 49 | 51 | 53 | 55 to 79 |
| 160, tty | 1 to 10 | 12 to 21 | 28 to 41 | 43 to 69 | 71 | 73 | 75 to 159 |
| plain | 1 to 10 | 12 to 21 | 28 to 41 | 43 to 69 | 71 | 73 | 75 to end, no cut |

A long instruction pushes only its own note. In a tty a line past the edge
loses note text first, ending in `..`, then operand text, then the mark. An
edge past the lane budget ends at the rail in a `+` stub. `pdd` (D568) indents
4 cells per level with a `│` rail per level and folds past 24 levels to a depth
count (`│ 25>`). `afi` notes follow the value as `key: value ; M note`.

### Header (D566)

```
; CALL XREF from sym.main @ 0x400e72(x)
; ? xrefs may be short: 29 indirect transfers unresolved
┌ 132: sym.phase_3 (?);
│ ; ~ at least 0 args: a register past them reaches sscanf
│ ; ! result undecided: rax written, no reader proven
```

Xref lines come before `┌` in radare2's spelling. The `┌` line shows the
realsz and the demangled name. At most 2 `│ ;` lines give arity, widths and
result, each with its mark, plus 1 span line where blocks lie away from the
entry.

### Controls

| Control | Effect | Default |
|---|---|---|
| `e scr.color=0..3` | none, 16, 256, truecolor (2 and 3 with D569) | 1 on a tty, 0 in a pipe |
| `e scr.utf8` | box rails, or radare2's ASCII rails | true |
| `e asm.lines`, `asm.lines.width` | flow lanes (D565) | true; 6 at 80 columns |
| `e asm.bytes` | byte column | true |
| `e asm.cmt.col` | the `;` column | 71 |
| `e asm.demangle` | demangled names (D574) | true |
| `e asm.addr` | `pdd` statement addresses (D568) | false |
| `e asm.proof` (r2s only) | the basis word and setter back-links after each note | false |
| visual `z` (D582) | cycles notes: reader, proof, none | reader |
| `ao @ addr` (D582) | a `notes:` block with each note in full | |
| `pd?` (D582) | ends with the 8-line mark legend | |

`asm.proof` and `z` change only the text after a `;`. Line count and columns
stay fixed.

### Plain mode (D581)

Plain mode applies when stdout is no terminal: a pipe, a file, `-qc`, the
golden harness.

- No ESC byte is written. `scr.color` defaults to 0, and an explicit
  `e scr.color=1` still paints. The text equals the painted text with ANSI
  removed.
- Plain mode uses the 160 grid with no cut (with D565, D566).
- Marks and the header stay; `pdfj` and `aoj` carry each note's `Confidence`
  and refusal as typed fields (D582).

The differential stays green:

- `scripts/diff_r2.py` keeps each line from its first `0x` and strips
  `\s+;.*$`, so a mark after `;` is stripped on instruction lines.
- `┌` lines hold no `0x`; xref and coverage lines start with `;`.
- Rail-prefixed note rows escape `^\s*;` (`│   ;-- 7 bytes in no block`,
  radare2's `│ ;-- case 0: ; from 0x00400f75`), so `ANNOTATION` widens to
  ``^[\s│┌└├┐┘─<>|,`+]*;`` for both tools.
- `afi` is diffed only on its `noreturn:` row, which keeps its prefix.
- The `pd 8` exact count and every `diff_r2_baseline.json` count must not move.

## Owners

r2s renders and computes no fact: it chooses spelling, layout and order, and
tests whether a setter's call is the next call line.

| Fact | Owner | Contract |
|---|---|---|
| Mark per confidence | r2source `confidence.rs` | `Confidence::mark()` beside `Basis::spelled()` |
| A note's confidence and refusal | r2engine `query/records.rs` | `Annotation { kind, confidence }`; `AnnotationKind::standing()`; `Call { arguments: Result<_, CallBoundaryRefusal> }` |
| A refusal's words | r2ssa `semantic/facts.rs` | `Display for CallBoundaryRefusal`, `VariadicCallsiteArgumentCountRefusal::spelled()` |
| Callee noreturn | r2engine | `Call { noreturn: Option<Fact<bool>> }` from the callee's `Never` |
| Arity floor, result, widths | r2types through r2engine's frame answer | `Fact`, floor, `UnprovenCause` |
| Block edges, gaps, span | r2engine block index | D565 edges |
| Xrefs and coverage | r2engine reference index | the `axt` answer and the unresolved count |
| Names, demangled | r2engine `names.rs` | D574 |
| `pdd` rails, statement addresses | r2dec | D568 |
| Theme | r2s-tui `theme.rs` | D569 |
| Layout, cut, plain mode, e-vars | r2s | `listing.rs`, `config.rs`, `function.rs`, `opcodes.rs` |

## Costs

- Notes: `O(k log k)` per line with `k <= 4`; `O(n)` over a listing.
- Flow lanes: `O(E log E)` interval colouring (D565); 0pack 0x62ecf0 has 492
  edges.
- Header: `O(1)` lookups of answers the query database holds.
- Gap rows: one pass over the sorted block ranges, `O(B)`.
- Memory: `Annotation` holds a `Confidence` (a basis and a premise set of at
  most 4) in place of a `Basis`. No pass, cache or table.
- Peak RSS of `aa; pdd @ 0x62ecf0` on 0pack must not rise.

## Rejected

- Mark order equal to `Confidence::cmp`: false, since the order is
  basis-first (see Visual grammar).
- A 2-cell gutter left of the flow lines with a tick on every proven line: 348
  to 628 ticks per function, and every golden and `diff_r2.py` prefix shifts.
- Dim and italic as the grade channel: grey 240 on black has low contrast;
  conhost, and tmux without terminfo, drop italic.
- Word tags such as `[decl]` on every tty note: 6 to 17 of the 25 note cells at
  80 columns. Words live in `asm.proof`, `ao` and the legend.
- A 4-line header box, shortened addresses, Tab-cycled layers: `diff_r2.py`
  cannot align a box, radare2 pads addresses to 8 digits, Tab is bound twice.
- Unmarked `w32`, `rax∈[..]` and `printf("Password: ")`: each shows a Read,
  Bounded or Declared fact as proven.
- `⊥` without an engine noreturn fact: a noreturn guessed from a name is a
  fabricated fact.
- Today's text in pipes: it keeps the 1,467 `(certified)` notes, and its
  refusals read as proven.
- A grade span on every operand: a mark per note, plus inline marks inside
  call arguments, carries the same states with one field on `Annotation`.
