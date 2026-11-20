# ADR: display

Status: D580, D579, D583, D581 and D567 built in round 14 ("Round 14 as
built"); D569, D565 and D568 built and D566 built in part in round 15
("Round 15 as built: listing", open parts D619 to D622); D574 and D582
proposed (ROADMAP).

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
| `e scr.color=0..3` | none, 16, 256, truecolor (D569) | 1 on a tty, 0 in a pipe |
| `e scr.utf8` | box rails, or radare2's ASCII rails | true |
| `e asm.lines`, `asm.lines.width` | flow lanes (D565) | true; 6 at 80 columns |
| `e asm.bytes` | byte column | true |
| `e asm.cmt.col` | the `;` column | 71 |
| `e asm.demangle` | demangled names (D574) | true |
| `e asm.rails` (r2s only) | `pdd` rails, one `│` per level, and the proof comment in the mark grammar (D568) | true on a tty, false in a pipe |
| `e asm.pdd.addr` (r2s only) | `pdd` statement addresses (D568); radare2's `asm.addr` hides `pd` offsets (`cconfig.c:4301`) | false |
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
| Xrefs and coverage | r2engine reference index (`axt`); the survey's caller rows (`pdf` header, D566) | the `axt` answer and its unresolved count; `Header { calls, tails, unresolved }` |
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
- Memory: `Annotation` holds a `Confidence` (a basis and a 4-bit premise
  set, 2 bytes) in place of a `Basis`. No pass, cache or table.
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

## Round 14 as built (rd14-display-core)

- D580: `Mark` and `Confidence::mark()` in r2source; `Mark::weakest_first`
  is the one note order, read by `Annotation::weakest_first`.
- D579: `Annotation.confidence`; `AnnotationKind::standing()`; a refused
  `Call` carries its `CallBoundaryRefusal`, whose `Display` is the one
  speller. Premises: a certificate note carries its function's recorded set
  past the decoded and folded rungs. No owner states `ClosedWorld` per call
  (step 0 on 0pack 0x62ee83), so a call to a function of the image and its
  setters carry it (default-deny over-mark, D592). A call to an import and
  its setters stand on `declared`: the arity is the name-found declaration's.
  `Call.noreturn` reads the walk's closed site only where the callee's own
  `Never` proves (`ExitSite.callee`); a halting argument is no callee fact.
  A premise set is `Premises(u8)`, one bit per `Premise`: the
  `BTreeSet<Premise>` raised peak RSS of `aa; pdd @ 0x62ecf0` on 0pack by
  368 kB; four bits lower it 2.6% below the base (Mac).
- D583: `stack-0x2c`.
- D581: the contract is a test; `ANNOTATION` widened.
- D567: `e asm.proof`; the call note names its callee only where no operand
  names it, so no line loses a name; the `afi` `noreturn:` row is unchanged
  because `diff_r2_judged.toml` matches it whole-line; notes are unpainted
  until D569's proof roles land, so colour adds nothing yet.

## Round 15 as built: explain, premises (rd15-call-facts)

- D592: a call's note carries the premises its argument mapping rests on
  (`CallsiteCertificate.premises`): none where the callee's alone read records
  none and states the same parameter list exactly, else the closed world and
  the read's set; an import's stays `declared`. A function's
  own closed-result premises rest on the result fact (`result_premises()`):
  the `ret` note and `afi` carry them, a loop or induction note does not.
  `pdd`'s proof line and `pddj` state the union, unchanged. A whole-function
  note still carries the body's own premises (a decided canary's `ub-free`,
  `frame-isolation`): bash `main`'s 80 call notes keep `*` for those.
- D582: `Mark::reads_as` is the one speller of what a cell says, read by the
  `pd?` legend; `ao` and `pdfj` write each note's `Mark::cell`. `ao` reads the
  notes `pdf` prints on the line from the listing of the first function
  holding it (`functions_holding`), so `ao` pays for that function's
  analysis; outside every function they are the instruction's own. The new
  `pdfj` carries each note as `NoteJson` (kind by one exhaustive match, mark,
  basis, grade, premises, refusal, citation); a refusal states no basis.
  `aoj` carries no notes: reading them made D490's `aoj` sample time out on
  vim and gzdoom.arm_64.1 (stop fact; the row stays open for it). Visual `z`
  cycles reader, proof (`e asm.proof=true`) and none (the text after the first
  ` ; ` cut in the held lines). Plain and colour print the
  same bytes; the exit paints the cells with D569's proof roles.
## Round 15 as built: names

- D574, one spelling. An unnamed function is `fcn.%08x`, radare2's form
  (`libr/core/canal.c:158` and `:888`, `"%s.%08"PFMT64x`), written by
  `r2source::unnamed_function` alone; `afl`, `axt`, `pddj`'s `name` and the
  visual mode ask `NameDb::function`. C keeps `unnamed_identifier`
  (`fcn_1e1d0`): `rendered_name_of` takes no display spelling, and a refused
  rendering's definition is `rendered_name_of(None, entry)`. A refusal comment
  of an unnamed function reads the listing's spelling (below). bash `main` stays `fcn_1e1d0` in `pdd`:
  `respell_nonconforming_main` (r2dec `ast.rs:2072-2095`) refuses the name
  `main` to a prototype C11 5.1.2.2.1 does not allow, which is correct C.
- D574, seeking. `OpenProgram::address_spelled` resolves a name the table
  holds (`NameDb::address_of`), else `fcn.%08x` where the survey lists that
  entry (a binary search of its sorted functions); `fcn.1e1d0` names nothing.
  `s` and every `@` read it through `parse_number`. The command line keeps
  radare2's operators (`~ ; @ | > " ' # $( &&`, `line.rs`, cmd.c:5241-5247), so
  a demangled name holding one seeks through the API and by its flag spelling
  on the line: 3,096 of 0pack's 8,699 `afl` names, 2,107 of pumasim's 15,298
  (D624, open). `crates/r2s/tests/names.rs` seeks every `afl` name both ways
  and holds the uncarried set (`Guard::~Guard()`).
- D574, the one moved `pdd` class: a refused unnamed function's comment
  (`/* r2sleigh refused fcn.0001e1d0: ... */`, also `pddj` `code`) reads the
  listing's spelling. Census, goldens and x86-64 and AArch64 equivalence hold
  none; win64 equivalence holds 15, whose reason `gate.reason` normalises to
  the same key (`\b(?:fcn|sub)[._][0-9a-f]+\b`). Keeping `fcn.{x}` there would
  be the second speller this row deletes.
- D574, demangling. `r2abi::mangled` parses each type in two readings at once
  (`Both = (Ty, Node)`): the C spelling `parse` states, unchanged on all 23,770
  names below, and libiberty's component tree. `Mangled::spelled` is a port of
  `d_print_comp` (the modifier list that prints a declarator inside out,
  reference collapsing, `> >`, `operator< <`, literals, `[abi:...]`,
  `(anonymous namespace)`, `[clone .x]`, `DMGL_VERBOSE` expansions of
  `Ss`/`Si`/`So`/`Sd`). It refuses what `parse` refuses, a restrict-qualified
  type (a candidate `parse` does not count), a float literal and an empty one.
  Differential against GNU `c++filt` 2.42 (contabo) and 2.47 (Mac), which
  agree, over every `_Z` FUNC symbol (`readelf -sW`, version suffix cut):
  0pack 8,884 names, 8,371 equal, 513 refused (5.8%), 0 different; pumasim
  14,814, 14,476, 338 (2.3%), 0; demangle-test-cpp 72, 67, 5, 0. Under 10% on
  both, so no `cpp_demangle` dependency. Script:
  `designs/round15/demangle/compare.py` in the round's scratchpad.
- `Name::shown(demangle)`: the spelled form of a `Symbol` or `Import` whose
  text parses whole, else `spelled()`. It is the same symbol respelled by the
  ABI's grammar, so as Stated as the mangled text; no fact reads it.
  `e asm.demangle` (radare2's, `cconfig.c:4363`, default true) reaches `afl`,
  `afi`'s `name:`, `axt` and `pdf`/`pd` operands and word notes; `aflj`, `ao`,
  `f`, `is` and `pddj` keep the flag spelling. `diff_r2.py` runs radare2 with
  `asm.demangle=false bin.demangle=false` and r2s with `asm.demangle=false`,
  so names compare as flags. Scripts that read names from `afl` read `aflj`
  (census `orders`, `run_refuter.py`, DecBench's `renderings.py` and
  `r2sleigh_raw.py`, the stub `aflj`), which an older r2s also answers; the
  coverage sweep passes the key.
- Cost: `Names` keeps no demangled key. A seek that misses every table and
  holds `(` asks each C++ name in address order, O(names x length): demangling
  all 14,814 of pumasim's takes 20 ms (Mac), which an eager key would add to
  every session's `Names`, about 0.1% of the pumasim `aa; pdd` row. Showing a
  name demangles it at print, O(length).
- D571, text. A terminated run is text where each character is printable or
  a byte a C string literal names by a simple escape (`\a \b \t \n \v \f \r`,
  ISO C 6.4.4.4) or ESC, the alphabet radare2's scanner admits
  (`libr/bin/bfile.c:288-298`); any other control byte ends it, and the
  first start whose suffix is text is what a scan finds (`first_text_in`).
  `names::escaped` is the one speller, radare2's string scanner's table
  (`bfile.c:303-310`: `\a \b \t \n \v \f \r`, `\e` for ESC, `\\` for a
  backslash, no quote escaping, as radare2's `iz` and string comments print);
  a string flag is its `flag_filter` (macOS `ansi`: `str.e8qo__d_n`, as
  radare2 names it; `\x1b` first gave `str.x1b8qo__d_n`, a D490 `pd` line).
  Rendered C reads `native::literal_at`, the pre-D571 alphabet, so rendering moves no
  byte: census, goldens 0 moves.
- D571, immediates. A constant the line moves whole, by a copy, an extension
  or as the word a store writes, and that no claim on the line uses as an
  address, gets `AnnotationKind::TextIfAddress` where static data the file
  backs reads as text there: standing `Unknown`, mark `?`, role none, so it is
  no reference and names no operand. A constant an arithmetic, compare or mask
  operation reads gets nothing (`moved_whole`, O(ops of one instruction)).
  bomb 0x400f51 `mov esi, 0x4025cf ; ? "%d %d"`; bash 0x1f8b2 keeps
  `and eax, 0xf000 ;   defines rax in [0x0, 0xf000]`; crackme 0x4006ac keeps
  `^ "Password: "`.
- D571, pages. AArch64 `adrp` lifts as a copy of its page, as `adr` lifts as a
  copy of its address, so the lift alone does not tell them apart. A value a
  line forms from its own position alone is lifted again `STEP` (4) bytes on:
  an address moves 4 bytes, a rounded page base moves 0 or a page. A page
  holds no text or held word until an `add` or a load completes it; its
  `Computes` claim and reference stay. One extra lift per such line, no pass.
  ls-toybox `seq_main` (0x392dc): text notes 15 to 8, the 7 on `adrp` lines
  gone; the AArch64 goldens hold no page-base note, so none moves.
- D571, quotes: a note's text was Rust's `{:?}`, which escaped `"` and spelled
  other characters as `\u{..}`; it is `"` + `names::escaped` + `"` now, a quote
  bare as radare2's comment prints it (bash 0x2c8b9: `"Use "%s" to leave the
  shell.\n"`). Goldens: 0 lines.
- D571, `iz` and `izz` against radare2 6.2.5 (Mac) over 241 ELF testbins:
  r2s-only `iz` rows 5,827 to 5,420 and `izz` 5,414 to 3,730; radare2-only
  rows fall too. Rows r2s newly lists alone: `iz` 44 (23 radare2's `izz`
  lists within 2 bytes, 12 shorter than radare2's 4, 9 packed `.\v` tables
  in libflutter.so and textile), `izz` 709 (663 within 2 bytes, radare2's
  start backs up after a short run, `bfile.c:331-334`; 46 code bytes and
  tables radare2's UTF-8 block filter, `bfile.c:356-390`, refuses). bashbot
  0x9908 `wget ... \r\n` is listed by `izz` and `iz`.
- D571, the floor (D623, open). radare2's rule, at least 4 characters
  (`bfile.c:335`, `bin_elf64.c:147`), lists 0pack 17,560 strings (radare2
  17,874, r2s 6,641) but raises r2s-only `iz` rows 5,420 to 7,543 over the
  same 241 files, so the chance bound stays.
## Round 15 as built: listing

- D569: `Role` gains the 8 proof roles, `Flow`, `FlowLoop` and `Rail`. One
  table in `theme.rs` gives each role its SGR parameters at depth 1, 2 and 3;
  `ansi` takes the depth and `style()` reads the depth-1 column for the visual
  mode, so the visual mode and the shell paint from one table. The light
  column is not built: no key selects it. `Role::marked` maps a mark cell to
  its proof role, so colour repeats the glyph; r2s-tui reads no `r2source`
  type. `scr.color` takes 0 to 3 (`Session.color` is the depth). The listing
  and `afi` write every note through `listing::noted`: the cell in its proof
  role, a refusal's words in `ProofReason`, a quoted string in `String`.
  Plain output moves 0 bytes.
- D565: `FunctionListing.edges` holds each `Jump` and `Taken` edge as
  `FlowEdge { from, to, kind, latch }`, read once off the shape `listed_body`
  already builds, `O(B log L)`. `latch` is the engine's: the target line
  carries `Loop` and the source block is one of its latches (the block starts
  are in the shape, not in the lines r2s reads). r2s `flow.rs` lays rows out:
  label, trailing and gap rows are rows, so a lane passes through them.
  Admission is a segment tree over rows (range add, range maximum) taking
  edges by (span, from); colouring takes admitted edges by span start and
  gives each the lowest free lane from a min-heap, lane 1 nearest the
  address. Glyphs are radare2's: `┌─<`, `└─>`, an upward edge mirrored
  (`┌─>` at its target, `└─<` at its source) with `╎` for its lane, as
  `get_utf8_char` maps `:` (`libr/core/disasm.c:446-460`); ASCII as
  `reflines.c:486-503` and `:552-555` write it. A horizontal run keeps a lane
  it crosses. A row any edge reaches takes `>`, else `<`. A stub sits in cell
  `w`, or `w + 1` where a head stands. `asm.lines=false` keeps the rail and the
  address column. The first `;` stands at `asm.cmt.col` on `pd` and `pdf`
  rows; a terminal cuts note text, then operand text, then the mark
  (`flow::cut`); a pipe never cuts. `VV` writes radare2's `t` and `f` beside
  a conditional branch's two edges, each on the side its route turns to.
- D566: the trace records each call and tail branch with its instruction
  (`Trace::call_sites`, `tail_sites`; `transfer` and `branch` take the site).
  `Survey.callers` and `tail_callers` hold one compressed row per callee: the
  distinct callers as one slice (`callers_of` is unchanged) and each caller's
  sites, so no second map of callers exists; `xrefs_of` answers in
  `O(log F + k)`. `FunctionListing.header` holds the calls, the tails,
  `unresolved` and the `FunctionInfo` read off the seal the `ret` notes read.
  `unresolved` is `None`: a trace counts neither the indirect calls it walks
  past nor which dispatch stops a table later resolved, so the header prints
  `; ? xrefs may be short: indirect transfers unread` on every function
  (default-deny). r2s spells radare2's grammar (`disasm.c:1723-1734`,
  `:1849-1866`): `CALL XREF`/`CALL XREFS` per caller, `CODE XREF` for a tail
  branch, `; XREFS(N)` past 5. `┌ realsz: name (args);` takes the proven
  parameters by name and `?` where the interface states a floor (`?` alone
  where no analysis states any). The notes are `afi`'s, one speller in
  `function.rs`: `~ at least N args` (also on `afi`'s `args:` row) and
  `! result unproven: carrier, cause`. A span line where blocks lie below the
  entry, and a gap row `;-- N bytes not in this function: A..B` between
  non-adjacent lines. Not built: the `*` result line (the closed result's
  premise moves to the result fact with D592), the `.` unstated-sign width
  line, the `?` kind of gap (bytes no body holds needs a range query on
  `Holders`), and the floor's causes in the header (they stay on `pdd`'s proof
  line, whose speller is r2dec's). Cost left open: `afb`, `agf` and `VV` go
  through `listed_body` and pay for the header's `FunctionInfo` read and
  survey lookup they discard.
- D568: r2dec's `Emission` states `depths` (one byte per definition line, the
  indentation `emit_indent` writes), `proof_line` (the line of
  `/* r2dec proof: ... */`), `indent` (the bytes one level takes) and
  `lowest_addresses` (each line's lowest instruction, from `lines`, unit
  numbering less the prelude). r2s `rails.rs` lays the definition out only
  under `asm.rails` or `asm.pdd.addr`; plain `pdd` prints the definition's
  bytes, so `census.py:138`, `certify_render.py:98` and the four `r2dec
  proof:` parsers read what they read. Each level's indentation becomes `│`
  and three spaces (`Rail`); past 24 levels one `│ N>`. The column is
  `0x%08x` and a space, blank where a line accounts for no instruction; a
  blank line takes neither. The proof line gives way to at most 2 lines: the
  refused and undecided facts (`afi`'s result note, the residual count, the
  ledger's refused and residual columns), then the assumed column, `afi`'s
  floor note, the compiler-inserted column and the response's premises. The
  type clauses (`N data object types refused`, `N never assigned`) are not in
  the typed response, so they stay in plain `pdd` and `pddo` only. A grep
  reads plain `pdd` and an uncut `pdf`, as a pipe does. Not held: the
  160-cell bound. A statement alone exceeds it (plain `pdd` on
  hashes has 57 lines over 149 cells, branchy 12, shapes 41; bash `main`
  reaches 2,594 with the proof line and 310 without); a rail never widens a
  line, so with the column a line is at most 11 cells past its plain width.
