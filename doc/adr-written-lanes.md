# ADR: written lanes, and widths read from them

Status: accepted, result widths landed (ROADMAP PE)

## Context

A function's result width is decided today by `narrow_zero_extend_input_size`
(`r2ssa/src/recover_interface.rs`): where the returned carrier is defined by
`IntZExt` or by an `Insert` at position zero, the width is that operation's
input width. That is a syntactic rule over the prepared IR, and it fails both
ways:

- **Too wide.** `xor eax, eax; ret` lifts to `EAX = EAX ^ EAX; RAX = ZEXT(EAX)`.
  Constant folding turns the pair into `RAX = COPY 0:8` before interface
  recovery runs, so the extension the rule looks for is gone and `main`
  returns `uint64_t` where the source says `int`. Same for `fnv1a32` at -O1/-O2
  (issue #58).
- **Too narrow.** `xor eax, eax; setg al` defines RAX by an INSERT of one byte
  at position zero, so the rule answers one byte and `gt` returns `uint8_t`
  where the source returns `int` — the three `ub` records of issue #63's
  corpus, because the caller reads `eax`.

The question the rule tries to answer is which bytes of the result the
function *computed*, as against bytes the machine filled by a convention (a
32-bit write zeroing the upper half) or left from the caller. That is a fact
about each operation's output bytes, and it is lost when the operation is
rewritten.

## Decision

**One byte-dependency relation.** For every operation, `dep(op, out_byte)`
names the input bytes the output byte depends on, or says it is a fill:

| Class | Meaning |
|-------|---------|
| `Data` | computed by the operation from its inputs or a literal |
| `Passed(class)` | copied from one input byte, carrying that byte's class |
| `ZeroFill` | the constant zero an unsigned extension writes |
| `SignFill` | a copy of the source's sign bit, as a signed extension writes |

The backward demand pass (`demand.rs`) and this forward pass both read the
relation, so the two cannot disagree about what an operation does with a
byte. A per-operation proof harness checks the relation against `r2il::eval`
exhaustively at 8 and 16 bits, and under Kani at 32 and 64.

**Written lanes, captured before optimisation.** In the `Lifted` stage, before
any rewrite, every operation defining a register carrier records its output's
class per byte, in its arena slot keyed by `OpId`. The forward closure over
phis is the join: a byte is `Data` if any arm writes data there. Rewriting an
op in place keeps its id (ADR stable identity), so folding `ZEXT(EAX ^ EAX)`
to a constant keeps the record of what the instruction wrote.

**Widths.**

- *Result:* the carrier is defined on every return path (P7 owns that proof);
  its width is one past the highest byte any return path's live-out value
  writes as `Data`, rounded up to the carrier's lane sizes. Upper bytes that
  are `SignFill` on every path are evidence of a signed result. Value ranges
  never decide a width.
- *Parameter:* the smallest lane covering the bytes demanded of the entry
  value (`cover(demanded)`), as the demand pass already computes.

**Deleted:** `narrow_zero_extend_input_size`, and the XMM lane noise that came
from treating a vector register's partial writes as its width.

## Consequences

- Fixes the return widths of `main`, `fnv1a32` and `gt` above, and `pearson`
  (`movzx eax, byte` writes one `Data` byte, so `uint8_t`, which is the
  source's type) — four entries of the source-gold baseline and three
  equivalence `ub` records.
- Depends on F1 step 2: the record is taken in `Lifted` and read in `Sealed`.
- Cost: one forward pass over the operations at construction, O(ops × W) for
  width W in bytes; one lookup per live-out value at recovery.

## As landed

- `r2ssa::lanes` holds the record. `Lifted::prepare` takes it before
  optimisation and keeps it on the function by `OpId`
  (`SSAFunction::written`). Interface recovery reads it for the value each
  return hands back. A value defined after the lift (a lane projection) is
  read through its inputs by the same transfer.
- Each byte is `Data` or the set of ways it was not computed: `Zero`,
  `Sign`, or `Entry(register byte)`. A byte is *written* if it is data, or
  if it holds an entry byte from anywhere other than where it now sits.
  `mov eax, edi` writes four bytes; `setg al` alone writes one. The join is
  the union, and more than four ways count as data. The relation is the
  forward one only. Folding the demand pass onto the same relation is still
  to do.
- A literal's bytes are data, so `return 1` is as wide as the instruction
  that wrote it.
- Fills are of two kinds. The architecture's zero above a lower-half
  write (`RAX = zext(EAX)` after `xor eax, eax`, arm64's `X0 = zext(tmp)`)
  is not written. A zero extension doubling a register lane, with nothing
  later in its instruction extending it again, is taken as that. An
  extension the instruction states (`movzx eax, al`, then the
  convention's) writes its destination whole, as `Widened`. The pure-data
  rule made gcc's `return (m > 0) ^ (n > 0);` (`movzx eax, al`) a
  `uint8_t`, which the equivalence gate caught as `ub`: the caller reads
  EAX. Where one P-code operation does both (arm64 `cset w0` is
  `X0 = zext(ZR)`), the whole is taken as written. Too wide is sound; too
  narrow drops bytes the caller reads. A sign extension is never the
  convention.
- A result some path never wrote is unproven, not void. On arm64,
  `int id(int x) { return x; }` is a bare `ret`, and the untouched `x0` is
  the result.
- A result whose top written bytes are a stated sign extension is minted
  `SignedInteger`. `movsx eax, al` returning -1, 0 or 1 is `int8_t`, not
  `uint8_t`. Interface types are now keyed by width and sign.
- Two consequences were fixed at the owner. `exact_logical_lane_input`
  follows a chain of extensions or low inserts down to the lane exactly as
  wide as the result, so `return (uint64_t)DIL_0` from a `uint8_t` function
  is now `return` of the byte.
- Not done: the XMM lane noise, and the `cover(demanded)` restatement of
  parameter widths, which the demand pass computes already.

