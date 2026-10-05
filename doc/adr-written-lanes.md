# ADR: written lanes, and widths read from them

Status: in progress; result widths done (ROADMAP PE)

## Decision

A result's width is which bytes of the returned carrier the function
*computed*, as against bytes the machine filled by convention or the caller
left. That is a fact about each operation's output bytes, recorded before
optimisation rewrites it away. A syntactic rule over prepared IR fails both
ways: constant folding erases the `ZEXT` in `xor eax, eax; ret` (too wide,
`uint64_t` for `int`), and `setg al` defines `RAX` by a one-byte `INSERT` that
the caller reads as `eax` (too narrow).

- **The record.** `r2ssa::lanes::Written`, captured in `Lifted::prepare`
  before any optimisation and kept on the function by `OpId`
  (`SSAFunction::written`). Rewriting an op in place keeps its id
  (doc/adr-stable-identity.md), so folding `ZEXT(EAX ^ EAX)` to a constant
  keeps what the instruction wrote. A value defined after the lift (a lane
  projection) is read through its inputs by the same transfer.
- **Per-byte class** (`lanes::Byte`): `Data`; `Widened { sign }` for an
  extension the instruction states; or `Filled` with the set of ways it was not
  computed (`Fill::Zero`, `Fill::Sign`, `Fill::Entry(RegisterByte)`). A byte is
  *written* if it is data, or holds an entry byte from anywhere other than
  where it now sits. The phi join is the union; more than four ways count as
  data. A literal's bytes are data.
- **Convention fills are not written.** The architecture's zero above a
  lower-half write (`RAX = zext(EAX)`, arm64 `X0 = zext(tmp)`) is a fill; a zero
  extension doubling a register lane with nothing later in its instruction
  extending again is taken as that (`Written::is_conventional_extension`). An
  extension the instruction states (`movzx eax, al`) writes its destination
  whole. Where one P-code op does both (arm64 `cset w0`), the whole is
  written. A sign extension is never the convention. Too wide is sound; too
  narrow drops bytes the caller reads.
- **Result width:** one past the highest byte any return path's live-out
  value writes, rounded to the carrier's lanes (`lanes::written_width`). Upper
  bytes that are stated sign extensions on every path make the result
  `SignedInteger` (`lanes::signed`); interface types are keyed by width and
  sign. A result some path never wrote is unproven, not void (arm64's bare
  `ret` returning untouched `x0`). Value ranges never decide a width.
- **Parameter width:** the smallest lane covering the bytes demanded of the
  entry value (`cover(demanded)`).
- **One relation.** The backward demand pass (`demand.rs`) and this forward
  pass should read one byte-dependency relation, so they cannot disagree
  about what an operation does with a byte, checked against `r2il::eval`
  exhaustively at 8 and 16 bits and under Kani at 32 and 64.
- Cost: one forward pass at construction, O(ops × W) for width W bytes; one
  lookup per live-out value at recovery.

## Done

- `r2ssa::lanes` and its capture in `Lifted::prepare`; interface recovery reads it for each return's value; `narrow_zero_extend_input_size` deleted.
- Result widths fixed for `main`, `fnv1a32`, `gt` and `pearson` (issues #58, #63).
- `exact_logical_lane_input` follows extension and low-insert chains to the lane exactly as wide as the result, so a `uint8_t` function returns the byte.

## Left

- The demand pass reads its own transfer, not `lanes`' relation. Exit: one relation feeds both, as an F2 index (ROADMAP PE).
- The per-operation proof harness against `r2il::eval` and Kani does not exist yet. Exit: it runs in the quality gate.
- Parameter widths are not restated as `cover(demanded)` over the shared relation. Exit: lands with the demand fold.
- XMM lane noise (a vector register's partial writes read as its width). Exit: no vector-lane width in the census interfaces.
