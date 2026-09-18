# ADR: floating-point values travel as their own type

## Context

The lifter produces every p-code floating operation (`FLOAT_ADD` through
`TRUNC`), and nothing after it did. The machine projection had no floating
type or expression kind, so a `FloatMult` was an `UnsupportedOperation` and
its function refused; worse, where the interface named the wrong carrier the
floating body was dead and was elided, and `fp_interpolate` rendered as
`return (double)X0_0;`. The capture placed a `double` parameter in `x0` and
a `double` return in `x0`, because radare2's convention tables name only the
integer sequences and the capture used them for every class.

## Decisions

1. **Placement is by class.** A parameter whose type is a floating scalar is
   placed in the convention's floating sequence (`fparg`, addressed as index
   `R_ANAL_CC_MAXARG + n`) at its own position; integer parameters keep their
   own count. The carrier is the listed register of the operand's width
   (`{d0,s0,v0,q0}`), or the low lane of a wider home (`xmm0`). A floating
   return comes back in `fpret0`, which the radare2 fork now names per
   convention. A floating operand past the floating registers is not placed.
2. **`MachineType::Float { width_bits }`**, for 32 and 64 bits. Any other
   width refuses at the projection. A value is interned per `(value, type)`,
   as booleans already are, so one register read as bits and as a double is
   two nodes and the typed boundary decides the spelling.
3. **Distinct kinds, not modes.** `FloatArithmetic`, `FloatUnary` and
   `FloatCompare` are their own expression and term kinds, and the casts are
   `IntegerToFloat`, `FloatToInteger` and `FloatToFloat`. Every integer
   rewrite rule (`x + 0`, literal folding, reassociation, width masking) is
   false over IEEE values, and a distinct kind keeps each from firing by
   construction rather than by a guard in every rule. The evaluator computes
   them exactly with `f32`/`f64`, whose default rounding is the machine's.
4. **`SSAOp::Trunc` is p-code `TRUNC`**, a float-to-integer conversion toward
   zero, and is lowered as `FloatToInteger`. It was lowered as an integer
   truncation, which is `SUBPIECE`'s job; the integer-narrowing arms that
   listed it are corrected.
5. **C spelling.** Arithmetic and comparison are the C operators, which are
   the IEEE operations under default rounding; `fmadd` is what Sleigh makes
   of it, a multiply and an add. Negation is `-x`. Absolute value, square
   root, ceiling, floor and NaN tests are the compiler builtins
   (`__builtin_fabs`, with `f` for `float`), which need no header. Round is
   `floor(x + 0.5)`, which is p-code's definition. A constant spells as the
   shortest round-trip literal, `f`-suffixed at 32 bits; infinities as
   `__builtin_inf()`; the canonical quiet NaN as `__builtin_nan("")` and any
   other NaN payload refuses. A conversion the machine states is a C cast; a
   floating value met at an integer boundary, or the reverse, is a
   reinterpretation and spells through `r2sleigh_float_from_bits_64` and its
   inverses in the intrinsic header, never as `(double)x`.
6. **Declared type.** A binding with no stated type is declared `double` or
   `float` when its definition is floating, or when every read of every
   member is floating; otherwise the machine word, and the floating reads
   reinterpret.

## Consequences

Two `bzip2` bodies and the four `stress_test` floating fixtures become
renderable; `fp_magnitude` stops refusing at the wire because its `float`
parameters now have four-byte carriers. Variadic floating operands on Darwin
arm64 render from their stack slots. x87 80-bit values still refuse.
