# ADR: floating-point values travel as their own type

Status: done (placement moves to the compiler specification at M1d)

## Decision

1. **Placement is by class.** A floating-scalar parameter is placed in the
   convention's floating sequence at its own position, and integer parameters
   keep their own count. The carrier is the register of the operand's width
   (`{d0,s0,v0,q0}`) or the low lane of a wider home (`xmm0`). A floating
   result is returned in the convention's float result slot. A floating
   operand past the floating registers is not placed. The slots are carried
   on `SourceConventionSlots::float_argument_slots`/`float_result_slot`. They
   are read from r2abi's sdb (`fparg`, `fpret0`) until M1d moves them to the
   `.cspec`'s float entries (doc/adr-machine-profile.md).
2. **`MachineType::Float { width_bits }`** covers 32 and 64 bits; any other
   width refuses at the projection. A value is interned per `(value, type)`,
   so one register read as bits and as a double is two nodes, and the typed
   boundary decides the spelling.
3. **Distinct kinds, not modes.** `FloatArithmetic`, `FloatUnary` and
   `FloatCompare` are their own expression and term kinds, and the casts are
   `IntegerToFloat`, `FloatToInteger` and `FloatToFloat`. Integer rewrite
   rules (`x + 0`, literal folding, reassociation, width masking) are false
   over IEEE values, and distinct kinds keep them from firing by construction.
   The evaluator computes with `f32`/`f64` under default rounding.
4. **`SSAOp::Trunc` is p-code `TRUNC`,** a float-to-integer conversion toward
   zero, lowered as `FloatToInteger`. Integer narrowing is `SUBPIECE`.
5. **C spelling.**
   - Arithmetic and comparison use the C operators. `fmadd` is a multiply and
     an add, as Sleigh lifts it. Negation is `-x`.
   - Absolute value, square root, ceiling, floor, round and the NaN test are
     helpers in the intrinsic header (`r2sleigh_float_{abs,sqrt,ceil,floor,
     round,isnan}_{32,64}`). Absolute value clears the sign bit, the NaN test
     is `x != x`, and the others call the compiler builtins. Round is p-code's
     `floor(x + 0.5)`, evaluated in double at every width.
   - A constant is the shortest round-trip literal, with an `f` suffix at 32
     bits. Infinities are `__builtin_inf[f]()`, the canonical quiet NaN is
     `__builtin_nan[f]("")`, and any other NaN payload refuses.
   - A conversion the machine states is a C cast. A floating value met at an
     integer boundary, or the reverse, is a reinterpretation through
     `r2sleigh_float_from_bits_{32,64}` / `r2sleigh_float_to_bits_{32,64}`,
     never `(double)x`.
6. **Declared type.** A binding with no stated type is declared `double` or
   `float` when its definition is floating, or when every read of every member
   is floating. Otherwise it is the machine word, and floating reads
   reinterpret.

## Done

- All six decisions landed. The `stress_test` floating fixtures render on
  arm64 and x86-64, and Darwin arm64 variadic floating operands render from
  their stack slots.

## Left

- M1d: float slots from the `.cspec` as lanes of the program root. Exit:
  r2abi's `fparg`/`fpret` reads are deleted.
- x87 80-bit values still refuse. Exit: an 80-bit `MachineType::Float` with
  an exact evaluator, or a stated permanent refusal.
