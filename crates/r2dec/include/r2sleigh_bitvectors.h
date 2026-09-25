#ifndef R2SLEIGH_BITVECTORS_H
#define R2SLEIGH_BITVECTORS_H

/*
 * External C11 helpers for operations C has no operator for.
 *
 * A carrier wider than 128 bits is not defined here. Each rendering defines
 * the `struct r2sleigh_bits_N` it declares, and the helpers it calls on one,
 * from r2dec's single statement of that representation (crates/r2dec/src/
 * bitvector.rs), so a rendering compiles on its own and there is no second
 * definition to disagree with it.
 */

#include <stdint.h>

#if defined(__clang__) || defined(__GNUC__)
#define R2SLEIGH_UNUSED __attribute__((unused))
#else
#define R2SLEIGH_UNUSED
#endif

/*
 * Exact arithmetic-flag helpers.  Keeping the intermediate arithmetic in the
 * unsigned carrier type avoids C signed-overflow undefined behavior.  A
 * rendered source operand appears once at the callsite; repeated bit tests are
 * performed only on these helper-local values.
 */
#define R2SLEIGH_DEFINE_ARITHMETIC_FLAGS(BITS, TYPE)                              \
    static inline R2SLEIGH_UNUSED uint8_t                                         \
        r2sleigh_int_carry_##BITS(TYPE left, TYPE right)                          \
    {                                                                             \
        const TYPE result = (TYPE)(left + right);                                 \
        return (uint8_t)(result < left);                                          \
    }                                                                             \
    static inline R2SLEIGH_UNUSED uint8_t                                         \
        r2sleigh_int_scarry_##BITS(TYPE left, TYPE right)                         \
    {                                                                             \
        const TYPE result = (TYPE)(left + right);                                 \
        const TYPE same_sign = (TYPE)~(TYPE)(left ^ right);                       \
        const TYPE changed_sign = (TYPE)(left ^ result);                          \
        const TYPE overflow = (TYPE)(same_sign & changed_sign);                   \
        return (uint8_t)((overflow >> ((BITS)-1)) & (TYPE)1);                     \
    }                                                                             \
    static inline R2SLEIGH_UNUSED uint8_t                                         \
        r2sleigh_int_sborrow_##BITS(TYPE left, TYPE right)                        \
    {                                                                             \
        const TYPE result = (TYPE)(left - right);                                 \
        const TYPE different_sign = (TYPE)(left ^ right);                         \
        const TYPE changed_sign = (TYPE)(left ^ result);                          \
        const TYPE overflow = (TYPE)(different_sign & changed_sign);              \
        return (uint8_t)((overflow >> ((BITS)-1)) & (TYPE)1);                     \
    }

R2SLEIGH_DEFINE_ARITHMETIC_FLAGS(8, uint8_t)
R2SLEIGH_DEFINE_ARITHMETIC_FLAGS(16, uint16_t)
R2SLEIGH_DEFINE_ARITHMETIC_FLAGS(32, uint32_t)
R2SLEIGH_DEFINE_ARITHMETIC_FLAGS(64, uint64_t)
R2SLEIGH_DEFINE_ARITHMETIC_FLAGS(128, __uint128_t)

/*
 * Floating-point helpers.  A value that crosses between an integer object and
 * a floating reader keeps its bits; the unary operations are the compiler
 * builtins, so no libm header is needed.  Round is p-code's floor(x + 0.5).
 */
#define R2SLEIGH_DEFINE_FLOAT(BITS, TYPE, INT, SUFFIX)                            \
    static inline R2SLEIGH_UNUSED TYPE r2sleigh_float_from_bits_##BITS(INT bits)    \
    {                                                                             \
        TYPE value;                                                               \
        __builtin_memcpy(&value, &bits, sizeof value);                            \
        return value;                                                             \
    }                                                                             \
    static inline R2SLEIGH_UNUSED INT r2sleigh_float_to_bits_##BITS(TYPE value)     \
    {                                                                             \
        INT bits;                                                                 \
        __builtin_memcpy(&bits, &value, sizeof bits);                             \
        return bits;                                                              \
    }                                                                             \
    static inline R2SLEIGH_UNUSED TYPE r2sleigh_float_abs_##BITS(TYPE x)            \
    {                                                                             \
        return __builtin_fabs##SUFFIX(x);                                         \
    }                                                                             \
    static inline R2SLEIGH_UNUSED TYPE r2sleigh_float_sqrt_##BITS(TYPE x)           \
    {                                                                             \
        return __builtin_sqrt##SUFFIX(x);                                         \
    }                                                                             \
    static inline R2SLEIGH_UNUSED TYPE r2sleigh_float_ceil_##BITS(TYPE x)           \
    {                                                                             \
        return __builtin_ceil##SUFFIX(x);                                         \
    }                                                                             \
    static inline R2SLEIGH_UNUSED TYPE r2sleigh_float_floor_##BITS(TYPE x)          \
    {                                                                             \
        return __builtin_floor##SUFFIX(x);                                        \
    }                                                                             \
    static inline R2SLEIGH_UNUSED TYPE r2sleigh_float_round_##BITS(TYPE x)          \
    {                                                                             \
        return __builtin_floor##SUFFIX(x + (TYPE)0.5);                            \
    }                                                                             \
    static inline R2SLEIGH_UNUSED uint8_t r2sleigh_float_isnan_##BITS(TYPE x)       \
    {                                                                             \
        return (uint8_t)__builtin_isnan(x);                                       \
    }

R2SLEIGH_DEFINE_FLOAT(32, float, uint32_t, f)
R2SLEIGH_DEFINE_FLOAT(64, double, uint64_t, )

#undef R2SLEIGH_DEFINE_FLOAT
#undef R2SLEIGH_DEFINE_ARITHMETIC_FLAGS
#undef R2SLEIGH_UNUSED

#endif
