/*
 * What a Win64 rendering (built with -mabi=ms) calls that is no link: the compiler's own memory
 * calls, a C library call the image holds no import of, and in the ubsan variant UBSan's
 * handlers, each forwarded to glibc's System V one. Hidden, so only the rendering binds here,
 * and weak, so a link the shim defines under the same name wins.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>

#define SUPPORT __attribute__((visibility("hidden"), weak, no_sanitize_undefined, used, \
                               optimize("no-tree-loop-distribute-patterns")))

SUPPORT void *memset(void *d, int c, size_t n)
{
    volatile unsigned char *p = d;
    while (n--)
        *p++ = (unsigned char)c;
    return d;
}

SUPPORT void *memcpy(void *d, const void *s, size_t n)
{
    volatile unsigned char *p = d;
    const unsigned char *q = s;
    while (n--)
        *p++ = *q++;
    return d;
}

SUPPORT void *memmove(void *d, const void *s, size_t n)
{
    volatile unsigned char *p = d;
    const unsigned char *q = s;
    if (p < q) {
        while (n--)
            *p++ = *q++;
    } else {
        while (n--)
            p[n] = q[n];
    }
    return d;
}

SUPPORT int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *p = a, *q = b;
    for (; n; n--, p++, q++)
        if (*p != *q)
            return *p < *q ? -1 : 1;
    return 0;
}

/* glibc's loader calls, made under System V: -mabi=ms would call them with rcx and rdx. */
typedef int (__attribute__((sysv_abi)) *dladdr_t)(const void *, Dl_info *);
typedef void *(__attribute__((sysv_abi)) *dlopen_t)(const char *, int);
typedef void *(__attribute__((sysv_abi)) *dlsym_t)(void *, const char *);

/* glibc's own `name`: the weak wrappers here hide it from this file. */
static void *libc(const char *name)
{
    void *volatile at = (void *)dlsym;
    return ((dlsym_t)at)(RTLD_DEFAULT, name);
}

typedef struct _IO_FILE FILE;

SUPPORT int fputs(const char *text, FILE *stream)
{
    return ((int (__attribute__((sysv_abi)) *)(const char *, FILE *))libc("fputs"))(text, stream);
}

SUPPORT int puts(const char *text)
{
    return ((int (__attribute__((sysv_abi)) *)(const char *))libc("puts"))(text);
}

SUPPORT int putchar(int c)
{
    return ((int (__attribute__((sysv_abi)) *)(int))libc("putchar"))(c);
}

SUPPORT int raise(int sig)
{
    return ((int (__attribute__((sysv_abi)) *)(int))libc("raise"))(sig);
}

/* A Microsoft x64 `...` is 8-byte slots: a System V list with its registers spent reads them. */
SUPPORT int printf(const char *format, ...)
{
    __builtin_ms_va_list slots;
    __builtin_ms_va_start(slots, format);
    __builtin_sysv_va_list list;
    list[0].gp_offset = 48;
    list[0].fp_offset = 176;
    list[0].overflow_arg_area = (void *)slots;
    list[0].reg_save_area = 0;
    int written = ((int (__attribute__((sysv_abi)) *)(const char *, __builtin_sysv_va_list))
                   libc("vprintf"))(format, list);
    __builtin_ms_va_end(slots);
    return written;
}

/* The ubsan variant defines EQUIV_UBSAN (link.py). */
#if defined(EQUIV_UBSAN)
typedef void (__attribute__((sysv_abi)) *handler)(uintptr_t, uintptr_t, uintptr_t, uintptr_t);

/* libubsan's handler: this object's own handle searches its dependencies, and the hidden
 * wrappers here are no dynamic symbol (RTLD_NEXT sees no RTLD_LOCAL dependency). */
static handler real(const char *name)
{
    static void *self;
    void *volatile at[3] = { (void *)dladdr, (void *)dlopen, (void *)dlsym };
    Dl_info where;
    if (!self && ((dladdr_t)at[0])((void *)real, &where) && where.dli_fname)
        self = ((dlopen_t)at[1])(where.dli_fname, RTLD_NOW | RTLD_NOLOAD);
    return self ? (handler)((dlsym_t)at[2])(self, name) : (handler)0;
}

/* Every handler takes at most four pointer-sized operands (libubsan's ValueHandle). */
#define HANDLER(name)                                                                           \
    SUPPORT void __ubsan_handle_##name(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)      \
    {                                                                                           \
        real("__ubsan_handle_" #name)(a, b, c, d);                                               \
    }

HANDLER(add_overflow)
HANDLER(add_overflow_abort)
HANDLER(alignment_assumption)
HANDLER(alignment_assumption_abort)
HANDLER(builtin_unreachable)
HANDLER(divrem_overflow)
HANDLER(divrem_overflow_abort)
HANDLER(float_cast_overflow)
HANDLER(float_cast_overflow_abort)
HANDLER(function_type_mismatch)
HANDLER(function_type_mismatch_abort)
HANDLER(implicit_conversion)
HANDLER(implicit_conversion_abort)
HANDLER(invalid_builtin)
HANDLER(invalid_builtin_abort)
HANDLER(load_invalid_value)
HANDLER(load_invalid_value_abort)
HANDLER(missing_return)
HANDLER(mul_overflow)
HANDLER(mul_overflow_abort)
HANDLER(negate_overflow)
HANDLER(negate_overflow_abort)
HANDLER(nonnull_arg)
HANDLER(nonnull_arg_abort)
HANDLER(nonnull_return_v1)
HANDLER(nonnull_return_v1_abort)
HANDLER(out_of_bounds)
HANDLER(out_of_bounds_abort)
HANDLER(pointer_overflow)
HANDLER(pointer_overflow_abort)
HANDLER(shift_out_of_bounds)
HANDLER(shift_out_of_bounds_abort)
HANDLER(sub_overflow)
HANDLER(sub_overflow_abort)
HANDLER(type_mismatch_v1)
HANDLER(type_mismatch_v1_abort)
HANDLER(vla_bound_not_positive)
HANDLER(vla_bound_not_positive_abort)
#endif
