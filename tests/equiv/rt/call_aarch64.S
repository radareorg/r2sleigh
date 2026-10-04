/*
 * The register-level thunk of the equivalence gate, for AArch64 (AAPCS64).
 *
 *   void equiv_call(void *fn, const struct equiv_regs *in, struct equiv_ret *out);
 *
 * Both the original function and its rendering are entered through this one
 * routine, from the same forked parent state, so each sees the identical
 * machine entry state: x0..x7, v0..v7 (all 128 bits) and the stack argument
 * words. The rendering is therefore judged against the machine ABI the
 * original was compiled to, not against the C prototype it declares. Every
 * register no argument travels in is whatever this routine left there, the
 * same for both: in particular x8, the indirect result register, which no
 * graded signature uses (an aggregate return is unsupported).
 *
 * struct equiv_regs (see equiv_rt.c):
 *     0   uint64_t gpr[8]        x0..x7
 *    64   uint8_t  v[8][16]      q0..q7
 *   192   uint64_t n_stack       at most 16
 *   200   uint64_t stack[16]     stack[0] is the word at [sp] on entry
 *
 * AAPCS64 (as Linux uses it) gives every stack argument its own 8-byte word,
 * in order from the stack pointer, and wants sp 16-byte aligned at the call.
 *
 * struct equiv_ret:
 *     0   uint64_t x0
 *     8   uint64_t x1
 *    16   uint8_t  q0[16]
 *    32   uint8_t  q1[16]
 */
    .text
    .globl  equiv_call
    .type   equiv_call, %function
    .p2align 2
equiv_call:
    .cfi_startproc
    stp     x29, x30, [sp, #-48]!
    .cfi_def_cfa_offset 48
    .cfi_offset x29, -48
    .cfi_offset x30, -40
    mov     x29, sp
    .cfi_def_cfa_register x29
    stp     x19, x20, [sp, #16]
    .cfi_offset x19, -32
    .cfi_offset x20, -24
    str     x21, [sp, #32]
    .cfi_offset x21, -16

    mov     x19, x0                 /* fn  */
    mov     x20, x1                 /* in  */
    mov     x21, x2                 /* out */

    ldr     x9, [x20, #192]         /* n_stack */
    cmp     x9, #16
    b.ls    1f
    mov     x9, #16
1:
    add     x10, x9, #1             /* words rounded up to an even count: */
    and     x10, x10, #-2           /* sp stays 16-byte aligned at the call */
    lsl     x10, x10, #3
    mov     x11, sp
    sub     x11, x11, x10
    mov     sp, x11
    add     x12, x20, #200          /* &in->stack[0] */
    mov     x11, #0
2:
    cmp     x11, x9
    b.hs    3f
    ldr     x13, [x12, x11, lsl #3]
    str     x13, [sp, x11, lsl #3]
    add     x11, x11, #1
    b       2b
3:
    ldp     q0, q1, [x20, #64]
    ldp     q2, q3, [x20, #96]
    ldp     q4, q5, [x20, #128]
    ldp     q6, q7, [x20, #160]
    ldp     x0, x1, [x20, #0]
    ldp     x2, x3, [x20, #16]
    ldp     x4, x5, [x20, #32]
    ldp     x6, x7, [x20, #48]
    blr     x19

    stp     x0, x1, [x21, #0]
    stp     q0, q1, [x21, #16]

    mov     sp, x29
    ldr     x21, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #48
    .cfi_def_cfa sp, 0
    ret
    .cfi_endproc
    .size   equiv_call, .-equiv_call

    .section .note.GNU-stack,"",%progbits
