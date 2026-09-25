/*
 * The register-level thunk of the equivalence gate.
 *
 *   void equiv_call(void *fn, const struct equiv_regs *in, struct equiv_ret *out);
 *
 * Both the original function and its rendering are entered through this one
 * routine, from the same forked parent state, so each sees the identical
 * machine entry state: rdi..r9, xmm0..xmm7 (all 128 bits), rax (which carries
 * AL, the vector-register count a variadic callee reads) and the stack
 * argument words. The rendering is therefore judged against the machine ABI
 * the original was compiled to, not against the C prototype it declares.
 *
 * struct equiv_regs (see equiv_rt.c):
 *     0   uint64_t gpr[6]        rdi rsi rdx rcx r8 r9
 *    48   uint8_t  xmm[8][16]
 *   176   uint64_t rax
 *   184   uint64_t n_stack       at most 16
 *   192   uint64_t stack[16]     stack[0] is the word at 8(%rsp) on entry
 *
 * struct equiv_ret:
 *     0   uint64_t rax
 *     8   uint64_t rdx
 *    16   uint8_t  xmm0[16]
 *    32   uint8_t  xmm1[16]
 */
    .text
    .globl  equiv_call
    .type   equiv_call, @function
equiv_call:
    .cfi_startproc
    pushq   %rbp
    .cfi_def_cfa_offset 16
    .cfi_offset %rbp, -16
    movq    %rsp, %rbp
    .cfi_def_cfa_register %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    subq    $8, %rsp                /* rsp is now 16-byte aligned */

    movq    %rdi, %r12              /* fn  */
    movq    %rsi, %r13              /* in  */
    movq    %rdx, %r14              /* out */

    movq    184(%r13), %rcx         /* n_stack */
    cmpq    $16, %rcx
    jbe     1f
    movq    $16, %rcx
1:
    leaq    15(,%rcx,8), %rax
    andq    $-16, %rax
    subq    %rax, %rsp              /* still 16-byte aligned at the call */
    xorq    %rax, %rax
2:
    cmpq    %rcx, %rax
    jae     3f
    movq    192(%r13,%rax,8), %rdx
    movq    %rdx, (%rsp,%rax,8)
    incq    %rax
    jmp     2b
3:
    movdqu  48(%r13), %xmm0
    movdqu  64(%r13), %xmm1
    movdqu  80(%r13), %xmm2
    movdqu  96(%r13), %xmm3
    movdqu  112(%r13), %xmm4
    movdqu  128(%r13), %xmm5
    movdqu  144(%r13), %xmm6
    movdqu  160(%r13), %xmm7
    movq    0(%r13), %rdi
    movq    8(%r13), %rsi
    movq    16(%r13), %rdx
    movq    24(%r13), %rcx
    movq    32(%r13), %r8
    movq    40(%r13), %r9
    movq    176(%r13), %rax
    call    *%r12

    movq    %rax, 0(%r14)
    movq    %rdx, 8(%r14)
    movdqu  %xmm0, 16(%r14)
    movdqu  %xmm1, 32(%r14)

    leaq    -40(%rbp), %rsp
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    .cfi_def_cfa %rsp, 8
    ret
    .cfi_endproc
    .size   equiv_call, .-equiv_call

    .section .note.GNU-stack,"",@progbits
