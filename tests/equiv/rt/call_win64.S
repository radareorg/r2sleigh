/*
 * The Win64 thunk: equiv_call(fn, in, out) entered from System V, calling fn under Microsoft x64.
 *
 * struct equiv_regs keeps the x86-64 layout (equiv_rt.c): gpr[0..3] are rcx rdx r8 r9 and
 * xmm[0..3] xmm0..xmm3; the rest is unread. stack[0] is the word at 0x28(%rsp) on entry, past
 * the return address and the 32-byte home area the caller allocates (Microsoft x64 "Stack
 * allocation"). Every System V callee-saved register is Microsoft's too, so only those the
 * thunk itself uses are saved. The results are rax, rdx, xmm0 and xmm1, as on System V.
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
    leaq    47(,%rcx,8), %rax       /* the home area, the words, rounded to 16 */
    andq    $-16, %rax
    subq    %rax, %rsp
    xorq    %rax, %rax
2:
    cmpq    %rcx, %rax
    jae     3f
    movq    192(%r13,%rax,8), %rdx
    movq    %rdx, 32(%rsp,%rax,8)
    incq    %rax
    jmp     2b
3:
    movdqu  48(%r13), %xmm0
    movdqu  64(%r13), %xmm1
    movdqu  80(%r13), %xmm2
    movdqu  96(%r13), %xmm3
    movq    0(%r13), %rcx
    movq    8(%r13), %rdx
    movq    16(%r13), %r8
    movq    24(%r13), %r9
    xorl    %eax, %eax
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
