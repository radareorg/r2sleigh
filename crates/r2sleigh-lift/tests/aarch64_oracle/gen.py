import sys

# Symbols carry the platform's C prefix: '_' on Mach-O, none on ELF.
P = sys.argv[1] if len(sys.argv) > 1 else ''
cases=[]
for line in open('cases.txt'):
    line=line.rstrip('\n')
    if not line or line.startswith('#'): continue
    name,flags,asm=line.split('|',2)
    cases.append((name,flags,[a.strip() for a in asm.split(';')]))
# State layout: x[31] @0, nzcv @248, fpcr @256, fpsr @264, v[32] @272 (512B), taken @784
PRO = """
    stp x29, x30, [sp, #-16]!
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp d8, d9, [sp, #-16]!
    stp d10, d11, [sp, #-16]!
    stp d12, d13, [sp, #-16]!
    stp d14, d15, [sp, #-16]!
    sub sp, sp, #16
    str x1, [sp]
    msr fpcr, xzr
    msr fpsr, xzr
    add x2, x0, #272
    ld1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x2], #64
    ld1 {v4.16b, v5.16b, v6.16b, v7.16b}, [x2], #64
    ld1 {v8.16b, v9.16b, v10.16b, v11.16b}, [x2], #64
    ld1 {v12.16b, v13.16b, v14.16b, v15.16b}, [x2], #64
    ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x2], #64
    ld1 {v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #64
    ld1 {v24.16b, v25.16b, v26.16b, v27.16b}, [x2], #64
    ld1 {v28.16b, v29.16b, v30.16b, v31.16b}, [x2], #64
    ldr x2, [x0, #248]
    msr nzcv, x2
    mov x30, x0
    ldp x0, x1, [x30, #0]
    ldp x2, x3, [x30, #16]
    ldp x4, x5, [x30, #32]
    ldp x6, x7, [x30, #48]
    ldp x8, x9, [x30, #64]
    ldp x10, x11, [x30, #80]
    ldp x12, x13, [x30, #96]
    ldp x14, x15, [x30, #112]
    ldp x16, x17, [x30, #128]
    ldr x19, [x30, #152]
    ldp x20, x21, [x30, #160]
    ldp x22, x23, [x30, #176]
    ldp x24, x25, [x30, #192]
    ldp x26, x27, [x30, #208]
    ldp x28, x29, [x30, #224]
    ldr x30, [x30, #240]
"""
def EPI(t):
    return f"""
    str x30, [sp, #-16]!
    ldr x30, [sp, #16]
    stp x0, x1, [x30, #0]
    stp x2, x3, [x30, #16]
    stp x4, x5, [x30, #32]
    stp x6, x7, [x30, #48]
    stp x8, x9, [x30, #64]
    stp x10, x11, [x30, #80]
    stp x12, x13, [x30, #96]
    stp x14, x15, [x30, #112]
    stp x16, x17, [x30, #128]
    stp x18, x19, [x30, #144]
    stp x20, x21, [x30, #160]
    stp x22, x23, [x30, #176]
    stp x24, x25, [x30, #192]
    stp x26, x27, [x30, #208]
    stp x28, x29, [x30, #224]
    ldr x0, [sp], #16
    str x0, [x30, #240]
    mrs x0, nzcv
    str x0, [x30, #248]
    mrs x0, fpsr
    str x0, [x30, #264]
    add x0, x30, #272
    st1 {{v0.16b, v1.16b, v2.16b, v3.16b}}, [x0], #64
    st1 {{v4.16b, v5.16b, v6.16b, v7.16b}}, [x0], #64
    st1 {{v8.16b, v9.16b, v10.16b, v11.16b}}, [x0], #64
    st1 {{v12.16b, v13.16b, v14.16b, v15.16b}}, [x0], #64
    st1 {{v16.16b, v17.16b, v18.16b, v19.16b}}, [x0], #64
    st1 {{v20.16b, v21.16b, v22.16b, v23.16b}}, [x0], #64
    st1 {{v24.16b, v25.16b, v26.16b, v27.16b}}, [x0], #64
    st1 {{v28.16b, v29.16b, v30.16b, v31.16b}}, [x0], #64
    mov x0, #{t}
    str x0, [x30, #784]
    add sp, sp, #16
    ldp d14, d15, [sp], #16
    ldp d12, d13, [sp], #16
    ldp d10, d11, [sp], #16
    ldp d8, d9, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret
"""
s=['.arch_extension sha3','.arch_extension cssc','.text','.p2align 4']
for i,(name,flags,asm) in enumerate(cases):
    s.append(f'.globl {P}case_{i}\n.p2align 4\n{P}case_{i}:')
    s.append(PRO)
    s.append(f'.globl {P}case_{i}_insn\n.globl {P}case_{i}_end\n.globl {P}case_{i}_tgt\n{P}case_{i}_insn:')
    for a in asm: s.append('    '+a.replace('TGT',f'{P}case_{i}_tgt').replace('_oracle_mem@PAGE', '_oracle_mem@PAGE' if P else 'oracle_mem'))
    s.append(f'{P}case_{i}_end:')
    s.append(EPI(0))
    s.append(f'{P}case_{i}_tgt:')
    s.append(EPI(1))
open('cases.S','w').write('\n'.join(s)+'\n')
h=[]
for i,(name,flags,asm) in enumerate(cases):
    h.append(f'extern void case_{i}(void*,void*); extern char case_{i}_insn[], case_{i}_end[], case_{i}_tgt[];')
h.append('static struct Case CASES[] = {')
for i,(name,flags,asm) in enumerate(cases):
    h.append(f'  {{"{name}", "{flags}", case_{i}, case_{i}_insn, case_{i}_end, case_{i}_tgt}},')
h.append('};')
open('cases.h','w').write('\n'.join(h)+'\n')
print(len(cases), file=sys.stderr)
