"""Writes cases.S and cases.h for driver.c from cases.txt, and each case's undefined set.

What a case leaves undefined is derived here, from the flag table below, so the
recorder prints only defined state and the replay compares only defined state.
"""
import re
import sys

# Symbols carry the platform's C prefix: none on ELF.
P = sys.argv[1] if len(sys.argv) > 1 else ''

# RFLAGS bits the oracle draws and compares (SDM Vol. 1, 3.4.3).
BIT = {'cf': 0, 'pf': 2, 'af': 4, 'zf': 6, 'sf': 7, 'df': 10, 'of': 11}
STATUS = ('cf', 'pf', 'af', 'zf', 'sf', 'of')
GPRS = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'] + [f'r{n}' for n in range(8, 16)]


def widths():
    width = {}
    for n, name in enumerate(['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']):
        width['r' + name], width['e' + name], width[name] = 64, 32, 16
    for name in ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh', 'spl', 'bpl', 'sil', 'dil']:
        width[name] = 8
    for n in range(8, 16):
        width[f'r{n}'], width[f'r{n}d'], width[f'r{n}w'], width[f'r{n}b'] = 64, 32, 16, 8
    return width


WIDTH = widths()
PTR = {'byte': 8, 'word': 16, 'dword': 32, 'qword': 64}

# Each mnemonic's flags as "Flags Affected" in the Intel SDM Vol. 2 states them:
# (defined, undefined); a flag in neither is unaffected.
ALL = set(STATUS)
FLAGS = {
    # ADD, ADC, SUB, SBB, CMP, NEG, XADD, CMPXCHG, SCAS, CMPS: "The OF, SF, ZF, AF, CF, and PF
    # flags are set according to the result."
    **{m: (ALL, set()) for m in ['add', 'adc', 'sub', 'sbb', 'cmp', 'neg', 'xadd', 'cmpxchg',
                                 'scasb', 'scasw', 'scasd', 'scasq', 'cmpsb', 'cmpsw', 'cmpsq']},
    # INC, DEC: "The CF flag is not affected. The OF, SF, ZF, AF, and PF flags are set according
    # to the result."
    **{m: (ALL - {'cf'}, set()) for m in ['inc', 'dec']},
    # AND, OR, XOR, TEST: "The OF and CF flags are cleared; the SF, ZF, and PF flags are set
    # according to the result. The state of the AF flag is undefined."
    **{m: (ALL - {'af'}, {'af'}) for m in ['and', 'or', 'xor', 'test']},
    # MUL, IMUL: OF and CF from the upper half; "The SF, ZF, AF, and PF flags are undefined."
    **{m: ({'cf', 'of'}, {'sf', 'zf', 'af', 'pf'}) for m in ['mul', 'imul']},
    # DIV, IDIV: "The CF, OF, SF, ZF, AF, and PF flags are undefined."
    **{m: (set(), ALL) for m in ['div', 'idiv']},
    # BSF, BSR: "The ZF flag is set to 1 if the source operand is 0; otherwise, the ZF flag is
    # cleared. The CF, OF, SF, AF, and PF flags are undefined."
    **{m: ({'zf'}, ALL - {'zf'}) for m in ['bsf', 'bsr']},
    # TZCNT, LZCNT: ZF on a zero output, CF on a zero input; "OF, SF, PF, and AF flags are
    # undefined."
    **{m: ({'zf', 'cf'}, {'of', 'sf', 'pf', 'af'}) for m in ['tzcnt', 'lzcnt']},
    # POPCNT: "OF, SF, ZF, AF, CF, PF are all cleared. ZF is set if SRC = 0".
    'popcnt': (ALL, set()),
    # UCOMISD, UCOMISS: ZF, PF and CF from the comparison; "The OF, SF, and AF flags in the
    # EFLAGS register are set to 0."
    **{m: (ALL, set()) for m in ['ucomisd', 'ucomiss']},
    'clc': ({'cf'}, set()), 'stc': ({'cf'}, set()), 'cmc': ({'cf'}, set()),
    'cld': ({'df'}, set()), 'std': ({'df'}, set()),
}
# "Flags Affected: None."
NONE = {'mov', 'movzx', 'movsx', 'movsxd', 'xchg', 'not', 'lea', 'bswap', 'cbw', 'cwde', 'cdqe',
        'cwd', 'cdq', 'cqo', 'lodsb', 'lodsw', 'lodsd', 'lodsq', 'stosb', 'stosw', 'stosd',
        'stosq', 'movsb', 'movsw', 'movsd', 'movsq', 'addsd', 'subsd', 'mulsd', 'divsd', 'sqrtsd',
        'addss', 'mulss', 'cvtsi2sd', 'cvtsi2ss', 'cvttsd2si', 'cvtsd2si', 'cvtsd2ss',
        'cvttss2si', 'vcvttsd2si', 'vcvttss2si',
        'cvtss2sd', 'movq', 'movd', 'nop'}
CONDITIONS = ['o', 'no', 'b', 'nb', 'c', 'nc', 'ae', 'nae', 'e', 'z', 'ne', 'nz', 'be', 'nbe',
              'a', 'na', 's', 'ns', 'p', 'np', 'pe', 'po', 'l', 'nl', 'ge', 'nge', 'le', 'nle',
              'g', 'ng']
NONE |= {'cmov' + c for c in CONDITIONS} | {'set' + c for c in CONDITIONS}


def operands(text):
    return [o.strip() for o in text.split(',')] if text.strip() else []


def width_of(operand):
    if operand in WIDTH:
        return WIDTH[operand]
    m = re.match(r'(byte|word|dword|qword) ptr', operand)
    if not m:
        raise SystemExit(f'no width for {operand!r}')
    return PTR[m.group(1)]


def count_of(ops, earlier):
    """A shift's or rotate's count: its immediate, 1, or the immediate an earlier mov put in cl."""
    if len(ops) == 1:
        return 1
    if ops[1] != 'cl':
        return int(ops[1], 0)
    for mnemonic, args in reversed(earlier):
        if mnemonic == 'mov' and args[0] in ('cl', 'cx', 'ecx', 'rcx'):
            return int(args[1], 0)
    raise SystemExit('a count in cl needs an earlier `mov ecx, imm` in the case')


def shift(mnemonic, ops, earlier):
    """SAL/SAR/SHL/SHR and RCL/RCR/ROL/ROR, Flags Affected; the count masked to 5 bits, or 6 at 64."""
    size = width_of(ops[0])
    count = count_of(ops, earlier) & (0x3f if size == 64 else 0x1f)
    if count == 0:
        return set(), set()  # "If the count is 0, the flags are not affected."
    over = {'of'} if count == 1 else set()
    under = set() if count == 1 else {'of'}  # "OF ... undefined" unless a 1-bit shift or rotate
    if mnemonic in ('rol', 'ror', 'rcl', 'rcr'):
        return {'cf'} | over, under  # "SF, ZF, AF, and PF flags are always unaffected."
    defined, undefined = {'cf', 'sf', 'zf', 'pf'} | over, {'af'} | under
    if mnemonic in ('shl', 'sal', 'shr') and count >= size:
        # CF "is undefined for SHL and SHR instructions where the count is greater than or equal
        # to the size (in bits) of the destination operand."
        defined, undefined = defined - {'cf'}, undefined | {'cf'}
    return defined, undefined


def double_shift(ops, earlier):
    """SHLD/SHRD, Flags Affected; the count masked to 5 bits, or 6 at 64."""
    size = width_of(ops[0])
    count = count_of([ops[0], ops[2]], earlier) & (0x3f if size == 64 else 0x1f)
    if count == 0:
        return set(), set()  # "If the count operand is 0, the flags are not affected."
    if count > size:
        return set(), set(ALL)  # "If the count is greater than the operand size, the flags are undefined."
    # CF the last bit out, SF ZF PF by the result; OF a 1-bit shift's sign change, else undefined;
    # "If a shift occurs, the AF flag is undefined."
    over = {'of'} if count == 1 else set()
    return {'cf', 'sf', 'zf', 'pf'} | over, {'af'} | ({'of'} - over)


def undefined(asm, extra):
    """The flags and registers this sequence leaves undefined, the SDM's terms, instruction by instruction."""
    left, earlier = set(), []
    for line in asm:
        if line.startswith('.'):
            raise SystemExit(f'a directive needs its flags stated: {line!r}')
        words = line.split(None, 1)
        mnemonic = words[0].lower()
        if mnemonic == 'lock':
            words = words[1].split(None, 1)
            mnemonic = words[0].lower()
        ops = operands(words[1] if len(words) > 1 else '')
        if mnemonic in ('shl', 'sal', 'shr', 'sar', 'rol', 'ror', 'rcl', 'rcr'):
            defined, undef = shift(mnemonic, ops, earlier)
        elif mnemonic in ('shld', 'shrd'):
            defined, undef = double_shift(ops, earlier)
        elif mnemonic == 'cmpsd' and ops:
            defined, undef = set(), set()  # SSE2's CMPSD: "Flags Affected: None."
        elif mnemonic == 'cmpsd':
            defined, undef = ALL, set()  # the string CMPSD, as CMPS
        elif mnemonic in FLAGS:
            defined, undef = FLAGS[mnemonic]
        elif mnemonic in NONE:
            defined, undef = set(), set()
        else:
            raise SystemExit(f'no SDM flags row for {mnemonic!r}; add one to gen.py')
        left = (left - defined) | undef
        earlier.append((mnemonic, ops))
    for token in extra:
        if token not in BIT and token not in GPRS:
            raise SystemExit(f'unknown undefined token {token!r}')
        left.add(token)
    return left


def parse():
    cases = []
    for line in open('cases.txt'):
        line = line.rstrip('\n')
        if not line or line.startswith('#'):
            continue
        fields = line.split('|')
        name, flags, asm = fields[0], fields[1], [a.strip() for a in fields[2].split(';')]
        extra = fields[3].split(',') if len(fields) > 3 and fields[3] else []
        if any(name == case[0] for case in cases):
            raise SystemExit(f'two cases named {name}')
        cases.append((name, flags, asm, sorted(undefined(asm, extra), key=lambda t: (t in GPRS, t))))
    return cases


# State: r[16] @0, rflags @128, xmm[16] @144.
LOAD = ['rax', 'rcx', 'rdx', 'rbx', None, 'rbp', 'rsi', None] + [f'r{n}' for n in range(8, 16)]


def prologue():
    s = ['    push rbx', '    push rbp', '    push r12', '    push r13', '    push r14',
         '    push r15', '    push rdi']
    s += [f'    movdqu xmm{n}, [rdi + {144 + 16 * n}]' for n in range(16)]
    s.append('    push qword ptr [rdi + 128]')
    s += [f'    mov {r}, [rdi + {8 * n}]' for n, r in enumerate(LOAD) if r]
    s += ['    popfq', '    mov rdi, [rdi + 56]']
    return s


def epilogue():
    # pushfq first: nothing may write the flags before they are kept.
    s = ['    pushfq', '    push rax', '    mov rax, [rsp + 16]']
    s += [f'    mov [rax + {8 * n}], {r}' for n, r in enumerate(GPRS) if r not in ('rax', 'rsp')]
    s += ['    pop rcx', '    mov [rax], rcx', '    pop rcx', '    mov [rax + 128], rcx']
    s += [f'    movdqu [rax + {144 + 16 * n}], xmm{n}' for n in range(16)]
    s += ['    cld', '    add rsp, 8', '    pop r15', '    pop r14', '    pop r13', '    pop r12',
          '    pop rbp', '    pop rbx', '    ret']
    return s


def main():
    cases = parse()
    s = [".intel_syntax noprefix", ".section .note.GNU-stack,\"\",@progbits", ".text"]
    for i, (name, flags, asm, undef) in enumerate(cases):
        s += [f'.globl {P}case_{i}', '.p2align 4', f'{P}case_{i}:'] + prologue()
        s += [f'.globl {P}case_{i}_insn', f'.globl {P}case_{i}_end', f'{P}case_{i}_insn:']
        s += ['    ' + a for a in asm]
        s += [f'{P}case_{i}_end:'] + epilogue()
    open('cases.S', 'w').write('\n'.join(s) + '\n')
    h = [f'extern void case_{i}(void*); extern char case_{i}_insn[], case_{i}_end[];'
         for i in range(len(cases))]
    h.append('static struct Case CASES[] = {')
    for i, (name, flags, asm, undef) in enumerate(cases):
        mask = sum(1 << BIT[t] for t in undef if t in BIT)
        regs = sum(1 << GPRS.index(t) for t in undef if t in GPRS)
        spelled = ','.join(undef) or '-'
        h.append(f'  {{"{name}", "{flags}", "{spelled}", {mask:#x}, {regs:#x}, case_{i}, '
                 f'case_{i}_insn, case_{i}_end}},')
    h.append('};')
    open('cases.h', 'w').write('\n'.join(h) + '\n')
    print(len(cases), file=sys.stderr)


main()
