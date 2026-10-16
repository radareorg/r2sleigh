#!/usr/bin/env python3
"""Write the static-weak fixtures: a linked ELF whose symbol table holds an undefined weak symbol.

`static_weak.elf` has no `PT_DYNAMIC`, so no loader binds the reference and it stays null.
`static_weak_dynamic.elf` adds a `PT_DYNAMIC`, so the same symbol is one a loader may bind.
"""

import pathlib
import struct

names = b"\0.data\0.symtab\0.strtab\0.shstrtab\0"
offset = {n: names.index(b"\0" + n.encode() + b"\0") + 1 for n in (".data", ".symtab", ".strtab", ".shstrtab")}

STB_GLOBAL, STB_WEAK, STT_NOTYPE, STT_OBJECT = 1, 2, 0, 1
strtab = b"\0weak_ref\0kept\0"
symbols = [
    (0, 0, 0, 0),
    (strtab.index(b"\0weak_ref\0") + 1, (STB_WEAK << 4) | STT_NOTYPE, 0, 0),  # undefined
    (strtab.index(b"\0kept\0") + 1, (STB_GLOBAL << 4) | STT_OBJECT, 1, 0x400000),
]
symtab = b"".join(struct.pack("<IBBHQQ", n, i, 0, s, v, 8) for n, i, s, v in symbols)
DATA = bytes(8)


def build(dynamic):
    phnum = 2 if dynamic else 1
    data_off = 64 + 56 * phnum
    symtab_off = data_off + len(DATA)
    strtab_off = symtab_off + len(symtab)
    shstrtab_off = strtab_off + len(strtab)
    shoff = shstrtab_off + len(names)

    def sh(name, kind, flags, addr, off, size, link, info, align, entsize):
        return struct.pack("<IIQQQQIIQQ", name, kind, flags, addr, off, size, link, info, align, entsize)

    sections = b"".join(
        [
            sh(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            sh(offset[".data"], 1, 0x3, 0x400000, data_off, len(DATA), 0, 0, 8, 0),
            sh(offset[".symtab"], 2, 0, 0, symtab_off, len(symtab), 3, 1, 8, 24),
            sh(offset[".strtab"], 3, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0),
            sh(offset[".shstrtab"], 3, 0, 0, shstrtab_off, len(names), 0, 0, 1, 0),
        ]
    )
    elf = bytearray(b"\x7fELF\x02\x01\x01" + bytes(9))
    elf += struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x400000, 64, shoff, 0, 64, 56, phnum, 64, 5, 4)
    total = shoff + len(sections)
    phdr = lambda kind, flags: struct.pack("<IIQQQQQQ", kind, flags, 0, 0x400000, 0x400000, total, total, 8)
    elf += phdr(1, 6)  # PT_LOAD
    if dynamic:
        elf += struct.pack("<IIQQQQQQ", 2, 6, data_off, 0x400000, 0x400000, 8, 8, 8)  # PT_DYNAMIC
    elf += DATA + symtab + strtab + names + sections
    return bytes(elf)


here = pathlib.Path(__file__).parent
(here / "static_weak.elf").write_bytes(build(False))
(here / "static_weak_dynamic.elf").write_bytes(build(True))
