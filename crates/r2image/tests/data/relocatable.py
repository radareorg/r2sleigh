#!/usr/bin/env python3
"""Write the relocatable-object fixture: two unplaced sections and two symbols.

A relocatable object states no addresses. Every section carries `sh_addr = 0`,
which means unplaced rather than "at zero", and a symbol's `st_value` is an
offset into its section. The reader has to place the sections itself, and this
fixture is the smallest file that says so: one code section, one data section,
a `STT_FUNC` symbol in the first and a `STT_NOTYPE` label in the second.
"""

import struct

TEXT = bytes([0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90])  # xor rax, rax; ret
DATA = bytes([0x2A, 0x00, 0x00, 0x00])

names = b"\0.text\0.data\0.symtab\0.strtab\0.shstrtab\0"
offset = {
    name: names.index(b"\0" + name.encode() + b"\0") + 1
    for name in (".text", ".data", ".symtab", ".strtab", ".shstrtab")
}

strtab = b"\0f\0label\0"
symbols = [
    (0, 0, 0, 0, 0),  # the null symbol
    (strtab.index(b"\0f\0") + 1, (1 << 4) | 2, 0, 1, 0),  # LOCAL FUNC .text +0
    (strtab.index(b"\0label\0") + 1, 0, 0, 2, 0),  # LOCAL NOTYPE .data +0
]
symtab = b"".join(
    struct.pack("<IBBHQQ", name, info, 0, shndx, value, 0)
    for name, info, _other, shndx, value in symbols
)

text_off = 0x40
data_off = text_off + len(TEXT)
symtab_off = data_off + len(DATA)
strtab_off = symtab_off + len(symtab)
shstrtab_off = strtab_off + len(strtab)
shoff = shstrtab_off + len(names)

def header(name, kind, flags, off, size, link, info, align, entsize):
    return struct.pack(
        "<IIQQQQIIQQ", name, kind, flags, 0, off, size, link, info, align, entsize
    )

sections = b"".join(
    [
        header(0, 0, 0, 0, 0, 0, 0, 0, 0),
        header(offset[".text"], 1, 0x6, text_off, len(TEXT), 0, 0, 1, 0),
        header(offset[".data"], 1, 0x3, data_off, len(DATA), 0, 0, 1, 0),
        header(offset[".symtab"], 2, 0, symtab_off, len(symtab), 4, len(symbols), 8, 24),
        header(offset[".strtab"], 3, 0, strtab_off, len(strtab), 0, 0, 1, 0),
        header(offset[".shstrtab"], 3, 0, shstrtab_off, len(names), 0, 0, 1, 0),
    ]
)

elf = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8)
elf += struct.pack("<HHIQQQIHHHHHH", 1, 0x3E, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 6, 5)
elf += b"\0" * (text_off - len(elf))
elf += TEXT + DATA + symtab + strtab + names + sections

import pathlib

pathlib.Path(__file__).with_name("relocatable.elf").write_bytes(bytes(elf))
print("wrote relocatable.elf", len(elf), "bytes")
