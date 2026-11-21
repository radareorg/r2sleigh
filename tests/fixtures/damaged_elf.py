#!/usr/bin/env python3
"""Writes the damaged ELF fixtures (ROADMAP D577) from radare2-testbins' elf/crackme.

Each is the crackme with three header or section-table bytes rewritten, as the end-user sweep's
mutations left them (offset: old -> new). The raw blob is the crackme's `_start`, 42 bytes.

    python3 tests/fixtures/damaged_elf.py <radare2-testbins>/elf/crackme
"""

import hashlib
import pathlib
import sys

# sha256 of radare2-testbins' elf/crackme, 7,441 bytes.
CRACKME = "ec7b7a2853f74e23920c849cf68d50a3d1719e0f657f4be3b2f32adb6cce5dac"
EDITS = {
    # e_shoff's third byte, e_version: the section table runs past the file.
    "crackme_shoff_past_end": [(0x2B, 0x00, 0x32), (0x14, 0x01, 0xEF), (0x2B, 0x32, 0x42)],
    # e_machine 0x653e, which no ELF machine names.
    "crackme_unknown_machine": [(0x13, 0x00, 0x65), (0xCFA, 0x00, 0xC1), (0xF80, 0x89, 0xBF)],
    # e_entry 0x40052f, in .rela.plt: no code backs the header's entry.
    "crackme_entry_in_data": [(0x31, 0x00, 0xD7), (0xD66, 0x00, 0x42), (0x18, 0xC0, 0x2F)],
    # e_shoff's top bytes: the table starts past the file.
    "crackme_shoff_high": [(0x2F, 0x00, 0xB8), (0x2D, 0x00, 0xE4), (0xF7B, 0x00, 0x0D)],
    # e_shoff's second byte.
    "crackme_shoff_byte2": [(0x2A, 0x00, 0x36), (0x1127, 0x00, 0x60), (0x1389, 0x00, 0x6B)],
    # e_shoff's sixth byte and e_shentsize 0x5b.
    "crackme_shentsize": [(0x2E, 0x00, 0xCC), (0x1342, 0x00, 0x99), (0x3A, 0x40, 0x5B)],
    # e_flags, e_shstrndx's high byte and e_shentsize 0x48.
    "crackme_shentsize_strndx": [(0x31, 0x00, 0xE3), (0x3D, 0x00, 0x34), (0x3A, 0x40, 0x48)],
}
START = (0x5C0, 42)


def main(source):
    data = pathlib.Path(source).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != CRACKME:
        sys.exit(f"{source}: {len(data)} bytes, not radare2-testbins' crackme (sha256 {digest})")
    here = pathlib.Path(__file__).parent
    for name, edits in EDITS.items():
        out = bytearray(data)
        for offset, old, new in edits:
            assert out[offset] == old, (name, hex(offset), out[offset])
            out[offset] = new
        (here / name).write_bytes(out)
    offset, size = START
    (here / "raw_x64_start.bin").write_bytes(data[offset : offset + size])


if __name__ == "__main__":
    main(sys.argv[1])
