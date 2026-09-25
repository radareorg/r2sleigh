"""The inputs a function is called with, and the job file the runtime reads.

Every vector is a complete machine entry state (argument registers, the AL
count, stack words) plus the objects its pointers point at, laid out in a
fixed-address arena. Both the original and each rendering see the same state,
so the vectors never need to be *valid* for the source's contract: a vector the
original cannot survive (a length that walks off the arena, a NULL it
dereferences) is dropped by the runtime as outside the function's domain, and
only the survivors grade the rendering.

Values are chosen to reach boundaries first -- the corpus lengths
``{0,1,2,3,4,7,8,15,16,17,31,32,61}``, ``0``, ``+-1``, ``+-2``, ``MIN``,
``MAX`` and ``2^k +- 1`` at every width -- and then at random. Everything is
derived from a seed text, so a record is reproducible from its key.

A parameter narrower than its register is passed the way the ABI lets a caller
pass it: bits below 32 extended by the source type's signedness (the de facto
rule both compilers' callers follow), bits 32..63 arbitrary. An argument
register the function does not take, and the unused upper lanes of a vector
register, are arbitrary too. A rendering that reads bits the ABI never gave it
is therefore caught; the original, which is correct by construction, never
reads them.
"""

from __future__ import annotations

import hashlib
import math
import random
import struct
from dataclasses import dataclass, field

from dwarf import Dwarf
from spec import CallSpec, Param

ARENA_BASE = 0x3E00_0000_0000
ARENA_SIZE = 256 * 1024
REGION_SIZE = 32 * 1024
REGIONS = ARENA_SIZE // REGION_SIZE

LENGTHS = (0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 61)
# Entries in a pointer-to-pointer argument's table: past the largest length.
POINTER_TABLE = 64
MASK64 = (1 << 64) - 1

RET_KINDS = {"void": 0, "int": 1, "f32": 2, "f64": 3, "int128": 4}
JOB_MAGIC = b"EQVJOB01"


def int_pool(size: int, signed: bool, constants: tuple[int, ...] | list[int] = ()) -> list[int]:
    """Boundary values of one width, as unsigned bit patterns of that width.

    Each constant the original's code uses comes first with its two
    neighbours, so a boundary the source wrote is tested on both sides.
    """
    bits = size * 8
    mask = (1 << bits) - 1
    values: list[int] = []
    for constant in constants:
        values += [constant - 1, constant, constant + 1]
    values += list(LENGTHS)
    values += [-1, -2, 100, 255, 256, 1000]
    if signed:
        values += [-(1 << (bits - 1)), (1 << (bits - 1)) - 1, -(1 << (bits - 1)) + 1, -3]
    else:
        values += [mask, mask - 1, 1 << (bits - 1)]
    for k in (7, 8, 15, 16, 31, 32, 63):
        if k < bits:
            values += [(1 << k) - 1, 1 << k, (1 << k) + 1]
    seen: list[int] = []
    for value in values:
        masked = value & mask
        if masked not in seen:
            seen.append(masked)
    return seen


def float_pool() -> list[float]:
    return [0.0, 1.0, -1.0, 0.5, -0.0, 3.25, 2.5, 100.0, 1e-310, 1e300, -1e300,
            math.inf, -math.inf, math.nan, 7.0, -12.75]


def int_register(value: int, size: int, signed: bool, garbage: int) -> int:
    bits = size * 8
    v = value & ((1 << bits) - 1)
    if size < 4:
        if signed and (v >> (bits - 1)) & 1:
            v |= 0xFFFFFFFF ^ ((1 << bits) - 1)
    if size <= 4:
        v = (v & 0xFFFFFFFF) | ((garbage & 0xFFFFFFFF) << 32)
    return v & MASK64


@dataclass
class Vector:
    index: int
    seed: int
    gpr: list[int]
    xmm: list[bytes]
    rax: int
    stack: list[int]
    patches: list[tuple[int, bytes]] = field(default_factory=list)
    shown: list[str] = field(default_factory=list)


def _seed(text: str) -> int:
    return int.from_bytes(hashlib.sha256(text.encode()).digest()[:8], "little")


class _Arena:
    """Objects placed in one pointer parameter's region."""

    def __init__(self, region: int):
        self.base = region * REGION_SIZE
        self.cursor = 0
        self.patches: list[tuple[int, bytes]] = []

    def address(self, offset: int) -> int:
        return ARENA_BASE + self.base + offset

    def reserve(self, size: int, align: int = 16) -> int:
        self.cursor = (self.cursor + align - 1) // align * align
        offset = self.cursor
        self.cursor += max(size, 1)
        if self.cursor > REGION_SIZE:
            raise ValueError("an object does not fit its arena region")
        return offset

    def patch(self, offset: int, data: bytes) -> None:
        self.patches.append((self.base + offset, data))


def _string(rng: random.Random, length: int) -> bytes:
    return bytes(rng.randrange(32, 127) for _ in range(length)) + b"\0"


def _fill_struct(dwarf: Dwarf, struct_offset: int, arena: _Arena, at: int, next_node: int,
                 rng: random.Random, depth: int = 0) -> None:
    """Make one node's pointer and flag members valid; the filler supplies the rest."""
    for member in dwarf.members(struct_offset):
        info = dwarf.type(member.type_offset)
        where = at + member.offset
        if member.bit_size is not None:
            continue
        if info.kind == "bool":
            arena.patch(where, bytes([rng.randrange(2)]))
        elif info.kind == "pointer":
            target = dwarf.strip(info.target)
            target_info = dwarf.type(info.target)
            if target == struct_offset:
                value = next_node
            elif target_info.kind == "int" and target_info.size == 1:
                offset = arena.reserve(64)
                arena.patch(offset, _string(rng, rng.choice((0, 1, 5, 17, 40))))
                value = arena.address(offset)
            elif target_info.kind in ("int", "float", "void", "bool"):
                offset = arena.reserve(512)
                value = arena.address(offset)
            else:
                value = 0
            arena.patch(where, struct.pack("<Q", value))
        elif info.kind == "array":
            element = dwarf.type(info.target)
            if element.kind == "int" and element.size == 1 and info.count:
                cut = rng.randrange(info.count)
                arena.patch(where + cut, b"\0")
        elif info.kind in ("struct", "union") and info.target is not None and depth < 4:
            _fill_struct(dwarf, info.target, arena, where, 0, rng, depth + 1)


def _pointer_value(param: Param, dwarf: Dwarf, arena: _Arena, rng: random.Random,
                   choice: int) -> tuple[int, str]:
    pointee = param.pointee
    assert pointee is not None
    if pointee.shape == "string":
        length = LENGTHS[choice % len(LENGTHS)] if choice >= 0 else rng.randrange(0, 200)
        offset = arena.reserve(length + 1)
        arena.patch(offset, _string(rng, length))
        return arena.address(offset), f"<string of {length}>"
    if pointee.shape == "struct" and pointee.type_offset is not None:
        nodes = 1 + (choice % 4 if choice >= 0 else rng.randrange(4))
        stride = (pointee.element_size + 15) // 16 * 16
        offsets = [arena.reserve(stride) for _ in range(nodes)]
        for n, offset in enumerate(offsets):
            following = arena.address(offsets[n + 1]) if n + 1 < nodes else 0
            _fill_struct(dwarf, pointee.type_offset, arena, offset, following, rng)
        return arena.address(offsets[0]), f"<{nodes} linked object(s)>"
    if pointee.shape == "pointers":
        # A NULL after `count` entries serves a consumer that walks to the
        # terminator (argv); valid pointers past it serve one that indexes
        # (rows[i]), so an index inside the table never lands on filler.
        count = 1 + (choice % 5 if choice >= 0 else rng.randrange(5))
        table = arena.reserve(8 * POINTER_TABLE)
        words: list[int] = []
        for slot in range(POINTER_TABLE):
            if slot == count:
                words.append(0)
                continue
            if pointee.element_is_char:
                length = rng.choice(LENGTHS)
                offset = arena.reserve(length + 1)
                arena.patch(offset, _string(rng, length))
            else:
                offset = arena.reserve(256)
            words.append(arena.address(offset))
        arena.patch(table, struct.pack(f"<{len(words)}Q", *words))
        return arena.address(table), f"<{count} pointer(s), NULL, then {POINTER_TABLE - count - 1} more>"
    # A plain buffer: the arena filler is its contents. Offset by a multiple of
    # the element size so an aligned access stays aligned.
    offset = arena.reserve(REGION_SIZE // 2)
    return arena.address(offset), "<buffer>"


def build_vectors(spec: CallSpec, dwarf: Dwarf, count: int, seed_text: str) -> list[Vector]:
    vectors: list[Vector] = []
    widest = max(
        [len(int_pool(p.size, p.signed, spec.constants)) for p in spec.params if p.kind == "int"]
        or [len(LENGTHS)]
    )
    # Boundaries first, and at least a quarter of the vectors at random.
    boundary = min(count - count // 4, widest)
    for index in range(count):
        seed = _seed(f"{seed_text}/{index}")
        rng = random.Random(seed)
        gpr = [rng.getrandbits(64) for _ in range(6)]
        xmm = [rng.getrandbits(128).to_bytes(16, "little") for _ in range(8)]
        stack: list[int] = []
        patches: list[tuple[int, bytes]] = []
        shown: list[str] = []
        used_sse = 0
        pointer_index = 0
        for j, param in enumerate(spec.params):
            choice = (index + j * 5) if index < boundary else -1
            garbage = rng.getrandbits(64)
            if param.kind in ("int", "bool"):
                if param.kind == "bool":
                    value = (index + j) % 2 if choice >= 0 else rng.randrange(2)
                    word = int_register(value, 4, False, garbage)
                    shown.append(f"{param.name}={value}")
                else:
                    pool = int_pool(param.size, param.signed, spec.constants)
                    if choice >= 0:
                        value = pool[choice % len(pool)]
                    elif rng.random() < 0.5:
                        value = rng.choice(pool)
                    else:
                        value = rng.getrandbits(param.size * 8)
                    word = int_register(value, param.size, param.signed, garbage)
                    signed_value = value
                    if param.signed and value >> (param.size * 8 - 1):
                        signed_value = value - (1 << (param.size * 8))
                    shown.append(f"{param.name}={signed_value}")
                data: int | bytes = word
            elif param.kind == "float":
                pool = float_pool()
                value_f = pool[choice % len(pool)] if choice >= 0 else rng.uniform(-1e6, 1e6)
                packed = struct.pack("<f" if param.size == 4 else "<d", value_f)
                # The lanes above the scalar are the caller's leftovers.
                data = (packed + garbage.to_bytes(8, "little") + bytes(8))[:16]
                shown.append(f"{param.name}={value_f!r}")
                used_sse += 1
            elif param.kind == "funcptr":
                target = param.targets[(index + j) % len(param.targets)]
                data = target
                shown.append(f"{param.name}=0x{target:x}")
            else:
                region = pointer_index % REGIONS
                pointer_index += 1
                if index == 1:
                    data = 0
                    shown.append(f"{param.name}=NULL")
                else:
                    arena = _Arena(region)
                    try:
                        address, what = _pointer_value(param, dwarf, arena, rng, choice)
                    except ValueError:
                        # The objects outgrow one region: point at filler instead,
                        # which the original may or may not survive.
                        arena = _Arena(region)
                        address, what = arena.address(0), "<buffer: object too large>"
                    patches += arena.patches
                    data = address
                    shown.append(f"{param.name}={what}")
            register = param.register
            if register.startswith("xmm"):
                xmm[int(register[3:])] = data if isinstance(data, bytes) else bytes(16)
            elif register.startswith("stack"):
                stack.append(int.from_bytes(data[:8], "little") if isinstance(data, bytes)
                             else data & MASK64)
            else:
                slot = ("rdi", "rsi", "rdx", "rcx", "r8", "r9").index(register)
                gpr[slot] = data & MASK64 if isinstance(data, int) else 0
        vectors.append(
            Vector(index=index, seed=seed, gpr=gpr, xmm=xmm, rax=used_sse, stack=stack,
                   patches=patches, shown=shown)
        )
    return vectors


@dataclass
class Run:
    label: str
    address: int = 0
    so_path: str = ""
    symbol: str = ""


def encode_job(spec: CallSpec, runs: list[Run], pairs: list[tuple[int, int]],
               vectors: list[Vector], timeout_ms: int, out_cap: int = 65536) -> bytes:
    """The binary job ``rt/equiv_rt.c`` reads (``struct job_header`` and after)."""
    out = bytearray()
    out += struct.pack(
        "<8sQQ8I",
        JOB_MAGIC,
        ARENA_BASE,
        ARENA_SIZE,
        len(runs),
        len(vectors),
        len(pairs),
        timeout_ms,
        RET_KINDS[spec.ret_kind],
        spec.ret_bytes,
        out_cap,
        0,
    )
    for run in runs:
        so = run.so_path.encode()
        symbol = run.symbol.encode()
        label = run.label.encode()
        if len(so) >= 512 or len(symbol) >= 256 or len(label) >= 32:
            raise ValueError(f"run {run.label}: a path or name is too long for the job")
        out += struct.pack("<Q512s256s32s", run.address, so, symbol, label)
    for a, b in pairs:
        out += struct.pack("<II", a, b)
    for vector in vectors:
        stack = vector.stack + [0] * (16 - len(vector.stack))
        out += struct.pack(
            "<Q6Q128sQQ16QII",
            vector.seed,
            *vector.gpr,
            b"".join(vector.xmm),
            vector.rax,
            len(vector.stack),
            *stack,
            len(vector.patches),
            0,
        )
        for offset, data in vector.patches:
            out += struct.pack("<QQ", offset, len(data))
            out += data + bytes((-len(data)) % 8)
    return bytes(out)
