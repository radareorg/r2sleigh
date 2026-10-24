"""The oracle side's reading of DWARF: what each function of the source is.

The gate grades a rendering of a *stripped* binary against the original
function, and the only thing it needs to know about that function is how to
call it: where it starts, what its parameters are and what it returns. The
unstripped build of the same source states exactly that in its DWARF, and the
tool under test never sees that build, so reading it here is the oracle's
privilege, not a leak.

The reader parses ``readelf --debug-dump=info``: binutils is already a
dependency of every build this gate makes, the text format is stable across
DWARF 4 and 5 and across GCC and Clang, and it keeps the gate on the standard
library. It reads only the tags a call needs -- subprograms, their formal
parameters, and the type graph those reach -- and refuses per node: a type it
does not model is described as ``unsupported`` with the tag that stopped it,
never guessed.

A function's address is its entry (DWARF 5, section 2.18): ``DW_AT_entry_pc``, else ``DW_AT_low_pc``, else the
start of the first range of ``DW_AT_ranges``. ``subprograms()`` lists the functions that have a ``DW_AT_low_pc``;
``placed()`` lists every function with code and names each one it cannot place.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from target import X86_64, Target

_DIE = re.compile(r"^\s*<(\d+)><([0-9a-f]+)>: Abbrev Number: (\d+)(?: \((DW_TAG_\w+)\))?")
_ATTR = re.compile(r"^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s?(.*)$")
_REF = re.compile(r"<0x([0-9a-f]+)>")
_PLUS_UCONST = re.compile(r"DW_OP_plus_uconst: (\d+)")
# One row of a `--debug-dump=Ranges` table: `<offset> <begin> <end>`, a `(base address)` selection, or the end of a list.
_RANGE_ROW = re.compile(
    r"^\s+(?P<offset>[0-9a-f]{8})\s+(?:(?P<end><End of list>)|(?P<begin>[0-9a-f]{8,16})\s+(?:(?P<base>\(base address\))|[0-9a-f]{8,16}))"
)
_RANGE_SECTION = re.compile(r"^Contents of the \.debug_(?:ranges|rnglists) section")
# What a linker writes over the address of code it discarded: 0, all ones, or lld's 1 in `.debug_ranges`.
TOMBSTONES = frozenset({0, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})
# `readelf --wide` names the attribute's form first: `(data1) 7`, `(strp) (offset: 0x7a): x`.
_FORM = re.compile(r"^\([a-z][a-z0-9_]*\)\s*")

# Tags that only qualify another type and never change how it is passed.
_QUALIFIERS = frozenset(
    {
        "DW_TAG_typedef",
        "DW_TAG_const_type",
        "DW_TAG_volatile_type",
        "DW_TAG_restrict_type",
        "DW_TAG_atomic_type",
    }
)


@dataclass
class Die:
    offset: int
    tag: str
    depth: int
    attrs: dict[str, str] = field(default_factory=dict)
    # The form readelf names each attribute's value in (`addr`, `data1`, `sec_offset`), where it names one.
    forms: dict[str, str] = field(default_factory=dict)
    children: list["Die"] = field(default_factory=list)

    def text(self, name: str) -> str | None:
        """A string attribute, with readelf's form annotation removed."""
        raw = self.attrs.get(name)
        if raw is None:
            return None
        if raw.startswith("(") and "): " in raw:
            return raw.split("): ", 1)[1].strip()
        return raw.strip()

    def ref(self, name: str) -> int | None:
        raw = self.attrs.get(name)
        if raw is None:
            return None
        found = _REF.search(raw)
        return int(found.group(1), 16) if found else None

    def number(self, name: str) -> int | None:
        raw = self.text(name)
        if raw is None:
            return None
        token = raw.split()[0] if raw.split() else ""
        try:
            return int(token, 0)
        except ValueError:
            found = _PLUS_UCONST.search(raw)
            return int(found.group(1)) if found else None

    def flag(self, name: str) -> bool:
        return name in self.attrs and self.attrs[name].strip() not in ("0", "")


def parse_readelf(text: str) -> tuple[list[Die], dict[int, Die]]:
    """Every compile unit's DIE tree, and an index of every DIE by offset."""
    units: list[Die] = []
    index: dict[int, Die] = {}
    stack: list[Die] = []
    current: Die | None = None
    for line in text.splitlines():
        header = _DIE.match(line)
        if header:
            depth = int(header.group(1))
            tag = header.group(4)
            current = None
            if tag is None:
                # A null entry closes the sibling chain at this depth.
                continue
            die = Die(offset=int(header.group(2), 16), tag=tag, depth=depth)
            index[die.offset] = die
            while stack and stack[-1].depth >= depth:
                stack.pop()
            if stack:
                stack[-1].children.append(die)
            elif tag in ("DW_TAG_compile_unit", "DW_TAG_partial_unit"):
                units.append(die)
            stack.append(die)
            current = die
            continue
        attr = _ATTR.match(line)
        if attr and current is not None:
            raw = attr.group(2).strip()
            value = _FORM.sub("", raw, count=1)
            if attr.group(1) not in current.attrs and value != raw:
                current.forms[attr.group(1)] = _FORM.match(raw).group(0).strip()[1:-1]
            current.attrs.setdefault(attr.group(1), value)
    return units, index


def parse_ranges(text: str) -> dict[int, tuple[int, ...]]:
    """The first range of the list at each section offset of a ``--debug-dump=Ranges`` dump.

    DWARF 4 prints a list's own offset on every row of it; DWARF 5 prints each row's offset, and a list starts at
    its first row. A ``(base address)`` row selects a base and holds no range; a list with no range at all has no
    entry. An empty range (``start == end``) is a range: GCC lists a split function's entry first, empty.
    An offset two sections hold with different first ranges keeps both, for the caller to refuse.
    """
    rows: list[tuple[int, int, str, int]] = []
    section = 0
    in_ranges = False
    for line in text.splitlines():
        if line.startswith("Contents of"):
            in_ranges = bool(_RANGE_SECTION.match(line))
            section += 1
            continue
        row = _RANGE_ROW.match(line) if in_ranges else None
        if row is None:
            continue
        kind = "end" if row.group("end") else "base" if row.group("base") else "range"
        rows.append((section, int(row.group("offset"), 16), kind, int(row.group("begin") or "0", 16)))
    firsts: dict[int, list[int]] = {}
    for at, (part, offset, _, _) in enumerate(rows):
        if at and rows[at - 1][:2] == (part, offset):
            continue
        index = at
        while index < len(rows) and rows[index][2] == "base":
            index += 1
        found = firsts.setdefault(offset, [])
        if index < len(rows) and rows[index][2] == "range" and rows[index][3] not in found:
            found.append(rows[index][3])
    return {offset: tuple(begins) for offset, begins in firsts.items() if begins}


@dataclass(frozen=True)
class TypeInfo:
    """How a C type is laid out and passed, as far as a call needs to know.

    ``kind`` is one of ``void``, ``int``, ``bool``, ``float``, ``pointer``,
    ``struct``, ``union``, ``array``, ``function`` or ``unsupported``.
    Pointers and arrays name their element by DIE offset so a recursive type
    (``struct node { struct node *next; }``) stays finite.
    """

    kind: str
    size: int = 0
    signed: bool = False
    spelling: str = ""
    target: int | None = None
    count: int | None = None
    reason: str = ""


@dataclass(frozen=True)
class Member:
    name: str
    offset: int
    type_offset: int | None
    bit_size: int | None = None


@dataclass
class Parameter:
    name: str
    type_offset: int | None


@dataclass
class Subprogram:
    name: str
    low_pc: int
    unit: str
    external: bool
    return_type: int | None
    parameters: list[Parameter]
    variadic: bool
    prototyped: bool
    via_origin: bool


@dataclass(frozen=True)
class Unplaced:
    """A function with code that has no one address in the binary: its name, its DIE and why."""

    name: str
    offset: int
    why: str


class Dwarf:
    """One binary's DWARF: its functions and the type graph they reach."""

    def __init__(self, units: list[Die], index: dict[int, Die], ranges: dict[int, tuple[int, ...]] | None = None):
        self.units = units
        self.index = index
        self.ranges = ranges or {}
        self._types: dict[int | None, TypeInfo] = {}

    @classmethod
    def read(cls, binary: Path, target: Target = X86_64) -> "Dwarf":
        proc = subprocess.run(
            [target.tool("readelf"), "--wide", "--debug-dump=info", "--debug-dump=Ranges", str(binary)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"readelf failed on {binary}: {proc.stderr.strip()}")
        units, index = parse_readelf(proc.stdout)
        return cls(units, index, parse_ranges(proc.stdout))

    # ------------------------------------------------------------ functions

    def _origin(self, die: Die) -> Die | None:
        for name in ("DW_AT_abstract_origin", "DW_AT_specification"):
            target = die.ref(name)
            if target is not None and target in self.index:
                return self.index[target]
        return None

    def _attr_via_origin(self, die: Die, name: str) -> tuple[Die, bool]:
        seen = 0
        node: Die | None = die
        while node is not None and seen < 8:
            if name in node.attrs:
                return node, seen > 0
            node = self._origin(node)
            seen += 1
        return die, False

    def subprograms(self) -> list[Subprogram]:
        """Every function with a ``DW_AT_low_pc`` in the binary, in address order."""
        found: list[Subprogram] = []
        for unit in self.units:
            unit_name = unit.text("DW_AT_name") or ""
            for die in _walk(unit):
                if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attrs:
                    continue
                low = die.text("DW_AT_low_pc")
                try:
                    low_pc = int(low or "", 16)
                except ValueError:
                    continue
                found.append(self._subprogram(die, unit_name, low_pc))
        found.sort(key=lambda s: (s.low_pc, s.name))
        return found

    def placed(self) -> tuple[list[Subprogram], list[Unplaced]]:
        """Every function with code at its entry address, and each one with none.

        The function's ``low_pc`` here is its entry. A DIE with neither ``DW_AT_low_pc`` nor ``DW_AT_ranges`` holds
        no code (a declaration, an abstract instance) and is in neither list. Whatever the DWARF does not state as
        one address is unplaced with the reason, never guessed: a constant ``DW_AT_entry_pc``, a range list
        that is empty or unreadable, an address a linker discarded.
        """
        found: list[Subprogram] = []
        unplaced: list[Unplaced] = []
        for unit in self.units:
            unit_name = unit.text("DW_AT_name") or ""
            for die in _walk(unit):
                if die.tag != "DW_TAG_subprogram" or not {"DW_AT_low_pc", "DW_AT_ranges"} & die.attrs.keys():
                    continue
                entry, why = self._entry(die)
                if entry is None:
                    named, _ = self._attr_via_origin(die, "DW_AT_name")
                    unplaced.append(Unplaced(named.text("DW_AT_name") or "", die.offset, why))
                else:
                    found.append(self._subprogram(die, unit_name, entry))
        found.sort(key=lambda s: (s.low_pc, s.name))
        unplaced.sort(key=lambda u: (u.name, u.offset))
        return found, unplaced

    def _entry(self, die: Die) -> tuple[int | None, str]:
        """``(entry, "")`` for a function with one, else ``(None, why)``."""
        if "DW_AT_entry_pc" in die.attrs:
            if not die.forms.get("DW_AT_entry_pc", "").startswith("addr"):
                return None, "its DW_AT_entry_pc is an offset from a base, not an address"
            source = "DW_AT_entry_pc"
        elif "DW_AT_low_pc" in die.attrs:
            source = "DW_AT_low_pc"
        else:
            source = ""
        if source:
            try:
                entry = int(die.text(source) or "", 16)
            except ValueError:
                return None, f"its {source} is not an address"
        else:
            offset = die.number("DW_AT_ranges")
            begins = self.ranges.get(offset, ()) if offset is not None else ()
            if len(begins) != 1:
                return None, "its DW_AT_ranges list has no one readable first range"
            entry = begins[0]
        if entry in TOMBSTONES:
            return None, f"its code was discarded by the linker (address {entry:#x})"
        return entry, ""

    def _subprogram(self, die: Die, unit_name: str, low_pc: int) -> Subprogram:
        named, via_name = self._attr_via_origin(die, "DW_AT_name")
        typed, _ = self._attr_via_origin(die, "DW_AT_type")
        external_die, _ = self._attr_via_origin(die, "DW_AT_external")
        proto_die, _ = self._attr_via_origin(die, "DW_AT_prototyped")
        formals = self._formals(die)
        return Subprogram(
            name=named.text("DW_AT_name") or "",
            low_pc=low_pc,
            unit=unit_name,
            external=external_die.flag("DW_AT_external"),
            return_type=typed.ref("DW_AT_type"),
            parameters=formals[0],
            variadic=formals[1],
            prototyped=proto_die.flag("DW_AT_prototyped"),
            via_origin=via_name,
        )

    def _formals(self, die: Die) -> tuple[list[Parameter], bool]:
        """The declared parameters, from the concrete DIE or the one it realises."""
        source = die
        if not any(
            child.tag in ("DW_TAG_formal_parameter", "DW_TAG_unspecified_parameters")
            for child in die.children
        ):
            origin = self._origin(die)
            while origin is not None:
                source = origin
                if any(
                    child.tag in ("DW_TAG_formal_parameter", "DW_TAG_unspecified_parameters")
                    for child in origin.children
                ):
                    break
                origin = self._origin(origin)
        parameters: list[Parameter] = []
        variadic = False
        for child in source.children:
            if child.tag == "DW_TAG_unspecified_parameters":
                variadic = True
            if child.tag != "DW_TAG_formal_parameter":
                continue
            named, _ = self._attr_via_origin(child, "DW_AT_name")
            typed, _ = self._attr_via_origin(child, "DW_AT_type")
            parameters.append(
                Parameter(name=named.text("DW_AT_name") or "", type_offset=typed.ref("DW_AT_type"))
            )
        return parameters, variadic

    # ---------------------------------------------------------------- types

    def strip(self, offset: int | None) -> int | None:
        """The type under every typedef and qualifier."""
        seen = 0
        while offset is not None and offset in self.index and seen < 64:
            die = self.index[offset]
            if die.tag not in _QUALIFIERS:
                return offset
            offset = die.ref("DW_AT_type")
            seen += 1
        return offset

    def type(self, offset: int | None) -> TypeInfo:
        if offset in self._types:
            return self._types[offset]
        info = self._describe(offset)
        self._types[offset] = info
        return info

    def _describe(self, offset: int | None) -> TypeInfo:
        spelled = self.spelling(offset)
        base = self.strip(offset)
        if base is None:
            return TypeInfo(kind="void", spelling=spelled or "void")
        die = self.index.get(base)
        if die is None:
            return TypeInfo(kind="unsupported", reason=f"no DIE at 0x{base:x}", spelling=spelled)
        size = die.number("DW_AT_byte_size") or 0
        if die.tag == "DW_TAG_base_type":
            encoding = die.number("DW_AT_encoding")
            # DW_ATE_boolean 2, float 4, signed 5, signed_char 6, unsigned 7,
            # unsigned_char 8, complex 3, UTF 0x10.
            if encoding == 2:
                return TypeInfo(kind="bool", size=size, spelling=spelled)
            if encoding == 4:
                if size in (4, 8):
                    return TypeInfo(kind="float", size=size, spelling=spelled)
                return TypeInfo(
                    kind="unsupported", size=size, spelling=spelled,
                    reason=f"{size}-byte floating type (x87 or quad)",
                )
            if encoding in (5, 6):
                return TypeInfo(kind="int", size=size, signed=True, spelling=spelled)
            if encoding in (7, 8, 0x10):
                return TypeInfo(kind="int", size=size, signed=False, spelling=spelled)
            return TypeInfo(
                kind="unsupported", size=size, spelling=spelled,
                reason=f"base type encoding {encoding}",
            )
        if die.tag == "DW_TAG_enumeration_type":
            underlying = self.type(die.ref("DW_AT_type")) if die.ref("DW_AT_type") else None
            signed = underlying.signed if underlying else False
            return TypeInfo(kind="int", size=size or 4, signed=signed, spelling=spelled)
        if die.tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type"):
            return TypeInfo(
                kind="pointer", size=size or 8, target=die.ref("DW_AT_type"), spelling=spelled
            )
        if die.tag in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_class_type"):
            kind = "union" if die.tag == "DW_TAG_union_type" else "struct"
            if die.flag("DW_AT_declaration"):
                return TypeInfo(kind=kind, size=0, spelling=spelled, reason="incomplete")
            return TypeInfo(kind=kind, size=size, target=base, spelling=spelled)
        if die.tag == "DW_TAG_array_type":
            count = None
            for child in die.children:
                if child.tag == "DW_TAG_subrange_type":
                    upper = child.number("DW_AT_upper_bound")
                    counted = child.number("DW_AT_count")
                    if counted is not None:
                        count = counted
                    elif upper is not None:
                        count = upper + 1
                    break
            element = die.ref("DW_AT_type")
            element_size = self.type(element).size if element is not None else 0
            return TypeInfo(
                kind="array",
                size=(count or 0) * element_size,
                target=element,
                count=count,
                spelling=spelled,
            )
        if die.tag == "DW_TAG_subroutine_type":
            return TypeInfo(kind="function", target=base, spelling=spelled)
        return TypeInfo(kind="unsupported", reason=die.tag, spelling=spelled)

    def members(self, struct_offset: int) -> list[Member]:
        die = self.index.get(struct_offset)
        if die is None:
            return []
        out: list[Member] = []
        for child in die.children:
            if child.tag != "DW_TAG_member":
                continue
            location = child.number("DW_AT_data_member_location") or 0
            out.append(
                Member(
                    name=child.text("DW_AT_name") or "",
                    offset=location,
                    type_offset=child.ref("DW_AT_type"),
                    bit_size=child.number("DW_AT_bit_size"),
                )
            )
        return out

    def subroutine_signature(self, offset: int | None) -> tuple[str, tuple[str, ...], bool] | None:
        """``(return, parameters, variadic)`` of a subroutine type, canonically spelled."""
        base = self.strip(offset)
        die = self.index.get(base) if base is not None else None
        if die is None or die.tag != "DW_TAG_subroutine_type":
            return None
        params: list[str] = []
        variadic = False
        for child in die.children:
            if child.tag == "DW_TAG_formal_parameter":
                params.append(self.canonical(child.ref("DW_AT_type")))
            elif child.tag == "DW_TAG_unspecified_parameters":
                variadic = True
        return self.canonical(die.ref("DW_AT_type")), tuple(params), variadic

    def function_signature(self, sub: Subprogram) -> tuple[str, tuple[str, ...], bool]:
        return (
            self.canonical(sub.return_type),
            tuple(self.canonical(p.type_offset) for p in sub.parameters),
            sub.variadic,
        )

    def canonical(self, offset: int | None, depth: int = 0) -> str:
        """A spelling that two identical types share and two different ones do not."""
        info = self.type(offset)
        if depth > 6:
            return info.kind
        if info.kind == "pointer":
            return self.canonical(info.target, depth + 1) + "*"
        if info.kind in ("int", "bool"):
            return f"{'s' if info.signed else 'u'}{info.size * 8}" if info.kind == "int" else "bool"
        if info.kind == "float":
            return f"f{info.size * 8}"
        if info.kind in ("struct", "union"):
            die = self.index.get(info.target) if info.target is not None else None
            name = die.text("DW_AT_name") if die is not None else None
            return f"{info.kind} {name or hex(info.target or 0)}"
        if info.kind == "array":
            return self.canonical(info.target, depth + 1) + f"[{info.count}]"
        if info.kind == "function":
            sig = self.subroutine_signature(offset)
            return f"fn{sig}" if sig else "fn"
        return info.kind

    def spelling(self, offset: int | None) -> str:
        """The type as its DWARF names it, for evidence only."""
        parts: list[str] = []
        seen = 0
        while offset is not None and offset in self.index and seen < 16:
            die = self.index[offset]
            seen += 1
            name = die.text("DW_AT_name")
            if die.tag == "DW_TAG_pointer_type":
                parts.append("*")
                offset = die.ref("DW_AT_type")
                continue
            if die.tag == "DW_TAG_const_type":
                parts.append("const")
                offset = die.ref("DW_AT_type")
                continue
            if die.tag in ("DW_TAG_volatile_type", "DW_TAG_restrict_type", "DW_TAG_atomic_type"):
                offset = die.ref("DW_AT_type")
                continue
            if die.tag == "DW_TAG_structure_type":
                parts.append(f"struct {name or '?'}")
            elif die.tag == "DW_TAG_union_type":
                parts.append(f"union {name or '?'}")
            elif die.tag == "DW_TAG_enumeration_type":
                parts.append(f"enum {name or '?'}")
            elif die.tag == "DW_TAG_subroutine_type":
                parts.append("fn")
            else:
                parts.append(name or die.tag)
            break
        else:
            if offset is None:
                parts.append("void")
        base = parts[-1] if parts else "void"
        prefix = parts[:-1]
        return " ".join([base] + list(reversed(prefix))).replace(" *", "*")


def _walk(die: Die):
    stack = [die]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def function_symbols(binary: Path, target: Target = X86_64) -> dict[int, tuple[list[str], int]]:
    """``address -> (names, size)`` of every FUNC symbol in the binary's ``.symtab``."""
    proc = subprocess.run(
        [target.tool("readelf"), "--wide", "--syms", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    symbols: dict[int, tuple[list[str], int]] = {}
    in_symtab = False
    for line in proc.stdout.splitlines():
        if line.startswith("Symbol table"):
            in_symtab = "'.symtab'" in line
            continue
        fields = line.split()
        if not in_symtab or len(fields) < 8 or fields[3] != "FUNC":
            continue
        try:
            address = int(fields[1], 16)
            size = int(fields[2], 0)
        except ValueError:
            continue
        names, known = symbols.get(address, ([], 0))
        names.append(fields[7].split("@", 1)[0])
        symbols[address] = (names, max(known, size))
    return symbols


def code_constants(binary: Path, address: int, size: int, limit: int = 32,
                   target: Target = X86_64) -> list[int]:
    """The immediates the original's own instructions compare and compute with.

    A boundary written in the source (`x > 100`) is an immediate in the code
    (`cmp $0x64`, `cmp w0, #0x64`). Reading them from the original -- the
    oracle side, never the rendering -- lets the vectors sit on each side of
    every such boundary, which is where an off-by-one lives. Returned as signed
    64-bit values in first-seen order.
    """
    if size <= 0:
        return []
    proc = subprocess.run(
        [target.tool("objdump"), "-d", "--no-show-raw-insn", f"--start-address=0x{address:x}",
         f"--stop-address=0x{address + size:x}", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    seen: list[int] = []
    for value in target.asm.immediates(proc.stdout):
        value &= (1 << 64) - 1
        if value >= 1 << 63:
            value -= 1 << 64
        if value not in seen:
            seen.append(value)
        if len(seen) >= limit:
            break
    return seen
