"""A C prototype as a typed value: what r2s's `signature` states and what a debug build's DWARF declares.

Both are read into one `CType`, so two spellings of one type are equal (`unsigned long`, `size_t` and
`uint64_t` are one 8-byte unsigned integer on the x86-64 and AArch64 Linux targets the gate grades) and two
different types are never equal by an accident of text. `classify` says how a recovered type differs from
the source's, by the bucket a fix empties.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from dwarf import UNRESOLVED  # tests/equiv is on the path of every importer

VOID, INT, BOOL, FLOAT, NAMED, PTR, FUNC, ARRAY = "void", "int", "bool", "float", "named", "ptr", "func", "array"


@dataclass(frozen=True)
class CType:
    """One C type. `signed` is None where the type does not say (plain `char`)."""

    kind: str
    width: int = 0
    signed: bool | None = None
    name: str = ""
    target: "CType | None" = None
    params: tuple["CType", ...] = ()
    variadic: bool = False
    count: int | None = None
    const: bool = False
    volatile: bool = False


class NotExpressible(Exception):
    """A type the gate cannot state, so a fact about it is no fact."""


class ParseError(ValueError):
    """Text that is no prototype."""


def integer(width: int, signed: bool | None) -> CType:
    return CType(INT, width=width, signed=signed)


def pointer(target: CType) -> CType:
    return CType(PTR, target=target)


NO_VALUE = CType(VOID)

# Each integer name a prototype spells, as (bytes, signed). Sizes are those of LP64, the targets graded.
INT_NAMES = {
    "int8_t": (1, True), "uint8_t": (1, False), "int16_t": (2, True), "uint16_t": (2, False),
    "int32_t": (4, True), "uint32_t": (4, False), "int64_t": (8, True), "uint64_t": (8, False),
    "intmax_t": (8, True), "uintmax_t": (8, False), "size_t": (8, False), "ssize_t": (8, True),
    "intptr_t": (8, True), "uintptr_t": (8, False), "ptrdiff_t": (8, True),
}
TYPE_WORDS = {"void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool", "bool"}
QUALIFIER_WORDS = {"const", "volatile", "restrict", "__restrict", "__restrict__"}
IGNORED_WORDS = {"static", "extern", "inline", "register", "auto", "__inline", "__inline__"}
TAG_WORDS = {"struct", "union", "enum"}
KEYWORDS = TYPE_WORDS | QUALIFIER_WORDS | IGNORED_WORDS | TAG_WORDS
NAME = re.compile(r"[A-Za-z_]\w*")
TOKEN = re.compile(r"\s*(?:([A-Za-z_]\w*)|(\.\.\.)|(\d+)|([*()\[\],;]))")


def is_name(word: str) -> bool:
    """Is this token an identifier that is no keyword of a declaration?"""
    return bool(NAME.fullmatch(word)) and word not in KEYWORDS


def decay(ty: CType) -> CType:
    """The type a parameter or a result has: an array or a function becomes a pointer, a top-level qualifier is dropped."""
    if ty.kind == ARRAY:
        ty = pointer(ty.target)
    elif ty.kind == FUNC:
        ty = pointer(ty)
    return replace(ty, const=False, volatile=False)


@dataclass(frozen=True)
class Prototype:
    """A function's name, result and parameters. `variadic` is a trailing `...`."""

    name: str
    ret: CType
    params: tuple[CType, ...] = ()
    variadic: bool = False


def tokenize(text: str) -> list[str]:
    tokens, at = [], 0
    text = text.rstrip()
    while at < len(text):
        found = TOKEN.match(text, at)
        if found is None:
            raise ParseError(f"cannot read {text[at:at + 12]!r}")
        tokens.append(found.group(0).strip())
        at = found.end()
    return tokens


class Parser:
    """Recursive descent over C declarators: pointers with qualifiers, groups, arrays and function suffixes."""

    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.at = 0

    def peek(self, ahead: int = 0) -> str:
        return self.tokens[self.at + ahead] if self.at + ahead < len(self.tokens) else ""

    def take(self) -> str:
        if self.at >= len(self.tokens):
            raise ParseError("the text ends inside a declaration")
        self.at += 1
        return self.tokens[self.at - 1]

    def expect(self, token: str) -> None:
        if self.take() != token:
            raise ParseError(f"expected {token!r} at token {self.at}")

    def identifier(self) -> str:
        word = self.take()
        if not is_name(word):
            raise ParseError(f"{word!r} is no name")
        return word

    def specifiers(self) -> CType:
        """The base type with its qualifiers: `const unsigned long`, `struct pair`, `uint8_t`."""
        words: list[str] = []
        const = volatile = False
        tag = typedef = ""
        while True:
            word = self.peek()
            if word in QUALIFIER_WORDS:
                const |= word == "const"
                volatile |= word == "volatile"
            elif word in IGNORED_WORDS:
                pass
            elif word in TAG_WORDS:
                self.take()
                tag = f"{word} {self.identifier()}"
                continue
            elif word in TYPE_WORDS:
                words.append(word)
            elif is_name(word) and not (words or tag or typedef):
                typedef = word
            else:
                break
            self.take()
        if not (words or tag or typedef):
            raise ParseError("no type")
        return replace(base_type(words, tag, typedef), const=const, volatile=volatile)

    def declarator(self, base: CType, named: bool) -> CType:
        """`base` declared by the text ahead; a name in it is read and dropped where `named`, and ends the text where not."""
        while self.peek() == "*":
            self.take()
            const = volatile = False
            while self.peek() in QUALIFIER_WORDS:
                word = self.take()
                const |= word == "const"
                volatile |= word == "volatile"
            base = CType(PTR, target=base, const=const, volatile=volatile)
        inner: list[str] | None = None
        if self.peek() == "(" and self.peek(1) in ("*", "("):
            inner = self.group()
        elif named and is_name(self.peek()):
            self.take()
        suffixes: list[tuple[str, object]] = []
        while self.peek() in ("[", "("):
            if self.peek() == "[":
                self.take()
                count = int(self.take()) if self.peek().isdigit() else None
                self.expect("]")
                suffixes.append(("array", count))
            else:
                suffixes.append(("function", self.parameters()))
        for kind, detail in reversed(suffixes):
            if kind == "array":
                base = CType(ARRAY, target=base, count=detail)
            else:
                params, variadic = detail
                base = CType(FUNC, target=base, params=params, variadic=variadic)
        if inner is None:
            return base
        nested = Parser(inner)
        base = nested.declarator(base, named)
        nested.finish()
        return base

    def group(self) -> list[str]:
        """The tokens of a parenthesised declarator, consumed with both parentheses."""
        self.expect("(")
        start, depth = self.at, 1
        while depth:
            token = self.take()
            depth += token == "("
            depth -= token == ")"
        return self.tokens[start:self.at - 1]

    def parameters(self) -> tuple[tuple[CType, ...], bool]:
        self.expect("(")
        params: list[CType] = []
        variadic = False
        if self.peek() != ")":
            while True:
                if self.peek() == "...":
                    self.take()
                    variadic = True
                else:
                    params.append(self.declarator(self.specifiers(), named=True))
                if self.peek() != ",":
                    break
                self.take()
        self.expect(")")
        if NO_VALUE in params:
            if len(params) > 1 or variadic:
                raise ParseError("`void` is a parameter only on its own")
            params = []
        return tuple(decay(param) for param in params), variadic

    def finish(self) -> None:
        if self.at != len(self.tokens):
            raise ParseError(f"unread text from token {self.at}: {' '.join(self.tokens[self.at:self.at + 4])!r}")


def base_type(words: list[str], tag: str, typedef: str) -> CType:
    """The type named by C's type words (`unsigned long int`), a tag (`struct pair`) or a typedef name."""
    if tag:
        return CType(NAMED, name=tag)
    if typedef:
        return integer(*INT_NAMES[typedef]) if typedef in INT_NAMES else CType(NAMED, name=typedef)
    if "void" in words:
        return NO_VALUE
    if "_Bool" in words or "bool" in words:
        return CType(BOOL)
    if "float" in words:
        return CType(FLOAT, width=4)
    if "double" in words:
        return CType(FLOAT, width=16 if "long" in words else 8)
    signed = False if "unsigned" in words else True if "signed" in words else None
    if "char" in words:
        return integer(1, signed)
    width = 2 if "short" in words else 8 if "long" in words else 4
    return integer(width, signed is not False)


def parse_type(text: str) -> CType:
    """A type name: `const uint8_t*`, `int32_t (*)(int32_t, int32_t)`."""
    parser = Parser(tokenize(text))
    ty = parser.declarator(parser.specifiers(), named=False)
    parser.finish()
    return ty


def parse_prototype(text: str) -> Prototype:
    """r2s's header `ret name(params)`: the result is a type name, so a function pointer is spelled
    `int32_t(*)(int32_t, int32_t) pick(int32_t sel)`, which is no C declaration but is read as one type name and a name."""
    parser = Parser(tokenize(text))
    ret = parser.declarator(parser.specifiers(), named=False)
    name = parser.identifier()
    params, variadic = parser.parameters()
    if parser.peek() == ";":
        parser.take()
    parser.finish()
    return Prototype(name, decay(ret), params, variadic)


def spell(ty: CType) -> str:
    """The type as C writes it, one way for every equal type: the stdint names, `char`, `bool`, `const T*`."""
    return declare(ty, "")


def declare(ty: CType, inner: str) -> str:
    if ty.kind == PTR:
        qualifiers = (" const" if ty.const else "") + (" volatile" if ty.volatile else "")
        star = "*" + qualifiers
        grouped = f"({star}{inner})" if ty.target.kind in (FUNC, ARRAY) else star + inner
        return declare(ty.target, grouped)
    if ty.kind == ARRAY:
        return declare(ty.target, f"{inner}[{'' if ty.count is None else ty.count}]")
    if ty.kind == FUNC:
        params = [spell(param) for param in ty.params] + (["..."] if ty.variadic else [])
        return declare(ty.target, f"{inner}({', '.join(params) or 'void'})")
    words = [word for word, on in (("const", ty.const), ("volatile", ty.volatile)) if on]
    words.append(base_name(ty))
    base = " ".join(words)
    return base + ("" if not inner or inner.startswith("*") else " ") + inner


def base_name(ty: CType) -> str:
    if ty.kind == INT:
        return "char" if ty.signed is None else f"{'' if ty.signed else 'u'}int{ty.width * 8}_t"
    if ty.kind == FLOAT:
        return {4: "float", 8: "double"}.get(ty.width, "long double")
    return {VOID: "void", BOOL: "bool"}.get(ty.kind) or ty.name


def unqualified(ty: CType) -> CType:
    """The type with every qualifier removed, at every level."""
    ty = replace(ty, const=False, volatile=False)
    if ty.target is not None:
        ty = replace(ty, target=unqualified(ty.target))
    if ty.params:
        ty = replace(ty, params=tuple(unqualified(param) for param in ty.params))
    return ty


def classify(expected: CType, actual: CType) -> str:
    """How a type that differs from the source's differs, so a fix is graded by the bucket it empties."""
    if (expected.kind == VOID) != (actual.kind == VOID):
        return "void_vs_value"
    if (expected.kind == PTR) != (actual.kind == PTR):
        return "pointer_as_integer" if expected.kind == PTR else "integer_as_pointer"
    if expected.kind == PTR:
        return "qualifier" if unqualified(expected) == unqualified(actual) else "pointee"
    if expected.kind == actual.kind == INT:
        if expected.width != actual.width:
            return "width_wider" if actual.width > expected.width else "width_narrower"
        if expected.signed is not None and actual.signed is not None and expected.signed != actual.signed:
            return "sign"
    return "other"


def integer_class(ty: CType) -> bool:
    """Is a parameter of this type passed in an integer register (System V x86-64, AAPCS64)?"""
    return ty.kind in (INT, BOOL, PTR) and ty.width <= 8


def from_dwarf(dwarf, offset: int | None, depth: int = 0) -> CType:
    """The type at a DIE offset (`None` is `void`), typedefs resolved and `const` and `volatile` kept.

    A struct is named by its tag, or by the outermost typedef when it has none. A type the gate cannot state
    (a complex number, a vector, an aggregate with no name, a DIE that is missing) raises `NotExpressible`, and so
    does a DIE that states itself elsewhere (`DW_AT_signature`, `DW_AT_declaration`).
    """
    if depth > 32:
        raise NotExpressible("a type nested more than 32 levels deep")
    const = volatile = False
    alias = ""
    steps = 0
    while offset is not None:
        die = dwarf.index.get(offset)
        if die is None:
            raise NotExpressible("a type in another unit" if offset == UNRESOLVED else f"no DIE at {offset:#x}")
        if "DW_AT_signature" in die.attrs or die.flag("DW_AT_declaration"):
            raise NotExpressible(f"a {die.tag} stated elsewhere (a type unit stub or a declaration)")
        steps += 1
        if steps > 64:
            raise NotExpressible("a chain of more than 64 typedefs and qualifiers")
        if die.tag in ("DW_TAG_const_type", "DW_TAG_volatile_type"):
            const |= die.tag == "DW_TAG_const_type"
            volatile |= die.tag == "DW_TAG_volatile_type"
        elif die.tag == "DW_TAG_typedef":
            alias = alias or die.text("DW_AT_name") or ""
        elif die.tag not in ("DW_TAG_restrict_type", "DW_TAG_atomic_type"):
            break
        offset = die.ref("DW_AT_type")
    else:
        return replace(NO_VALUE, const=const, volatile=volatile)
    return replace(shape_of_dwarf(dwarf, die, alias, depth), const=const, volatile=volatile)


def shape_of_dwarf(dwarf, die, alias: str, depth: int) -> CType:
    size = die.number("DW_AT_byte_size")
    if die.tag in ("DW_TAG_base_type", "DW_TAG_enumeration_type") and size is None:
        raise NotExpressible(f"a {die.tag} that states no byte size")
    if die.tag == "DW_TAG_base_type":
        return base_of_dwarf(die, size)
    if die.tag == "DW_TAG_enumeration_type":
        # Only the underlying type states the sign: an enum with none, or one of another size, is no integer.
        underlying = from_dwarf(dwarf, die.ref("DW_AT_type"), depth + 1)
        if underlying.signed is None or underlying.width != size:
            raise NotExpressible("an enum that states no underlying integer of its size")
        return integer(size, underlying.signed)
    if die.tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type"):
        return pointer(from_dwarf(dwarf, die.ref("DW_AT_type"), depth + 1))
    if die.tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
        keyword = "union" if die.tag == "DW_TAG_union_type" else "struct"
        tag = die.text("DW_AT_name")
        if not (tag or alias):
            raise NotExpressible(f"a {keyword} with neither a tag nor a typedef name")
        return CType(NAMED, name=f"{keyword} {tag}" if tag else alias)
    if die.tag == "DW_TAG_array_type":
        if die.flag("DW_AT_GNU_vector"):
            raise NotExpressible("a vector type")
        element = from_dwarf(dwarf, die.ref("DW_AT_type"), depth + 1)
        counts = []
        for child in die.children:
            if child.tag == "DW_TAG_subrange_type":
                if any(bound in child.attrs and child.number(bound) is None for bound in ("DW_AT_upper_bound", "DW_AT_count")):
                    raise NotExpressible("an array bound that is no constant")
                upper = child.number("DW_AT_upper_bound")
                counted = child.number("DW_AT_count")
                counts.append(counted if counted is not None else None if upper is None else upper + 1)
        for count in reversed(counts or [None]):
            element = CType(ARRAY, target=element, count=count)
        return element
    if die.tag == "DW_TAG_subroutine_type":
        params = tuple(
            decay(from_dwarf(dwarf, child.ref("DW_AT_type"), depth + 1))
            for child in die.children if child.tag == "DW_TAG_formal_parameter"
        )
        variadic = any(child.tag == "DW_TAG_unspecified_parameters" for child in die.children)
        return CType(FUNC, target=from_dwarf(dwarf, die.ref("DW_AT_type"), depth + 1), params=params, variadic=variadic)
    raise NotExpressible(die.tag)


def base_of_dwarf(die, size: int) -> CType:
    """DW_ATE_ encodings: boolean 2, float 4, signed 5, signed char 6, unsigned 7, unsigned char 8, UTF 0x10."""
    encoding = die.number("DW_AT_encoding")
    if encoding == 2:
        return CType(BOOL)
    if encoding == 4:
        return CType(FLOAT, width=size)
    if encoding in (6, 8) and die.text("DW_AT_name") == "char":
        return integer(1, None)
    if encoding in (5, 6):
        return integer(size, True)
    if encoding in (7, 8, 0x10):
        return integer(size, False)
    raise NotExpressible(f"base type encoding {encoding}")
