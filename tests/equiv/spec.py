"""How to call a function of the source, from its DWARF: the SysV x86-64 view.

A :class:`CallSpec` says which register or stack word carries each parameter,
what kind of value it is (so the vectors can build one), and at which class and
width the return is compared. Anything the register-level thunk does not model
-- an aggregate passed or returned by value, an x87 or quad float, a variadic
definition, a function pointer with no function of its type to point at -- is
``unsupported`` with the reason, which the gate records as its own status
rather than calling it wrongly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dwarf import Dwarf, Subprogram

INTEGER_REGISTERS = 6
SSE_REGISTERS = 8
MAX_STACK_WORDS = 16


@dataclass
class Pointee:
    """What a pointer parameter points at, as the vectors build it."""

    shape: str  # string | bytes | struct | pointers | none
    type_offset: int | None = None
    element_size: int = 1
    element_is_char: bool = False


@dataclass
class Param:
    name: str
    kind: str  # int | bool | float | pointer | funcptr
    size: int
    signed: bool = False
    spelling: str = ""
    register: str = ""  # rdi.. / xmm0.. / stack0..
    pointee: Pointee | None = None
    targets: list[int] = field(default_factory=list)


@dataclass
class CallSpec:
    name: str
    address: int
    params: list[Param]
    ret_kind: str  # void | int | f32 | f64 | int128
    ret_bytes: int
    ret_spelling: str
    unsupported: str | None = None
    constants: list[int] = field(default_factory=list)

    def describe(self) -> str:
        args = ", ".join(f"{p.spelling or p.kind} {p.name}@{p.register}" for p in self.params)
        return f"{self.ret_spelling} {self.name}({args})"


_INT_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


def _is_plain_char(dwarf: Dwarf, offset: int | None) -> bool:
    base = dwarf.strip(offset)
    die = dwarf.index.get(base) if base is not None else None
    return die is not None and die.tag == "DW_TAG_base_type" and die.text("DW_AT_name") == "char"


def _pointee(dwarf: Dwarf, target: int | None) -> Pointee | str:
    info = dwarf.type(target)
    if info.kind == "void":
        return Pointee("bytes", target, 1)
    if info.kind in ("int", "bool", "float"):
        if info.kind == "int" and info.size == 1 and _is_plain_char(dwarf, target):
            return Pointee("string", target, 1, element_is_char=True)
        return Pointee("bytes", target, max(info.size, 1))
    if info.kind in ("struct", "union"):
        if info.reason == "incomplete" or info.size == 0:
            return Pointee("bytes", target, 1)
        return Pointee("struct", info.target, info.size)
    if info.kind == "pointer":
        inner = dwarf.type(info.target)
        is_char = inner.kind == "int" and inner.size == 1 and _is_plain_char(dwarf, info.target)
        return Pointee("pointers", info.target, 8, element_is_char=is_char)
    if info.kind == "array":
        return Pointee("bytes", target, max(info.size, 1))
    if info.kind == "function":
        return "function"
    return f"pointer to {info.reason or info.kind}"


def call_spec(dwarf: Dwarf, sub: Subprogram, functions: list[Subprogram]) -> CallSpec:
    """The call the thunk makes for ``sub``, or the reason it cannot make one."""
    spec = CallSpec(
        name=sub.name,
        address=sub.low_pc,
        params=[],
        ret_kind="void",
        ret_bytes=0,
        ret_spelling=dwarf.spelling(sub.return_type),
    )
    if sub.variadic:
        spec.unsupported = "variadic definition: the count of its trailing arguments is unknown"
        return spec

    ret = dwarf.type(sub.return_type)
    if ret.kind == "void":
        spec.ret_kind, spec.ret_bytes = "void", 0
    elif ret.kind in ("int", "bool", "pointer"):
        size = ret.size or 8
        if size == 16:
            spec.ret_kind, spec.ret_bytes = "int128", 16
        elif size in (1, 2, 4, 8):
            spec.ret_kind, spec.ret_bytes = "int", size
        else:
            spec.unsupported = f"a {size}-byte integer return"
            return spec
    elif ret.kind == "float":
        spec.ret_kind, spec.ret_bytes = ("f32", 4) if ret.size == 4 else ("f64", 8)
    elif ret.kind in ("struct", "union", "array"):
        spec.unsupported = f"an aggregate return ({ret.spelling or ret.kind})"
        return spec
    else:
        spec.unsupported = f"a return of {ret.reason or ret.kind}"
        return spec

    signatures = {f.low_pc: dwarf.function_signature(f) for f in functions}
    used_int = used_sse = used_stack = 0
    for index, parameter in enumerate(sub.parameters):
        info = dwarf.type(parameter.type_offset)
        name = parameter.name or f"arg{index}"
        spelled = dwarf.spelling(parameter.type_offset)
        if info.kind in ("int", "bool"):
            if info.size not in (1, 2, 4, 8):
                spec.unsupported = f"parameter {name}: a {info.size}-byte integer"
                return spec
            param = Param(name, info.kind, info.size, info.signed, spelled)
            sse = False
        elif info.kind == "float":
            param = Param(name, "float", info.size, True, spelled)
            sse = True
        elif info.kind == "pointer":
            pointee = _pointee(dwarf, info.target)
            if pointee == "function":
                wanted = dwarf.subroutine_signature(info.target)
                targets = sorted(
                    address for address, signature in signatures.items()
                    if wanted is not None and signature == wanted and address != sub.low_pc
                )
                if not targets:
                    targets = sorted(
                        address for address, signature in signatures.items()
                        if wanted is not None and signature == wanted
                    )
                if not targets:
                    spec.unsupported = (
                        f"parameter {name}: no function of type {spelled} to point at"
                    )
                    return spec
                param = Param(name, "funcptr", 8, False, spelled, targets=targets)
            elif isinstance(pointee, str):
                spec.unsupported = f"parameter {name}: {pointee}"
                return spec
            else:
                param = Param(name, "pointer", 8, False, spelled, pointee=pointee)
            sse = False
        elif info.kind in ("struct", "union", "array"):
            spec.unsupported = f"parameter {name}: an aggregate passed by value ({spelled})"
            return spec
        else:
            spec.unsupported = f"parameter {name}: {info.reason or info.kind}"
            return spec

        if sse and used_sse < SSE_REGISTERS:
            param.register = f"xmm{used_sse}"
            used_sse += 1
        elif not sse and used_int < INTEGER_REGISTERS:
            param.register = _INT_REGISTERS[used_int]
            used_int += 1
        else:
            if used_stack >= MAX_STACK_WORDS:
                spec.unsupported = f"more than {MAX_STACK_WORDS} stack argument words"
                return spec
            param.register = f"stack{used_stack}"
            used_stack += 1
        spec.params.append(param)
    return spec
