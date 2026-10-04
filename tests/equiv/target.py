"""The machine the gate grades: its compilers, tools, calling convention and runner.

Everything the gate does that depends on the architecture of the binaries it
builds is a field of one :class:`Target`, so the rest of the gate is written
once:

* **compilers**: the argv prefix of each population compiler, by the name the
  records and the baseline use for it (``gcc``, ``clang``), and the compiler
  the renderings are built with;
* **binutils**: the prefix of ``strip``, ``nm``, ``readelf`` and ``objdump``
  for this machine, and the sysroot its shared libraries live in when it is
  not the host;
* **calling convention** (:class:`Abi`): which registers carry integer and
  floating arguments, how a narrow integer argument fills its register, and
  how a vector's entry state is laid out for the thunk;
* **assembly**: the thunk (``rt/call_*.S``), and the jumps the link-map shim
  and the identity trampoline are made of;
* **runner**: the prefix that runs one of its programs on this host, and how
  the runtime's variables reach that program;
* **trap**: the signal ``__builtin_trap`` raises, which is how a reached
  residual ends.

x86-64 is the gate's first target and its keys predate this axis: its
configurations are spelled ``gcc-O0``, its work directories carry no target
name, and its baseline is ``baseline.json``. Every other target qualifies all
three with its name (``aarch64-gcc-O0``, ``rt-aarch64``,
``baseline-aarch64.json``), so records of two machines can never share a key.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent

MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class Abi:
    """A calling convention, as far as the thunk models one.

    ``int_registers`` and ``fp_registers`` are the argument registers in
    allocation order; an argument past them takes the next stack word (both
    conventions here give every stack argument one 8-byte word). The vector
    of floating registers is always eight 16-byte lanes in the job.
    """

    name: str
    int_registers: tuple[str, ...]
    fp_registers: tuple[str, ...]
    # x86-64 passes the count of vector registers a variadic callee reads in
    # AL; the job then carries a word for it after the vector registers.
    count_register: bool
    # Bits of a narrow integer argument the caller extends by its type's
    # signedness. SysV x86-64 callers extend to 32 bits (not written in the
    # psABI, but both compilers' callers do it and both compilers' callees
    # rely on it); AAPCS64 leaves every bit above the type unspecified.
    extended_bits: int
    # The width a _Bool argument is passed at, before the bits above it are
    # left unspecified.
    bool_bytes: int

    def argument_word(self, value: int, size: int, signed: bool, garbage: int) -> int:
        """The register (or stack word) a ``size``-byte integer argument arrives in.

        Bits the convention defines are the value, extended to
        ``extended_bits`` by its signedness; every bit above is the caller's
        leftover, taken from ``garbage``. A rendering that reads a bit the
        convention never gave it is then caught, and the original, which is
        correct by construction, never reads one.
        """
        bits = size * 8
        v = value & ((1 << bits) - 1)
        defined = max(bits, self.extended_bits)
        if bits < defined and signed and (v >> (bits - 1)) & 1:
            v |= ((1 << defined) - 1) ^ ((1 << bits) - 1)
        if defined < 64:
            v = (v & ((1 << defined) - 1)) | ((garbage << defined) & MASK64)
        return v & MASK64

    def regs_format(self) -> str:
        """``struct equiv_regs`` of this machine (``rt/equiv_rt.c``), for :mod:`struct`."""
        count = "Q" if self.count_register else ""
        return f"{len(self.int_registers)}Q{len(self.fp_registers) * 16}s{count}Q16Q"


SYSV_X86_64 = Abi(
    name="SysV x86-64",
    int_registers=("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    fp_registers=tuple(f"xmm{n}" for n in range(8)),
    count_register=True,
    extended_bits=32,
    bool_bytes=4,
)

AAPCS64 = Abi(
    name="AAPCS64",
    int_registers=tuple(f"x{n}" for n in range(8)),
    fp_registers=tuple(f"v{n}" for n in range(8)),
    count_register=False,
    extended_bits=0,
    bool_bytes=1,
)


_X86_IMMEDIATE = re.compile(r"\$0x([0-9a-f]+)")
_A64_IMMEDIATE = re.compile(r"#(-?(?:0x[0-9a-f]+|\d+))(?![.\w])")
_A64_ADDRESS = re.compile(r"\[[^\]]*\]")


class Assembly:
    """The few lines of assembly the gate writes for one machine.

    A function link of a rendering, and the identity trampoline, are jumps to
    an address in the image; a recursion through the graded function's own
    entry is a jump to the rendering's definition.
    """

    def jump_to_address(self, symbol: str, address: int) -> list[str]:
        """A global function ``symbol`` that jumps to ``address`` in the image.

        The address goes through a scratch register no argument travels in, so
        every argument register arrives untouched.
        """
        raise NotImplementedError

    def jump_to_symbol(self, symbol: str, definition: str) -> list[str]:
        """A global function ``symbol`` that is a direct jump to ``definition``."""
        raise NotImplementedError

    def stack_note(self) -> str:
        """The section that marks an object's stack as not executable."""
        raise NotImplementedError

    def immediates(self, disassembly: str) -> list[int]:
        """Every immediate operand in ``objdump -d`` output, in order."""
        raise NotImplementedError


class X86_64Assembly(Assembly):
    """r11 is scratch and never an argument register, so a variadic callee's AL survives."""

    def jump_to_address(self, symbol: str, address: int) -> list[str]:
        return [
            f"    .globl {symbol}",
            f"    .type {symbol}, @function",
            f"{symbol}:",
            f"    movabs $0x{address:x}, %r11",
            "    jmp *%r11",
        ]

    def jump_to_symbol(self, symbol: str, definition: str) -> list[str]:
        return [
            f"    .globl {symbol}",
            f"    .type {symbol}, @function",
            f"{symbol}:",
            f"    jmp {definition}",
        ]

    def stack_note(self) -> str:
        return '    .section .note.GNU-stack,"",@progbits'

    def immediates(self, disassembly: str) -> list[int]:
        return [int(found, 16) for found in _X86_IMMEDIATE.findall(disassembly)]


class AArch64Assembly(Assembly):
    """x16 (IP0) is the register AAPCS64 gives the linker for its own veneers
    between a caller and its callee: no argument and no result travels in it,
    and x8, the indirect result register, is left alone. The address is built
    with movz/movk, so no literal sits in the code."""

    def jump_to_address(self, symbol: str, address: int) -> list[str]:
        return [
            f"    .globl {symbol}",
            f"    .type {symbol}, %function",
            f"{symbol}:",
            f"    movz x16, #0x{address & 0xFFFF:x}",
            f"    movk x16, #0x{(address >> 16) & 0xFFFF:x}, lsl #16",
            f"    movk x16, #0x{(address >> 32) & 0xFFFF:x}, lsl #32",
            f"    movk x16, #0x{(address >> 48) & 0xFFFF:x}, lsl #48",
            "    br x16",
        ]

    def jump_to_symbol(self, symbol: str, definition: str) -> list[str]:
        return [
            f"    .globl {symbol}",
            f"    .type {symbol}, %function",
            f"{symbol}:",
            f"    b {definition}",
        ]

    def stack_note(self) -> str:
        return '    .section .note.GNU-stack,"",%progbits'

    def immediates(self, disassembly: str) -> list[int]:
        """``#`` operands outside an address (``[sp, #12]`` is a frame offset)
        and outside objdump's ``//`` comment, which repeats one in decimal; a
        floating immediate (``#1.0e+00``) is not an integer and is skipped."""
        found: list[int] = []
        for line in disassembly.splitlines():
            line = _A64_ADDRESS.sub("", line.split("//", 1)[0])
            found += [int(text, 0) for text in _A64_IMMEDIATE.findall(line)]
        return found


# Compared and hashed by identity: each target is one module-level value.
@dataclass(frozen=True, eq=False)
class Target:
    name: str
    # The name every key, directory and baseline of this target carries; ""
    # for x86-64, whose keys predate the target axis.
    qualifier: str
    abi: Abi
    # The ELF e_machine readelf names, checked on what the compilers built.
    elf_machine: str
    compilers: dict[str, tuple[str, ...]]
    rendering_cc: str
    binutils_prefix: str
    sysroot: Path | None
    call_asm: Path
    # The host machine (os.uname) that runs this target's programs natively.
    native_machines: tuple[str, ...]
    # The emulator that runs them elsewhere, and its arguments before the
    # program's own.
    emulator: str | None
    emulator_args: tuple[str, ...]
    # How many times slower than native the emulator runs this corpus's code.
    # qemu-aarch64 (TCG, 8.2) ran a bitwise CRC over 2 MiB 3.5 times slower
    # than x86-64 natively at -O2 and 5 times at -O0; the larger is taken.
    emulator_slowdown: int
    trap_signal: int
    asm: Assembly
    # GNU ld for AArch64 (2.42; gold too) resolves the GOT entry of an
    # absolute symbol a shared object defines as if the symbol were
    # section-relative, so the loader adds the object's load base to it: the
    # shim's `.set name, addr` would point a load base past the image's
    # object. There the object links are left to the dynamic loader instead,
    # which places an SHN_ABS definition at its value (link.loader_conflicts).
    objects_through_loader: bool = False

    # ----------------------------------------------------------- naming

    def config(self, compiler: str, opt: str) -> str:
        """The configuration part of a record key: ``gcc-O0`` or ``aarch64-gcc-O0``."""
        plain = f"{compiler}-{opt}"
        return f"{self.qualifier}-{plain}" if self.qualifier else plain

    def directory(self, name: str) -> str:
        """A work directory of this target's own (``rt``, ``rt-aarch64``)."""
        return f"{name}-{self.qualifier}" if self.qualifier else name

    # ------------------------------------------------------------ tools

    def compiler(self, name: str) -> list[str]:
        """The argv prefix of population compiler ``name`` (``gcc``, ``clang``)."""
        try:
            return list(self.compilers[name])
        except KeyError:
            raise ValueError(f"{self.name} has no compiler named {name!r} "
                             f"(it has {', '.join(sorted(self.compilers))})") from None

    def tool(self, name: str) -> str:
        """A binutils program for this machine: ``strip``, ``nm``, ``readelf``, ``objdump``."""
        return self.binutils_prefix + name

    def library(self, soname: str) -> str | None:
        """The sysroot file a ``DT_NEEDED`` name resolves to, or None (host libraries)."""
        if self.sysroot is None:
            return None
        for directory in ("lib", "usr/lib"):
            candidate = self.sysroot / directory / soname
            if candidate.exists():
                return str(candidate)
        return None

    # ------------------------------------------------------------ runner

    def emulated(self) -> bool:
        return os.uname().machine not in self.native_machines

    def time_scale(self) -> int:
        """The factor every per-call time budget is multiplied by on this host.

        The budgets (``--timeout-ms``: the original's, four times it for a
        rendering) are native wall-clock time. Under an emulator the same code
        takes longer, and a budget that is not scaled leaves a rendering
        a fraction of its native margin, so a loaded host turns an equal
        record slow on one run and not the next.
        """
        return self.emulator_slowdown if self.emulated() else 1

    def run_argv(self, program: Path, environment: list[str]) -> list[str]:
        """The command that runs ``program`` of this target with ``environment`` set in it.

        Natively, ``env(1)`` sets the variables as the last program before the
        binary, so nothing before it (setarch) loads the runtime itself.
        Under qemu-user the variables are handed to the guest with ``-E``, so
        the host's loader, which runs qemu, never sees an ``LD_PRELOAD`` of a
        foreign object. qemu splits an ``-E`` argument at commas, so a value
        with one is refused rather than passed in pieces.
        """
        if not self.emulated():
            return ["/usr/bin/env", *environment, str(program)]
        argv = [str(self.emulator), *self.emulator_args]
        for assignment in environment:
            if "," in assignment:
                raise ValueError(f"qemu -E cannot pass a value with a comma: {assignment}")
            argv += ["-E", assignment]
        return [*argv, str(program)]

    def environment_problem(self) -> str | None:
        """Why this host cannot run the gate for this target, or None."""
        machine = os.uname().machine
        if not self.emulated():
            if not Path("/proc/self/exe").exists():
                return "runtime equivalence needs Linux"
            return None
        if self.emulator is None:
            return f"runtime equivalence needs {self.name} (this is {machine})"
        if not Path("/proc/self/exe").exists():
            return "runtime equivalence needs Linux"
        if shutil.which(self.emulator) is None:
            return (f"runtime equivalence for {self.name} needs {self.emulator} "
                    f"on this {machine} host")
        if self.sysroot is not None and not (self.sysroot / "lib").is_dir():
            return f"runtime equivalence for {self.name} needs its sysroot at {self.sysroot}"
        if shutil.which(self.rendering_cc) is None:
            return f"runtime equivalence for {self.name} needs {self.rendering_cc}"
        return None


X86_64 = Target(
    name="x86-64",
    qualifier="",
    abi=SYSV_X86_64,
    elf_machine="Advanced Micro Devices X86-64",
    compilers={"gcc": ("gcc",), "clang": ("clang",)},
    rendering_cc="gcc",
    binutils_prefix="",
    sysroot=None,
    call_asm=HERE / "rt" / "call_x86_64.S",
    native_machines=("x86_64", "amd64"),
    emulator=None,
    emulator_args=(),
    emulator_slowdown=1,
    trap_signal=signal.SIGILL,  # ud2
    asm=X86_64Assembly(),
)

_AARCH64_TRIPLE = "aarch64-linux-gnu"
_AARCH64_SYSROOT = Path("/usr") / _AARCH64_TRIPLE

AARCH64 = Target(
    name="aarch64",
    qualifier="aarch64",
    abi=AAPCS64,
    elf_machine="AArch64",
    compilers={"gcc": (f"{_AARCH64_TRIPLE}-gcc",),
               "clang": ("clang", f"--target={_AARCH64_TRIPLE}")},
    rendering_cc=f"{_AARCH64_TRIPLE}-gcc",
    binutils_prefix=f"{_AARCH64_TRIPLE}-",
    sysroot=_AARCH64_SYSROOT,
    call_asm=HERE / "rt" / "call_aarch64.S",
    native_machines=("aarch64", "arm64"),
    emulator="qemu-aarch64",
    # -L: the guest's loader and libraries come from the sysroot. -seed: the
    # 16 bytes qemu gives the guest as AT_RANDOM, from which glibc derives the
    # stack-protector canary, are the same on every run, so a record that
    # shows stack memory (a UBSan report does) is the same on every run too.
    emulator_args=("-L", str(_AARCH64_SYSROOT), "-seed", "1"),
    emulator_slowdown=5,
    trap_signal=signal.SIGTRAP,  # brk
    asm=AArch64Assembly(),
    objects_through_loader=True,
)

TARGETS = {target.name: target for target in (X86_64, AARCH64)}


def by_name(name: str) -> Target:
    try:
        return TARGETS[name]
    except KeyError:
        raise ValueError(f"no target {name!r} (known: {', '.join(TARGETS)})") from None
