"""Build the gate's population: every source, every compiler, every level.

Each source is built non-PIE with ``-g`` (the oracle's copy: its DWARF says how
to call each function, and it is the image the rendering runs inside), and
then copied with ``strip --strip-all`` (the only file r2s is ever shown). The
two live in sibling directories, ``oracle/`` and ``shown/``, under the same
file name, so nothing that opens the shown copy finds its twin by editing the
name it was given.
Non-PIE keeps the link address and the run-time address the same, so an
address the rendering spells is an address in the running image.

A source with no ``main`` of its own (a file of functions) is linked with an
empty one; its functions are what the gate grades, not its entry point.

Every build is for one :class:`target.Target`: its compilers (``gcc`` names
``aarch64-linux-gnu-gcc`` there, ``clang`` names ``clang
--target=aarch64-linux-gnu``) and its ``strip``. What a compiler made is read
back (``readelf -h``) before it is graded, so a compiler that built for the
wrong machine is a failed build, never a binary graded under the wrong ABI.

A Windows target builds a PE32+ with clang-cl instead (:func:`pe_argv`), reads
its format back with ``objdump -f`` and strips it with ``llvm-strip``.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from target import X86_64, Target, first_on_path, xwin_root

REPO = Path(__file__).resolve().parents[2]
COMPILERS = ("gcc", "clang")
OPT_LEVELS = ("O0", "O1", "O2")
BUILD_FLAGS = ("-g", "-no-pie", "-fno-pie")
_EMPTY_MAIN = "int main(void) { return 0; }\n"


@dataclass
class Binary:
    source: Path
    compiler: str
    opt: str
    unstripped: Path
    stripped: Path
    error: str | None = None
    target: Target = X86_64

    @property
    def config(self) -> str:
        return self.target.config(self.compiler, self.opt)

    @property
    def source_key(self) -> str:
        try:
            return self.source.resolve().relative_to(REPO).as_posix()
        except ValueError:
            return self.source.name


def toolchain(compilers: list[str], target: Target = X86_64) -> dict[str, str]:
    """What each compiler says it is: the first line of its ``--version``.

    The population is built by these, and what a binary is depends on which
    compiler made it, so a baseline only grades runs built the same way.
    """
    found = {}
    for compiler in compilers:
        argv = target.compiler(compiler)
        try:
            proc = subprocess.run([*argv, "--version"], capture_output=True, text=True,
                                  check=False)
            first = proc.stdout.splitlines()
        except FileNotFoundError:
            first = []
        found[compiler] = (first or ["absent"])[0].strip()
    return found


def default_sources() -> list[Path]:
    """``tests/corpus/*.c`` and ``tests/gold/*.c``: every program the repository keeps."""
    found = sorted((REPO / "tests" / "corpus").glob("*.c"))
    found += sorted((REPO / "tests" / "gold").glob("*.c"))
    return found


# clang-cl's level for each of the gate's: /O1 is MSVC's smallest code, /O2 its fastest.
_CL_LEVELS = {"O0": "/Od", "O1": "/O1", "O2": "/O2"}


def pe_argv(cc: list[str], sources: list[Path], out: Path, opt: str) -> list[str]:
    """clang-cl building a PE32+ against UCRT's DLLs (/MD), with /GS and DWARF.

    The xwin sysroot (``$EQUIV_XWIN``) gives the headers and import libraries;
    ``/debug:dwarf`` keeps the DWARF the oracle reads in the image.
    """
    root = xwin_root() or Path("/nonexistent")
    includes = [root / "crt" / "include", root / "sdk" / "include" / "ucrt",
                root / "sdk" / "include" / "um", root / "sdk" / "include" / "shared"]
    libraries = [root / "crt" / "lib" / "x86_64", root / "sdk" / "lib" / "um" / "x86_64",
                 root / "sdk" / "lib" / "ucrt" / "x86_64"]
    return [*cc, "/nologo", "/MD", "/GS", _CL_LEVELS[opt], "/Z7", "/clang:-gdwarf",
            "-Wno-everything", "/D_CRT_SECURE_NO_WARNINGS",
            f"-fuse-ld={first_on_path('lld-link', 'lld-link-18')}",
            *(arg for path in includes for arg in ("/imsvc", str(path))),
            *map(str, sources), f"/Fe{out}", f"/Fo{out.parent}/",
            "/link", *(f"/libpath:{path}" for path in libraries),
            "/subsystem:console", "/debug:dwarf", "/incremental:no"]


def strip_argv(target: Target, unstripped: Path, stripped: Path) -> list[str]:
    """``strip --strip-all``; a PE is stripped by llvm-strip, which keeps every section's address."""
    tool = first_on_path("llvm-strip", "llvm-strip-18") if target.windows else target.tool("strip")
    return [tool, "--strip-all", "-o", str(stripped), str(unstripped)]


def build(source: Path, compiler: str, opt: str, out_dir: Path,
          target: Target = X86_64) -> Binary:
    where = out_dir / source.stem / target.config(compiler, opt)
    where.mkdir(parents=True, exist_ok=True)
    name = source.stem + (".exe" if target.windows else "")
    unstripped = where / "oracle" / name
    stripped = where / "shown" / name
    unstripped.parent.mkdir(parents=True, exist_ok=True)
    stripped.parent.mkdir(parents=True, exist_ok=True)
    binary = Binary(source, compiler, opt, unstripped, stripped, target=target)
    cc = target.compiler(compiler)
    if shutil.which(cc[0]) is None:
        binary.error = f"{cc[0]} is not installed"
        return binary
    stub = where / "equiv_empty_main.c"
    if target.windows:
        def argv(*extra: Path) -> list[str]:
            return pe_argv(cc, [source, *extra], unstripped, opt)
        no_main = "undefined symbol: main"
    else:
        def argv(*extra: Path) -> list[str]:
            return [*cc, *BUILD_FLAGS, f"-{opt}", str(source), *map(str, extra), "-o",
                    str(unstripped), "-lm"]
        no_main = "undefined reference to `main'"
    proc = subprocess.run(argv(), capture_output=True, text=True, check=False)
    if proc.returncode != 0 and no_main in proc.stderr + proc.stdout:
        stub.write_text(_EMPTY_MAIN, encoding="utf-8")
        proc = subprocess.run(argv(stub), capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        binary.error = "build failed: " + " | ".join((proc.stderr + proc.stdout).splitlines()[:6])
        return binary
    machine = machine_of(unstripped, target)
    if machine != target.elf_machine:
        binary.error = (f"{' '.join(cc)} built for {machine or 'an unknown machine'}, "
                        f"not {target.elf_machine}")
        return binary
    proc = subprocess.run(strip_argv(target, unstripped, stripped),
                          capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        binary.error = "strip failed: " + proc.stderr.strip()[:300]
    return binary


def machine_of(binary: Path, target: Target = X86_64) -> str:
    """What ``binary`` was built for: the ELF machine, or a PE's ``objdump -f`` format."""
    if not target.windows:
        return elf_machine(binary, target)
    proc = subprocess.run([target.tool("objdump"), "-f", str(binary)], capture_output=True,
                          text=True, check=False)
    found = re.search(r"file format (\S+)", proc.stdout)
    return found.group(1) if found else ""


def elf_machine(binary: Path, target: Target = X86_64) -> str:
    """The ELF header's machine, as ``readelf -h`` names it ("" when unreadable)."""
    proc = subprocess.run([target.tool("readelf"), "-h", str(binary)], capture_output=True,
                          text=True, check=False)
    for line in proc.stdout.splitlines():
        name, _, value = line.partition(":")
        if name.strip() == "Machine":
            return value.strip()
    return ""


def build_all(sources: list[Path], compilers: list[str], opts: list[str],
              out_dir: Path, target: Target = X86_64) -> list[Binary]:
    return [build(source, compiler, opt, out_dir, target)
            for source in sources for compiler in compilers for opt in opts]
