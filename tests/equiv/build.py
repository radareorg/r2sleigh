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
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from target import X86_64, Target

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


def build(source: Path, compiler: str, opt: str, out_dir: Path,
          target: Target = X86_64) -> Binary:
    where = out_dir / source.stem / target.config(compiler, opt)
    where.mkdir(parents=True, exist_ok=True)
    unstripped = where / "oracle" / source.stem
    stripped = where / "shown" / source.stem
    unstripped.parent.mkdir(parents=True, exist_ok=True)
    stripped.parent.mkdir(parents=True, exist_ok=True)
    binary = Binary(source, compiler, opt, unstripped, stripped, target=target)
    cc = target.compiler(compiler)
    if shutil.which(cc[0]) is None:
        binary.error = f"{cc[0]} is not installed"
        return binary
    argv = [*cc, *BUILD_FLAGS, f"-{opt}", str(source), "-o", str(unstripped), "-lm"]
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    if proc.returncode != 0 and "undefined reference to `main'" in proc.stderr:
        stub = where / "equiv_empty_main.c"
        stub.write_text(_EMPTY_MAIN, encoding="utf-8")
        argv = [*cc, *BUILD_FLAGS, f"-{opt}", str(source), str(stub), "-o",
                str(unstripped), "-lm"]
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        binary.error = "build failed: " + " | ".join(proc.stderr.splitlines()[:6])
        return binary
    machine = elf_machine(unstripped, target)
    if machine != target.elf_machine:
        binary.error = (f"{' '.join(cc)} built for {machine or 'an unknown machine'}, "
                        f"not {target.elf_machine}")
        return binary
    proc = subprocess.run([target.tool("strip"), "--strip-all", "-o", str(stripped),
                           str(unstripped)],
                          capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        binary.error = "strip failed: " + proc.stderr.strip()[:300]
    return binary


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
