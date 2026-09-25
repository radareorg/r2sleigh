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
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

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

    @property
    def config(self) -> str:
        return f"{self.compiler}-{self.opt}"

    @property
    def source_key(self) -> str:
        try:
            return self.source.resolve().relative_to(REPO).as_posix()
        except ValueError:
            return self.source.name


def default_sources() -> list[Path]:
    """``tests/corpus/*.c`` and ``tests/gold/*.c``: every program the repository keeps."""
    found = sorted((REPO / "tests" / "corpus").glob("*.c"))
    found += sorted((REPO / "tests" / "gold").glob("*.c"))
    return found


def build(source: Path, compiler: str, opt: str, out_dir: Path) -> Binary:
    where = out_dir / source.stem / f"{compiler}-{opt}"
    where.mkdir(parents=True, exist_ok=True)
    unstripped = where / "oracle" / source.stem
    stripped = where / "shown" / source.stem
    unstripped.parent.mkdir(parents=True, exist_ok=True)
    stripped.parent.mkdir(parents=True, exist_ok=True)
    binary = Binary(source, compiler, opt, unstripped, stripped)
    if shutil.which(compiler) is None:
        binary.error = f"{compiler} is not installed"
        return binary
    argv = [compiler, *BUILD_FLAGS, f"-{opt}", str(source), "-o", str(unstripped), "-lm"]
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    if proc.returncode != 0 and "undefined reference to `main'" in proc.stderr:
        stub = where / "equiv_empty_main.c"
        stub.write_text(_EMPTY_MAIN, encoding="utf-8")
        argv = [compiler, *BUILD_FLAGS, f"-{opt}", str(source), str(stub), "-o",
                str(unstripped), "-lm"]
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        binary.error = "build failed: " + " | ".join(proc.stderr.splitlines()[:6])
        return binary
    proc = subprocess.run(["strip", "--strip-all", "-o", str(stripped), str(unstripped)],
                          capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        binary.error = "strip failed: " + proc.stderr.strip()[:300]
    return binary


def build_all(sources: list[Path], compilers: list[str], opts: list[str],
              out_dir: Path) -> list[Binary]:
    return [build(source, compiler, opt, out_dir)
            for source in sources for compiler in compilers for opt in opts]
