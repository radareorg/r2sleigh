"""Every rendering of one binary, the way the benchmark asks for it.

The local censuses (``compile_census.py``, ``byte_match_census.py``) measure
what DecBench would measure, so they ask the way its official driver does: r2s
is shown a ``strip --strip-all`` copy and asked ``pddj`` at each function's
address. The addresses and the source names come from the file the caller
gave -- its DWARF when it has one, its symbol table otherwise -- and only for a
binary that is already stripped from ``afl``, the engine's own discovery.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "equiv"))

from dwarf import Dwarf, function_symbols  # noqa: E402
from r2s_batch import Answer, run_batch  # noqa: E402

REPO = HERE.parents[1]
DEFAULT_R2S = REPO / "target" / "release" / "r2s"
# Runtime scaffolding a linker adds; never a source function.
CRT = frozenset({
    "_start", "_init", "_fini", "deregister_tm_clones", "register_tm_clones",
    "__do_global_dtors_aux", "frame_dummy", "_dl_relocate_static_pie", "__libc_csu_init",
    "__libc_csu_fini",
})


@dataclass
class Rendering:
    name: str | None
    address: int
    answer: Answer


def section_names(binary: Path) -> set[str]:
    proc = subprocess.run(["readelf", "-SW", str(binary)], capture_output=True, text=True,
                          check=False)
    names = set()
    for line in proc.stdout.splitlines():
        if "]" in line:
            fields = line.split("]", 1)[1].split()
            if fields:
                names.add(fields[0])
    return names


def targets(binary: Path) -> list[tuple[str, int]] | None:
    """``(name, address)`` from the file's own DWARF or symbols; None when it has neither."""
    sections = section_names(binary)
    if ".debug_info" in sections:
        found = [(s.name, s.low_pc) for s in Dwarf.read(binary).subprograms() if s.name]
        seen: set[int] = set()
        return [(n, a) for n, a in found if not (a in seen or seen.add(a))]
    if ".symtab" in sections:
        return sorted(
            ((names[0], address) for address, (names, size) in function_symbols(binary).items()
             if size > 0 and names[0] not in CRT),
            key=lambda item: item[1],
        )
    return None


def afl(r2s: Path, binary: Path) -> list[tuple[str, int]]:
    proc = subprocess.run([str(r2s), "-q", "-c", "afl", str(binary)], capture_output=True,
                          text=True, check=False)
    found = []
    for line in proc.stdout.splitlines():
        fields = line.split()
        if fields and fields[0].startswith("0x"):
            name = fields[-1]
            if name not in CRT and not name.startswith(("sym.imp.", "entry")):
                found.append((name, int(fields[0], 16)))
    return found


def render_binary(binary: Path, r2s: Path, function_timeout: float = 300.0,
                  limit: int = 0) -> list[Rendering]:
    wanted = targets(binary)
    from_file = wanted is not None
    with tempfile.TemporaryDirectory(prefix="r2sleigh-census-") as tmp:
        shown = binary
        if wanted is not None:
            shown = Path(tmp) / binary.name
            shutil.copyfile(binary, shown)
            subprocess.run(["strip", "--strip-all", str(shown)], check=True,
                           capture_output=True)
        else:
            wanted = afl(r2s, binary)
        if limit:
            wanted = wanted[:limit]
        report = run_batch(r2s, shown, [address for _, address in wanted],
                           function_timeout=function_timeout)
    answers = report.by_address()
    # A name from afl is the engine's own, not the source's: it names nothing.
    return [Rendering(name if from_file else None, address, answers[address])
            for name, address in wanted]
