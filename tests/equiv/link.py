"""Compile a rendering into the original image: the link-map shim and the variants.

A rendering's ``pddj`` names every external identifier its code references
(``links``). The shim turns each into what the original image already has at
that address, so the rendering runs against the program it was recovered from
rather than a re-created copy of it:

* a ``function`` becomes a trampoline, ``name: movabs $addr, %r11; jmp *%r11``
  on x86-64 (r11 is scratch and never an argument register, so a variadic
  callee's AL survives) and ``movz/movk x16, addr; br x16`` on AArch64 (x16 is
  the linker's veneer register, never an argument) -- :class:`target.Assembly`;
* an ``object`` becomes an absolute symbol, ``.set name, addr``, so ``&name`` is
  the image's own object and a write through it lands in the image (on a
  target whose linker cannot keep an absolute symbol absolute, the dynamic
  loader binds it instead: :func:`loader_conflicts`);
* an ``import`` is left undefined and binds to the C library, which is also
  what the original's PLT reaches.

The function being graded is the rendering itself. A ``function`` link to its
entry address (a recursion the rendering spells by the function's name) is a
jump to the rendering's own definition, never to the original; a link to any
other address inside the function's code is refused (:func:`links_into_body`):
it names part of the original, which a rendering may not delegate to.

``-Wl,-Bsymbolic`` makes a recursive rendering call itself, and
``-Wl,--no-undefined`` turns an identifier the link map forgot into a link
error that names it. The rendering links against every library the original
names in its ``DT_NEEDED`` (libm, say), resolved to the files the dynamic
loader would map, so an import the original reaches through one of them binds
the same way here rather than failing as a false compile error.

Each rendering is built four ways. ``O0`` is the one graded against the
original. ``pattern`` differs only in how uninitialised locals start
(``-ftrivial-auto-var-init=pattern`` instead of ``=zero``), so any difference
between the two is a read of a value nothing wrote. ``O2`` differs only in
optimisation, so a difference there is behaviour the compiler was entitled to
change -- undefined behaviour, including a strict-aliasing violation. ``ubsan``
traps on the undefined behaviour UBSan can see. A fifth, strict compile
(``-std=c11 -Wall -Wextra -Werror``) is recorded as evidence and does not
change the status.
"""

from __future__ import annotations

import functools
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from target import X86_64, Target

VARIANTS: dict[str, list[str]] = {
    "O0": ["-O0", "-ftrivial-auto-var-init=zero"],
    "pattern": ["-O0", "-ftrivial-auto-var-init=pattern"],
    "O2": ["-O2", "-ftrivial-auto-var-init=zero"],
    "ubsan": ["-O0", "-ftrivial-auto-var-init=zero", "-fsanitize=undefined",
              "-fno-sanitize-recover=all"],
}
COMMON = ["-shared", "-fPIC", "-std=gnu11", "-g0",
          "-Wl,-Bsymbolic", "-Wl,-z,now", "-Wl,--no-undefined"]
STRICT = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-c", "-o", "/dev/null"]

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass
class Built:
    variant: str
    ok: bool
    path: Path
    diagnostics: str
    # False when the compiler never gave a verdict (it timed out, was not
    # found, or died of a signal): the build failed for the harness, not for
    # the rendering.
    ran: bool = True


def links_into_body(links: list[dict], guard: tuple[int, int]) -> list[str]:
    """Every link naming an address inside the graded function other than its entry."""
    start, end = guard
    found = []
    for entry in links:
        address = entry.get("addr")
        if (entry.get("kind") in ("function", "object") and isinstance(address, int)
                and start < address < end):
            found.append(f"link `{entry.get('ident')}` ({entry.get('kind')}) is 0x{address:x}, "
                         f"inside the function being graded (0x{start:x}..0x{end:x})")
    return found


def _shim_entries(links: list[dict], definition: str
                  ) -> tuple[list[tuple[str, str, int]], list[str]]:
    """``(ident, kind, address)`` of every function and object the shim defines,
    in identifier order; and what it skipped."""
    entries: list[tuple[str, str, int]] = []
    skipped: list[str] = []
    seen: set[str] = set()
    for link in sorted(links, key=lambda item: str(item.get("ident"))):
        ident = str(link.get("ident", ""))
        kind = link.get("kind")
        address = link.get("addr")
        if ident in seen or ident == definition:
            continue
        seen.add(ident)
        if not _IDENT.match(ident):
            skipped.append(f"{ident}: not a C identifier")
            continue
        if kind == "import":
            continue
        if not isinstance(address, int) or address <= 0:
            skipped.append(f"{ident}: no address")
            continue
        if kind in ("function", "object"):
            entries.append((ident, str(kind), address))
    return entries, skipped


def shim_objects(links: list[dict], definition: str) -> list[tuple[str, int]]:
    """``(ident, address)`` of every object the shim defines."""
    return [(ident, address) for ident, kind, address in _shim_entries(links, definition)[0]
            if kind == "object"]


def shim_source(links: list[dict], definition: str, entry: int | None = None,
                target: Target = X86_64) -> tuple[str, list[str]]:
    """Assembly defining every linked function and object; and what it skipped.

    ``entry`` is the graded function's address: a function link there jumps to
    ``definition``.
    """
    lines = ["    .text"]
    entries, skipped = _shim_entries(links, definition)
    for ident, kind, address in entries:
        if kind == "function" and address == entry:
            lines += target.asm.jump_to_symbol(ident, definition)
        elif kind == "function":
            lines += target.asm.jump_to_address(ident, address)
        else:
            lines += [f"    .globl {ident}", f"    .set {ident}, 0x{address:x}"]
    lines.append(target.asm.stack_note())
    return "\n".join(lines) + "\n", skipped


def trampoline_source(symbol: str, address: int, target: Target = X86_64) -> str:
    lines = ["    .text", *target.asm.jump_to_address(symbol, address), target.asm.stack_note()]
    return "\n".join(lines) + "\n"


COMPILE_TIMEOUT = 120.0


def _compile(cc: str, argv: list[str], timeout: float = COMPILE_TIMEOUT,
             cwd: Path | None = None) -> tuple[bool, str, bool]:
    """``(built, diagnostics, ran)``: ``ran`` is False when the compiler gave no verdict."""
    try:
        proc = subprocess.run(
            [cc, *argv], capture_output=True, text=True, timeout=timeout, check=False, cwd=cwd
        )
    except subprocess.TimeoutExpired:
        return False, f"{cc} timed out after {timeout:g}s", False
    except (FileNotFoundError, PermissionError):
        return False, f"{cc} could not be run", False
    diagnostics = (proc.stderr or "") + (proc.stdout or "")
    if proc.returncode < 0:
        return False, f"{cc} was killed by signal {-proc.returncode}: {diagnostics.strip()}", False
    return proc.returncode == 0, diagnostics.strip(), True


@functools.lru_cache(maxsize=None)
def needed_libraries(binary: str, target: Target = X86_64) -> tuple[str, ...]:
    """The link arguments naming each ``DT_NEEDED`` library of ``binary``.

    Each is the file the loader maps (the one the original's own imports bind
    to), or ``-l:<soname>`` when that cannot be said. On the host's own
    machine ``ldd`` says which file; ``ldd`` cannot trace a foreign binary,
    and a target with a sysroot names the file there instead -- the
    directory its runner hands the loader (``qemu -L``).
    """
    dynamic = subprocess.run([target.tool("readelf"), "-d", "-W", binary], capture_output=True,
                             text=True, check=False).stdout
    names = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", dynamic)
    mapped: dict[str, str] = {}
    if target.sysroot is not None:
        for name in names:
            found = target.library(name)
            if found is not None:
                mapped[name] = found
        return tuple(mapped.get(name, f"-l:{name}") for name in names)
    trace = subprocess.run(["ldd", binary], capture_output=True, text=True, check=False).stdout
    for line in trace.splitlines():
        found = re.match(r"\s*(\S+)\s+=>\s+(/\S+)", line)
        if found:
            mapped[found.group(1)] = found.group(2)
    return tuple(mapped.get(name, f"-l:{name}") for name in names)


def build_rendering(cc: str, workdir: Path, code: str, links: list[dict],
                    definition: str, needed: tuple[str, ...] = (), entry: int | None = None,
                    timeout: float = COMPILE_TIMEOUT, target: Target = X86_64
                    ) -> tuple[dict[str, Built], str, list[str]]:
    """Compile a rendering four ways; returns the builds, the strict verdict, and skipped links.

    ``needed`` is what :func:`needed_libraries` says the original links against.

    The compiler runs inside ``workdir`` and is given relative names, so the
    objects it writes do not depend on where the run keeps its files. UBSan
    stores each check's source file name in ``.rodata``. An absolute name would
    move every literal after it by the length of the ``--out`` path, and a
    rendering that reads outside a literal would then be graded differently
    for the same code.
    """
    workdir.mkdir(parents=True, exist_ok=True)
    source = "rendering.c"
    (workdir / source).write_text(code, encoding="utf-8")
    shim, skipped = shim_source(links, definition, entry, target)
    shim_path = "shim.S"
    (workdir / shim_path).write_text(shim, encoding="utf-8")
    loader = []
    objects = shim_objects(links, definition)
    if target.objects_through_loader and objects:
        # Only the object links are left to the loader; every other symbol
        # still binds inside the rendering, as -Bsymbolic says.
        listed = "".join(f" {ident};" for ident, _ in objects)
        (workdir / "objects.list").write_text(f"{{{listed} }};\n", encoding="utf-8")
        loader = ["-Wl,--dynamic-list=objects.list"]
    builds: dict[str, Built] = {}
    for variant, flags in VARIANTS.items():
        out = f"rendering-{variant}.so"
        ok, diagnostics, ran = _compile(cc, [*COMMON, *loader, *flags, source, shim_path,
                                             *needed, "-o", out], timeout, cwd=workdir)
        builds[variant] = Built(variant, ok, workdir / out, diagnostics, ran)
    ok, diagnostics, ran = _compile(cc, [*STRICT, source], timeout, cwd=workdir)
    strict = "ok" if ok else ("fail: " if ran else "not run: ") + _first_lines(diagnostics, 6)
    return builds, strict, skipped


@functools.lru_cache(maxsize=None)
def _dynamic(path: str, target: Target) -> tuple[dict[str, int], tuple[str, ...]]:
    """The symbols ``path`` defines for the dynamic loader, and its ``DT_NEEDED``."""
    tool = target.tool("readelf")
    symbols = subprocess.run([tool, "--dyn-syms", "-W", path], capture_output=True, text=True,
                             check=False).stdout
    defined: dict[str, int] = {}
    for line in symbols.splitlines():
        fields = line.split()
        # Num: Value Size Type Bind Vis Ndx Name
        if len(fields) < 8 or fields[4] not in ("GLOBAL", "WEAK") or fields[6] == "UND":
            continue
        try:
            defined.setdefault(fields[7].split("@", 1)[0], int(fields[1], 16))
        except ValueError:
            continue
    dynamic = subprocess.run([tool, "-d", "-W", path], capture_output=True, text=True,
                             check=False).stdout
    needed = tuple(re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", dynamic))
    return defined, needed


def loader_conflicts(objects: list[tuple[str, int]], binary: str, runtime: str,
                     target: Target) -> list[str]:
    """Every object link the dynamic loader would not bind to its own address.

    On a target whose static linker turns an absolute symbol in a shared
    object into a load-base-relative one (``Target.objects_through_loader``),
    the rendering leaves its object links to the loader, which places an
    ``SHN_ABS`` definition at its value. The loader searches the global scope
    first: the program, the preloaded runtime and the program's libraries. A
    name the program exports binds there, which is the link's own address
    only if the two agree; a name a library exports binds into that library.
    Either would grade the rendering against an object it never named, so
    each is reported instead.
    """
    program, needed = _dynamic(binary, target)
    libraries: dict[str, str] = {}
    pending = [runtime, *(path for name in needed
                          if (path := target.library(name)) is not None)]
    exported: dict[str, str] = {}
    while pending:
        path = pending.pop(0)
        if path in libraries.values():
            continue
        libraries[Path(path).name] = path
        defined, more = _dynamic(path, target)
        for name in defined:
            exported.setdefault(name, Path(path).name)
        pending += [found for name in more if name not in libraries
                    and (found := target.library(name)) is not None]
    conflicts = []
    for ident, address in objects:
        if ident in program and program[ident] != address:
            conflicts.append(f"object link `{ident}` (0x{address:x}) would bind to the "
                             f"program's own `{ident}` at 0x{program[ident]:x}")
        elif ident not in program and ident in exported:
            conflicts.append(f"object link `{ident}` (0x{address:x}) would bind to "
                             f"`{ident}` of {exported[ident]}")
    return conflicts


RESIDUAL_PREFIX = "r2sleigh_residual_"


def residual_helpers(shared_object: Path, target: Target = X86_64) -> list[tuple[int, int, str]]:
    """``(start, end, name)`` of every ``r2sleigh_residual_*`` function the object defines.

    Offsets are from the object's load base (a shared object is linked at 0),
    read from its own ``.symtab``: an unoptimised build keeps each
    ``static inline`` helper as a local function of its own.
    """
    proc = subprocess.run([target.tool("nm"), "-S", "--defined-only", str(shared_object)],
                          capture_output=True, text=True, check=False)
    found: list[tuple[int, int, str]] = []
    for line in proc.stdout.splitlines():
        fields = line.split()
        if len(fields) != 4 or fields[2] not in "tT" or not fields[3].startswith(RESIDUAL_PREFIX):
            continue
        try:
            start, size = int(fields[0], 16), int(fields[1], 16)
        except ValueError:
            continue
        found.append((start, start + size, fields[3]))
    return sorted(found)


def build_trampoline(cc: str, workdir: Path, address: int, target: Target = X86_64) -> Built:
    workdir.mkdir(parents=True, exist_ok=True)
    source = workdir / "identity.S"
    source.write_text(trampoline_source("equiv_identity", address, target), encoding="utf-8")
    out = workdir / "identity.so"
    ok, diagnostics, ran = _compile(cc, ["-shared", "-fPIC", str(source), "-o", str(out)])
    return Built("identity", ok, out, diagnostics, ran)


def build_runtime(cc: str, rt_dir: Path, out_dir: Path, target: Target = X86_64) -> Path:
    """The runtime for ``target``: ``equiv_rt.c`` and the target's thunk.

    ``out_dir`` must be the target's own (:meth:`target.Target.directory`):
    the build is reused while it is newer than its sources.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "equiv_rt.so"
    sources = [rt_dir / "equiv_rt.c", target.call_asm]
    if out.exists() and all(out.stat().st_mtime >= s.stat().st_mtime for s in sources):
        return out
    ok, diagnostics, _ = _compile(
        cc, ["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", "-std=gnu11",
             *map(str, sources), "-ldl", "-o", str(out)]
    )
    if not ok:
        raise RuntimeError(f"cannot build the equivalence runtime:\n{diagnostics}")
    return out


def _first_lines(text: str, count: int) -> str:
    return " | ".join(line for line in text.splitlines()[:count] if line.strip())
