"""Compile a rendering into the original image: the link-map shim and the variants.

A rendering's ``pddj`` names every external identifier its code references
(``links``). The shim turns each into what the original image already has at
that address, so the rendering runs against the program it was recovered from
rather than a re-created copy of it:

* a ``function`` becomes a trampoline, ``name: movabs $addr, %r11; jmp *%r11``
  (r11 is scratch and never an argument register, so a variadic callee's AL
  survives);
* an ``object`` becomes an absolute symbol, ``.set name, addr``, so ``&name`` is
  the image's own object and a write through it lands in the image;
* an ``import`` is left undefined and binds to the C library, which is also
  what the original's PLT reaches.

``-Wl,-Bsymbolic`` makes a recursive rendering call itself, and
``-Wl,--no-undefined`` turns an identifier the link map forgot into a link
error that names it.

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

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

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


def shim_source(links: list[dict], definition: str) -> tuple[str, list[str]]:
    """Assembly defining every linked function and object; and what it skipped."""
    lines = ["    .text"]
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
        if kind == "function":
            lines += [
                f"    .globl {ident}",
                f"    .type {ident}, @function",
                f"{ident}:",
                f"    movabs $0x{address:x}, %r11",
                "    jmp *%r11",
            ]
        elif kind == "object":
            lines += [f"    .globl {ident}", f"    .set {ident}, 0x{address:x}"]
    lines.append('    .section .note.GNU-stack,"",@progbits')
    return "\n".join(lines) + "\n", skipped


def trampoline_source(symbol: str, address: int) -> str:
    return (
        "    .text\n"
        f"    .globl {symbol}\n"
        f"    .type {symbol}, @function\n"
        f"{symbol}:\n"
        f"    movabs $0x{address:x}, %r11\n"
        "    jmp *%r11\n"
        '    .section .note.GNU-stack,"",@progbits\n'
    )


def _compile(cc: str, argv: list[str], timeout: float = 120.0) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            [cc, *argv], capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return False, f"{cc} timed out after {timeout:g}s"
    except FileNotFoundError:
        return False, f"{cc} not found"
    diagnostics = (proc.stderr or "") + (proc.stdout or "")
    return proc.returncode == 0, diagnostics.strip()


def build_rendering(cc: str, workdir: Path, code: str, links: list[dict],
                    definition: str) -> tuple[dict[str, Built], str, list[str]]:
    """Compile a rendering four ways; returns the builds, the strict verdict, and skipped links."""
    workdir.mkdir(parents=True, exist_ok=True)
    source = workdir / "rendering.c"
    source.write_text(code, encoding="utf-8")
    shim, skipped = shim_source(links, definition)
    shim_path = workdir / "shim.S"
    shim_path.write_text(shim, encoding="utf-8")
    builds: dict[str, Built] = {}
    for variant, flags in VARIANTS.items():
        out = workdir / f"rendering-{variant}.so"
        ok, diagnostics = _compile(cc, [*COMMON, *flags, str(source), str(shim_path), "-o", str(out)])
        builds[variant] = Built(variant, ok, out, diagnostics)
    ok, diagnostics = _compile(cc, [*STRICT, str(source)])
    strict = "ok" if ok else "fail: " + _first_lines(diagnostics, 6)
    return builds, strict, skipped


def build_trampoline(cc: str, workdir: Path, address: int) -> Built:
    workdir.mkdir(parents=True, exist_ok=True)
    source = workdir / "identity.S"
    source.write_text(trampoline_source("equiv_identity", address), encoding="utf-8")
    out = workdir / "identity.so"
    ok, diagnostics = _compile(cc, ["-shared", "-fPIC", str(source), "-o", str(out)])
    return Built("identity", ok, out, diagnostics)


def build_runtime(cc: str, rt_dir: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "equiv_rt.so"
    sources = [rt_dir / "equiv_rt.c", rt_dir / "call_x86_64.S"]
    if out.exists() and all(out.stat().st_mtime >= s.stat().st_mtime for s in sources):
        return out
    ok, diagnostics = _compile(
        cc, ["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", "-std=gnu11",
             *map(str, sources), "-ldl", "-o", str(out)]
    )
    if not ok:
        raise RuntimeError(f"cannot build the equivalence runtime:\n{diagnostics}")
    return out


def _first_lines(text: str, count: int) -> str:
    return " | ".join(line for line in text.splitlines()[:count] if line.strip())
