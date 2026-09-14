#!/usr/bin/env python3
"""Compile every rendering in a control census and report what did not build.

DecBench scores `byte_match` by recompiling the rendered C and comparing the
assembly, so a rendering the compiler rejects scores zero however good it is.
The benchmark's own result record never says which ones those were -- its
`compiles` field is empty on every function -- so a rendering that is wrong and
one that never built are indistinguishable in the numbers.

This runs the same question locally against the output of
`tests/corpus/control_census.sh`, which is the one place a full binary's worth
of renderings is already on disk.

    tests/decbench/compile_census.py <census-dir-or-file> [...]

Each rendering is compiled on its own, with `stdint.h` ahead of it and warnings
silenced, because the question is whether the translation unit is well formed
and not whether a compiler would complain about it. Failures are grouped by the
compiler's own first message.
"""

from __future__ import annotations

import argparse
import collections
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# The census writes two certificate lines above each rendering; everything from
# the first line that is neither of those down to the closing brace is the C.
_CERTIFICATE = re.compile(r"^(control-certificate|register-identity) ")
_REFUSED = "r2sleigh refused"

# Silenced deliberately. An old GCC accepts a `char *` passed to a `uint64_t`
# parameter with a warning and the ABI is unaffected on a 64-bit target, so
# treating it as a failure here would measure the compiler's era rather than
# the rendering. What is left is a translation unit that genuinely will not
# build.
_LENIENT = (
    "-std=gnu11",
    "-w",
    "-Wno-error=int-conversion",
    "-Wno-error=incompatible-pointer-types",
    "-Wno-error=implicit-function-declaration",
    "-Wno-error=incompatible-pointer-types-discards-qualifiers",
    "-Wno-error=return-type",
)

_PROLOGUE = "#include <stdint.h>\n"


def renderings(text: str) -> list[tuple[str, str]]:
    """Every `(marker, C source)` pair a census file holds."""
    found: list[tuple[str, str]] = []
    for block in text.split("==MARK ")[1:]:
        lines = block.splitlines()
        marker = lines[0].strip() if lines else "?"
        if any(_REFUSED in line for line in lines):
            continue
        start = next(
            (
                index
                for index, line in enumerate(lines[1:], start=1)
                if line.strip() and not _CERTIFICATE.match(line)
            ),
            None,
        )
        if start is None:
            continue
        closes = [index for index, line in enumerate(lines) if line.rstrip() == "}"]
        if not closes or closes[-1] <= start:
            continue
        found.append((marker, "\n".join(lines[start : closes[-1] + 1])))
    return found


def first_error(stderr: str) -> str:
    """The compiler's first message, with its quoted names generalised."""
    for line in stderr.splitlines():
        match = re.search(r"error: (.*?)(\s*\[|$)", line)
        if match:
            return re.sub(r"'[^']*'", "'X'", match.group(1)).strip()
    return "failed without naming an error"


def compile_one(source: str, compiler: str) -> str | None:
    """``None`` when it built, else the first error."""
    handle = tempfile.NamedTemporaryFile("w", suffix=".c", delete=False)
    try:
        handle.write(_PROLOGUE + source + "\n")
        handle.close()
        run = subprocess.run(
            [compiler, "-c", "-O0", "-o", os.devnull, handle.name, *_LENIENT],
            capture_output=True,
            text=True,
        )
    finally:
        os.unlink(handle.name)
    return None if run.returncode == 0 else first_error(run.stderr)


def census_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        files.extend(sorted(path.glob("*.txt")) if path.is_dir() else [path])
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="census directories or files")
    parser.add_argument("--compiler", default=os.environ.get("CC", "cc"))
    parser.add_argument(
        "--limit", type=int, default=0, help="stop after this many renderings"
    )
    parser.add_argument(
        "--show", type=int, default=0, help="print this many failing markers per cause"
    )
    args = parser.parse_args()

    causes: collections.Counter[str] = collections.Counter()
    examples: dict[str, list[str]] = collections.defaultdict(list)
    total = failed = 0
    for path in census_files(args.paths):
        for marker, source in renderings(path.read_text(errors="ignore")):
            if args.limit and total >= args.limit:
                break
            total += 1
            error = compile_one(source, args.compiler)
            if error is None:
                continue
            failed += 1
            causes[error] += 1
            if len(examples[error]) < max(args.show, 1):
                examples[error].append(f"{path.name} {marker}")

    if not total:
        print("no renderings found", file=sys.stderr)
        return 70
    print(f"renderings {total} built {total - failed} failed {failed} "
          f"({failed / total:.1%})")
    for cause, count in causes.most_common():
        print(f"  {count:5d}  {cause}")
        for example in examples[cause][: args.show]:
            print(f"           {example}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
