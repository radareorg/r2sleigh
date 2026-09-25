#!/usr/bin/env python3
"""Compile every rendering of a binary on its own, and report what did not build.

DecBench scores ``byte_match`` by recompiling the rendered C, so a rendering
the compiler rejects scores zero however good it is, and the benchmark's own
record never says which ones those were. ``pddj`` prints a self-contained
translation unit (its headers, the helpers it uses, its residual declaration,
its externs), so each one is compiled exactly as printed, with nothing
prepended:

    tests/decbench/compile_census.py <binary> [...] [--r2s target/release/r2s]

* ``builds``: ``-std=gnu11 -c`` with every warning off except
  ``implicit-function-declaration``, which stays an error -- a call to a helper
  the rendering does not define means the unit is not self-contained;
* ``strict``: ``-std=c11 -O2 -Wall -Wextra -Werror -c``, the bar the plan sets
  for every rendering.

Failures are grouped by the compiler's first message with its quoted names
generalised. r2s is shown a ``strip --strip-all`` copy (``renderings.py``).
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from renderings import DEFAULT_R2S, render_binary  # noqa: E402

BUILDS = ("-std=gnu11", "-O0", "-w", "-Werror=implicit-function-declaration", "-c")
STRICT = ("-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-c")


def first_error(stderr: str) -> str:
    """The compiler's first message, with its quoted names generalised."""
    for line in stderr.splitlines():
        match = re.search(r"error: (.*?)(\s*\[|$)", line)
        if match:
            return re.sub(r"'[^']*'", "'X'", match.group(1)).strip()
    return "failed without naming an error"


def compile_one(code: str, compiler: str, flags: tuple[str, ...]) -> str | None:
    """``None`` when it built, else the first error."""
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as handle:
        handle.write(code)
        path = handle.name
    try:
        run = subprocess.run([compiler, *flags, "-o", os.devnull, path],
                             capture_output=True, text=True, check=False)
    finally:
        os.unlink(path)
    return None if run.returncode == 0 else first_error(run.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("binaries", nargs="+", type=Path)
    parser.add_argument("--r2s", type=Path, default=DEFAULT_R2S)
    parser.add_argument("--compiler", default=os.environ.get("CC", "cc"))
    parser.add_argument("--limit", type=int, default=0, help="functions per binary")
    parser.add_argument("--show", type=int, default=3, help="examples per failure cause")
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()

    totals = collections.Counter()
    declines: collections.Counter[str] = collections.Counter()
    causes: dict[str, collections.Counter[str]] = {
        "builds": collections.Counter(), "strict": collections.Counter()}
    examples: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    rows = []
    for binary in args.binaries:
        for rendering in render_binary(binary, args.r2s, limit=args.limit):
            where = f"{binary.name}@0x{rendering.address:x}" + (
                f" ({rendering.name})" if rendering.name else "")
            totals["asked"] += 1
            answer = rendering.answer
            if not answer.ok or answer.record is None:
                totals["declined"] += 1
                declines[answer.cause] += 1
                rows.append({"function": where, "declined": answer.cause})
                continue
            totals["rendered"] += 1
            code = str(answer.record.get("code", ""))
            row = {"function": where}
            for tier, flags in (("builds", BUILDS), ("strict", STRICT)):
                error = compile_one(code, args.compiler, flags)
                row[tier] = error or "ok"
                if error is None:
                    totals[tier] += 1
                    continue
                causes[tier][error] += 1
                if len(examples[(tier, error)]) < args.show:
                    examples[(tier, error)].append(where)
            rows.append(row)

    if not totals["asked"]:
        print("no function was asked", file=sys.stderr)
        return 70
    rendered = totals["rendered"]
    print(f"asked {totals['asked']}  rendered {rendered}  declined {totals['declined']}")
    if rendered:
        print(f"builds {totals['builds']}/{rendered}  strict {totals['strict']}/{rendered}")
    for tier in ("builds", "strict"):
        for cause, count in causes[tier].most_common():
            print(f"  {tier:6} {count:5d}  {cause}")
            for example in examples[(tier, cause)]:
                print(f"                {example}")
    for cause, count in declines.most_common(10):
        print(f"  declined {count:5d}  {cause[:160]}")
    if args.json:
        args.json.write_text(json.dumps({"totals": dict(totals), "functions": rows}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
