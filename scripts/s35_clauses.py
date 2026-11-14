#!/usr/bin/env python3
"""The counting halves of S35's gate clauses (ROADMAP D277), each run base against head.

    s35_clauses.py seventh --r2s R2S [--census tests/db/census]
        D163: every census golden whose expected output calls `__libc_start_main` is rerun; the reason its call gap
        prints is listed. Fails where a reason is `import-unplaced` or the call no longer gaps (the golden moved).
    s35_clauses.py sweep {tail,win64} --r2s BASE --r2s HEAD BINARY...
        3.7.3 (`tail`): `TailTransferNotRendered` gaps per function, base and head; fails where head has more.
        D210 (`win64`): `import-unplaced` gaps per function; fails where head has any.
    s35_clauses.py probes --r2s R2S BINARY
        D209: every function of an aarch64 build of tests/gold/s35/probes.c; fails on a `int8_t *` or `int32_t *`.
    s35_clauses.py named-type BASE.jsonl HEAD.jsonl
        D167: `fp:library_named_type` verdicts in `tests/decbench/type_causes.py collect` rows; fails unless head falls.

The engine-test halves (D163's seventh, D209's probes, W11's arm64 floats) are r2engine's. O(functions) per side.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWEEP = ROOT / "tests" / "coverage" / "sweep_binary.sh"
START_GAP = re.compile(r"call to __libc_start_main: (.*?) \*/")
UNPLACED = "declaration has an argument this convention does not place"
SIGNED_POINTER = re.compile(r"(?<![\w])int(8|32)_t\s*\*")
PATTERNS = {"tail": "r2dec gap: TailTransferNotRendered", "win64": UNPLACED}
BEGIN = "R2SLEIGH_COV_BEGIN__"
END = "R2SLEIGH_COV_END__"


@dataclass(frozen=True)
class Golden:
    path: Path
    name: str
    file: str
    cmds: str


def goldens(census: Path, needle: str) -> list[Golden]:
    """The r2r tests of `census` whose EXPECT block holds `needle`, in file order."""
    found = []
    for path in sorted(census.iterdir()):
        test: dict[str, str] = {}
        expect: list[str] | None = None
        for line in path.read_text(errors="replace").splitlines():
            if expect is not None:
                if line == "EOF":
                    test["EXPECT"], expect = "\n".join(expect), None
                else:
                    expect.append(line)
            elif line == "EXPECT=<<EOF":
                expect = []
            elif line == "RUN":
                if needle in test.get("EXPECT", ""):
                    found.append(Golden(path, test.get("NAME", "?"), test.get("FILE", ""), test.get("CMDS", "")))
                test = {}
            elif "=" in line and not line.startswith("#"):
                key, _, value = line.partition("=")
                test[key] = value
    return found


def seventh(r2s: str, census: Path) -> int:
    failures = 0
    for test in goldens(census, "call to __libc_start_main"):
        out = subprocess.run([r2s, "-q", "-c", test.cmds, str(ROOT / test.file)], capture_output=True, text=True,
                             check=False, cwd=ROOT).stdout
        found = START_GAP.search(out)
        reason = found.group(1) if found else "no gap"
        bad = found is None or UNPLACED in reason
        failures += bad
        index = "names its argument" if re.search(r"\bargument \d+\b|\barg\d+\b", reason) else "names no argument"
        print(f"{'FAIL' if bad else 'ok  '} {test.path.name} {test.name}: {reason} ({index})")
    return 1 if failures else 0


def sweep_counts(r2s: str, binary: Path, pattern: str) -> collections.Counter:
    """Gap lines matching `pattern` per function `sweep_binary.sh` rendered."""
    out = subprocess.run(["bash", str(SWEEP), str(binary)], capture_output=True, text=True, check=False,
                         env={**os.environ, "R2SLEIGH_R2S": r2s}).stdout
    counts: collections.Counter = collections.Counter()
    function = None
    for line in out.splitlines():
        if line.startswith(BEGIN):
            function = line[len(BEGIN):]
        elif line.startswith(END):
            function = None
        elif function is not None and pattern in line:
            counts[function] += 1
    return counts


def sweep(clause: str, sides: list[str], binaries: list[Path]) -> int:
    if len(sides) != 2:
        print("give --r2s twice: base, then head", file=sys.stderr)
        return 2
    totals = [0, 0]
    for binary in binaries:
        base, head = (sweep_counts(r2s, binary, PATTERNS[clause]) for r2s in sides)
        totals[0] += sum(base.values())
        totals[1] += sum(head.values())
        print(f"{binary}: base {sum(base.values())}, head {sum(head.values())}")
        for function in sorted(set(base) | set(head)):
            print(f"  {function}: {base[function]} to {head[function]}")
    print(f"total: base {totals[0]}, head {totals[1]}")
    worse = totals[1] > 0 if clause == "win64" else totals[1] > totals[0]
    return 1 if worse else 0


def probes(r2s: str, binary: Path) -> int:
    out = subprocess.run(["bash", str(SWEEP), str(binary)], capture_output=True, text=True, check=False,
                         env={**os.environ, "R2SLEIGH_R2S": r2s}).stdout
    found = [line.strip() for line in out.splitlines() if SIGNED_POINTER.search(line)]
    for line in found:
        print(line)
    print(f"{len(found)} lines spell int8_t* or int32_t*")
    return 1 if found else 0


def named_type(base: Path, head: Path) -> int:
    def count(path: Path) -> int:
        return sum(json.loads(line).get("verdict") == "fp:library_named_type"
                   for line in path.read_text().splitlines() if line.strip())
    before, after = count(base), count(head)
    print(f"library_named_type: base {before}, head {after}")
    return 0 if after < before else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="clause", required=True)
    one = sub.add_parser("seventh")
    one.add_argument("--r2s", required=True)
    one.add_argument("--census", type=Path, default=ROOT / "tests" / "db" / "census")
    two = sub.add_parser("sweep")
    two.add_argument("kind", choices=sorted(PATTERNS))
    two.add_argument("--r2s", action="append", required=True)
    two.add_argument("binaries", nargs="+", type=Path)
    four = sub.add_parser("probes")
    four.add_argument("--r2s", required=True)
    four.add_argument("binary", type=Path)
    three = sub.add_parser("named-type")
    three.add_argument("base", type=Path)
    three.add_argument("head", type=Path)
    args = parser.parse_args(argv)
    if args.clause == "seventh":
        return seventh(args.r2s, args.census)
    if args.clause == "sweep":
        return sweep(args.kind, args.r2s, args.binaries)
    if args.clause == "probes":
        return probes(args.r2s, args.binary)
    return named_type(args.base, args.head)


if __name__ == "__main__":
    sys.exit(main())
