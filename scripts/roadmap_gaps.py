#!/usr/bin/env python3
"""The gap table's gate (ROADMAP "Gap rows", D349).

Every citation `G1` to `G99` in ROADMAP.md and doc/adr-*.md reads "gap G<n>" and resolves to one row of the table.
A row names one owner and one state from a closed set, and the state agrees with the D-rows the row names:

    closed      every named D-row exists, its text says built, landed, done or measured, and its last cell says no open
    open        some named D-row is not closed yet
    refused     a named D-row's text says refused
    planned     no D-row is named yet, and the rows cell names the slice (`S34 step 1`)
    not sliced  the rows cell is `none`

`G0` is the roadmap item and doc/debugger.md's phases are outside the glob. O(lines). Exit 1 lists each failure.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GAP = re.compile(r"(?<![\w.])G([1-9]\d?)(?![\w.])")
CITED = re.compile(r"\bgap G[1-9]\d?(?![\w.])", re.IGNORECASE)
D_ROW = re.compile(r"\bD(\d+)\b")
DONE = re.compile(r"\b(built|landed|done|measured)\b", re.IGNORECASE)
OPEN = re.compile(r"\bopen\b", re.IGNORECASE)
REFUSED = re.compile(r"\brefused\b", re.IGNORECASE)
STATES = ("closed", "open", "refused", "planned", "not sliced")
SLICE = re.compile(r"\bS\d+[a-z]?\b")
HEADER = "| Gap | Fact | Owner | Rows | Gate | State |"


@dataclass(frozen=True)
class Gap:
    number: int
    owner: str
    rows: tuple[int, ...]
    slice: str
    state: str
    line: int


def cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split(" | ")]


def read_table(lines: list[str]) -> tuple[dict[int, Gap], set[int], list[str]]:
    """The gap rows, the table's line numbers, and each malformed row."""
    gaps: dict[int, Gap] = {}
    table: set[int] = set()
    failures = []
    try:
        start = lines.index(HEADER)
    except ValueError:
        return gaps, table, [f"ROADMAP.md: no gap table (`{HEADER}`)"]
    for number in range(start, len(lines)):
        line = lines[number]
        if not line.startswith("|"):
            break
        table.add(number)
        if number < start + 2:
            continue
        row = cells(line)
        found = re.fullmatch(r"G([1-9]\d?)", row[0])
        if len(row) != 6 or not found:
            failures.append(f"ROADMAP.md:{number + 1}: not `| G<n> | fact | owner | rows | gate | state |`")
            continue
        gap = Gap(int(found.group(1)), row[2], tuple(int(d) for d in D_ROW.findall(row[3])), row[3], row[5],
                  number + 1)
        if gap.number in gaps:
            failures.append(f"ROADMAP.md:{gap.line}: G{gap.number} has two rows")
        if not gap.owner or re.search(r"[,;]| and ", gap.owner):
            failures.append(f"ROADMAP.md:{gap.line}: G{gap.number} names one owner, not `{gap.owner}`")
        if gap.state not in STATES:
            failures.append(f"ROADMAP.md:{gap.line}: G{gap.number} state `{gap.state}` is none of {', '.join(STATES)}")
        gaps[gap.number] = gap
    return gaps, table, failures


def d_rows(lines: list[str]) -> dict[int, str]:
    """Each D-row's text; a number with two rows keeps both."""
    rows: dict[int, str] = {}
    for line in lines:
        found = re.match(r"\| D(\d+) \|", line)
        if found:
            rows[int(found.group(1))] = rows.get(int(found.group(1)), "") + line + "\n"
    return rows


def built(text: str) -> bool:
    """Default-deny: a row is built only where it says so and its state cell leaves nothing open."""
    return bool(DONE.search(text)) and all(not OPEN.search(cells(line)[-1]) for line in text.splitlines() if line)


def judge_state(gap: Gap, rows: dict[int, str]) -> str | None:
    """The failure of a row whose state its D-rows contradict, else None."""
    if not gap.rows:
        if gap.slice == "none":
            return None if gap.state == "not sliced" else f"G{gap.number} names no slice, so it is `not sliced`"
        if SLICE.search(gap.slice):
            return None if gap.state == "planned" else f"G{gap.number} names a slice and no D-row, so it is `planned`"
        return f"G{gap.number} rows cell names no D-row, no slice and is not `none`"
    if gap.state in ("planned", "not sliced"):
        return f"G{gap.number} names D-rows, so it is closed, open or refused"
    if gap.state == "refused":
        if any(REFUSED.search(rows.get(d, "")) for d in gap.rows):
            return None
        return f"G{gap.number} is refused, but no named D-row says refused"
    unbuilt = [f"D{d}" for d in gap.rows if not built(rows.get(d, ""))]
    if gap.state == "closed" and unbuilt:
        return f"G{gap.number} is closed, but {', '.join(unbuilt)} is not built"
    if gap.state == "open" and not unbuilt:
        return f"G{gap.number} is open, but every named D-row is built: close it"
    return None


def citations(path: Path, lines: list[str], skip: set[int], gaps: dict[int, Gap]) -> list[str]:
    failures = []
    for number, line in enumerate(lines):
        if number in skip:
            continue
        cited = {m.start() + m.group(0).rindex("G") for m in CITED.finditer(line)}
        for found in GAP.finditer(line):
            where = f"{path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}:{number + 1}"
            if int(found.group(1)) not in gaps:
                failures.append(f"{where}: {found.group(0)} has no row in the gap table")
            elif found.start() not in cited:
                failures.append(f"{where}: cite {found.group(0)} as `gap {found.group(0)}`")
    return failures


def check(root: Path) -> list[str]:
    roadmap = (root / "ROADMAP.md").read_text().splitlines()
    gaps, table, failures = read_table(roadmap)
    rows = d_rows(roadmap)
    failures += [f"ROADMAP.md:{gap.line}: {why}" for gap in gaps.values() if (why := judge_state(gap, rows))]
    failures += citations(root / "ROADMAP.md", roadmap, table, gaps)
    for path in sorted((root / "doc").glob("adr-*.md")):
        failures += citations(path, path.read_text().splitlines(), set(), gaps)
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    failures = check(args.root)
    for failure in failures:
        print(failure, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
