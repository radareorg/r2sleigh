#!/usr/bin/env python3
"""Counts the runs of more than two `//` lines, and fails a change that adds or lengthens one (AGENTS.md, Comments).

A run is consecutive lines whose first non-blank characters are `//`, which takes in `///` and `//!`.
`--count` is what `scripts/structure-report.sh` ratchets; it only falls. `--base` reads the change itself,
because a run lengthened from three lines to four moves no count: a run of the head fails when it is
longer than every run of the base it keeps a line of, so an edit inside a long run or a shortening passes.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from typing import NamedTuple

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOTS = ("crates", "tools")
LONG = 3
COMMENT = re.compile(rb"^\s*//")
HUNK = re.compile(rb"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def in_scope(path: str) -> bool:
    """A Rust source under `crates` or `tools`, outside any build directory: the files the ratchet counts."""
    parts = path.split("/")
    return path.endswith(".rs") and parts[0] in ROOTS and "target" not in parts[:-1]


def lines_of(data: bytes) -> list[bytes]:
    """Split on newlines alone, as the ratchet's awk does; `splitlines` also breaks on form feeds."""
    return data.split(b"\n")


def spans(lines: Sequence[bytes]) -> list[tuple[int, int]]:
    """The maximal runs of comment lines, as half-open index ranges."""
    runs: list[tuple[int, int]] = []
    start = None
    for index, line in enumerate(lines):
        if COMMENT.match(line):
            start = index if start is None else start
        elif start is not None:
            runs.append((start, index))
            start = None
    if start is not None:
        runs.append((start, len(lines)))
    return runs


def long_runs(lines: Sequence[bytes]) -> int:
    """How many runs of more than two comment lines the file holds."""
    return sum(1 for start, end in spans(lines) if end - start >= LONG)


def count(roots: Iterable[str]) -> int:
    """The runs of more than two comment lines under `roots`, build directories left out."""
    total = 0
    for root in roots:
        for directory, names, files in os.walk(root):
            names[:] = [name for name in names if name != "target"]
            for file in files:
                if file.endswith(".rs"):
                    with open(os.path.join(directory, file), "rb") as source:
                        total += long_runs(lines_of(source.read()))
    return total


class Hunk(NamedTuple):
    """One `-U0` hunk, as the index of the first line it covers on each side."""

    old_first: int
    old_count: int
    new_first: int
    new_count: int


class Run(NamedTuple):
    """A run of the head that grew: its first and last line (1-based), its length, and the base's."""

    first: int
    last: int
    length: int
    was: int


def parse_hunks(diff: bytes) -> list[Hunk]:
    hunks = []
    for line in diff.split(b"\n"):
        found = HUNK.match(line)
        if found:
            old_start, old_count = int(found[1]), 1 if found[2] is None else int(found[2])
            new_start, new_count = int(found[3]), 1 if found[4] is None else int(found[4])
            # A side with no lines names the line before the gap; the others name their first line.
            hunks.append(
                Hunk(
                    old_start - 1 if old_count else old_start,
                    old_count,
                    new_start - 1 if new_count else new_start,
                    new_count,
                )
            )
    return hunks


def kept_from(hunks: Sequence[Hunk], head_len: int) -> list[int | None]:
    """For each line of the head, the line of the base it is unchanged from, or None where the change wrote it."""
    base_of: list[int | None] = [None] * head_len
    old = new = 0
    for hunk in hunks:
        for step in range(max(hunk.new_first - new, 0)):
            if new + step < head_len:
                base_of[new + step] = old + step
        old, new = hunk.old_first + hunk.old_count, hunk.new_first + hunk.new_count
    for step in range(max(head_len - new, 0)):
        base_of[new + step] = old + step
    return base_of


def lengthened(base: Sequence[bytes], head: Sequence[bytes], hunks: Sequence[Hunk]) -> list[Run]:
    """The runs of more than two lines in `head` that exceed every run of `base` they keep a line of."""
    run_of = {line: end - start for start, end in spans(base) for line in range(start, end)}
    base_of = kept_from(hunks, len(head))
    grown = []
    for start, end in spans(head):
        length = end - start
        was = max((run_of.get(base_of[line], 0) for line in range(start, end) if base_of[line] is not None), default=0)
        if length >= LONG and length > was:
            grown.append(Run(start + 1, end, length, was))
    return grown


def git(*args: str) -> bytes:
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


def changed(fork: str, head: str) -> list[tuple[str | None, str]]:
    """The (base path, head path) of every added, modified or renamed file; the base path is None for an added one."""
    fields = git("diff", "--name-status", "-z", "-M", "--diff-filter=AMR", fork, head).decode().split("\0")
    files: list[tuple[str | None, str]] = []
    index = 0
    while index + 1 < len(fields):
        status = fields[index]
        if status.startswith("R"):
            files.append((fields[index + 1], fields[index + 2]))
            index += 3
        else:
            files.append((None if status == "A" else fields[index + 1], fields[index + 1]))
            index += 2
    return files


def grown_runs(base: str, head: str) -> dict[str, list[Run]]:
    """Every run of more than two comment lines the change since `head` left `base` adds or lengthens, by file."""
    fork = git("merge-base", base, head).decode().strip()
    found = {}
    for old, new in changed(fork, head):
        if not in_scope(new):
            continue
        lines = lines_of(git("show", f"{head}:{new}"))
        if old is None:
            before, hunks = [], [Hunk(0, 0, 0, len(lines))]
        else:
            before = lines_of(git("show", f"{fork}:{old}"))
            hunks = parse_hunks(git("diff", "-U0", "--minimal", "--no-color", f"{fork}:{old}", f"{head}:{new}"))
        runs = lengthened(before, lines, hunks)
        if runs:
            found[new] = runs
    return found


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--count", action="store_true", help="print the runs of more than two lines under crates and tools")
    mode.add_argument("--base", help="the commit the change is graded against")
    parser.add_argument("--head", default="HEAD")
    args = parser.parse_args(argv)
    if args.count:
        print(count(os.path.join(REPO, root) for root in ROOTS))
        return 0
    found = grown_runs(args.base, args.head)
    if not found:
        print("comment runs: the change adds or lengthens no run of more than two `//` lines")
        return 0
    print("The change adds or lengthens a run of more than two `//` lines (AGENTS.md, Comments):")
    for path, runs in sorted(found.items()):
        for run in runs:
            print(f"  {path}:{run.first}-{run.last}  {run.length} lines (the run it grew from: {run.was})")
            if os.environ.get("GITHUB_ACTIONS"):
                print(f"::error file={path},line={run.first},endLine={run.last}::{run.length} comment lines in a row")
    print("A comment is one or two lines: what the code cannot say, the invariant or the reason.")
    print("Move design, derivations and measurements to doc/adr-*.md and link it.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
