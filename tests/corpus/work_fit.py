#!/usr/bin/env python3
"""Fit counted work against the body it was given.

The engine's deadline is wall clock, so the same binary refuses different
functions on a loaded machine and a census cannot be reproduced. `work=` counts
the same thing deterministically: one unit per cooperative poll. A bound over
that count is reproducible, but only if the count is predictable from the
function's own measure, which is what this reads.

Pairs each `r2dec stage timing <name>: instructions=N` line with the
`r2dec timing: ... work=W` line that follows it, then reports the ratio's
spread and the log-log slope of work against instructions.

usage: tests/corpus/work_fit.py <timing log> [<timing log> ...]
"""

from __future__ import annotations

import math
import re
import sys

STAGE = re.compile(r"r2dec stage timing (?P<name>\S+): instructions=(?P<n>\d+)")
WORK = re.compile(r"r2dec timing: measured=\d+us work=(?P<w>\d+)")
CAPTURE = re.compile(r"r2dec timing: capture=\d+us .*?callees=(?P<c>\d+) .*?captured_bytes=(?P<b>\d+)")


def read(paths: list[str]) -> list[tuple[str, int, int, int, int]]:
    """Rows of (name, instructions, work, callees, captured bytes)."""
    rows: list[tuple[str, int, int, int, int]] = []
    pending: tuple[str, int] | None = None
    counted: tuple[str, int, int] | None = None
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stage = STAGE.search(line)
                if stage:
                    pending = (stage["name"], int(stage["n"]))
                    continue
                work = WORK.search(line)
                if work and pending:
                    counted = (pending[0], pending[1], int(work["w"]))
                    pending = None
                    continue
                # The capture line follows the engine's, and names how many
                # bodies the count covers besides the root's own.
                capture = CAPTURE.search(line)
                if capture and counted:
                    rows.append((*counted, int(capture["c"]), int(capture["b"])))
                    counted = None
    return rows


def fit(rows, measure) -> tuple[float, float]:
    points = [(measure(row), row[2]) for row in rows if measure(row) > 0 and row[2] > 0]
    if len(points) < 2:
        return (float("nan"), float("nan"))
    xs = [math.log(n) for n, _ in points]
    ys = [math.log(w) for _, w in points]
    mean_x = sum(xs) / len(xs)
    mean_y = sum(ys) / len(ys)
    cov = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    var = sum((x - mean_x) ** 2 for x in xs)
    slope = cov / var if var else float("nan")
    return (slope, math.exp(mean_y - slope * mean_x))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    rows = read(argv[1:])
    if not rows:
        print("no paired work and instruction counts found", file=sys.stderr)
        return 1
    own = lambda row: row[1]
    # The count covers the root and every body captured with it, so the measure
    # the cost is a function of has to name them too.
    with_callees = lambda row: row[1] + row[3]
    captured = lambda row: row[4]
    print(f"functions {len(rows)}")
    for label, measure in (
        ("instructions", own),
        ("instructions+callees", with_callees),
        ("captured bytes", captured),
    ):
        slope, factor = fit(rows, measure)
        tail = sorted(rows, key=measure)[len(rows) // 2 :]
        tail_slope, tail_factor = fit(tail, measure)
        ratios = sorted(row[2] / measure(row) for row in rows if measure(row) > 0)
        print(f"{label}:")
        print(f"  ratio  min {ratios[0]:.1f} median {ratios[len(ratios) // 2]:.1f} max {ratios[-1]:.1f}")
        print(f"  all    work ~ {factor:.2f} * n^{slope:.3f}")
        print(f"  tail   work ~ {tail_factor:.2f} * n^{tail_slope:.3f}   (n >= {measure(tail[0])})")
    # The bound a deadline can be: work never exceeded this affine function of
    # the captured input on the measured corpus. The slope comes from the large
    # captures, where fixed cost is a rounding error; the intercept is then
    # whatever the small ones still need.
    large = [row for row in rows if row[4] >= 8192]
    slope = max((row[2] / row[4] for row in large), default=0.0)
    intercept = max((row[2] - slope * row[4] for row in rows), default=0.0)
    print(f"envelope: work <= {intercept:.0f} + {slope:.3f} * captured_bytes")
    print(f"  slope from {len(large)} captures of 8 KiB or more")
    # Sorted by the measure the cost is a function of, so the list is the cost
    # defects rather than the small functions with fixed overhead.
    worst = sorted(
        (row for row in rows if row[4] >= 8192),
        key=lambda row: -(row[2] / max(row[4], 1)),
    )[:8]
    for name, n, w, c, b in worst:
        print(
            f"  worst {w / max(b, 1):8.2f} work/byte  work {w:9d}  captured {b:8d}"
            f"  instructions {n:6d}  callees {c:4d}  {name}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
