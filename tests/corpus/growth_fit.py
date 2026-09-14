#!/usr/bin/env python3
"""Fit each render stage's growth exponent against the body it was given.

A stage that takes longer on a bigger function is doing its job; a stage whose
time grows faster than the function does is the defect. Both look the same in a
profile of one function, so this reads many `r2dec stage timing` lines and fits
the log-log slope of time against instruction count for each stage separately.

An exponent near 1.0 is proportionate. Anything at or above about 1.5 is a
quadratic term wearing a constant factor, and is the thing to trace.

Two exponents are reported because one is misleading on its own. A corpus is
mostly small functions, whose time is fixed overhead rather than work, and a fit
over all of them reads well below 1.0 no matter what the stage does on a large
body. The `tail` column fits only the renders at or above the median size, which
is where a superlinear term is visible at all.

usage: tests/corpus/growth_fit.py <timing log> [<timing log> ...]
  tests/corpus/locked_probe.sh ./bzip2-O0 'a:sla; aaa; pd:s @@F' \
      R2SLEIGH_TIMING=1 2>&1 | tee sweep.log
  tests/corpus/growth_fit.py sweep.log
"""

import math
import re
import sys

LINE = re.compile(r"r2dec stage timing (\S+): instructions=(\d+) (.*)")
FIELD = re.compile(r"(\w+)=(\d+)(us|)")


def read(paths):
    """Every render's size and per-stage microseconds, keyed by stage."""
    samples = {}
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                found = LINE.search(line)
                if not found:
                    continue
                size = int(found.group(2))
                if size <= 0:
                    continue
                for stage, value, unit in FIELD.findall(found.group(3)):
                    if unit != "us" or stage == "total":
                        continue
                    samples.setdefault(stage, []).append((size, int(value)))
    return samples


def exponent(points):
    """Least-squares slope of log(time) against log(size)."""
    usable = [(math.log(size), math.log(time)) for size, time in points if time > 0]
    if len(usable) < 3:
        return None
    mean_x = sum(x for x, _ in usable) / len(usable)
    mean_y = sum(y for _, y in usable) / len(usable)
    spread = sum((x - mean_x) ** 2 for x, _ in usable)
    if spread == 0:
        return None
    covariance = sum((x - mean_x) * (y - mean_y) for x, y in usable)
    return covariance / spread


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 64
    samples = read(argv[1:])
    if not samples:
        print("no `r2dec stage timing` lines found", file=sys.stderr)
        return 1
    rows = []
    for stage, points in samples.items():
        total = sum(time for _, time in points)
        ordered = sorted(points)
        tail = ordered[len(ordered) // 2 :]
        rows.append((total, stage, len(points), exponent(points), exponent(tail)))
    rows.sort(reverse=True)
    print(f"{'stage':<24}{'renders':>8}{'total ms':>11}{'all':>8}{'tail':>8}")
    for total, stage, count, slope, tail_slope in rows:
        spelling = "-" if slope is None else f"{slope:.2f}"
        tail_spelling = "-" if tail_slope is None else f"{tail_slope:.2f}"
        print(
            f"{stage:<24}{count:>8}{total / 1000:>11.1f}{spelling:>8}{tail_spelling:>8}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
