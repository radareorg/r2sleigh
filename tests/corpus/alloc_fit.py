#!/usr/bin/env python3
"""Fit bytes against the body they were spent on.

The engine reports where a decompile spends its time and, under the plugin's
`alloc-probe` feature, where it spends its bytes. Memory is what the deleted
complexity caps were really guarding: one function once reached several
gigabytes and the kernel killed radare2, which loses every function in the
binary rather than the one that was too big.

Two measures come out of one run. The preparation phases report their own
high-water mark as `collect-phase` evidence, and the render reports the live
total at each of its stages. Neither is meaningful alone: what matters is bytes
per instruction, because the cost follows the largest single function rather
than the function count.

usage:
  RUST_FEATURES=all-archs,alloc-probe tests/corpus/locked_probe.sh <binary> \\
      'a:sla; aaa; pd:s @@F' R2SLEIGH_TIMING=1 R2DEC_TRACE_REFUSAL=1 2> log
  tests/corpus/alloc_fit.py log [log ...]
"""

from __future__ import annotations

import collections
import re
import sys

# `prepare@0xcc30/501 obligations 584 ms size 8981 bytes 16841780`
PHASE = re.compile(
    r"(?P<role>prepare|recover|build|capture)@(?P<addr>0x[0-9a-f]+)/(?P<blocks>\d+)\s+"
    r"(?P<phase>\w+)\s+(?P<ms>\d+) ms size (?P<size>\d+) bytes (?P<bytes>\d+)"
)
# `r2dec stage timing dbg_x: instructions=30281 total=...us a=1us entry_bytes=N peak_bytes=M a_bytes=K`
STAGE = re.compile(r"r2dec stage timing (?P<name>\S+): instructions=(?P<n>\d+)")
BYTES = re.compile(r"(?P<key>\w+)_bytes=(?P<v>\d+)")
LIVE = re.compile(r"(?P<key>\w+)_live=(?P<v>\d+)")


class Render:
    """One function's render: its size, and the bytes each stage stood at."""

    def __init__(self, name: str, instructions: int) -> None:
        self.name = name
        self.instructions = instructions
        self.entry = 0
        self.peak = 0
        self.stages: list[tuple[str, int]] = []
        self.live: list[tuple[str, int]] = []

    @property
    def growth(self) -> int:
        return max(0, self.peak - self.entry)


def read(paths: list[str]) -> tuple[list[Render], list[dict]]:
    renders: list[Render] = []
    phases: list[dict] = []
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                phase = PHASE.search(line)
                if phase:
                    phases.append(
                        {
                            "role": phase["role"],
                            "addr": phase["addr"],
                            "blocks": int(phase["blocks"]),
                            "phase": phase["phase"],
                            "ms": int(phase["ms"]),
                            "bytes": int(phase["bytes"]),
                        }
                    )
                    continue
                stage = STAGE.search(line)
                if not stage:
                    continue
                render = Render(stage["name"], int(stage["n"]))
                for match in LIVE.finditer(line):
                    render.live.append((match["key"], int(match["v"])))
                for match in BYTES.finditer(line):
                    key, value = match["key"], int(match["v"])
                    if key == "entry":
                        render.entry = value
                    elif key == "peak":
                        render.peak = value
                    else:
                        render.stages.append((key, value))
                renders.append(render)
    return renders, phases


def megabytes(value: float) -> str:
    return f"{value / (1 << 20):.1f} MB"


def report_phases(phases: list[dict]) -> None:
    """What one root's preparation holds, phase by phase."""
    for role in ("capture", "build", "prepare"):
        report_role(phases, role)


def report_role(phases: list[dict], role: str) -> None:
    roots = [row for row in phases if row["role"] == role]
    if not roots:
        return
    worst = max(roots, key=lambda row: row["bytes"])
    same_root = [row for row in roots if row["addr"] == worst["addr"]]
    print(f"{role} of {worst['addr']}, {worst['blocks']} blocks:")
    for row in sorted(same_root, key=lambda row: -row["bytes"]):
        print(f"  {row['phase']:<18} {row['ms']:>6} ms  {megabytes(row['bytes']):>10}")
    totals = collections.Counter()
    for row in roots:
        totals[row["phase"]] += row["bytes"]
    total = sum(totals.values()) or 1
    print(f"every root {role}, by phase:")
    for phase, value in totals.most_common(8):
        print(f"  {phase:<18} {megabytes(value):>10}  {100 * value / total:5.1f}%")


def report_renders(renders: list[Render]) -> None:
    """What a render adds on top of what preparation already held."""
    sized = [row for row in renders if row.instructions > 0 and row.peak > 0]
    if not sized:
        print("no render carried byte counts; build with alloc-probe")
        return
    print(f"renders: {len(sized)}")
    density = sorted(sized, key=lambda row: -(row.peak / row.instructions))
    print("bytes per instruction, worst first:")
    for row in density[:5]:
        print(
            f"  {row.peak / row.instructions:8.0f} B/inst  peak {megabytes(row.peak):>10}"
            f"  entry {megabytes(row.entry):>10}  {row.instructions:>7} inst  {row.name}"
        )
    biggest = max(sized, key=lambda row: row.growth)
    print(f"largest render growth: {biggest.name}, {megabytes(biggest.growth)}")
    live = dict(biggest.live)
    previous = biggest.entry
    held = biggest.entry
    for stage, value in biggest.stages:
        step = value - previous
        now = live.get(stage, 0)
        kept = now - held if now else 0
        if step > 0 or kept:
            print(
                f"  {stage:<24} high +{megabytes(step):>10}"
                f"   kept {megabytes(kept):>10}   live {megabytes(now):>10}"
            )
        previous = max(previous, value)
        if now:
            held = now


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    renders, phases = read(argv[1:])
    if not renders and not phases:
        print("nothing to read; is alloc-probe built in?", file=sys.stderr)
        return 1
    report_phases(phases)
    report_renders(renders)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
