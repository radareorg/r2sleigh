#!/usr/bin/env python3
"""Turn whole-binary decompilation dumps into a blessed coverage baseline.

What is scored is one bit per function -- did it render -- plus the typed cause
when it did not. The cause is normalised: counts, addresses and function names
vary between builds and between runs of an unchanged tree, and a baseline that
churns on those is a baseline nobody re-blesses honestly.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

BEGIN = re.compile(r"^R2SLEIGH_COV_BEGIN__(?P<name>.+)$")
# How many functions the sweep set out to measure, so a run cut short is told
# apart from a binary that simply holds fewer.
ASKED = re.compile(r"^R2SLEIGH_COV_ASKED__(?P<count>\d+)$")
END = re.compile(r"^R2SLEIGH_COV_END__(?P<name>.+)$")
FALLBACK = re.compile(r"/\* r2sleigh refused \S+: (?P<cause>.*) \*/")
# The shell answering with an error instead of a rendering is a refusal too.
# It was counted as rendered, so a function that stopped before the renderer
# even ran -- `invalid owned source snapshot` -- raised the score.
SHELL_ERROR = re.compile(r"^r2s: (?P<cause>.*)$", re.M)

# The proof line a rendering opens with. A marked gap renders as a residual
# that traps, and is not proven: its obligations are counted in the proof
# line's `residual` column, which is what a function that renders only part of
# itself reports. The baseline keeps calling the count `gapped`.
PROOF = re.compile(r"/\* r2dec proof: (?P<proof>[^*]*)\*/")
GAPPED = re.compile(r"(?P<count>\d+) residual\b")
# An address names a site in one build; the same cause in another build is at
# another address.
ADDRESS = re.compile(r"0x[0-9a-fA-F]+")
# Numbers inside a cause are counts of refused obligations or conflicting
# values. They say how much went wrong, not what, and they move with the
# function's size. A digit inside a name -- the `2` of `vpmovsxbd_avx2`, the
# `0` of an address already spelled `0xN` -- is part of what went wrong, and
# is kept.
DIGITS = re.compile(r"(?<!\w)\d+(?!\w)")


def normalise(cause: str) -> str:
    """The part of a refusal that identifies it across builds.

    The lowering site a refusal now carries is deliberately kept: it is what
    separates two unrelated predicates that used to be counted as one cause.
    Its line number is not, for the same reason equality ignores it -- moving a
    line must not churn a baseline.
    """
    cause = re.sub(r"(\w+\.rs):\d+", r"\1", cause)
    cause = ADDRESS.sub("0xN", cause)
    cause = DIGITS.sub("N", cause)
    return " ".join(cause.split())


def gapped_obligations(text: str) -> int:
    """How many of the function's source obligations a marked gap accounts for.

    A rendering whose body is mostly gaps is still a rendering, and scoring it
    only as `rendered` is what let a function with 242 of its 274 obligations
    gapped pass as clean. The count is read from the proof line, which states
    it whenever it is not zero.
    """
    proof = PROOF.search(text)
    if proof is None:
        return 0
    gapped = GAPPED.search(proof["proof"])
    return 0 if gapped is None else int(gapped["count"])


def parse_dump(path: Path) -> list[dict]:
    functions: list[dict] = []
    current: dict | None = None
    body: list[str] = []
    asked: int | None = None
    for line in path.read_text(errors="replace").splitlines():
        stated = ASKED.match(line.strip())
        if stated:
            asked = int(stated["count"])
        begin = BEGIN.match(line.strip())
        if begin:
            current = {"function": begin["name"]}
            body = []
            continue
        end = END.match(line.strip())
        if end and current is not None:
            text = "\n".join(body)
            fallback = FALLBACK.search(text) or SHELL_ERROR.search(text)
            current["rendered"] = fallback is None and bool(text.strip())
            current["cause"] = None if fallback is None else normalise(fallback["cause"])
            if not text.strip():
                current["cause"] = "no output"
            current["gapped"] = gapped_obligations(text) if current["rendered"] else 0
            functions.append(current)
            current = None
            continue
        if current is not None:
            body.append(line)
    if asked is not None and len(functions) != asked:
        raise SystemExit(
            f"{path.name}: the sweep asked for {asked} functions and recorded "
            f"{len(functions)}; the run was cut short and its numbers are not "
            "a measurement"
        )
    return functions


def collect(artifact_root: Path) -> list[dict]:
    entries: list[dict] = []
    for dump in sorted((artifact_root / "dumps").glob("*.txt")):
        cell = dump.stem
        for function in parse_dump(dump):
            entries.append({"cell": cell, **function})
    return entries


POPULATIONS = (("pinned_", "pinned"), ("system_", "system"))


def population_of_cell(cell: str) -> str:
    """Which of the three populations a swept binary belongs to.

    `pinned` is a program the repository ships as bytes, so the cell names the
    same program on every machine and can be gated on anywhere. `compiled` is
    built here by whichever clang this machine has, so the cell only means what
    the baseline recorded while the compiler string matches. `system` is
    whatever the machine happened to have at that path, so it is measured and
    reported and never gates.
    """
    for prefix, name in POPULATIONS:
        if cell.startswith(prefix):
            return name
    return "compiled"


def population(key: str) -> str:
    return population_of_cell(key.split("::", 1)[0])


def gates(key: str, compiler_moved: bool) -> bool:
    name = population(key)
    if name == "system":
        return False
    if name == "compiled":
        return not compiler_moved
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--clang", default="")
    parser.add_argument("--accept-baseline", action="store_true")
    args = parser.parse_args()

    entries = collect(args.artifact_root)
    if not entries:
        print("no functions were swept", file=sys.stderr)
        return 70

    rendered = sum(1 for entry in entries if entry["rendered"])
    causes = Counter(entry["cause"] for entry in entries if not entry["rendered"])
    measured = {
        "clang": args.clang,
        "functions": len(entries),
        "rendered": rendered,
        "entries": {
            f"{entry['cell']}::{entry['function']}": (
                "rendered" if entry["rendered"] else entry["cause"]
            )
            for entry in entries
        },
        # Rendered functions part of which is a marked gap, and how many of
        # their obligations the gaps account for. Absent means none.
        "gapped": {
            f"{entry['cell']}::{entry['function']}": entry["gapped"]
            for entry in entries
            if entry["gapped"] > 0
        },
    }
    (args.artifact_root / "coverage.json").write_text(json.dumps(measured, indent=2) + "\n")

    print(f"functions: {len(entries)}")
    print(f"rendered:  {rendered} ({rendered * 100 // len(entries)}%)")
    gapped_functions = measured["gapped"]
    print(
        f"gapped:    {len(gapped_functions)} rendered functions, "
        f"{sum(gapped_functions.values())} obligations"
    )
    for cause, count in causes.most_common():
        print(f"  {count:4d}  {cause}")

    if args.accept_baseline:
        args.baseline.write_text(json.dumps(measured, indent=2) + "\n")
        print(f"baseline accepted: {args.baseline}")
        return 0

    if not args.baseline.exists():
        print(
            f"no baseline at {args.baseline}; run with --accept-baseline to record one",
            file=sys.stderr,
        )
        return 65

    baseline = json.loads(args.baseline.read_text())
    if "gapped" not in baseline:
        # Without the section every gap would read as new; a baseline blessed
        # before gaps were counted cannot gate them, so it is not used at all.
        print(
            f"the baseline at {args.baseline} records no gapped obligations; read "
            "this sweep and re-bless it with --accept-baseline",
            file=sys.stderr,
        )
        return 65
    compiler_moved = baseline.get("clang") != args.clang
    if compiler_moved:
        print(
            "the compiler moved, so the compiled cells are not the same programs "
            f"the baseline recorded:\n  baseline: {baseline.get('clang')}\n  here:     {args.clang}\n"
            "compiled cells are reported below and not gated; the pinned cells "
            "still gate, because the repository ships those as bytes."
        )

    before = baseline["entries"]
    after = measured["entries"]
    lost = sorted(key for key, value in after.items() if value != "rendered" and before.get(key) == "rendered")
    gained = sorted(key for key, value in after.items() if value == "rendered" and before.get(key) not in (None, "rendered"))
    vanished = sorted(set(before) - set(after))
    appeared = sorted(set(after) - set(before))
    changed = sorted(
        key
        for key, value in after.items()
        if key in before and before[key] != "rendered" and value != "rendered" and before[key] != value
    )

    # A function that rendered in the baseline and now gaps more of itself has
    # lost part of its body exactly as a refusal loses all of it, and is gated
    # the same way.
    gaps_before = baseline["gapped"]
    gaps_after = measured["gapped"]
    gap_lost = sorted(
        key
        for key, count in gaps_after.items()
        if before.get(key) == "rendered"
        and after.get(key) == "rendered"
        and count > gaps_before.get(key, 0)
    )
    gap_narrowed = sorted(
        key
        for key, count in gaps_before.items()
        if after.get(key) == "rendered" and gaps_after.get(key, 0) < count
    )

    for key in gained:
        print(f"gained: {key} (was {before[key]})")
    for key in gap_narrowed:
        print(f"gap narrowed: {key}: {gaps_before[key]} -> {gaps_after.get(key, 0)} gapped")
    for key in changed:
        print(f"cause changed: {key}: {before[key]} -> {after[key]}")
    for key in appeared:
        print(f"new function: {key} = {after[key]}")

    failed = False
    for key in lost:
        if gates(key, compiler_moved):
            print(f"REGRESSION: {key} rendered in the baseline and now refuses: {after[key]}", file=sys.stderr)
            failed = True
        else:
            print(f"not gated, {population(key)}: {key} rendered in the baseline and now refuses: {after[key]}")
    for key in gap_lost:
        was = gaps_before.get(key, 0)
        now = gaps_after[key]
        if gates(key, compiler_moved):
            print(
                f"REGRESSION: {key} rendered with {was} gapped obligations in the baseline "
                f"and now gaps {now}",
                file=sys.stderr,
            )
            failed = True
        else:
            print(
                f"not gated, {population(key)}: {key} rendered with {was} gapped "
                f"obligations in the baseline and now gaps {now}"
            )
    for key in vanished:
        if gates(key, compiler_moved):
            print(f"MISSING: {key} is in the baseline and was not swept", file=sys.stderr)
            failed = True
        else:
            print(f"not measured here, {population(key)}: {key}")
    if failed:
        return 1

    if gained or appeared or gap_narrowed:
        print("coverage improved; re-bless with --accept-baseline to record it")
    for name in ("pinned", "compiled", "system"):
        cells = [entry for entry in entries if population_of_cell(entry["cell"]) == name]
        if cells:
            hit = sum(1 for entry in cells if entry["rendered"])
            gated = "gates" if (name == "pinned" or (name == "compiled" and not compiler_moved)) else "reported"
            print(f"  {name:9} {hit}/{len(cells)} rendered ({gated})")
    print(f"coverage gate: {rendered}/{len(entries)} rendered, no regressions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
