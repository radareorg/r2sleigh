#!/usr/bin/env python3
"""The scratch-void gate (doc/adr-scratch-result.md, slice S4; ROADMAP D203).

Each build is a debug build and its stripped copy. The debug build's DWARF says whether a function returns a value
(its `DW_AT_type`, through `DW_AT_abstract_origin`); r2s says what it renders from the stripped copy (`pddj`'s
signature and premises). Every function is counted under one class:

    void-open      rendered `void` with no closed-world premise (every lane undefined or unwritten)
    void-closed    rendered `void` under the closed-world premise (the entry lane decided by its call sites)
    unproven:CAUSE rendered with a value; CAUSE is what the engine names (`unstated` until D201 spells one)
    refused        `pddj` refused the function
    unanswered     no readable answer (a crash, a deadline, a decline)

The gate fails (exit 1) on a false void: a source-value function rendered `void` that the known list does not name,
either as a clone whose machine code returns nothing (`.isra`, `.constprop`, `.part`) or as a defect its D-row owns.
Names are read by this gate only; the engine reads none.
Against a baseline it also fails on a source-void function the baseline renders `void` that is no longer `void`,
unless the known list names it as moving (ADR, Decided 2), and on an unanswered function the baseline does not list:
a crash, a deadline or a malformed `pddj` could hide either failure. `--floor-open` and `--floor-closed` are D203's totals;
absent, the baseline's recorded `floors` apply. Exit 2 is a build the gate cannot grade: one whose debug or stripped file
is not of `--target`'s ELF machine, or a baseline recorded for another target (ROADMAP D245).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests" / "equiv"))
import build as equiv_build  # noqa: E402
import c_types  # noqa: E402
import r2s_batch  # noqa: E402
from dwarf import Dwarf, function_symbols, loaded_code  # noqa: E402
from target import TARGETS, Target, by_name  # noqa: E402

CLASSES = ("void-open", "void-closed", "refused", "unanswered")
VOIDS = ("void-open", "void-closed")
# The Unproven causes the ADR names (doc/adr-scratch-result.md, "Rendering of Unproven").
CAUSES = ("Written", "EntryInput", "Unread", "ForwardCycle")
CAUSE = re.compile(r"r2dec proof:[^\n]*?\b(" + "|".join(CAUSES) + r")\b")
CLONE = re.compile(r"\.(isra|constprop|part)\.\d")
KINDS = ("clone", "defect", "moves")
OWNER = re.compile(r"\bD\d+\b")
GNU_C = re.compile(r"GNU C\d")


class Ungradable(Exception):
    """A build the gate cannot read; exit 2."""


@dataclass(frozen=True)
class Source:
    """What the debug build's DWARF states of one function."""

    name: str
    value: bool


@dataclass
class Build:
    name: str
    debug: Path
    stripped: Path


@dataclass
class Graded:
    """One build's answer: each function's class and the source truth it is graded against."""

    name: str
    rows: dict[str, tuple[str, str]] = field(default_factory=dict)

    def counts(self) -> dict[str, dict[str, int]]:
        tally: dict[str, Counter] = {}
        for cls, truth in self.rows.values():
            tally.setdefault(cls, Counter())[truth] += 1
        return {cls: dict(sorted(t.items())) for cls, t in sorted(tally.items())}

    def named(self, cls: str) -> list[str]:
        return sorted(name for name, (c, _) in self.rows.items() if c == cls)

    def voids(self, truth: str) -> list[str]:
        return sorted(name for name, (cls, t) in self.rows.items() if cls in VOIDS and t == truth)


def target_of(name: str, prefix: str | None) -> Target:
    """The `Target` the gate grades; `prefix` overrides its binutils (`g` on macOS)."""
    target = by_name(name)
    return target if prefix is None else dataclasses.replace(target, binutils_prefix=prefix)


def check_machine(build: Build, target: Target) -> None:
    """Default-deny: both files of a build are of the target's ELF machine, or the build is ungradable."""
    for path in (build.debug, build.stripped):
        try:
            machine = equiv_build.elf_machine(path, target)
        except OSError as error:
            raise Ungradable(f"{path}: cannot read its ELF machine: {error}") from error
        if machine != target.elf_machine:
            raise Ungradable(f"{path}: machine {machine or 'unreadable'!r}, not {target.name}'s {target.elf_machine!r}")


def truth(debug: Path, target: Target) -> dict[int, Source]:
    """Every gcc C function of the debug build that may return, by entry, named by its symbol.

    A `DW_AT_noreturn` function and an entry two DIEs disagree on are left out: neither has one answer.
    """
    try:
        dwarf = Dwarf.read(debug, target)
        symbols = function_symbols(debug, target)
        placed, _ = dwarf.placed(symbols, loaded_code(debug))
    except (OSError, RuntimeError) as error:
        raise Ungradable(f"{debug}: {error}") from error
    found: dict[int, Source | None] = {}
    for sub in placed:
        if not GNU_C.match(sub.producer) or sub.noreturn:
            continue
        name = sorted(symbols[sub.low_pc][0], key=lambda n: ("." not in n, n))[0]
        source = Source(name, sub.return_type is not None)
        found[sub.low_pc] = source if found.get(sub.low_pc, source) == source else None
    return {addr: source for addr, source in sorted(found.items()) if source is not None}


def classify(answer: r2s_batch.Answer) -> str:
    """One answer's class; the cause of a value result is the one the engine names, else `unstated`."""
    if answer.refusal is not None:
        return "refused"
    if not answer.ok:
        return "unanswered"
    record = answer.record
    try:
        proto = c_types.parse_prototype(record["signature"])
    except c_types.ParseError:
        return "unanswered"
    if proto.ret.kind == c_types.VOID:
        return "void-closed" if "closed-world" in (record.get("premises") or []) else "void-open"
    found = CAUSE.search(record.get("code") or "")
    return f"unproven:{found.group(1) if found else 'unstated'}"


def grade(build: Build, r2s: str, target: Target, timeout: float) -> Graded:
    check_machine(build, target)
    sources = truth(build.debug, target)
    if not sources:
        raise Ungradable(f"{build.debug}: no gcc C function with an entry")
    try:
        report = r2s_batch.run_batch(r2s, build.stripped, list(sources), function_timeout=timeout,
                                     startup_timeout=max(timeout, 1800))
    except OSError as error:
        raise Ungradable(f"cannot run {r2s}: {error}") from error
    graded = Graded(build.name)
    for answer in report.answers:
        source = sources[answer.address]
        key = source.name if source.name not in graded.rows else f"{source.name}@{answer.address:#x}"
        graded.rows[key] = (classify(answer), "value" if source.value else "void")
    return graded


def read_known(path: Path | None) -> dict[tuple[str, str], str]:
    """`build symbol kind reason` lines; a clone entry names a clone symbol, a defect entry its D-row."""
    known: dict[tuple[str, str], str] = {}
    for number, line in enumerate(path.read_text().splitlines() if path else [], 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(None, 3)
        if len(parts) < 4 or parts[2] not in KINDS:
            raise Ungradable(f"{path}:{number}: not `build symbol {'|'.join(KINDS)} reason`")
        if parts[2] == "clone" and not CLONE.search(parts[1]):
            raise Ungradable(f"{path}:{number}: {parts[1]} is no .isra, .constprop or .part clone")
        if parts[2] == "defect" and not OWNER.search(parts[3]):
            raise Ungradable(f"{path}:{number}: a defect names the D-row that owns it")
        known[(parts[0], parts[1])] = parts[2]
    return known


def judge(results: list[Graded], known: dict[tuple[str, str], str], baseline: dict,
          floors: tuple[int | None, int | None]) -> list[str]:
    """Every failure, in build order: a false void, a lost void, an unlisted unanswered function, a floor."""
    failures = []
    for graded in results:
        for name in graded.voids("value"):
            if known.get((graded.name, name)) not in ("clone", "defect"):
                failures.append(f"FALSE VOID: {graded.name} {name}")
        recorded = baseline.get("builds", {}).get(graded.name, {})
        now = set(graded.voids("void"))
        for name in recorded.get("voids", []):
            if name not in now and known.get((graded.name, name)) != "moves":
                failures.append(f"VOID LOST: {graded.name} {name} ({graded.rows.get(name, ('absent',))[0]})")
        listed = set(recorded.get("unanswered", []))
        for name in graded.named("unanswered"):
            if name not in listed:
                failures.append(f"UNANSWERED: {graded.name} {name}")
    open_now = sum(g.counts().get("void-open", {}).get("void", 0) for g in results)
    closed_now = open_now + sum(g.counts().get("void-closed", {}).get("void", 0) for g in results)
    for label, floor, now in (("open world", floors[0], open_now), ("closed world", floors[1], closed_now)):
        if floor is not None and now < floor:
            failures.append(f"FLOOR: {label} void {now} under {floor}")
    return failures


def summary(results: list[Graded]) -> dict:
    totals: dict[str, Counter] = {}
    for graded in results:
        for cls, truths in graded.counts().items():
            totals.setdefault(cls, Counter()).update(truths)
    return {
        "totals": {cls: dict(sorted(t.items())) for cls, t in sorted(totals.items())},
        "builds": {g.name: {"counts": g.counts(), "voids": g.voids("void"), "false": g.voids("value"),
                         "unanswered": g.named("unanswered")}
                   for g in sorted(results, key=lambda g: g.name)},
    }


def builds_from(args) -> list[Build]:
    found = [Build(name, Path(debug), Path(stripped)) for name, debug, stripped in args.build or []]
    for line in args.manifest.read_text().splitlines() if args.manifest else []:
        if line.strip() and not line.startswith("#"):
            name, debug, stripped = line.split()
            found.append(Build(name, args.manifest.parent / debug, args.manifest.parent / stripped))
    if len({b.name for b in found}) != len(found):
        raise Ungradable("two builds share a name")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build", nargs=3, action="append", metavar=("NAME", "DEBUG", "STRIPPED"))
    parser.add_argument("--manifest", type=Path, help="lines of `name debug stripped`, paths relative to it")
    parser.add_argument("--r2s", default="target/release/r2s")
    parser.add_argument("--target", choices=sorted(TARGETS), default="x86-64",
                        help="the machine every build must be (tests/equiv/target.py)")
    parser.add_argument("--binutils-prefix", help="overrides the target's binutils: `g` for GNU binutils on macOS")
    parser.add_argument("--known", type=Path, help="clones and moving voids, by build and symbol")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--accept-baseline", action="store_true")
    parser.add_argument("--floor-open", type=int)
    parser.add_argument("--floor-closed", type=int)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=300.0, help="seconds per function")
    args = parser.parse_args(argv)
    try:
        builds = builds_from(args)
        if not builds:
            raise Ungradable("no build given")
        known = read_known(args.known)
        baseline = json.loads(args.baseline.read_text()) if args.baseline and args.baseline.exists() else {}
        # A baseline without the key predates D245 and was recorded on x86-64.
        if baseline and baseline.get("target", "x86-64") != args.target:
            raise Ungradable(f"{args.baseline} records target {baseline.get('target', 'x86-64')}, not {args.target}")
        target = target_of(args.target, args.binutils_prefix)
        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            results = list(pool.map(lambda b: grade(b, args.r2s, target, args.timeout), builds))
    except Ungradable as error:
        print(f"refusing to grade: {error}", file=sys.stderr)
        return 2
    report = summary(results)
    report["target"] = args.target
    for cls, truths in report["totals"].items():
        print(f"{cls:24} source void {truths.get('void', 0):5}  source value {truths.get('value', 0):5}")
    if args.json:
        args.json.write_text(json.dumps(report, indent=1) + "\n")
    # The floors default to the ones the baseline records (D203), so a lost void moves them only by name.
    recorded = {} if args.accept_baseline else baseline.get("floors", {})
    floors = (args.floor_open if args.floor_open is not None else recorded.get("open"),
              args.floor_closed if args.floor_closed is not None else recorded.get("closed"))
    failures = judge(results, known, {} if args.accept_baseline else baseline, floors)
    for failure in failures:
        print(failure, file=sys.stderr)
    false_now = {(g.name, name) for g in results for name in g.voids("value")}
    for (build, name), kind in sorted(known.items()):
        if kind != "moves" and build in {g.name for g in results} and (build, name) not in false_now:
            print(f"no longer false, drop it from the known list: {build} {name} ({kind})", file=sys.stderr)
    if args.accept_baseline and args.baseline:
        # An unanswered function is recorded by name, so the next run fails on any other; a false void never is.
        if any(not failure.startswith("UNANSWERED") for failure in failures):
            print("not recorded: a baseline holds no false void", file=sys.stderr)
            return 1
        totals = report["totals"]
        open_voids = totals.get("void-open", {}).get("void", 0)
        report["floors"] = {"open": open_voids,
                            "closed": open_voids + totals.get("void-closed", {}).get("void", 0)}
        args.baseline.write_text(json.dumps(report, indent=1) + "\n")
        print(f"baseline recorded: {args.baseline}", file=sys.stderr)
        return 0
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
