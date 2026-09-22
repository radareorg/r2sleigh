#!/usr/bin/env python3
"""Score recovery and soundness against a debug build of the same binary.

The same source compiled twice gives exact ground truth for free: the build
that kept its debug info says what every function really is, and the stripped
build is what the engine has to work from. Every fact the engine recovers from
the stripped build lands in one of four buckets.

    correct          recovered and it matches the debug build
    missing          the debug build has it and the engine does not
    marked-wrong     recovered wrongly, but the function carries a residual
                     marker, so a reader was told not to trust it
    silently-wrong   recovered wrongly and asserted as if proven

Recovery is how much of the truth comes back. Soundness is the share of
asserted facts that are not silently wrong, and it is the number that matters:
a decompiler that guesses confidently is worse than one that says it does not
know. Silently-wrong is a defect at the highest severity, never a quality nit.

The marker granularity is the function, because that is the granularity the
renderer annotates at. A function carrying any residual has its unmatched facts
counted as marked rather than silent.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

PROTOTYPE = re.compile(r"^(?P<ret>[\w \*]+?)\s+(?P<name>[\w.]+)\s*\((?P<args>.*)\);?\s*$")


def r2s(binary: Path, commands: str, r2s_bin: str) -> str:
    """Ask the shell, and let a refusal answer.

    A refused function is a fact this harness scores rather than an error, so a
    non-zero exit is read for its output like any other.
    """
    proc = subprocess.run(
        [r2s_bin, "-q", "-c", commands, str(binary)],
        capture_output=True, text=True, timeout=1800, check=False,
    )
    return proc.stdout


@dataclass
class Prototype:
    ret: str
    params: list[str] = field(default_factory=list)


def normalize_type(spelling: str) -> str:
    """Compare what a type means, not how it is spelled.

    `char *` and `char*` are the same type, and a debug build that says
    `unsigned long` against a plugin that says `size_t` is a naming difference
    rather than a recovery failure.
    """
    text = " ".join(spelling.split()).replace(" *", "*").strip()
    aliases = {
        "unsigned long": "size_t", "long unsigned int": "size_t",
        "unsigned int": "uint32_t", "int32_t": "int", "signed int": "int",
        "int64_t": "long", "uint64_t": "size_t", "_Bool": "bool",
    }
    return aliases.get(text, text)


def parse_prototype(line: str) -> Prototype | None:
    match = PROTOTYPE.match(line.strip())
    if not match:
        return None
    args = match.group("args").strip()
    params: list[str] = []
    if args and args != "void":
        for arg in args.split(","):
            # `char *s` gives its type by dropping the trailing identifier.
            tokens = arg.strip().rsplit(" ", 1)
            params.append(normalize_type(tokens[0] if len(tokens) > 1 else arg))
    return Prototype(normalize_type(match.group("ret")), params)


GENERIC_PARAM = re.compile(r"^(int64_t|int32_t|uint64_t|long|int)$")


def truth_is_real(truth: dict[int, Prototype]) -> bool:
    """Refuse a debug build whose prototypes are radare2's own guesses.

    Debug info that fails to load looks exactly like debug info that says
    nothing: every function comes back `void f(int64_t arg1)`. Scoring against
    that measures the plugin against a guess and reports the difference as the
    plugin's error, which is worse than reporting nothing. A real debug build
    names concrete types a generic recovery never produces.
    """
    if not truth:
        return False
    concrete = sum(
        1 for proto in truth.values()
        if proto.ret not in {"void", "int"}
        or any("*" in param or not GENERIC_PARAM.match(param) for param in proto.params)
    )
    return concrete * 4 >= len(truth)


def addresses(binary: Path, r2s_bin: str) -> list[int]:
    """Every function the engine believes this binary has."""
    found = []
    for line in r2s(binary, "afl", r2s_bin).splitlines():
        head = line.split(None, 1)[0] if line.split() else ""
        if head.startswith("0x"):
            try:
                found.append(int(head, 16))
            except ValueError:
                continue
    return found


def signatures(binary: Path, r2s_bin: str) -> dict[int, tuple[Prototype, bool]]:
    """What each function renders as, and whether it carries a marker.

    One command per function rather than one per binary, because a refusal is
    per function and a batch that stops at the first one would score the rest
    as missing.
    """
    out: dict[int, tuple[Prototype, bool]] = {}
    for addr in addresses(binary, r2s_bin):
        body = r2s(binary, f"s {addr:#x}; pdd", r2s_bin)
        lines = [line for line in body.splitlines() if line.strip()]
        if not lines:
            continue
        proto = parse_prototype(lines[0])
        if proto:
            out[addr] = (proto, "residual" in body or "r2sleigh refused" in body)
    return out


def names(binary: Path, r2s_bin: str) -> dict[int, str]:
    """What the binary calls each function it believes it has.

    A recorded fact has to be keyed by something that survives a rebuild, and
    an address does not: the same source compiled on another machine puts the
    same function somewhere else.
    """
    found = {}
    for line in r2s(binary, "afl", r2s_bin).splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].startswith("0x"):
            try:
                found[int(parts[0], 16)] = parts[-1]
            except ValueError:
                continue
    return found


def truth_from_debug_build(binary: Path, r2s_bin: str) -> dict[int, Prototype]:
    """What every function actually is, read out of the debug build.

    The debug build's DWARF is the source's own statement about a function, and
    the engine reads it, so the truth and the recovery come from one tool and
    differ only in what the binary carries.
    """
    return {addr: proto for addr, (proto, _) in signatures(binary, r2s_bin).items()}


def recovered_from_stripped(binary: Path, r2s_bin: str) -> dict[int, tuple[Prototype, bool]]:
    """What the engine recovers, and whether it marked the function."""
    return signatures(binary, r2s_bin)


def score(truth: dict[int, Prototype],
          recovered: dict[int, tuple[Prototype, bool]],
          silent: list[str] | None = None,
          called: dict[int, str] | None = None) -> dict[str, int]:
    buckets = {"correct": 0, "missing": 0, "marked_wrong": 0, "silently_wrong": 0}

    def judge(where: str, expected: str, actual: str | None, marked: bool) -> None:
        if actual is None:
            buckets["missing"] += 1
        elif actual == expected:
            buckets["correct"] += 1
        elif marked:
            buckets["marked_wrong"] += 1
        else:
            buckets["silently_wrong"] += 1
            # A silent error has to be nameable, or a gate that catches one
            # tells nobody which fact to go and look at.
            if silent is not None:
                silent.append(f"{where}: expected {expected!r}, said {actual!r}")

    for addr, expected in truth.items():
        entry = recovered.get(addr)
        if entry is None:
            buckets["missing"] += 1 + len(expected.params)
            continue
        actual, marked = entry
        where = (called or {}).get(addr) or f"{addr:#x}"
        judge(f"{where} return", expected.ret, actual.ret, marked)
        for index, param in enumerate(expected.params):
            got = actual.params[index] if index < len(actual.params) else None
            judge(f"{where} parameter {index}", param, got, marked)
    return buckets


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--debug-build", type=Path, required=True,
                        help="build that kept its debug info; the ground truth")
    parser.add_argument("--stripped-build", type=Path, required=True,
                        help="same source, stripped; what the engine is given")
    parser.add_argument("--r2s", default="target/release/r2s")
    parser.add_argument("--json", type=Path, help="write the report here")
    parser.add_argument("--baseline", type=Path,
                        help="the silent errors already recorded, each with a cause")
    parser.add_argument("--accept-baseline", action="store_true",
                        help="record this run's silent errors, after reading them")
    args = parser.parse_args()

    truth = truth_from_debug_build(args.debug_build, args.r2s)
    if not truth_is_real(truth):
        print("refusing to score: the debug build yields generic prototypes, so its "
              "debug info did not load. Check that the dSYM or DWARF sits where "
              "the reader looks for it; a copied binary usually leaves it behind.",
              file=sys.stderr)
        return 2
    recovered = recovered_from_stripped(args.stripped_build, args.r2s)
    silent: list[str] = []
    buckets = score(truth, recovered, silent, names(args.debug_build, args.r2s))

    asserted = buckets["correct"] + buckets["silently_wrong"]
    facts = sum(buckets.values())
    report = {
        "functions_in_truth": len(truth),
        "functions_recovered": len(recovered),
        "facts": buckets,
        "recovery_rate": round(buckets["correct"] / facts, 4) if facts else 0.0,
        "soundness_rate": round(1 - buckets["silently_wrong"] / asserted, 4) if asserted else 1.0,
        "silent": silent,
    }
    print(json.dumps(report, indent=2))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n")

    recorded = (
        json.loads(args.baseline.read_text())
        if args.baseline and args.baseline.exists()
        else {}
    )

    # Re-recording comes first. Checked after the comparison instead, the flag
    # did nothing at all whenever a baseline already existed, which is every
    # time anyone would reach for it -- and it said so only by leaving the file
    # unchanged.
    if args.accept_baseline and args.baseline:
        # The recorded cause of a silent error outlives the run that found it,
        # so the explanations for the errors still here are carried forward
        # rather than thrown away with the counts.
        why = recorded.get("why", {})
        args.baseline.write_text(
            json.dumps(
                {**report, "why": {fact: why[fact] for fact in silent if fact in why}},
                indent=2,
            )
            + "\n"
        )
        print(f"baseline accepted: {args.baseline}", file=sys.stderr)
        return 0

    # A recorded silent error has a recorded cause; an unrecorded one is the
    # failure this harness exists to catch. Gating on the set rather than on
    # zero is what lets a known defect be carried without hiding a new one.
    if recorded:
        known = set(recorded.get("silent", []))
        new_silent = [fact for fact in silent if fact not in known]
        fixed = sorted(known - set(silent))
        for fact in fixed:
            print(f"no longer silent: {fact}", file=sys.stderr)
        for fact in new_silent:
            print(f"SILENT ERROR: {fact}", file=sys.stderr)
        if fixed and not new_silent:
            print("re-record the baseline with --accept-baseline", file=sys.stderr)
        return 1 if new_silent else 0
    # A silent error is the one failure this harness exists to catch.
    return 1 if buckets["silently_wrong"] else 0


if __name__ == "__main__":
    sys.exit(main())
