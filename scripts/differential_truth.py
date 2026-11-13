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

The truth is what the debug build's DWARF declares, read by the oracle side's
own reader (`tests/equiv/dwarf.py`, `readelf`): each function's entry, its
result and its parameters. r2s never states the truth, because r2s on the
debug build recovers at most six register parameters and prints its own guess
for what it cannot read.

A function is graded only if it passes one predicate, `declared`: gcc produced
the DWARF, which states the signature (`DW_AT_prototyped`), the DIE states it
for itself (it is no instance of an origin, which is how a clone is described),
and its result and
every parameter are void, an integer or a pointer, the one register class the
gate states (it owns no table for any aggregate, vector, float or wide type).
The entry must also be the start of a FUNC symbol, one DIE per address, and
listed by the engine. Every other function is named in `ungradable` under its
reason and graded as nothing: a refusal costs a missing row, a wrong truth a
false soundness number. A debug build with no gradable function exits 2.

The marker granularity is the function, because that is the granularity the
renderer annotates at. A function whose `pddj` lists a residual has its
unmatched facts counted as marked rather than silent.

Every function is read from its `pddj` answer alone, by the reader the
equivalence gate and DecBench share (`tests/equiv/r2s_batch.py`). An answer the
reader cannot read is a failure of the gate (exit 2), never a marker: a gate
that scores a function it could not read grades a guess.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import subprocess
import sys
import traceback
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests" / "equiv"))
import c_types  # noqa: E402
import r2s_batch  # noqa: E402
from dwarf import Dwarf, Unplaced, function_symbols, loaded_code  # noqa: E402
from target import X86_64  # noqa: E402


def r2s(binary: Path, commands: str, r2s_bin: str) -> subprocess.CompletedProcess:
    """Ask the shell, and let a refusal answer.

    A refused function is a fact this harness scores rather than an error, so a
    non-zero exit is read for its output like any other.
    """
    return subprocess.run(
        [r2s_bin, "-q", "-c", commands, str(binary)],
        capture_output=True, text=True, errors="replace", timeout=1800, check=False,
    )


class Unreadable(Exception):
    """r2s or readelf gave an answer the gate cannot read, and scoring past it would grade a guess.

    `causes` is in the order the items were read, which is address order for a `pddj`.
    """

    def __init__(self, binary: Path, command: str, causes: dict[str, str]) -> None:
        super().__init__(f"no readable `{command}` answer for {len(causes)} item(s) of {binary}")
        self.binary = binary
        self.command = command
        self.causes = causes


def listing(binary: Path, r2s_bin: str) -> dict[int, str]:
    """Every function the engine believes this binary has, by address, with the name it gives it.

    A recorded fact has to be keyed by something that survives a rebuild, and
    an address does not: the same source compiled on another machine puts the
    same function somewhere else.
    """
    try:
        rows = json.loads(r2s(binary, "aflj", r2s_bin).stdout)
        if not all(isinstance(row["addr"], int) for row in rows):
            raise TypeError("an address that is no number")
        if not all(isinstance(row["name"], str) for row in rows):
            raise TypeError("a name that is no string")
        return {row["addr"]: row["name"] for row in rows}
    except (subprocess.TimeoutExpired, OSError) as error:
        raise Unreadable(binary, "aflj", {"": f"r2s did not answer ({error})"}) from error
    except (json.JSONDecodeError, TypeError, KeyError) as error:
        raise Unreadable(binary, "aflj", {"": f"not a list of functions ({error})"}) from error


def read_dwarf(binary: Path, binutils_prefix: str) -> tuple[Dwarf, list, list[Unplaced]]:
    """The binary's DWARF, its functions at their entries, and the ones that have none.

    An entry is placed only where the binary's own symbol table starts a function, and has code only where a loaded
    segment maps file bytes past the headers.
    """
    target = dataclasses.replace(X86_64, binutils_prefix=binutils_prefix)
    try:
        code = loaded_code(binary)
    except (OSError, RuntimeError) as error:
        raise Unreadable(binary, "program headers", {"": f"{error}; they show which entries have code"}) from error
    try:
        dwarf = Dwarf.read(binary, target)
        placed, unplaced = dwarf.placed(function_symbols(binary, target), code)
    except (OSError, RuntimeError) as error:
        raise Unreadable(binary, "readelf", {"": f"{error}; it lists the functions the source defines"}) from error
    return dwarf, placed, unplaced


def build_id(binary: Path, binutils_prefix: str) -> str | None:
    """The GNU build ID the linker wrote, which `strip` keeps; None where the binary has none."""
    target = dataclasses.replace(X86_64, binutils_prefix=binutils_prefix)
    try:
        proc = subprocess.run([target.tool("readelf"), "--wide", "--notes", str(binary)],
                              capture_output=True, text=True, check=False)
    except OSError as error:
        raise Unreadable(binary, "readelf", {"": f"{error}; it states the build ID"}) from error
    found = re.search(r"Build ID: ([0-9a-f]+)", proc.stdout)
    return found.group(1) if found else None


def ask(binary: Path, address: int, r2s_bin: str) -> r2s_batch.Answer:
    """One function's `pddj`, read by the reader the equivalence gate and DecBench share.

    The `r2s: <message>` lines on stderr are an answer's declines; any other stderr line is not part of it.
    """
    try:
        proc = r2s(binary, f"s {address:#x}; pddj", r2s_bin)
    except subprocess.TimeoutExpired:
        return r2s_batch.Answer(address, "crash", cause="harness: r2s ran past its deadline")
    except OSError as error:
        return r2s_batch.Answer(address, "crash", cause=f"harness: cannot run {r2s_bin}: {error}")
    declines = "".join(
        line + "\n" for line in proc.stderr.splitlines() if line.startswith(r2s_batch.ERROR_PREFIX)
    )
    return r2s_batch.parse_pddj(address, declines + proc.stdout)


@dataclass
class Seen:
    """What `pddj` says of one function."""

    proto: c_types.Prototype
    # The record lists a residual: a reader was told not to trust the function.
    marked: bool


def signatures(binary: Path, addresses: list[int], r2s_bin: str) -> dict[int, Seen]:
    """What each function renders as, and whether its record lists a residual.

    One process per function rather than one per binary, because a refusal is
    per function and a batch that stops at the first one would score the rest
    as missing. A function `pddj` says it refuses has no signature and is
    absent, so its facts are missing; an answer that cannot be read is not a
    refusal and raises `Unreadable` for every such function at once.
    """
    out: dict[int, Seen] = {}
    unreadable: dict[str, str] = {}
    for addr in addresses:
        answer = ask(binary, addr, r2s_bin)
        if answer.refusal is not None:
            continue
        if not answer.ok:
            unreadable[f"{addr:#x}"] = answer.cause
            continue
        record = answer.record
        try:
            proto = c_types.parse_prototype(record["signature"])
        except c_types.ParseError as error:
            unreadable[f"{addr:#x}"] = f"signature {record['signature']!r} is no prototype ({error})"
            continue
        if proto.name != record["definition"]:
            unreadable[f"{addr:#x}"] = f"signature names {proto.name!r}, the definition is {record['definition']!r}"
            continue
        out[addr] = Seen(proto, bool(record["residuals"]))
    if unreadable:
        raise Unreadable(binary, "pddj", unreadable)
    return out


NOT_GCC = "a producer other than GNU C: the truth model is validated on gcc's DWARF only"
INSTANCE = "an instance of an origin: its parameters are the origin's, not necessarily those at its address"
NOT_PROTOTYPED = "no DW_AT_prototyped: it states no signature (-g1, C++), or a K&R one with no prototype in scope"
NOT_STATED = "a result or parameter whose ABI class the gate does not state"
SHARED = "it shares its entry address with another function"
# A rate over fewer than one in three of a build's functions with code does not describe the build (ROADMAP D70).
GRADED_FLOOR = 3
UNLISTED = "the engine does not list it in the debug build"


class Ungradable(Exception):
    """A function the gate cannot grade, with the reason it is named under in the report."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class Declared:
    """What the source declares of one function."""

    name: str
    ret: c_types.CType
    params: list[c_types.CType]


# `GNU C17 13.3.0 ...`, not `GNU C++17` (no prototyped flag), `GNU AS` or clang (whose formals can outlive the argument).
GNU_C = re.compile(r"GNU C\d")


def declared(dwarf: Dwarf, sub) -> Declared:
    """A function's result and parameters as its DWARF states them, or `Ungradable` with the first reason.

    The positions of the integer registers are fixed only while the result and every parameter are void, an
    integer or a pointer. The gate states the class of nothing else on any architecture: a struct result over 16
    bytes takes the first integer register on x86-64 and x8 on AArch64, and a vector, a float, a long double or
    a complex number is in a register file DWARF does not name.
    """
    if not GNU_C.match(sub.producer):
        raise Ungradable(NOT_GCC)
    if sub.instance:
        raise Ungradable(INSTANCE)
    if not sub.prototyped:
        raise Ungradable(NOT_PROTOTYPED)
    offsets = [sub.return_type] + [param.type_offset for param in sub.parameters]
    try:
        ret, *params = [c_types.decay(c_types.from_dwarf(dwarf, offset)) for offset in offsets]
    except c_types.NotExpressible as error:
        raise Ungradable(NOT_STATED) from error
    if not (ret.kind == c_types.VOID or c_types.integer_class(ret)) or not all(map(c_types.integer_class, params)):
        raise Ungradable(NOT_STATED)
    return Declared(sub.name, ret, params)


PRESENCE = ("void_to_void", "void_to_value", "value_to_void", "value_to_value")
# D201's carrier typedef states where the machine leaves a result and claims no C type (doc/adr-scratch-result.md);
# D165's hole typedef states a slot the body never reads and claims none either (doc/adr-call-boundary.md);
# D265's word typedef states an integer's width and no sign, alone or as a pointee.
UNPROVEN_RESULT = re.compile(r"r2sleigh_result_u\d+|r2sleigh_unread_[uf]\d+")
UNSTATED_WORD = re.compile(r"r2sleigh_word_u(\d+)")


def unproven(actual: c_types.CType) -> bool:
    """A type spelled through a carrier or hole typedef: the engine marks it unproven, so it is no silent claim."""
    return actual.kind == c_types.NAMED and UNPROVEN_RESULT.fullmatch(actual.name) is not None


def unstated_sign(expected: c_types.CType, actual: c_types.CType) -> bool:
    """The word typedef where the source has an integer of its width, at the same pointer depth: only the sign is left
    unstated, which the word marks."""
    while expected.kind == actual.kind == c_types.PTR and expected.target is not None and actual.target is not None:
        expected, actual = expected.target, actual.target
    word = UNSTATED_WORD.fullmatch(actual.name) if actual.kind == c_types.NAMED else None
    return word is not None and expected.kind == c_types.INT and expected.width * 8 == int(word.group(1))


def claimed(actual: c_types.CType) -> c_types.CType:
    """The word typedef as the unsigned integer it is: everywhere it does not stand for an unstated sign, it claims that
    integer, so a pointer or width it gets wrong is graded as any other spelling's."""
    if actual.kind == c_types.PTR and actual.target is not None:
        return dataclasses.replace(actual, target=claimed(actual.target))
    word = UNSTATED_WORD.fullmatch(actual.name) if actual.kind == c_types.NAMED else None
    if word is None:
        return actual
    return c_types.CType(c_types.INT, int(word.group(1)) // 8, False)


@dataclass
class Tally:
    """What `score` records beyond the four counts."""

    # The silent errors, spelled as the baseline records them.
    silent: list[str] = field(default_factory=list)
    # Marked and silent errors by role and bucket.
    wrong: dict[str, dict[str, dict[str, int]]] = field(default_factory=dict)
    # Return presence, void or value, truth to recovered.
    presence: dict[str, dict[str, int]] = field(
        default_factory=lambda: {cell: {"total": 0, "silent": 0} for cell in PRESENCE}
    )


def score(truth: dict[int, Declared],
          recovered: dict[int, Seen],
          tally: Tally | None = None) -> dict[str, int]:
    """Count every fact as correct, missing, marked wrong or silently wrong.

    A claim resting on a premise (a closed-world `void`) is scored like any other: `pddj` states premises
    per function and no fact's basis, so none is attributed.
    """
    counts = {"correct": 0, "missing": 0, "marked_wrong": 0, "silently_wrong": 0}
    tally = tally if tally is not None else Tally()

    def judge(label: str, role: str, expected: c_types.CType, actual: c_types.CType | None, seen: Seen | None) -> None:
        """One fact. `actual` is None where the engine says nothing, which includes a function it did not render."""
        if actual is None:
            counts["missing"] += 1
            return
        if actual == expected:
            counts["correct"] += 1
            return
        word = unstated_sign(expected, actual)
        actual = actual if word else claimed(actual)
        marked = seen.marked or unproven(actual) or word
        how = "marked" if marked else "silent"
        counts["marked_wrong" if marked else "silently_wrong"] += 1
        kind = "unstated_sign" if word else c_types.classify(expected, actual)
        by_kind = tally.wrong.setdefault(how, {}).setdefault(role, {})
        by_kind[kind] = by_kind.get(kind, 0) + 1
        if not marked:
            # A silent error has to be nameable, or a gate that catches one
            # tells nobody which fact to go and look at.
            tally.silent.append(f"{label}: expected {c_types.spell(expected)!r}, said {c_types.spell(actual)!r}")

    for addr, source in truth.items():
        seen = recovered.get(addr)
        facts = [("return", "return", source.ret, seen.proto.ret if seen else None)] + [
            (f"parameter {index}", "parameter", expected,
             seen.proto.params[index] if seen and index < len(seen.proto.params) else None)
            for index, expected in enumerate(source.params)
        ]
        for label, role, expected, actual in facts:
            judge(f"{source.name} {label}", role, expected, actual, seen)
        if seen is not None:
            presence(tally, source.ret, seen.proto.ret, seen)
    return counts


def presence(tally: Tally, expected: c_types.CType, actual: c_types.CType, seen: Seen) -> None:
    """Does the function return a value at all: the question a proven `void` answers."""
    gone = (expected.kind == c_types.VOID, actual.kind == c_types.VOID)
    cell = tally.presence[f"{'void' if gone[0] else 'value'}_to_{'void' if gone[1] else 'value'}"]
    cell["total"] += 1
    if gone[0] != gone[1]:
        cell["silent"] += not (seen.marked or unproven(actual))


PLACEHOLDERS = {"todo", "tbd", "fixme", "xxx", "wip"}
MIN_CAUSE_WORDS = 3


def cause_is_stated(cause: object) -> bool:
    """A recorded cause is words about the fact: not a blank, a promise to write one, or a one-word shrug."""
    words = re.findall(r"\w+", cause) if isinstance(cause, str) else []
    return len(words) >= MIN_CAUSE_WORDS and words[0].lower() not in PLACEHOLDERS


def ordered(tally: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    """A tally with its keys sorted, so a report diffs the same on every run."""
    return {role: dict(sorted(kinds.items())) for role, kinds in sorted(tally.items())}


def refuse(message: str) -> int:
    print(f"refusing to score: {message}", file=sys.stderr)
    return 2


def partition(dwarf: Dwarf, placed: list, unplaced: list[Unplaced], called: dict[int, str]) -> tuple[dict[int, Declared], dict[str, list[str]]]:
    """The functions the gate grades, by entry, and every other function's name under the one reason it is not.

    A function DWARF cannot place, a DWARF the predicate refuses, two functions at one entry and a function the
    engine does not list on the debug build are all refused here, so none is graded by omission.
    """
    shared = Counter(sub.low_pc for sub in placed)
    truth: dict[int, Declared] = {}
    refused: dict[str, list[str]] = {}
    for gone in unplaced:
        refused.setdefault(gone.why, []).append(gone.name)
    for sub in placed:
        try:
            graded = declared(dwarf, sub)
        except Ungradable as error:
            refused.setdefault(error.reason, []).append(sub.name)
            continue
        if shared[sub.low_pc] > 1:
            refused.setdefault(SHARED, []).append(sub.name)
        elif sub.low_pc not in called:
            refused.setdefault(UNLISTED, []).append(sub.name)
        else:
            truth[sub.low_pc] = graded
    return truth, {reason: sorted(names) for reason, names in sorted(refused.items())}


def main() -> int:
    """Exit 0 or 1 on a verdict, 2 on anything else: CI accepts 0 and 1, and a Python traceback exits 1."""
    try:
        return grade()
    except Exception:
        traceback.print_exc()
        return 2


def grade() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--debug-build", type=Path, required=True,
                        help="build that kept its debug info; the ground truth")
    parser.add_argument("--stripped-build", type=Path, required=True,
                        help="same source, stripped; what the engine is given")
    parser.add_argument("--r2s", default="target/release/r2s")
    parser.add_argument("--binutils-prefix", default="",
                        help="prefix of readelf, which reads the DWARF (`g` for GNU binutils on macOS)")
    parser.add_argument("--json", type=Path, help="write the report here")
    parser.add_argument("--baseline", type=Path,
                        help="the silent errors already recorded, each with a cause")
    parser.add_argument("--accept-baseline", action="store_true",
                        help="record this run's silent errors, after reading them")
    args = parser.parse_args()

    try:
        called = listing(args.debug_build, args.r2s)
        dwarf, placed, unplaced = read_dwarf(args.debug_build, args.binutils_prefix)
        _, stripped_placed, stripped_unplaced = read_dwarf(args.stripped_build, args.binutils_prefix)
        if stripped_placed or stripped_unplaced:
            return refuse("the stripped build carries DWARF, so the engine would be graded against its own input.")
        ids = build_id(args.debug_build, args.binutils_prefix), build_id(args.stripped_build, args.binutils_prefix)
        if ids[0] is None or ids[0] != ids[1]:
            return refuse(f"the builds are not shown to be one program: build ID {ids[0]} against {ids[1]}.")
        truth, ungradable = partition(dwarf, placed, unplaced, called)
        why = "; ".join(f"{len(names)} {reason}" for reason, names in ungradable.items())
        if not truth:
            return refuse(f"no function of the debug build is gradable ({why or 'its DWARF declares no function'}).")
        # Every function with code counts, placed, shared or not: only an entry outside the loaded code is left out.
        defined = len(placed) + sum(gone.code for gone in unplaced)
        if len(truth) * GRADED_FLOOR < defined:
            return refuse(f"{len(truth)} of {defined} functions are gradable, under one in {GRADED_FLOOR} ({why}).")
        stripped = listing(args.stripped_build, args.r2s)
        recovered = signatures(args.stripped_build, [addr for addr in sorted(truth) if addr in stripped], args.r2s)
        if not recovered:
            return refuse("the engine recovered no function from the stripped build, so every fact would be missing.")
    except Unreadable as unreadable:
        causes = list(unreadable.causes.items())
        for where, cause in causes[:10]:
            print(f"UNREADABLE {unreadable.command}: {unreadable.binary}{' ' + where if where else ''}: {cause}",
                  file=sys.stderr)
        if len(causes) > 10:
            print(f"... and {len(causes) - 10} more", file=sys.stderr)
        return refuse(str(unreadable))
    tally = Tally()
    entries = {sub.low_pc for sub in placed}
    buckets = score(truth, recovered, tally)
    silent = tally.silent

    asserted = buckets["correct"] + buckets["silently_wrong"]
    facts = sum(buckets.values())  # a graded function states its result, so a gradable build has a fact
    # No stripped binary states `const`, so the rate is also given without the errors that only differ in a qualifier.
    qualifier = sum(kinds.get("qualifier", 0) for kinds in tally.wrong.get("silent", {}).values())
    report = {
        "functions_in_dwarf": len(placed) + len(unplaced),
        "functions_in_truth": len(truth),
        "functions_recovered": len(recovered),
        "ungradable": ungradable,
        "without_dwarf": sorted(name for addr, name in called.items() if addr not in entries),
        "facts": buckets,
        "recovery_rate": round(buckets["correct"] / facts, 4),
        "soundness_rate": round(1 - buckets["silently_wrong"] / asserted, 4) if asserted else 1.0,
        "soundness_without_qualifier": (
            round(1 - (buckets["silently_wrong"] - qualifier) / (asserted - qualifier), 4) if asserted > qualifier else 1.0
        ),
        "silent": silent,
        "silent_buckets": ordered(tally.wrong.get("silent", {})),
        "marked_buckets": ordered(tally.wrong.get("marked", {})),
        "marked_sign": sum(kinds.get("unstated_sign", 0) for kinds in tally.wrong.get("marked", {}).values()),
        "return_presence": tally.presence,
    }
    print(json.dumps(report, indent=2))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n")

    recorded = (
        json.loads(args.baseline.read_text())
        if args.baseline and args.baseline.exists()
        else {}
    )

    # Re-recording comes first: after the comparison the flag did nothing whenever a baseline existed.
    if args.accept_baseline and args.baseline:
        # A recorded cause outlives the run that found it: the causes of the errors still here carry forward.
        why = {fact: cause for fact, cause in recorded.get("why", {}).items() if cause_is_stated(cause)}
        args.baseline.write_text(
            json.dumps(
                {**report, "why": {fact: why[fact] for fact in silent if fact in why}},
                indent=2,
            )
            + "\n"
        )
        print(f"baseline accepted: {args.baseline}", file=sys.stderr)
        uncaused = [fact for fact in silent if fact not in why]
        for fact in uncaused:
            print(f"NO CAUSE: {fact}", file=sys.stderr)
        return 1 if uncaused else 0

    # A recorded silent error has a recorded cause, an unrecorded one is the failure this harness exists to catch.
    # The multiset keeps two functions that share a name apart; with no baseline every silent error is new.
    known = Counter(recorded.get("silent", []))
    new_silent = sorted((Counter(silent) - known).elements())
    causes = recorded.get("why", {})
    uncaused = sorted(fact for fact in known if not cause_is_stated(causes.get(fact)))
    fixed = sorted((known - Counter(silent)).elements())
    for fact in fixed:
        print(f"no longer silent: {fact}", file=sys.stderr)
    for fact in new_silent:
        print(f"SILENT ERROR: {fact}", file=sys.stderr)
    for fact in uncaused:
        print(f"NO CAUSE: {fact}", file=sys.stderr)
    if fixed and not new_silent:
        print("re-record the baseline with --accept-baseline", file=sys.stderr)
    return 1 if new_silent or uncaused else 0


if __name__ == "__main__":
    sys.exit(main())
