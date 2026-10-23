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
    names: list[str] = field(default_factory=list)


@dataclass
class Seen:
    """What `pdd` and `pddj` say of one function."""

    proto: Prototype
    # The text carries a residual or a refusal: the marker the gate has always read.
    marked: bool
    # The premises the rendering assumed (`closed-world`); None where pddj could not be read.
    premises: tuple[str, ...] | None = ()
    # The basis pddj states for a parameter, by slot; empty where it states none.
    basis: dict[int, str] = field(default_factory=dict)


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


def split_top_level(args: str) -> list[str]:
    """Split a parameter list at the commas outside every bracket.

    `int (*f)(int, int), char *s` is two parameters: the comma inside the
    function pointer's own list belongs to that parameter.
    """
    parts: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(args):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(args[start:index])
            start = index + 1
    parts.append(args[start:])
    return parts


FUNCTION_POINTER = re.compile(r"\(\s*\*+\s*(?P<name>\w*)[^)]*\)")
TRAILING_NAME = re.compile(r"^(?P<type>.*[\s*])(?P<name>\w+)$")


def split_declarator(param: str) -> tuple[str, str]:
    """A parameter's type and its name, where it has one.

    A function pointer carries its name inside the `(*name)`; any other
    parameter ends in it, so `char *s` is `char *` and `s`.
    """
    param = param.strip()
    pointer = FUNCTION_POINTER.search(param)
    if pointer:
        return param[:pointer.start()] + "(*)" + param[pointer.end():], pointer.group("name")
    named = TRAILING_NAME.match(param)
    if named:
        return named.group("type"), named.group("name")
    return param, ""


def parse_prototype(line: str) -> Prototype | None:
    match = PROTOTYPE.match(line.strip())
    if not match:
        return None
    args = match.group("args").strip()
    params: list[str] = []
    names: list[str] = []
    if args and args != "void":
        for arg in split_top_level(args):
            spelling, name = split_declarator(arg)
            params.append(normalize_type(spelling))
            names.append(name)
    return Prototype(normalize_type(match.group("ret")), params, names)


# Byte widths of the spellings normalize_type leaves, and which are unsigned.
INTEGER_WIDTH = {
    "bool": 1, "_Bool": 1, "char": 1, "int8_t": 1, "uint8_t": 1,
    "short": 2, "int16_t": 2, "uint16_t": 2,
    "int": 4, "int32_t": 4, "uint32_t": 4, "unsigned": 4, "wint_t": 4,
    "long": 8, "int64_t": 8, "uint64_t": 8, "size_t": 8, "ssize_t": 8,
    "intptr_t": 8, "uintptr_t": 8, "ptrdiff_t": 8, "long long": 8,
}
UNSIGNED = {"bool", "_Bool", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "unsigned", "size_t", "uintptr_t"}
QUALIFIERS = re.compile(r"\b(?:const|volatile|restrict)\b")


def split_pointer(spelling: str) -> tuple[int, str]:
    """A type's pointer depth and the name beneath it, qualifiers dropped.

    A function pointer is one level over `(fn)`, whatever its parameter list.
    """
    text = QUALIFIERS.sub("", spelling)
    if "(*" in text:
        return 1, "(fn)"
    depth = text.count("*")
    return depth, " ".join(text.replace("*", " ").split())


def classify(expected: str, actual: str) -> str:
    """Which way a recovered type differs from the source's, so a fix is graded by the bucket it empties."""
    want_depth, want = split_pointer(expected)
    got_depth, got = split_pointer(actual)
    if (want == "void" and not want_depth) != (got == "void" and not got_depth):
        return "void_vs_value"
    if want_depth and not got_depth:
        return "pointer_as_integer"
    if got_depth and not want_depth:
        return "integer_as_pointer"
    if want_depth:
        return "qualifier" if (want_depth, want) == (got_depth, got) else "pointee"
    if want in INTEGER_WIDTH and got in INTEGER_WIDTH:
        if INTEGER_WIDTH[got] != INTEGER_WIDTH[want]:
            return "width_wider" if INTEGER_WIDTH[got] > INTEGER_WIDTH[want] else "width_narrower"
        return "sign"
    return "other"


# What the engine names a parameter it recovered with no declaration: `argN`
# as its own header spells it, the register that carries it at its entry
# version (`RDI_0`, `X0_0`, `W1_0`), a register Sleigh gives no name
# (`reg_4008_1_0`), or the caller's stack slot (`stack_p8`).
RECOVERED_PARAM_NAME = re.compile(
    r"^(?:arg\d+|(?:(?:[A-Z][A-Z0-9]*|reg_[0-9a-f_]+)_\d+)|stack_p\d+)$"
)


def truth_is_real(truth: dict[int, Prototype]) -> bool:
    """Refuse a debug build whose prototypes are the engine's own recovery.

    Debug info that fails to load looks exactly like debug info that says
    nothing: the debug build renders what the stripped one does, and scoring
    the two against each other reports no error at all. That is how a Mach-O
    run passed with every pointer parameter recovered as an integer: r2s does
    not read a separate `.dSYM`, so its "truth" was its own guess.

    Debug information names a parameter by its source name, and the engine,
    recovering one, names it by the register that carries it, so a truth in
    which no parameter has a source name was not read from debug information.
    """
    names = [name for proto in truth.values() for name in proto.names]
    return any(name and not RECOVERED_PARAM_NAME.match(name) for name in names)


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


def answer_of(body: str) -> tuple[str, dict | None]:
    """Split `pdd; pddj` output into the C text and the JSON line that ends it.

    The JSON spells the word `residual` in its keys, so it must not be read as the marker.
    """
    lines = body.rstrip().splitlines()
    if lines and lines[-1].startswith("{"):
        try:
            return "\n".join(lines[:-1]), json.loads(lines[-1])
        except json.JSONDecodeError:
            pass
    return body, None


def signatures(binary: Path, r2s_bin: str) -> dict[int, Seen]:
    """What each function renders as, whether it carries a marker, and what it assumed.

    One command per function rather than one per binary, because a refusal is
    per function and a batch that stops at the first one would score the rest
    as missing.
    """
    out: dict[int, Seen] = {}
    for addr in addresses(binary, r2s_bin):
        body, answer = answer_of(r2s(binary, f"s {addr:#x}; pdd; pddj", r2s_bin))
        lines = [line for line in body.splitlines() if line.strip()]
        if not lines:
            continue
        proto = parse_prototype(lines[0])
        if proto:
            marked = "residual" in body or "r2sleigh refused" in body
            premises = tuple(answer.get("premises", [])) if answer is not None else None
            basis = stated_basis(answer) if answer is not None else {}
            out[addr] = Seen(proto, marked, premises, basis)
    return out


def stated_basis(answer: dict) -> dict[int, str]:
    """The basis pddj states for each parameter slot, where it states one."""
    found = {}
    for variable in answer.get("variables", []):
        slot = variable.get("location", "")
        if variable.get("kind") == "param" and slot.startswith("arg:") and "basis" in variable:
            found[int(slot.removeprefix("arg:"))] = variable["basis"]
    return found


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
    return {addr: seen.proto for addr, seen in signatures(binary, r2s_bin).items()}


def recovered_from_stripped(binary: Path, r2s_bin: str) -> dict[int, Seen]:
    """What the engine recovers, whether it marked the function, and what it assumed."""
    return signatures(binary, r2s_bin)


PRESENCE = ("void_to_void", "void_to_value", "value_to_void", "value_to_value")


@dataclass
class Tally:
    """What `score` records beyond the four counts."""

    # The silent errors, spelled as the baseline records them.
    silent: list[str] = field(default_factory=list)
    # Marked and silent errors by role and bucket.
    wrong: dict[str, dict[str, dict[str, int]]] = field(default_factory=dict)
    # Return presence, void or value, truth to recovered.
    presence: dict[str, dict[str, int]] = field(
        default_factory=lambda: {cell: {"total": 0, "silent": 0, "premised": 0} for cell in PRESENCE}
    )
    # Facts of a function whose rendering assumed a premise, and the silent ones among them.
    premised: dict[str, int] = field(default_factory=lambda: {"claims": 0, "silent": 0})
    # Marked parameter facts by the basis pddj states for them.
    marked_basis: dict[str, int] = field(default_factory=dict)
    marked: int = 0


def score(truth: dict[int, Prototype],
          recovered: dict[int, Seen],
          tally: Tally | None = None,
          called: dict[int, str] | None = None) -> dict[str, int]:
    """Count every fact as correct, missing, marked wrong or silently wrong.

    The silent keys stay what the baseline records. A claim resting on a premise is scored like
    any other: the gate is not loosened for it, only counted.
    """
    counts = {"correct": 0, "missing": 0, "marked_wrong": 0, "silently_wrong": 0}
    tally = tally if tally is not None else Tally()

    def judge(label: str, role: str, expected: str, actual: str | None, seen: Seen,
              basis: str | None = None) -> None:
        premised = bool(seen.premises) and "closed-world" in seen.premises
        if actual is None:
            counts["missing"] += 1
            return
        tally.premised["claims"] += premised
        if actual == expected:
            counts["correct"] += 1
            return
        how = "marked" if seen.marked else "silent"
        counts["marked_wrong" if seen.marked else "silently_wrong"] += 1
        kind = classify(expected, actual)
        by_kind = tally.wrong.setdefault(how, {}).setdefault(role, {})
        by_kind[kind] = by_kind.get(kind, 0) + 1
        if seen.marked:
            tally.marked += 1
            if role == "parameter":
                tally.marked_basis[basis or "unstated"] = tally.marked_basis.get(basis or "unstated", 0) + 1
            else:
                tally.marked_basis["unstated"] = tally.marked_basis.get("unstated", 0) + 1
        else:
            tally.premised["silent"] += premised
            # A silent error has to be nameable, or a gate that catches one
            # tells nobody which fact to go and look at.
            tally.silent.append(f"{label}: expected {expected!r}, said {actual!r}")

    for addr, expected in truth.items():
        seen = recovered.get(addr)
        if seen is None:
            counts["missing"] += 1 + len(expected.params)
            continue
        actual = seen.proto
        where = (called or {}).get(addr) or f"{addr:#x}"
        judge(f"{where} return", "return", expected.ret, actual.ret, seen)
        presence(tally, expected.ret, actual.ret, seen)
        for index, param in enumerate(expected.params):
            got = actual.params[index] if index < len(actual.params) else None
            judge(f"{where} parameter {index}", "parameter", param, got, seen, seen.basis.get(index))
    return counts


def presence(tally: Tally, expected: str, actual: str, seen: Seen) -> None:
    """Does the function return a value at all: the question a proven `void` answers."""
    cell = tally.presence[
        f"{'void' if expected == 'void' else 'value'}_to_{'void' if actual == 'void' else 'value'}"
    ]
    cell["total"] += 1
    if (expected == "void") != (actual == "void"):
        cell["silent"] += not seen.marked
        cell["premised"] += bool(seen.premises) and "closed-world" in seen.premises


def ordered(tally: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    """A tally with its keys sorted, so a report diffs the same on every run."""
    return {role: dict(sorted(kinds.items())) for role, kinds in sorted(tally.items())}


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
        print("refusing to score: no parameter in the debug build has a source name, "
              "so its debug info did not load. r2s reads DWARF the binary itself "
              "carries, and not a separate .dSYM.",
              file=sys.stderr)
        return 2
    recovered = recovered_from_stripped(args.stripped_build, args.r2s)
    tally = Tally()
    buckets = score(truth, recovered, tally, names(args.debug_build, args.r2s))
    silent = tally.silent

    asserted = buckets["correct"] + buckets["silently_wrong"]
    facts = sum(buckets.values())
    report = {
        "functions_in_truth": len(truth),
        "functions_recovered": len(recovered),
        "facts": buckets,
        "recovery_rate": round(buckets["correct"] / facts, 4) if facts else 0.0,
        "soundness_rate": round(1 - buckets["silently_wrong"] / asserted, 4) if asserted else 1.0,
        "silent": silent,
        "silent_buckets": ordered(tally.wrong.get("silent", {})),
        "marked_buckets": ordered(tally.wrong.get("marked", {})),
        "marked_by": {
            "residual": tally.marked,
            "basis": dict(sorted(tally.marked_basis.items()))
            if any(seen.basis for seen in recovered.values()) else "unavailable",
        },
        "premised": tally.premised,
        "return_presence": tally.presence,
        "pddj_unreadable": sum(seen.premises is None for seen in recovered.values()),
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
