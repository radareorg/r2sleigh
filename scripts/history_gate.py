#!/usr/bin/env python3
"""Fail if an answer depends on the commands run before it (ROADMAP D573).

Every request answers in the closed world, so `pdd`, `pdf` and `afi` at an address are a function
of the bytes and the request. For each function of the list this runs each command alone, after
`aa`, after `afl`, and inside one session that asks the binary's whole list, forward and reversed,
and compares the bytes. The order runs cover what the database holds between requests.

The radare2 test binaries (`--bins`) and the repository's fixtures always run; DecBench's stripped
builds run where `--decbench` names the directory holding `O2/<project>/stripped/<binary>`.

Exit status: 0 every answer equal, 1 an answer that moved (the case and the first differing line
are printed), 2 a binary of the list is missing or a command of the list answers nothing alone.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import pathlib
import subprocess
import sys
import tomllib
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parent.parent
COMMANDS = ("pdd", "pdf", "afi")
PREFIXES = ("aa", "afl")
FAILED = "<r2s exit "
JUDGED = pathlib.Path(__file__).resolve().parent / "residual_shift_judged.toml"

# (radare2 test binary under --bins, address)
TESTBINS = (
    ("0pack", 0x62ECF0),
    ("0pack", 0x58E3D0),
    ("pumasim", 0x23FDF0),
    ("pumasim", 0x4BAF30),
    ("pumasim", 0x3B6B20),
    ("bash", 0x2E630),
    ("bash", 0x1E1D0),
)

# (fixture under the repository root, address): two AArch64 functions that call, as `afl` lists them.
FIXTURES = (
    ("tests/fixtures/member_call_gcc_aarch64_O2g", 0x400558),
    ("tests/fixtures/member_call_gcc_aarch64_O2g", 0x400600),
)

# gzip O2's 0x4990 beside the functions residual_shift_judged.toml lists.
DECBENCH_EXTRA = (("O2", "gzip_gzip", 0x4990),)


@dataclass(frozen=True)
class Case:
    """One function of one binary."""

    binary: pathlib.Path
    address: int

    def ask(self, command: str) -> str:
        return f"{command} @ {self.address:#x}"


def decbench_cases(directory: pathlib.Path) -> list[Case]:
    """The DecBench functions, each at `<set>/<project>/stripped/<binary>`."""
    rows = tomllib.loads(JUDGED.read_text())["function"]
    listed = [(row["set"], row["binary"], int(str(row["address"]), 16)) for row in rows]
    cases = []
    for build, name, address in listed + list(DECBENCH_EXTRA):
        project, binary = name.split("_", 1)
        cases.append(Case(directory / build / project / "stripped" / binary, address))
    return cases


def cases_of(bins: pathlib.Path, decbench: pathlib.Path | None) -> list[Case]:
    cases = [Case(bins / name, address) for name, address in TESTBINS]
    cases += [Case(ROOT / name, address) for name, address in FIXTURES]
    if decbench is not None:
        cases += decbench_cases(decbench)
    return cases


def scripts_of(case: Case) -> list[tuple[str, list[str]]]:
    """Each script run on its own and the alone scripts it must equal, concatenated."""
    plans = []
    for command in COMMANDS:
        alone = case.ask(command)
        plans += [(f"{prefix}; {alone}", [prefix, alone]) for prefix in PREFIXES]
    return plans


def session_of(cases: list[Case]) -> list[str]:
    """One session's commands: every command of every case, in order."""
    return [case.ask(command) for case in cases for command in COMMANDS]


def first_difference(one: str, other: str) -> tuple[int, str, str] | None:
    """The first line, 1-based, where two outputs differ, and each side's text of it."""
    left, right = one.splitlines(), other.splitlines()
    for number, (a, b) in enumerate(zip(left, right), start=1):
        if a != b:
            return number, a, b
    if len(left) != len(right) or one != other:
        number = min(len(left), len(right)) + 1
        pick = lambda lines: lines[number - 1] if number <= len(lines) else "<end>"  # noqa: E731
        return number, pick(left), pick(right)
    return None


def run(r2s: str, binary: pathlib.Path, script: str, timeout: int) -> str:
    done = subprocess.run(
        [r2s, "-q", "-c", script, str(binary)],
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    status = "" if done.returncode == 0 else f"{FAILED}{done.returncode}>\n"
    return done.stdout.decode("utf-8", "replace") + status


class Unanswered(Exception):
    """A command of the list that fails or prints nothing alone: the list names no function there."""


def check(r2s: str, cases: list[Case], jobs: int, timeout: int) -> list[str]:
    """Every difference, as one line naming the binary, the script and the first differing line."""
    asked = {(case.binary, case.ask(command)) for case in cases for command in COMMANDS}
    asked |= {(case.binary, prefix) for case in cases for prefix in PREFIXES}
    by_binary: dict[pathlib.Path, list[Case]] = {}
    for case in cases:
        by_binary.setdefault(case.binary, []).append(case)
    runs: list[tuple[pathlib.Path, str, list[str]]] = []
    for case in cases:
        runs += [(case.binary, script, alone) for script, alone in scripts_of(case)]
    for binary, listed in by_binary.items():
        forward = session_of(listed)
        reverse = session_of(list(reversed(listed)))
        runs.append((binary, "; ".join(forward), forward))
        runs.append((binary, "; ".join(reverse), reverse))
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        alone = {key: pool.submit(run, r2s, key[0], key[1], timeout) for key in sorted(asked)}
        for (binary, script), future in sorted(alone.items()):
            text = future.result()
            if script not in PREFIXES and (not text.strip() or FAILED in text):
                raise Unanswered(f"{binary.name}: `{script}` alone: {text.strip()[:200]!r}")
        ran = [(b, s, parts, pool.submit(run, r2s, b, s, timeout)) for b, s, parts in runs]
        differences = []
        for binary, script, parts, future in ran:
            expected = "".join(alone[(binary, part)].result() for part in parts)
            found = first_difference(expected, future.result())
            if found is not None:
                number, want, got = found
                differences.append(
                    f"{binary.name}: `{script}` line {number}: alone {want!r}, here {got!r}"
                )
    return differences


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--r2s", default=str(ROOT / "target/release/r2s"))
    parser.add_argument("--bins", type=pathlib.Path, required=True, help="radare2's test/bins/elf")
    parser.add_argument("--decbench", type=pathlib.Path, help="DecBench builds: O2/<project>/stripped")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    cases = cases_of(args.bins, args.decbench)
    missing = sorted({str(case.binary) for case in cases if not case.binary.is_file()})
    if missing:
        print("missing binaries: " + ", ".join(missing), file=sys.stderr)
        return 2
    try:
        differences = check(args.r2s, cases, args.jobs, args.timeout)
    except Unanswered as unanswered:
        print(f"unanswered: {unanswered}", file=sys.stderr)
        return 2
    for line in differences:
        print(line)
    print(f"history gate: {len(cases)} functions, {len(differences)} answers moved")
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
